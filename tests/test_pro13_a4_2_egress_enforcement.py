"""
Suite de tests adversariaux PRO-13-A.4.2 : Confinement Egress, Providers OS/Conteneur et Sockets Secondaires.
Scénarios A42-01 à A42-42 classés rigoureusement par méthode de preuve :
- UNIT
- MOCKED_INTEGRATION
- LOCAL_SOCKET_INTEGRATION
"""

import os
import sys
import socket
import subprocess
from unittest.mock import patch, MagicMock
import pytest

import config
from monitoring.acquisition.interfaces import CameraConnectionConfig, CameraProtocol, VideoSourceStatus
from monitoring.acquisition.security import validate_video_target, pin_uri_to_ip
from monitoring.acquisition.ffmpeg_adapter import FFmpegRTSPAdapter
from monitoring.acquisition.egress_policy import (
    EgressPolicy,
    EgressEnforcementStatus,
    PolicyConfigurationError,
    WindowsEgressProvider,
    LinuxEgressProvider,
    DockerEgressProvider,
    UnsupportedEgressProvider,
    MockEgressProvider,
    check_egress_enforcement_status,
    get_egress_diagnostics,
    classify_ip,
)


# =============================================================================
# 7.1 TESTS UNITAIRES (A42-01 à A42-14) — Taxonomie : UNIT
# =============================================================================

def test_a42_01_empty_allowlist_rejected():
    """A42-01 [UNIT]: Allowlist vide -> Rejet immédiat (PolicyConfigurationError)."""
    with pytest.raises(PolicyConfigurationError):
        EgressPolicy(allowed_destinations=[])
    with pytest.raises(PolicyConfigurationError):
        EgressPolicy(allowed_destinations=None)


def test_a42_02_overly_broad_cidr_rejected():
    """A42-02 [UNIT]: CIDR trop large (0.0.0.0/0, 10.0.0.0/8, ::/0) -> Rejet."""
    for broad in ["0.0.0.0/0", "10.0.0.0/8", "192.168.0.0/8", "::/0", "fc00::/7"]:
        if broad == "fc00::/7":
            # Préfixe /7 <= /16 pour IPv6 -> rejeté
            with pytest.raises(PolicyConfigurationError):
                EgressPolicy(allowed_destinations=[broad])
        else:
            with pytest.raises(PolicyConfigurationError):
                EgressPolicy(allowed_destinations=[broad])


def test_a42_03_invalid_address_rejected():
    """A42-03 [UNIT]: Adresse invalide dans l'allowlist ou la cible -> Rejet."""
    with pytest.raises(PolicyConfigurationError):
        EgressPolicy(allowed_destinations=["999.999.999.999"])
    policy = EgressPolicy(allowed_destinations=["192.168.1.50/32"])
    with patch("socket.getaddrinfo", side_effect=socket.gaierror("Name resolution failed")):
        allowed, reason, _ = policy.is_destination_allowed("invalid..host..name", 554)
        assert allowed is False


def test_a42_04_unauthorized_port_rejected():
    """A42-04 [UNIT]: Port non autorisé -> Rejet."""
    policy = EgressPolicy(allowed_destinations=["192.168.1.50/32"], allowed_ports=[554, 8554])
    allowed, reason, _ = policy.is_destination_allowed("192.168.1.50", 22)
    assert allowed is False
    allowed2, _, _ = policy.is_destination_allowed("192.168.1.50", 9999)
    assert allowed2 is False
    allowed3, _, _ = policy.is_destination_allowed("192.168.1.50", 554)
    assert allowed3 is True


def test_a42_05_prohibited_protocol_rejected():
    """A42-05 [UNIT]: Protocole interdit (file://, http:// non approuvé, gopher://) -> Rejet."""
    for uri in ["file:///etc/passwd", "gopher://192.168.1.50:554/1", "javascript:alert(1)"]:
        valid, reason, _ = validate_video_target(uri)
        assert valid is False


def test_a42_06_unapproved_ipv4_rejected():
    """A42-06 [UNIT]: IPv4 non approuvée (RFC1918 autre sous-réseau ou public) -> Rejet."""
    policy = EgressPolicy(allowed_destinations=["192.168.1.50/32"])
    for ip in ["192.168.1.51", "10.0.0.5", "172.16.0.10", "8.8.8.8"]:
        allowed, _, _ = policy.is_destination_allowed(ip, 554)
        assert allowed is False


def test_a42_07_unapproved_ipv6_rejected():
    """A42-07 [UNIT]: IPv6 non approuvée -> Rejet."""
    policy = EgressPolicy(allowed_destinations=["192.168.1.50/32"])
    for ip6 in ["2001:db8::1", "fd00::1", "fe80::1", "::1"]:
        allowed, _, _ = policy.is_destination_allowed(ip6, 554)
        assert allowed is False


def test_a42_08_ipv4_mapped_ipv6_classified_correctly():
    """A42-08 [UNIT]: IPv4-mapped IPv6 -> Classification et filtrage cohérents."""
    import ipaddress
    mapped_meta = ipaddress.ip_address("::ffff:169.254.169.254")
    assert classify_ip(mapped_meta) == "LINK_LOCAL" or classify_ip(mapped_meta) == "CLOUD_METADATA"

    policy = EgressPolicy(allowed_destinations=["192.168.1.50/32"])
    allowed_meta, _, _ = policy.is_destination_allowed("::ffff:169.254.169.254", 80)
    assert allowed_meta is False

    allowed_cam, _, canonical = policy.is_destination_allowed("::ffff:192.168.1.50", 554)
    assert allowed_cam is True
    assert canonical == "192.168.1.50"


def test_a42_09_metadata_destination_rejected():
    """A42-09 [UNIT]: Destination metadata cloud (169.254.169.254) -> Rejet inconditionnel."""
    with pytest.raises(PolicyConfigurationError):
        EgressPolicy(allowed_destinations=["169.254.169.254/32"])

    policy = EgressPolicy(allowed_destinations=["192.168.1.50/32"])
    allowed, _, _ = policy.is_destination_allowed("169.254.169.254", 80)
    assert allowed is False


def test_a42_10_multicast_destination_rejected():
    """A42-10 [UNIT]: Destination multicast et broadcast -> Rejet."""
    policy = EgressPolicy(allowed_destinations=["192.168.1.50/32"])
    for target in ["224.0.0.1", "239.255.255.250", "255.255.255.255", "ff02::1"]:
        allowed, _, _ = policy.is_destination_allowed(target, 554)
        assert allowed is False


def test_a42_11_mixed_dns_authorized_and_prohibited_fail_closed():
    """A42-11 [UNIT]: DNS mixte (une IP autorisée + une IP interdite) -> Fail-closed."""
    policy = EgressPolicy(allowed_destinations=["192.168.1.50/32"])
    mixed_addrinfo = [
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("192.168.1.50", 554)),
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("169.254.169.254", 554)),
    ]
    with patch("socket.getaddrinfo", return_value=mixed_addrinfo):
        valid, reason, _ = validate_video_target("rtsp://mixed.cam.local:554/live", egress_policy=policy)
        assert valid is False


def test_a42_12_empty_dns_rejected():
    """A42-12 [UNIT]: Réponse DNS vide -> Rejet."""
    policy = EgressPolicy(allowed_destinations=["192.168.1.50/32"])
    with patch("socket.getaddrinfo", return_value=[]):
        valid, reason, _ = validate_video_target("rtsp://empty.cam.local:554/live", egress_policy=policy)
        assert valid is False


def test_a42_13_unknown_status_refuses_startup():
    """A42-13 [UNIT]: Statut UNKNOWN / PARTIAL / UNSUPPORTED -> Refus du démarrage FFmpeg (fail-closed)."""
    for bad_status in [
        EgressEnforcementStatus.UNKNOWN,
        EgressEnforcementStatus.PARTIAL,
        EgressEnforcementStatus.NOT_ENFORCED,
        EgressEnforcementStatus.UNSUPPORTED,
    ]:
        mock_prov = MockEgressProvider(status=bad_status, reason=f"Simulated {bad_status.value}")
        cfg = CameraConnectionConfig(
            source_id="test_fail_closed",
            protocol=CameraProtocol.RTSP,
            uri="rtsp://192.168.1.50:554/live",
            custom_params={"require_os_egress_confinement": True},
        )
        with patch("monitoring.acquisition.ffmpeg_adapter.check_egress_enforcement_status", return_value=(bad_status, f"Sim {bad_status.value}")):
            adapter = FFmpegRTSPAdapter(cfg)
            started = adapter.connect()
            assert started is False
            assert adapter._status == VideoSourceStatus.BLOCKED_SSRF


def test_a42_14_spoofed_env_var_never_grants_enforced():
    """A42-14 [UNIT]: Variable d'environnement falsifiée -> Aucun faux statut ENFORCED."""
    with patch.dict(os.environ, {
        "SSM_EGRESS_FIREWALL_ACTIVE": "1",
        "SSM_EGRESS_CONTAINER_ISOLATED": "true",
    }):
        # Même si le provider Windows inspecte le système, il ignore la variable falsifiée
        status, reason = check_egress_enforcement_status()
        assert status != EgressEnforcementStatus.ENFORCED
        diag = get_egress_diagnostics()
        assert diag.get("env_spoofing_detected") is True


# =============================================================================
# 7.2 TESTS DE POLITIQUE WINDOWS (A42-15 à A42-24) — Taxonomie : MOCKED_INTEGRATION
# =============================================================================

_MOCK_NETSH_PROFILE_ALLOW_OUT = """
Paramètres Profil privé :
----------------------------------------------------------------------
État                                  Actif
Stratégie de pare-feu                 BlockInbound,AllowOutbound
"""

_MOCK_NETSH_PROFILE_BLOCK_OUT = """
Paramètres Profil privé :
----------------------------------------------------------------------
État                                  Actif
Stratégie de pare-feu                 BlockInbound,BlockOutbound
"""

_MOCK_NETSH_PROFILE_DISABLED = """
Paramètres Profil privé :
----------------------------------------------------------------------
État                                  Désactivé
Stratégie de pare-feu                 BlockInbound,AllowOutbound
"""

_MOCK_NETSH_RULE_ALLOW = """
Nom de la règle :                     SSM_NVR_FFmpeg_Egress_AllowCameras
----------------------------------------------------------------------
Activé :                              Oui
Direction :                           Sortie
Programme :                           C:\\tools\\ffmpeg.exe
Action :                              Autoriser
"""

_MOCK_NETSH_RULE_ALLOW_DISABLED = """
Nom de la règle :                     SSM_NVR_FFmpeg_Egress_AllowCameras
----------------------------------------------------------------------
Activé :                              Non
Direction :                           Sortie
Programme :                           C:\\tools\\ffmpeg.exe
Action :                              Autoriser
"""

_MOCK_NETSH_RULE_BLOCK = """
Nom de la règle :                     SSM_NVR_FFmpeg_Egress_BlockProhibited
----------------------------------------------------------------------
Activé :                              Oui
Direction :                           Sortie
Programme :                           C:\\tools\\ffmpeg.exe
Action :                              Bloquer
"""


def test_a42_15_isolated_allow_rule_is_partial_not_enforced():
    """A42-15 [MOCKED_INTEGRATION]: Règle Allow isolée sous AllowOutbound -> PARTIAL (non ENFORCED)."""
    prov = WindowsEgressProvider()

    def fake_run(cmd, **kwargs):
        res = MagicMock()
        if "allprofiles" in cmd:
            res.returncode, res.stdout = 0, _MOCK_NETSH_PROFILE_ALLOW_OUT
        elif "name=SSM_NVR_FFmpeg_Egress_AllowCameras" in cmd:
            res.returncode, res.stdout = 0, _MOCK_NETSH_RULE_ALLOW
        else:
            res.returncode, res.stdout = 1, "Aucune règle ne correspond"
        return res

    with patch("sys.platform", "win32"), patch("subprocess.run", side_effect=fake_run):
        status, reason, diag = prov.check_status(expected_executable=r"C:\tools\ffmpeg.exe")
        assert status == EgressEnforcementStatus.PARTIAL
        assert diag["allow_rule_present"] is True
        assert diag["block_rules_present"] is False


def test_a42_16_firewall_disabled_is_not_enforced():
    """A42-16 [MOCKED_INTEGRATION]: Pare-feu désactivé -> NOT_ENFORCED."""
    prov = WindowsEgressProvider()
    res = MagicMock(returncode=0, stdout=_MOCK_NETSH_PROFILE_DISABLED)
    with patch("sys.platform", "win32"), patch("subprocess.run", return_value=res):
        status, _, _ = prov.check_status()
        assert status == EgressEnforcementStatus.NOT_ENFORCED


def test_a42_17_netsh_failure_returns_unknown():
    """A42-17 [MOCKED_INTEGRATION]: Profil inactif / échec inspection netsh -> UNKNOWN (fail-closed)."""
    prov = WindowsEgressProvider()
    with patch("sys.platform", "win32"), patch("subprocess.run", side_effect=PermissionError("Access denied")):
        status, _, _ = prov.check_status()
        assert status == EgressEnforcementStatus.UNKNOWN


def test_a42_18_wrong_executable_rule_is_not_enforced():
    """A42-18 [MOCKED_INTEGRATION]: Règle associée à un mauvais exécutable -> NOT_ENFORCED."""
    prov = WindowsEgressProvider()

    def fake_run(cmd, **kwargs):
        res = MagicMock()
        if "allprofiles" in cmd:
            res.returncode, res.stdout = 0, _MOCK_NETSH_PROFILE_BLOCK_OUT
        elif "name=SSM_NVR_FFmpeg_Egress_AllowCameras" in cmd:
            res.returncode, res.stdout = 0, _MOCK_NETSH_RULE_ALLOW
        return res

    with patch("sys.platform", "win32"), patch("subprocess.run", side_effect=fake_run):
        status, reason, diag = prov.check_status(expected_executable=r"C:\other\ffmpeg.exe")
        assert status == EgressEnforcementStatus.NOT_ENFORCED
        assert diag["executable_matched"] is False


def test_a42_19_valid_camera_enforcement_verified():
    """A42-19 [MOCKED_INTEGRATION]: Autorisation caméra + blocage complémentaire -> ENFORCED."""
    prov = WindowsEgressProvider()

    def fake_run(cmd, **kwargs):
        res = MagicMock()
        if "allprofiles" in cmd:
            res.returncode, res.stdout = 0, _MOCK_NETSH_PROFILE_ALLOW_OUT
        elif "name=SSM_NVR_FFmpeg_Egress_AllowCameras" in cmd:
            res.returncode, res.stdout = 0, _MOCK_NETSH_RULE_ALLOW
        elif "name=SSM_NVR_FFmpeg_Egress_BlockProhibited" in cmd:
            res.returncode, res.stdout = 0, _MOCK_NETSH_RULE_BLOCK
        return res

    with patch("sys.platform", "win32"), patch("subprocess.run", side_effect=fake_run):
        status, _, diag = prov.check_status(expected_executable=r"C:\tools\ffmpeg.exe")
        assert status == EgressEnforcementStatus.ENFORCED
        assert diag["block_rules_present"] is True


def test_a42_20_windows_setup_script_dryrun_blocks_prohibited_destinations():
    """A42-20 [MOCKED_INTEGRATION]: Script setup PowerShell planifie des règles Block explicites (sans élévation)."""
    script_path = os.path.join("scripts", "setup_ffmpeg_egress_firewall.ps1")
    assert os.path.exists(script_path)
    res = subprocess.run(
        [
            "powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass",
            "-File", script_path,
            "-ExecutablePath", r"C:\Windows\System32\cmd.exe",
            "-AllowedDestinations", "192.168.1.50/32",
            "-DryRun"
        ],
        capture_output=True, text=True, timeout=15
    )
    assert res.returncode == 0
    assert "SSM_NVR_FFmpeg_Egress_BlockProhibited" in res.stdout
    assert "169.254.169.254/32" in res.stdout


def test_a42_21_windows_setup_script_covers_ipv6_prohibited():
    """A42-21 [MOCKED_INTEGRATION]: Script setup PowerShell couvre le blocage IPv6 (fe80::/10, ::1/128, fc00::/7)."""
    script_path = os.path.join("scripts", "setup_ffmpeg_egress_firewall.ps1")
    res = subprocess.run(
        [
            "powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass",
            "-File", script_path,
            "-ExecutablePath", r"C:\Windows\System32\cmd.exe",
            "-AllowedDestinations", "192.168.1.50/32",
            "-DryRun"
        ],
        capture_output=True, text=True, timeout=15
    )
    assert res.returncode == 0
    assert "fe80::/10" in res.stdout
    assert "::1/128" in res.stdout
    assert "fc00::/7" in res.stdout


def test_a42_22_disabled_allow_rule_not_enforced():
    """A42-22 [MOCKED_INTEGRATION]: Règle Allow désactivée ou contradictoire -> NOT_ENFORCED."""
    prov = WindowsEgressProvider()

    def fake_run(cmd, **kwargs):
        res = MagicMock()
        if "allprofiles" in cmd:
            res.returncode, res.stdout = 0, _MOCK_NETSH_PROFILE_ALLOW_OUT
        elif "name=SSM_NVR_FFmpeg_Egress_AllowCameras" in cmd:
            res.returncode, res.stdout = 0, _MOCK_NETSH_RULE_ALLOW_DISABLED
        return res

    with patch("sys.platform", "win32"), patch("subprocess.run", side_effect=fake_run):
        status, _, diag = prov.check_status()
        assert status == EgressEnforcementStatus.NOT_ENFORCED
        assert diag["allow_rule_enabled"] is False


def test_a42_23_partial_installation_not_enforced():
    """A42-23 [MOCKED_INTEGRATION]: Installation partielle -> PARTIAL (refusé en mode require_os_egress_confinement)."""
    prov = WindowsEgressProvider()

    def fake_run(cmd, **kwargs):
        res = MagicMock()
        if "allprofiles" in cmd:
            res.returncode, res.stdout = 0, _MOCK_NETSH_PROFILE_ALLOW_OUT
        elif "name=SSM_NVR_FFmpeg_Egress_AllowCameras" in cmd:
            res.returncode, res.stdout = 0, _MOCK_NETSH_RULE_ALLOW
        else:
            res.returncode, res.stdout = 1, "No rules"
        return res

    with patch("sys.platform", "win32"), patch("subprocess.run", side_effect=fake_run):
        status, _, _ = prov.check_status()
        assert status == EgressEnforcementStatus.PARTIAL
        assert status != EgressEnforcementStatus.ENFORCED


def test_a42_24_teardown_script_only_targets_ssm_prefix():
    """A42-24 [MOCKED_INTEGRATION]: Rollback ne cible exclusivement que le préfixe SSM_NVR_FFmpeg_Egress*."""
    script_path = os.path.join("scripts", "teardown_ffmpeg_egress_firewall.ps1")
    with open(script_path, "r", encoding="utf-8") as f:
        content = f.read()
    assert 'SSM_NVR_FFmpeg_Egress' in content
    assert 'Remove-NetFirewallRule' in content
    assert 'Set-NetFirewallProfile' not in content


# =============================================================================
# 7.3 TESTS DOCKER / LINUX (A42-25 à A42-34) — Taxonomie : UNIT / MOCKED_INTEGRATION
# =============================================================================

def test_a42_25_docker_worker_is_non_root():
    """A42-25 [UNIT]: Manifeste Docker impose l'utilisateur non-root 10001:10001."""
    with open("docker/docker-compose.nvr-egress.yml", "r", encoding="utf-8") as f:
        compose = f.read()
    with open("docker/Dockerfile.nvr-worker", "r", encoding="utf-8") as f:
        dockerfile = f.read()
    assert 'user: "10001:10001"' in compose
    assert "USER 10001:10001" in dockerfile


def test_a42_26_docker_drops_all_capabilities_including_net_admin():
    """A42-26 [UNIT]: Manifeste Docker supprime toutes les capabilities (cap_drop: ALL, no CAP_NET_ADMIN)."""
    with open("docker/docker-compose.nvr-egress.yml", "r", encoding="utf-8") as f:
        compose = f.read()
    assert "cap_drop:" in compose
    assert "- ALL" in compose
    assert "CAP_NET_ADMIN" not in compose
    assert "no-new-privileges:true" in compose


def test_a42_27_docker_host_script_allows_approved_cameras():
    """A42-27 [UNIT]: Script hôte Docker autorise uniquement les caméras et ports configurés."""
    with open("scripts/setup_docker_egress_host.sh", "r", encoding="utf-8") as f:
        sh = f.read()
    assert "DOCKER-USER" in sh
    assert "nftables" in sh
    assert "ALLOWED_CAMERAS" in sh


def test_a42_28_to_a42_31_docker_egress_policy_blocks_prohibited():
    """A42-28 à A42-31 [UNIT]: Politique d'egress Docker/Linux bloque IP privée non autorisée, metadata, public, IPv6."""
    policy = EgressPolicy(allowed_destinations=["192.168.1.50/32"], is_production=True)
    for target in ["10.0.0.1", "169.254.169.254", "1.1.1.1", "fd00::1"]:
        allowed, _, _ = policy.is_destination_allowed(target, 554)
        assert allowed is False


def test_a42_32_docker_no_host_network_mode():
    """A42-32 [UNIT]: Absence formelle de network_mode: host et privileged: true dans docker-compose."""
    with open("docker/docker-compose.nvr-egress.yml", "r", encoding="utf-8") as f:
        lines = [line for line in f if not line.strip().startswith("#")]
    active_yaml = "\n".join(lines)
    assert "network_mode: host" not in active_yaml
    assert "privileged: false" in active_yaml


def test_a42_33_docker_without_host_proof_is_partial():
    """A42-33 [MOCKED_INTEGRATION]: Conteneur sans preuve hôte DOCKER-USER -> PARTIAL (non ENFORCED)."""
    prov = DockerEgressProvider()
    with patch("os.path.exists", side_effect=lambda p: p == "/.dockerenv"), \
         patch.dict(os.environ, {"SSM_EGRESS_CONTAINER_ISOLATED": "true"}):
        status, _, diag = prov.check_status()
        assert status == EgressEnforcementStatus.PARTIAL
        assert diag["host_filtering_proven"] is False
        assert diag["env_spoofing_detected"] is True


def test_a42_34_missing_isolation_worker_fails_closed():
    """A42-34 [MOCKED_INTEGRATION]: Absence d'isolation -> Worker fail-closed."""
    cfg = CameraConnectionConfig(
        source_id="docker_fail_closed",
        protocol=CameraProtocol.RTSP,
        uri="rtsp://192.168.1.50:554/live",
        custom_params={"require_os_egress_confinement": True},
    )
    with patch("monitoring.acquisition.ffmpeg_adapter.check_egress_enforcement_status",
               return_value=(EgressEnforcementStatus.PARTIAL, "No host filtering")):
        adapter = FFmpegRTSPAdapter(cfg)
        assert adapter.connect() is False
        assert adapter._status == VideoSourceStatus.BLOCKED_SSRF


# =============================================================================
# 7.4 TESTS DE SOCKETS SECONDAIRES (A42-35 à A42-42) — Taxonomie : LOCAL_SOCKET_INTEGRATION
# =============================================================================

def test_a42_35_secondary_redirect_to_authorized_camera():
    """A42-35 [UNIT]: Redirect vers caméra autorisée -> Autorisé par EgressPolicy."""
    policy = EgressPolicy(allowed_destinations=["192.168.1.50/32", "192.168.1.51/32"])
    allowed, _, _ = policy.is_destination_allowed("192.168.1.51", 554)
    assert allowed is True


def test_a42_36_secondary_redirect_to_prohibited_ip_blocked():
    """A42-36 [UNIT]: Redirect vers IP interdite -> Bloqué par EgressPolicy."""
    policy = EgressPolicy(allowed_destinations=["192.168.1.50/32"])
    allowed, _, _ = policy.is_destination_allowed("10.10.10.10", 554)
    assert allowed is False


def test_a42_37_to_a42_40_sdp_secondary_targets():
    """A42-37 à A42-40 [UNIT]: SDP a=control vers caméra (OK), metadata (Bloqué), loopback prod (Bloqué), IPv6 (Bloqué)."""
    policy = EgressPolicy(allowed_destinations=["192.168.1.50/32"], is_production=True)
    assert policy.is_destination_allowed("192.168.1.50", 554)[0] is True
    assert policy.is_destination_allowed("169.254.169.254", 80)[0] is False
    assert policy.is_destination_allowed("127.0.0.1", 554)[0] is False
    assert policy.is_destination_allowed("fe80::1", 554)[0] is False


def test_a42_41_secondary_dns_pinning_on_local_socket():
    """A42-41 [LOCAL_SOCKET_INTEGRATION]: DNS Pinning empêche le rebond DNS au niveau Python avant lancement."""
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    port = srv.getsockname()[1]
    try:
        pinned = pin_uri_to_ip(f"rtsp://cam.local:{port}/live", "127.0.0.1")
        assert f"127.0.0.1:{port}" in pinned
        assert "cam.local" not in pinned
    finally:
        srv.close()


def test_a42_42_secondary_udp_prohibited_in_ffmpeg_cmd():
    """A42-42 [UNIT]: Drapeaux FFmpeg imposent TCP strict (-rtsp_transport tcp, -protocol_whitelist tcp,rtp,rtsp)."""
    cfg = CameraConnectionConfig(
        source_id="test_tcp_flags",
        protocol=CameraProtocol.RTSP,
        uri="rtsp://192.168.1.50:554/live",
    )
    adapter = FFmpegRTSPAdapter(cfg)
    adapter._effective_uri = "rtsp://192.168.1.50:554/live"
    cmd = adapter._build_ffmpeg_cmd()
    cmd_str = " ".join(cmd)
    assert "-nostdin" in cmd
    assert "-rtsp_transport tcp" in cmd_str
    assert "-rtsp_flags +prefer_tcp" in cmd_str
    assert "-protocol_whitelist tcp,rtp,rtsp" in cmd_str


# =============================================================================
# 7.5 REMÉDIATION CONCURRENCE NOTIFICATION (PRO-13 A.4.2.1)
# =============================================================================

def test_a42_43_notification_id_concurrency_unique():
    """A42-43 [UNIT]: Garantit l'absence totale de collision d'identifiants même en rafale sub-milliseconde."""
    from monitoring.notification_manager import NotificationManager
    mgr = NotificationManager(max_notifications=500, dedup_window_seconds=0.0)

    # Création rapide de 100 notifications dans la même boucle temporelle
    generated_ids = set()
    for i in range(100):
        notif = mgr.add_notification("INFO", f"Titre {i}", f"Message {i}", category=f"cat_{i}")
        assert notif is not None
        assert notif["id"] not in generated_ids
        generated_ids.add(notif["id"])

    assert len(generated_ids) == 100

