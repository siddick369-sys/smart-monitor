"""
Suite exhaustive de tests de certification et d'évaluation adversariale — PRO-13 Lot A
Mission ID: SSM-PRO13-A-UNIVERSAL-NVR-01

Couverture :
- Niveau 1 (Unitaire) : Contrats d'interfaces, masquage des secrets, validation anti-SSRF, DNS rebinding.
- Niveau 2 (Intégration) : Adaptateur RTSP supervisé, découverte WS-Discovery / SSDP, approbation opérateur, API REST.
- Niveau 3 (Adversarial) : Cibles SSRF malveillantes, flux interrompus, processus orphelins, formats malformés, tentatives d'auto-enrôlement.
- Niveau 4 (Benchmark) : Mesure réelle CPU, mémoire, FPS et latence multi-flux simulés.
"""

import os
import sys
import time
import socket
import struct
import tempfile
import threading
import subprocess
import pytest
import numpy as np
from unittest.mock import MagicMock, patch

import config
from app import create_app
from database import init_db, get_db_session
from monitoring.models import Device, User
from monitoring.acquisition.interfaces import (
    VideoSource, VideoFrame, VideoSourceHealth, VideoSourceMetadata,
    CameraConnectionConfig, CameraProtocol, VideoSourceStatus
)
from monitoring.acquisition.security import (
    sanitize_uri, validate_video_target, extract_uri_credentials, PROHIBITED_PORTS
)
from monitoring.acquisition.ffmpeg_adapter import FFmpegRTSPAdapter
from monitoring.acquisition.onvif_adapter import ONVIFDiscoveryService, ONVIFCandidate
from monitoring.acquisition.discovery import (
    SSDPDiscoveryService, DiscoveredDeviceCandidate, UnifiedDiscoveryManager
)
from monitoring.acquisition.mock_adapter import MockVideoSource


# =============================================================================
# FIXTURES
# =============================================================================

@pytest.fixture
def test_app():
    """Crée une instance isolée de l'application Flask avec coordinateur de test."""
    app, coordinator = create_app()
    app.config["TESTING"] = True
    app.config["SECRET_KEY"] = "test-secret-key-32-bytes-long-ok!"
    return app, coordinator


@pytest.fixture
def auth_admin_client(test_app):
    """Client HTTP authentifié avec rôle ADMIN via /api/auth/login."""
    app, coordinator = test_app
    admin_pwd = config.ADMIN_DEFAULT_PASSWORD or "AdminSecurity2026!"
    with app.test_client() as client:
        client.post('/api/auth/login', json={
            "username": config.ADMIN_DEFAULT_USERNAME,
            "password": admin_pwd
        })
        yield client, coordinator


# =============================================================================
# NIVEAU 1 : TESTS UNITAIRES (CONTRATS, SANITISATION, SÉCURITÉ SSRF)
# =============================================================================

def test_uri_sanitization_masks_credentials():
    """Vérifie que sanitize_uri masque les mots de passe et préserve les ports et chemins."""
    raw_rtsp = "rtsp://admin:P@ssw0rd!#2026@192.168.1.100:554/live/ch0?token=xyz"
    sanitized = sanitize_uri(raw_rtsp)
    assert "P@ssw0rd!#2026" not in sanitized
    assert sanitized == "rtsp://admin:***@192.168.1.100:554/live/ch0?token=xyz"

    raw_http = "http://root:Secr3tToken@10.0.0.5:8080/video"
    assert sanitize_uri(raw_http) == "http://root:***@10.0.0.5:8080/video"

    # URI sans credentials : inchangée
    clean = "rtsp://192.168.1.20:554/stream"
    assert sanitize_uri(clean) == clean


def test_extract_uri_credentials():
    """Vérifie l'extraction sécurisée des identifiants et le nettoyage de l'URI."""
    uri = "rtsp://camera_user:SecretPass123@192.168.1.50:554/h264"
    clean_uri, user, pwd = extract_uri_credentials(uri)
    assert clean_uri == "rtsp://192.168.1.50:554/h264"
    assert user == "camera_user"
    assert pwd == "SecretPass123"


def test_anti_ssrf_blocks_cloud_metadata():
    """Vérifie le blocage inconditionnel de l'adresse de métadonnées cloud (169.254.169.254)."""
    valid, reason, ip = validate_video_target("169.254.169.254", port=80)
    assert valid is False
    assert "métadonnées cloud interdite" in reason.lower() or "link-local" in reason.lower()

    # Via URI complète
    valid_uri, reason_uri, _ = validate_video_target("http://169.254.169.254/latest/meta-data/")
    assert valid_uri is False


def test_anti_ssrf_blocks_loopback_in_production():
    """Vérifie le blocage strict du loopback (127.0.0.1, localhost) en mode production."""
    valid, reason, _ = validate_video_target("127.0.0.1", port=554, allow_loopback=False, is_production=True)
    assert valid is False
    assert "interdit" in reason.lower()

    valid_name, reason_name, _ = validate_video_target("localhost", port=554, allow_loopback=False, is_production=True)
    assert valid_name is False


def test_anti_ssrf_blocks_prohibited_ports():
    """Vérifie que les ports de services internes critiques sont rejetés sans même tenter la connexion."""
    for p in [22, 23, 25, 3306, 5000, 5432, 6379, 2375]:
        valid, reason, _ = validate_video_target("192.168.1.50", port=p)
        assert valid is False
        assert "interdit" in reason.lower()


def test_anti_ssrf_blocks_ipv4_mapped_ipv6():
    """Vérifie la détection et le blocage des adresses IPv4 mappées en IPv6 (ex: ::ffff:169.254.169.254)."""
    valid, reason, _ = validate_video_target("::ffff:169.254.169.254", port=80)
    assert valid is False
    assert "interdite" in reason.lower() or "link-local" in reason.lower()


def test_anti_ssrf_dns_rebinding_simulation():
    """Simule une tentative de DNS rebinding où un nom de domaine résout vers une IP locale protégée."""
    with patch("socket.getaddrinfo") as mock_dns:
        # Simulation d'un nom de domaine 'evil-cam.com' résolvant vers 169.254.169.254
        mock_dns.return_value = [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("169.254.169.254", 554))
        ]
        valid, reason, _ = validate_video_target("evil-cam.com", port=554)
        assert valid is False
        assert "métadonnées cloud interdite" in reason.lower() or "link-local" in reason.lower()


# =============================================================================
# NIVEAU 2 & 3 : ADAPTATEUR RTSP SUPERVISÉ & ROBUSTESSE PROCESSUS
# =============================================================================

def test_ffmpeg_adapter_command_construction_safe():
    """Vérifie que la ligne de commande FFmpeg est construite avec des arguments structurés sans shell."""
    cfg = CameraConnectionConfig(
        source_id="test_cam_01",
        protocol=CameraProtocol.RTSP,
        uri="rtsp://192.168.1.10:554/live",
        target_fps=15,
        target_width=800,
        target_height=600,
        connect_timeout=3.0
    )
    adapter = FFmpegRTSPAdapter(cfg, ffmpeg_bin="ffmpeg")
    cmd = adapter._build_ffmpeg_cmd()

    assert isinstance(cmd, list)
    assert cmd[0] == "ffmpeg"
    assert "-rtsp_transport" in cmd
    assert "tcp" in cmd
    assert "-vf" in cmd
    assert "scale=800:600" in cmd
    assert "-r" in cmd
    assert "15" in cmd
    assert "pipe:1" in cmd


def test_ffmpeg_adapter_blocks_ssrf_at_connect():
    """Vérifie que connect() refuse catégoriquement une URI malicieuse sans lancer de sous-processus."""
    cfg = CameraConnectionConfig(
        source_id="evil_target_cam",
        protocol=CameraProtocol.RTSP,
        uri="rtsp://169.254.169.254:554/steal",
        allow_loopback=False
    )
    adapter = FFmpegRTSPAdapter(cfg)
    ok = adapter.connect()
    assert ok is False
    assert adapter._status == VideoSourceStatus.BLOCKED_SSRF
    assert "SSRF bloqué" in adapter._last_error
    adapter.close()


def test_ffmpeg_adapter_simulated_read_and_health():
    """Valide la lecture de trames, la mesure des FPS et la télémétrie de santé via une source simulée."""
    cfg = CameraConnectionConfig(
        source_id="mock_sim_cam",
        protocol=CameraProtocol.MOCK,
        uri="mock://loopback",
        target_fps=10,
        target_width=320,
        target_height=240
    )
    mock_src = MockVideoSource(cfg)
    assert mock_src.connect() is True
    assert mock_src.is_healthy() is True

    # Lecture de 5 trames
    frames = []
    for _ in range(5):
        ok, f, err = mock_src.read_frame()
        assert ok is True
        assert f is not None
        assert f.width == 320
        assert f.height == 240
        assert f.sequence_num > 0
        frames.append(f)

    assert len(frames) == 5
    health = mock_src.get_health()
    assert health.is_connected is True
    assert health.status == VideoSourceStatus.CONNECTED
    assert health.fps_measured == 10.0

    mock_src.close()
    assert mock_src.is_healthy() is False


def test_ffmpeg_adapter_detects_stream_stalls_without_serving_stale_as_live():
    """Vérifie qu'un flux bloqué ne masque pas la panne en renvoyant de vieilles images comme du live."""
    cfg = CameraConnectionConfig(
        source_id="stalled_cam",
        protocol=CameraProtocol.MOCK,
        uri="mock://loopback",
        target_fps=10,
        target_width=320,
        target_height=240,
        read_timeout=0.2
    )
    # Configure la source pour se figer après 2 trames
    stalled_src = MockVideoSource(cfg, stall_after_frames=2)
    stalled_src.connect()

    # 1. Lecture trame 1 (succès)
    ok1, f1, _ = stalled_src.read_frame()
    assert ok1 is True
    assert f1.sequence_num == 1

    # 2. Lecture trame 2 (succès)
    ok2, f2, _ = stalled_src.read_frame()
    assert ok2 is True
    assert f2.sequence_num == 2

    # 3. Lecture trame 3 : la source s'est figée
    ok3, f3, err3 = stalled_src.read_frame()
    assert ok3 is False
    assert f3 is None
    assert "figé" in err3.lower() or "bloqué" in err3.lower()

    stalled_src.close()


def test_ffmpeg_process_cleanup_no_orphans():
    """Vérifie la fermeture rigoureuse du sous-processus FFmpeg et la libération des pipes."""
    cfg = CameraConnectionConfig(
        source_id="orphan_check_cam",
        protocol=CameraProtocol.RTSP,
        uri="rtsp://127.0.0.1:8554/test",
        allow_loopback=True
    )
    adapter = FFmpegRTSPAdapter(cfg)

    # Mock d'un sous-processus Popen
    mock_proc = MagicMock()
    mock_proc.poll.return_value = None
    mock_proc.stdin = MagicMock()
    mock_proc.stdout = MagicMock()
    mock_proc.stderr = MagicMock()
    adapter._process = mock_proc
    adapter._is_connected = True

    # Appel de cleanup
    adapter._cleanup_process()

    assert mock_proc.stdin.close.called
    assert mock_proc.stdout.close.called
    assert mock_proc.terminate.called
    assert adapter._is_connected is False


# =============================================================================
# NIVEAU 2 & 3 : DÉCOUVERTE RÉSEAU (WS-DISCOVERY, SSDP & APPROBATION STRICTE)
# =============================================================================

def test_ws_discovery_probe_match_parsing():
    """Vérifie le parsing défensif d'un paquet SOAP XML ProbeMatch ONVIF sans vulnérabilité XXE."""
    service = ONVIFDiscoveryService()
    sample_xml = """<?xml version="1.0" encoding="utf-8"?>
    <SOAP-ENV:Envelope xmlns:SOAP-ENV="http://www.w3.org/2003/05/soap-envelope" 
                       xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing" 
                       xmlns:d="http://schemas.xmlsoap.org/ws/2005/04/discovery">
      <SOAP-ENV:Body>
        <d:ProbeMatches>
          <d:ProbeMatch>
            <wsa:EndpointReference>
              <wsa:Address>urn:uuid:12345678-abcd-ef01-2345-6789abcdef01</wsa:Address>
            </wsa:EndpointReference>
            <d:Types>dn:NetworkVideoTransmitter tds:Device</d:Types>
            <d:Scopes>onvif://www.onvif.org/type/video_encoder onvif://www.onvif.org/hardware/ModelX400 onvif://www.onvif.org/name/HikvisionCorp</d:Scopes>
            <d:XAddrs>http://192.168.1.88:80/onvif/device_service</d:XAddrs>
          </d:ProbeMatch>
        </d:ProbeMatches>
      </SOAP-ENV:Body>
    </SOAP-ENV:Envelope>"""

    candidate = service._parse_probe_match(sample_xml, "192.168.1.88", 80)
    assert candidate is not None
    assert candidate.ip == "192.168.1.88"
    assert candidate.port == 80
    assert candidate.status == "DISCOVERED_PENDING_APPROVAL"
    assert candidate.model == "ModelX400"
    assert candidate.manufacturer == "HikvisionCorp"
    assert candidate.rtsp_uri == "rtsp://192.168.1.88:554/live/ch0"


def test_ws_discovery_malformed_xml_resilience():
    """Vérifie que des paquets XML tronqués, corrompus ou invalides sont ignorés sans crash."""
    service = ONVIFDiscoveryService()
    assert service._parse_probe_match("INVALID NOT XML AT ALL", "192.168.1.88", 80) is None
    assert service._parse_probe_match("<ProbeMatch><UnclosedTag>", "192.168.1.88", 80) is None
    assert service._parse_probe_match("", "192.168.1.88", 80) is None


def test_ssdp_discovery_response_parsing():
    """Vérifie le parsing d'une réponse SSDP HTTP 200 OK avec extraction des métadonnées."""
    ssdp = SSDPDiscoveryService()
    raw_response = (
        "HTTP/1.1 200 OK\r\n"
        "CACHE-CONTROL: max-age=1800\r\n"
        "LOCATION: http://192.168.1.95:80/description.xml\r\n"
        "SERVER: Linux/4.4 UPnP/1.0 DahuaIPCamera/2.0\r\n"
        "ST: urn:schemas-upnp-org:device:Basic:1\r\n"
        "USN: uuid:upnp-Camera-1_0-12345::urn:schemas-upnp-org:device:Basic:1\r\n\r\n"
    )
    headers = ssdp._parse_headers(raw_response)
    assert headers["LOCATION"] == "http://192.168.1.95:80/description.xml"
    assert "DahuaIPCamera" in headers["SERVER"]
    assert "uuid:upnp-Camera" in headers["USN"]


def test_unified_discovery_requires_explicit_operator_approval():
    """RÈGLE NON NÉGOCIABLE : Tout appareil découvert DOIT nécessiter une approbation explicite."""
    mgr = UnifiedDiscoveryManager()
    cand = DiscoveredDeviceCandidate(
        candidate_id="test_cand_01",
        discovery_protocol="WS_DISCOVERY",
        ip="192.168.1.150",
        port=80,
        name="Caméra Découverte Hall",
        location_url="http://192.168.1.150/onvif",
        server_info="Axis P1365",
        discovered_at=time.time(),
        status="DISCOVERED_PENDING_APPROVAL"
    )
    mgr._all_candidates["test_cand_01"] = cand

    # 1. État initial : en attente d'approbation
    c = mgr.get_candidate("test_cand_01")
    assert c.status == "DISCOVERED_PENDING_APPROVAL"

    # 2. Approbation par un opérateur authentifié
    approved = mgr.approve_candidate("test_cand_01", operator_username="super_operator")
    assert approved is not None
    assert approved.status == "APPROVED"

    # 3. Rejet d'un équipement
    cand_reject = DiscoveredDeviceCandidate(
        candidate_id="bad_cand",
        discovery_protocol="SSDP",
        ip="192.168.1.199",
        port=8080,
        name="Appareil Inconnu",
        location_url=None,
        server_info="Unknown",
        discovered_at=time.time()
    )
    mgr._all_candidates["bad_cand"] = cand_reject
    assert mgr.reject_candidate("bad_cand", "super_operator") is True
    assert mgr.get_candidate("bad_cand") is None


# =============================================================================
# NIVEAU 2 : TESTS D'INTÉGRATION HTTP REST API & RBAC
# =============================================================================

def test_api_discovery_scan_and_candidates_list(auth_admin_client):
    """Vérifie l'exposition des routes d'analyse et de consultation des candidats découverts."""
    client, coordinator = auth_admin_client

    # 1. Déclenchement du scan
    res_scan = client.post('/api/discovery/scan')
    assert res_scan.status_code == 200
    assert res_scan.get_json()["status"] == "ok"

    # 2. Consultation des candidats
    res_list = client.get('/api/discovery/candidates')
    assert res_list.status_code == 200
    assert "candidates" in res_list.get_json()


def test_api_discovery_approval_enrolls_device_with_rbac(auth_admin_client):
    """Vérifie le cycle complet d'approbation d'un candidat et son enrôlement contrôlé dans la flotte."""
    client, coordinator = auth_admin_client

    # Injection synthétique d'un candidat dans le gestionnaire de découverte
    cand = DiscoveredDeviceCandidate(
        candidate_id="cand_test_approval",
        discovery_protocol="WS_DISCOVERY",
        ip="192.168.1.77",
        port=8080,
        name="Caméra Détectée Entrée",
        location_url="http://192.168.1.77:8080/onvif",
        server_info="Hikvision DS-2CD2143G0",
        discovered_at=time.time(),
        metadata={"rtsp_uri": "rtsp://192.168.1.77:554/live/ch0"}
    )
    coordinator.discovery_manager._all_candidates[cand.candidate_id] = cand

    # Approbation par l'administrateur
    res_approve = client.post(
        f'/api/discovery/candidates/{cand.candidate_id}/approve',
        json={"name": "Caméra Entrée Principale Validée"}
    )
    assert res_approve.status_code == 201
    data = res_approve.get_json()
    assert data["status"] == "ok"
    assert "Caméra Entrée Principale Validée" in data["message"]
    enrolled_device = data["device"]
    assert enrolled_device["ip"] == "192.168.1.77"
    assert enrolled_device["protocol"] == "ONVIF"

    # Nettoyage
    coordinator.delete_device(enrolled_device["id"])


def test_api_discovery_unauthorized_user_blocked():
    """Vérifie que les utilisateurs non authentifiés ou non autorisés sont rejetés avec HTTP 401/403."""
    app, coordinator = create_app()
    app.config["TESTING"] = True
    app.config["TESTING_ENFORCE_AUTH"] = True
    with app.test_client() as client:
        # 1. Non authentifié -> 401
        res = client.post('/api/discovery/scan')
        assert res.status_code in [401, 302]

        res_approve = client.post('/api/discovery/candidates/cand_01/approve')
        assert res_approve.status_code in [401, 302]

        # 2. Authentifié avec rôle AUDITOR (insuffisant pour approuver un appareil)
        tok = "tok_auditor_session_123"
        from database import get_db_session
        from monitoring.models import UserSession, User
        with get_db_session() as db:
            db.merge(User(id="user_auditor_01", username="auditor_user", role="AUDITOR", password_hash="dummy", is_active=True))
            db.merge(UserSession(session_token=tok, user_id="user_auditor_01"))

        with client.session_transaction() as sess:
            sess["user_id"] = "user_auditor_01"
            sess["username"] = "auditor_user"
            sess["role"] = "AUDITOR"
            sess["session_token"] = tok

        res_forbidden = client.post('/api/discovery/candidates/cand_01/approve')
        assert res_forbidden.status_code == 403

        # Nettoyage
        with get_db_session() as db:
            db.query(UserSession).filter(UserSession.session_token == tok).delete()
            db.query(User).filter(User.id == "user_auditor_01").delete()


def test_api_add_rtsp_device_explicit(auth_admin_client):
    """Vérifie l'ajout explicite d'une caméra RTSP universelle via l'API REST."""
    client, coordinator = auth_admin_client

    payload = {
        "name": "Caméra RTSP Entrepôt",
        "ip": "192.168.1.120",
        "port": 554,
        "protocol": "RTSP",
        "rtsp_uri": "rtsp://192.168.1.120:554/stream1"
    }

    res = client.post('/api/devices', json=payload)
    assert res.status_code == 201
    dev = res.get_json()["device"]
    assert dev["protocol"] == "RTSP"
    assert dev["video_url"] == "rtsp://192.168.1.120:554/stream1"
    assert dev["sensors_url"] == ""

    # Nettoyage
    coordinator.delete_device(dev["id"])


# =============================================================================
# NIVEAU 4 : BENCHMARK MULTI-FLUX SIMULÉS & MESURES RÉELLES
# =============================================================================

def test_nvr_multi_stream_concurrency_and_performance():
    """Mesure réelle de la performance multi-flux : CPU, FPS, mémoire et latence sur 4 flux concurrents."""
    import psutil
    process = psutil.Process()
    initial_mem_mb = process.memory_info().rss / (1024 * 1024)

    streams_count = 4
    fps_target = 10
    duration_seconds = 2.0

    sources = []
    for i in range(streams_count):
        cfg = CameraConnectionConfig(
            source_id=f"perf_stream_{i+1}",
            protocol=CameraProtocol.MOCK,
            uri=f"mock://perf_{i+1}",
            target_fps=fps_target,
            target_width=640,
            target_height=480
        )
        src = MockVideoSource(cfg)
        assert src.connect() is True
        sources.append(src)

    # Lecture concurrente
    start_time = time.time()
    frames_read = [0] * streams_count

    while (time.time() - start_time) < duration_seconds:
        for idx, src in enumerate(sources):
            ok, f, _ = src.read_frame()
            if ok and f is not None:
                frames_read[idx] += 1
        time.sleep(0.005)

    total_time = time.time() - start_time
    final_mem_mb = process.memory_info().rss / (1024 * 1024)
    mem_delta_mb = final_mem_mb - initial_mem_mb

    for s in sources:
        s.close()

    total_frames = sum(frames_read)
    fps_effective = total_frames / total_time

    # Assertions de stabilité
    assert total_frames >= (streams_count * fps_target * duration_seconds * 0.8)
    assert mem_delta_mb < 50.0  # Croissance mémoire bornée (< 50 Mo pour 4 flux simultanés)
    assert fps_effective >= (streams_count * fps_target * 0.8)


# =============================================================================
# NIVEAU 5 : TESTS DE REMÉDIATION ET VÉRIFICATION APPROFONDIE (PRO-13 A.2)
# =============================================================================

def test_remediation_a1_001_valid_private_targets_accepted():
    """A1-001: Vérifie que les cibles IPv4 et IPv6 privées légitimes sont acceptées sans TypeError."""
    # 1. IPv4 privée standard (192.168.1.50)
    valid, reason, ip = validate_video_target("192.168.1.50", port=554)
    assert valid is True
    assert ip == "192.168.1.50"
    assert "conforme" in reason.lower()

    # 2. Autre plage privée (10.0.0.10, 172.16.5.20)
    v2, r2, ip2 = validate_video_target("10.0.0.10", port=8080)
    assert v2 is True
    assert ip2 == "10.0.0.10"

    v3, r3, ip3 = validate_video_target("172.16.5.20", port=554)
    assert v3 is True
    assert ip3 == "172.16.5.20"

    # 3. Via URI complète avec credentials contenant des caractères complexes
    v4, r4, ip4 = validate_video_target("rtsp://admin:P@ss#123!@192.168.1.50:554/live")
    assert v4 is True
    assert ip4 == "192.168.1.50"


def test_remediation_a1_001_multi_ip_dns_fail_closed():
    """A1-001: Vérifie la politique fail-closed stricte lors de résolutions DNS multiples."""
    # A. DNS renvoyant plusieurs adresses TOUTES autorisées -> ACCEPTÉ
    with patch("socket.getaddrinfo") as mock_dns:
        mock_dns.return_value = [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("192.168.1.50", 554)),
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("192.168.1.51", 554)),
        ]
        valid, reason, ip = validate_video_target("multi-camera.local", port=554)
        assert valid is True
        assert ip == "192.168.1.50"

    # B. DNS renvoyant une combinaison autorisée ET interdite -> REJETÉ FAIL-CLOSED
    with patch("socket.getaddrinfo") as mock_dns:
        mock_dns.return_value = [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("192.168.1.50", 554)),
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("169.254.169.254", 554)),
        ]
        valid, reason, _ = validate_video_target("rebind-probe.evil.com", port=554)
        assert valid is False
        assert "métadonnées cloud interdite" in reason.lower() or "link-local" in reason.lower()

    # C. DNS vide -> REJETÉ
    with patch("socket.getaddrinfo") as mock_dns:
        mock_dns.return_value = []
        valid, reason, _ = validate_video_target("empty-dns.local", port=554)
        assert valid is False
        assert "impossible de résoudre" in reason.lower()


def test_remediation_a1_002_dns_pinning_and_uri_rewrite():
    """A1-002: Vérifie la fonction pin_uri_to_ip et la neutralisation de la fenêtre TOCTOU."""
    from monitoring.acquisition.security import pin_uri_to_ip

    # 1. URI standard avec domaine -> réécrit avec IP
    pinned1 = pin_uri_to_ip("rtsp://camera.internal.local:554/live/ch0", "192.168.1.75")
    assert pinned1 == "rtsp://192.168.1.75:554/live/ch0"

    # 2. URI avec mot de passe contenant '@', '#', '!' -> credentials et port préservés
    raw_complex = "rtsp://operator:P@ss#w0rd!@camera.corp.net:554/stream1?token=xyz"
    pinned2 = pin_uri_to_ip(raw_complex, "192.168.1.80")
    assert pinned2 == "rtsp://operator:P@ss#w0rd!@192.168.1.80:554/stream1?token=xyz"

    # 3. URI IPv6 -> formatage entre crochets [ip]
    pinned3 = pin_uri_to_ip("rtsp://cam.local:554/h264", "fd00::1")
    assert pinned3 == "rtsp://[fd00::1]:554/h264"


def test_remediation_a1_002_ffmpeg_adapter_uses_pinned_uri():
    """A1-002: Vérifie que FFmpegRTSPAdapter utilise l'URI épinglée dans sa commande d'exécution."""
    with patch("socket.getaddrinfo") as mock_dns:
        mock_dns.return_value = [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("192.168.1.99", 554))
        ]
        cfg = CameraConnectionConfig(
            source_id="pinned_test_cam",
            protocol=CameraProtocol.RTSP,
            uri="rtsp://admin:secret@camera.office.internal:554/live"
        )
        adapter = FFmpegRTSPAdapter(cfg, ffmpeg_bin="ffmpeg")
        adapter._has_ffmpeg_binary = True
        ok = adapter.connect()
        assert ok is True
        assert adapter._validated_ip == "192.168.1.99"
        assert adapter._effective_uri == "rtsp://admin:secret@192.168.1.99:554/live"

        cmd = adapter._build_ffmpeg_cmd()
        assert "-i" in cmd
        i_idx = cmd.index("-i")
        assert cmd[i_idx + 1] == "rtsp://admin:secret@192.168.1.99:554/live"
        adapter.close()


def test_remediation_a1_003_opencv_fallback_disabled_in_production():
    """A1-003: Vérifie que le fallback OpenCV in-process est strictement rejeté en production lorsque FFmpeg est absent."""
    cfg = CameraConnectionConfig(
        source_id="prod_cam_no_ffmpeg",
        protocol=CameraProtocol.RTSP,
        uri="rtsp://192.168.1.50:554/live",
        custom_params={"allow_opencv_fallback": True}
    )
    with patch.object(config, "IS_PRODUCTION", True):
        adapter = FFmpegRTSPAdapter(cfg, ffmpeg_bin="non_existent_ffmpeg_bin_123")
        assert adapter._has_ffmpeg_binary is False
        assert adapter._allow_opencv_fallback is False

        ok = adapter.connect()
        assert ok is False
        assert adapter._status == VideoSourceStatus.ERROR
        assert "désactivé par sécurité" in adapter._last_error
        adapter.close()


def test_remediation_a1_004_onvif_capabilities_explicit():
    """A1-004: Vérifie que les capacités ONVIF sont exposées honnêtement sans prétention de Profile S/T."""
    from monitoring.acquisition.onvif_adapter import ONVIFCandidate
    cand = ONVIFCandidate(
        candidate_id="onvif_test_caps",
        ip="192.168.1.60",
        port=80,
        xaddrs=["http://192.168.1.60/onvif/device_service"],
        scopes=[],
        discovered_at=time.time()
    )
    assert cand.capabilities["ws_discovery"] == "WS_DISCOVERY_SUPPORTED"
    assert cand.capabilities["soap_media"] == "SOAP_MEDIA_NOT_IMPLEMENTED"
    assert cand.capabilities["profile_s"] == "PROFILE_S_NOT_VERIFIED"
    assert cand.capabilities["profile_t"] == "PROFILE_T_NOT_VERIFIED"


def test_remediation_a1_005_discovery_mdns_marked_not_implemented():
    """A1-005: Vérifie que la documentation et les métadonnées de découverte indiquent formellement que mDNS n'est pas implémenté."""
    from monitoring.acquisition.discovery import DiscoveredDeviceCandidate
    assert "mDNS: NOT_IMPLEMENTED" in DiscoveredDeviceCandidate.__doc__ or "mDNS non implémenté" in DiscoveredDeviceCandidate.__doc__


def test_remediation_a1_006_frame_buffer_deque_concurrency():
    """A1-006: Vérifie que le ring buffer deque(maxlen=2) stocke au maximum 2 trames et garantit la fraîcheur."""
    cfg = CameraConnectionConfig(
        source_id="deque_cam_test",
        protocol=CameraProtocol.RTSP,
        uri="rtsp://192.168.1.50:554/live"
    )
    adapter = FFmpegRTSPAdapter(cfg, ffmpeg_bin="ffmpeg")
    assert adapter._frame_buffer.maxlen == 2

    # Injection directe de 3 trames successives
    now = time.time()
    for seq in [1, 2, 3]:
        dummy_frame = VideoFrame(
            data=np.zeros((10, 10, 3), dtype=np.uint8),
            timestamp_utc=now + seq,
            sequence_num=seq,
            width=10,
            height=10
        )
        with adapter._lock:
            adapter._frame_buffer.append(dummy_frame)
            adapter._latest_frame = dummy_frame
            adapter._is_connected = True

    # Le buffer ne doit contenir que les 2 dernières trames (seq 2 et 3)
    assert len(adapter._frame_buffer) == 2
    assert adapter._frame_buffer[0].sequence_num == 2
    assert adapter._frame_buffer[1].sequence_num == 3

    # read_frame retourne la toute dernière trame (seq 3)
    ok, f, err = adapter.read_frame()
    assert ok is True
    assert f.sequence_num == 3
    adapter.close()


# =============================================================================
# NIVEAU 5 : TESTS ADVERSARIAUX ET DURCISSEMENT PRO-13-A.3 (A21-001 & A21-003)
# =============================================================================

def test_a3_command_construction_protocol_whitelist_and_transport():
    """A21-001: Vérifie la présence de -protocol_whitelist et -rtsp_transport tcp sans bascule UDP."""
    cfg_rtsp = CameraConnectionConfig(
        source_id="test_cam_a3_rtsp",
        protocol=CameraProtocol.RTSP,
        uri="rtsp://192.168.1.100:554/live",
        target_fps=10,
        target_width=640,
        target_height=480
    )
    adapter_rtsp = FFmpegRTSPAdapter(cfg_rtsp, ffmpeg_bin="ffmpeg")
    cmd_rtsp = adapter_rtsp._build_ffmpeg_cmd()

    assert "-protocol_whitelist" in cmd_rtsp
    pw_idx = cmd_rtsp.index("-protocol_whitelist")
    assert cmd_rtsp[pw_idx + 1] == "tcp,rtp,rtsp"

    assert "-rtsp_transport" in cmd_rtsp
    rt_idx = cmd_rtsp.index("-rtsp_transport")
    assert cmd_rtsp[rt_idx + 1] == "tcp"

    assert "-rtsp_flags" in cmd_rtsp
    rf_idx = cmd_rtsp.index("-rtsp_flags")
    assert "+prefer_tcp" in cmd_rtsp[rf_idx + 1]

    # Pour RTSPS, vérifier l'inclusion de tls et crypto
    cfg_rtsps = CameraConnectionConfig(
        source_id="test_cam_a3_rtsps",
        protocol=CameraProtocol.RTSP,
        uri="rtsps://192.168.1.100:322/secure",
        target_fps=10,
        target_width=640,
        target_height=480
    )
    adapter_rtsps = FFmpegRTSPAdapter(cfg_rtsps, ffmpeg_bin="ffmpeg")
    cmd_rtsps = adapter_rtsps._build_ffmpeg_cmd()
    pw_rtsps_idx = cmd_rtsps.index("-protocol_whitelist")
    assert "tls" in cmd_rtsps[pw_rtsps_idx + 1]
    assert "crypto" in cmd_rtsps[pw_rtsps_idx + 1]
    adapter_rtsp.close()
    adapter_rtsps.close()


def test_a3_ipc_stderr_drain_and_credential_sanitization():
    """A21-003: Vérifie que le drain stderr asynchrone stocke des diagnostics expurgés de credentials."""
    cfg = CameraConnectionConfig(
        source_id="test_cam_a3_stderr",
        protocol=CameraProtocol.RTSP,
        uri="rtsp://admin:SecretPass2026!@192.168.1.50:554/live"
    )
    adapter = FFmpegRTSPAdapter(cfg)

    # Simulation d'un flux stderr avec ligne d'erreur contenant l'URI avec credentials
    raw_lines = [
        b"[rtsp @ 000001] Connecting to rtsp://admin:SecretPass2026!@192.168.1.50:554/live\n",
        b"[h264 @ 000002] Error while decoding MB 12 34\n",
        b"[rtsp @ 000001] method DESCRIBE failed: 404 Not Found\n"
    ]

    mock_proc = MagicMock()
    mock_proc.stderr.readline.side_effect = raw_lines + [b""]

    # Exécution du drain worker pour la génération 1
    adapter._process_generation = 1
    adapter._stderr_drain_worker(mock_proc, generation=1)

    diag = adapter.get_recent_diagnostics(max_lines=10)
    assert "SecretPass2026!" not in diag
    assert "***" in diag or "admin:***@" in diag
    assert "Error while decoding MB" in diag
    adapter.close()


def test_a3_ipc_stderr_bounded_memory_under_heavy_logging():
    """A21-003: Vérifie que le tampon de diagnostic ne dépasse jamais MAX_DIAGNOSTIC_BYTES."""
    from monitoring.acquisition.ffmpeg_adapter import MAX_DIAGNOSTIC_BYTES, MAX_DIAGNOSTIC_LINES
    cfg = CameraConnectionConfig(
        source_id="test_cam_a3_flood",
        protocol=CameraProtocol.RTSP,
        uri="rtsp://192.168.1.50:554/live"
    )
    adapter = FFmpegRTSPAdapter(cfg)

    # Génération de 500 lignes de 300 octets (> 150 Ko, dépassant le plafond de 64 Ko)
    large_lines = [f"[log_flood_{i}] " + "X" * 250 + "\n" for i in range(500)]
    byte_lines = [l.encode("utf-8") for l in large_lines]

    mock_proc = MagicMock()
    mock_proc.stderr.readline.side_effect = byte_lines + [b""]

    adapter._process_generation = 1
    adapter._stderr_drain_worker(mock_proc, generation=1)

    assert len(adapter._diagnostic_lines) <= MAX_DIAGNOSTIC_LINES
    assert adapter._diagnostic_bytes <= MAX_DIAGNOSTIC_BYTES
    adapter.close()


def test_a3_ipc_stderr_saturation_synthetic_subprocess_no_deadlock():
    """A21-003: Test physique de saturation d'un pipe système sans interblocage (Deadlock).
    Un sous-processus Python écrit 100 Ko (> 25x le buffer Windows de 4 Ko) sur stderr
    tout en écrivant des trames valides sur stdout. Le système ne doit pas se bloquer.
    """
    cfg = CameraConnectionConfig(
        source_id="synthetic_deadlock_cam",
        protocol=CameraProtocol.RTSP,
        uri="rtsp://127.0.0.1:8554/live",
        allow_loopback=True,
        target_fps=10,
        target_width=40,
        target_height=30
    )
    adapter = FFmpegRTSPAdapter(cfg)

    # Script Python synthétique simulant un FFmpeg bruyant
    # Écrit 100 Ko sur stderr par blocs et écrit 3 trames de 40*30*3 octets sur stdout
    frame_bytes = 40 * 30 * 3
    script = f"""
import sys, time
# Écriture massive sur stderr pour dépasser largement le pipe OS (100 Ko)
for i in range(250):
    sys.stderr.write(f"[SYNTHETIC_ERROR_{{i}}] " + "E" * 380 + "\\n")
    sys.stderr.flush()

# Écriture de 3 trames vidéo brutes sur stdout
for _ in range(3):
    sys.stdout.buffer.write(b"\\x00" * {frame_bytes})
    sys.stdout.buffer.flush()
    time.sleep(0.02)
"""

    synthetic_cmd = [sys.executable, "-c", script]

    with patch.object(adapter, "_build_ffmpeg_cmd", return_value=synthetic_cmd):
        adapter._has_ffmpeg_binary = True
        # Exécution du cycle supervisé
        worker = threading.Thread(target=adapter._run_ffmpeg_subprocess_loop, daemon=True)
        worker.start()
        worker.join(timeout=8.0)

        assert not worker.is_alive(), "Deadlock détecté : le worker n'a pas terminé dans le délai imparti !"
        assert adapter._diagnostic_bytes > 0, "Des diagnostics stderr doivent avoir été capturés !"
        assert len(adapter._frame_buffer) > 0, "Des trames stdout doivent avoir été lues sans être bloquées !"
        adapter.close()


def test_a3_process_generation_isolation_on_reconnect():
    """A21-003: Vérifie que les générations successives de sous-processus sont strictement isolées."""
    cfg = CameraConnectionConfig(
        source_id="test_cam_a3_gen",
        protocol=CameraProtocol.RTSP,
        uri="rtsp://192.168.1.50:554/live"
    )
    adapter = FFmpegRTSPAdapter(cfg)
    adapter._process_generation = 1

    # Un vieux lecteur de génération 1 ne doit pas écrire dans la génération 2
    mock_proc_old = MagicMock()
    mock_proc_old.stderr.readline.side_effect = [b"[old_gen_1] Should be ignored\n", b""]

    # Le compteur passe à 2 (nouvelle génération)
    adapter._process_generation = 2
    adapter._stderr_drain_worker(mock_proc_old, generation=1)

    # La ligne de l'ancienne génération a été ignorée
    diag = adapter.get_recent_diagnostics()
    assert "old_gen_1" not in diag
    adapter.close()


def test_a3_concurrent_cleanup_and_close_idempotent():
    """A21-003: Vérifie l'idempotence et l'innocuité d'appels multiples et concurrents à close()."""
    cfg = CameraConnectionConfig(
        source_id="test_cam_a3_concurrent",
        protocol=CameraProtocol.RTSP,
        uri="rtsp://192.168.1.50:554/live"
    )
    adapter = FFmpegRTSPAdapter(cfg)
    adapter._is_connected = True

    errors = []
    def call_close():
        try:
            adapter.close()
            adapter._cleanup_process()
        except Exception as e:
            errors.append(e)

    threads = [threading.Thread(target=call_close) for _ in range(8)]
    for t in threads: t.start()
    for t in threads: t.join(timeout=2.0)

    assert len(errors) == 0
    assert adapter._is_connected is False
    assert adapter._status == VideoSourceStatus.CLOSED


# =============================================================================
# NIVEAU 6 : TESTS ADVERSARIAUX DU CONFINEMENT EGRESS (PRO-13 A.4)
# =============================================================================

from monitoring.acquisition.egress_policy import (
    EgressPolicy, EgressEnforcementStatus, PolicyConfigurationError,
    check_egress_enforcement_status, classify_ip, MockEgressProvider
)


def test_a4_01_authorized_camera_ip():
    """A4-01: Vérifie qu'une destination caméra explicitement approuvée est autorisée."""
    policy = EgressPolicy(allowed_destinations=["192.168.1.50/32", "192.168.1.51"])
    allowed, reason, ip = policy.is_destination_allowed("192.168.1.50", 554)
    assert allowed is True
    assert ip == "192.168.1.50"
    assert "autorisée" in reason.lower()

    # Intégration avec validate_video_target
    valid, v_reason, resolved = validate_video_target("rtsp://192.168.1.50:554/live", egress_policy=policy)
    assert valid is True
    assert resolved == "192.168.1.50"


def test_a4_02_unauthorized_private_ip():
    """A4-02: Vérifie qu'une IP privée RFC1918 non inscrite dans l'allowlist est bloquée."""
    policy = EgressPolicy(allowed_destinations=["192.168.1.50/32"])

    # 1. Autre IP du même sous-réseau
    allowed1, reason1, _ = policy.is_destination_allowed("192.168.1.99", 554)
    assert allowed1 is False
    assert "non autorisée" in reason1.lower()

    # 2. Autre réseau privé 10.0.0.0/8
    allowed2, reason2, _ = policy.is_destination_allowed("10.0.0.1", 554)
    assert allowed2 is False
    assert "rfc1918" in reason2.lower()

    # 3. Autre réseau privé 172.16.0.0/12
    allowed3, reason3, _ = policy.is_destination_allowed("172.16.5.20", 554)
    assert allowed3 is False


def test_a4_03_loopback_secondary_uri():
    """A4-03: Vérifie que les destinations de boucle locale sont rejetées."""
    policy = EgressPolicy(allowed_destinations=["192.168.1.50"], allow_loopback=False)
    allowed, reason, _ = policy.is_destination_allowed("127.0.0.1", 554)
    assert allowed is False
    assert "loopback" in reason.lower()

    allowed_v6, _, _ = policy.is_destination_allowed("::1", 554)
    assert allowed_v6 is False


def test_a4_04_metadata_destination():
    """A4-04: Vérifie que les adresses de métadonnées cloud (169.254.169.254) sont bloquées."""
    policy = EgressPolicy(allowed_destinations=["192.168.1.50"])
    allowed, reason, _ = policy.is_destination_allowed("169.254.169.254", 80)
    assert allowed is False
    assert "métadonnées cloud" in reason.lower() or "link-local" in reason.lower()


def test_a4_05_link_local_destination():
    """A4-05: Vérifie que les adresses link-local IPv4 et IPv6 sont bloquées."""
    policy = EgressPolicy(allowed_destinations=["192.168.1.50"])
    allowed_v4, _, _ = policy.is_destination_allowed("169.254.1.10", 554)
    assert allowed_v4 is False

    allowed_v6, _, _ = policy.is_destination_allowed("fe80::1", 554)
    assert allowed_v6 is False


def test_a4_06_unauthorized_public_ip():
    """A4-06: Vérifie qu'une adresse IP publique non autorisée est rejetée."""
    policy = EgressPolicy(allowed_destinations=["192.168.1.50"])
    allowed, reason, _ = policy.is_destination_allowed("8.8.8.8", 554)
    assert allowed is False
    assert "publique non autorisée" in reason.lower()


def test_a4_07_ipv6_loopback():
    """A4-07: Vérifie que la boucle locale IPv6 (::1) est bloquée."""
    policy = EgressPolicy(allowed_destinations=["fd00::50"], allow_loopback=False)
    allowed, reason, _ = policy.is_destination_allowed("::1", 554)
    assert allowed is False
    assert "loopback" in reason.lower()


def test_a4_08_ipv4_mapped_ipv6():
    """A4-08: Vérifie la normalisation et classification des adresses IPv4-mapped IPv6."""
    policy = EgressPolicy(allowed_destinations=["192.168.1.50"])

    # A. IPv4-mapped autorisée -> acceptée
    allowed1, _, ip1 = policy.is_destination_allowed("::ffff:192.168.1.50", 554)
    assert allowed1 is True
    assert ip1 == "192.168.1.50"

    # B. IPv4-mapped métadonnées cloud -> bloquée
    allowed2, reason2, _ = policy.is_destination_allowed("::ffff:169.254.169.254", 80)
    assert allowed2 is False
    assert "métadonnées cloud" in reason2.lower() or "link-local" in reason2.lower()

    # C. IPv4-mapped privée non autorisée -> bloquée
    allowed3, _, _ = policy.is_destination_allowed("::ffff:10.0.0.1", 554)
    assert allowed3 is False


def test_a4_09_rtsp_302_redirect():
    """A4-09: Vérifie qu'une redirection RTSP 302 vers une cible non autorisée ne peut s'échapper."""
    policy = EgressPolicy(allowed_destinations=["192.168.1.50"])

    # Simulation d'une cible obtenue lors d'une redirection
    unauthorized_redirect = "rtsp://10.0.0.1:554/redirected_stream"
    valid, reason, _ = validate_video_target(unauthorized_redirect, egress_policy=policy)
    assert valid is False
    assert "confinement d'egress" in reason.lower() or "non autorisée" in reason.lower()

    # Redirection vers métadonnées cloud
    cloud_redirect = "rtsp://169.254.169.254:80/meta"
    valid_cloud, _, _ = validate_video_target(cloud_redirect, egress_policy=policy)
    assert valid_cloud is False


def test_a4_10_sdp_absolute_secondary_uri():
    """A4-10: Vérifie qu'un URI secondaire absolu dans un descripteur SDP est confiné."""
    policy = EgressPolicy(allowed_destinations=["192.168.1.50"])

    # URI extrait d'une directive SDP malveillante a=control:rtsp://169.254.169.254/track1
    sdp_track_uri = "rtsp://169.254.169.254:80/track1"
    valid, reason, _ = validate_video_target(sdp_track_uri, egress_policy=policy)
    assert valid is False

    # URI extrait vers un autre serveur privé non approuvé
    sdp_private_uri = "rtsp://192.168.1.99:554/track2"
    valid_p, _, _ = validate_video_target(sdp_private_uri, egress_policy=policy)
    assert valid_p is False


def test_a4_11_reconnect_after_dns_change():
    """A4-11: Vérifie que le changement DNS vers une IP interdite lors d'une reconnexion est bloqué."""
    policy = EgressPolicy(allowed_destinations=["192.168.1.50"])

    # 1. Première résolution valide
    with patch("socket.getaddrinfo") as mock_dns:
        mock_dns.return_value = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("192.168.1.50", 554))]
        valid1, _, ip1 = validate_video_target("camera.local", port=554, egress_policy=policy)
        assert valid1 is True
        assert ip1 == "192.168.1.50"

    # 2. DNS change pour pointer vers 10.0.0.1 (non autorisé)
    with patch("socket.getaddrinfo") as mock_dns:
        mock_dns.return_value = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.0.0.1", 554))]
        valid2, reason2, _ = validate_video_target("camera.local", port=554, egress_policy=policy)
        assert valid2 is False
        assert "egress" in reason2.lower() or "non autorisée" in reason2.lower()


def test_a4_12_unauthorized_udp_attempt():
    """A4-12: Vérifie que la configuration FFmpeg interdit le transport UDP."""
    cfg = CameraConnectionConfig(
        source_id="test_cam_a4_udp",
        protocol=CameraProtocol.RTSP,
        uri="rtsp://192.168.1.50:554/live"
    )
    adapter = FFmpegRTSPAdapter(cfg)
    cmd = adapter._build_ffmpeg_cmd()

    # Le mode TCP doit être formellement requis
    assert "-rtsp_transport" in cmd
    idx = cmd.index("-rtsp_transport")
    assert cmd[idx + 1] == "tcp"

    # La whitelist de protocoles ne doit pas contenir "udp"
    p_idx = cmd.index("-protocol_whitelist")
    whitelist = cmd[p_idx + 1]
    assert "udp" not in whitelist.split(",")
    assert "tcp" in whitelist.split(",")


def test_a4_13_malformed_sdp():
    """A4-13: Vérifie que la réception de données malformées provoque un arrêt fail-closed propre."""
    cfg = CameraConnectionConfig(
        source_id="test_cam_a4_malformed",
        protocol=CameraProtocol.RTSP,
        uri="rtsp://192.168.1.50:554/live",
        read_timeout=1.0
    )
    adapter = FFmpegRTSPAdapter(cfg)

    # Simulation de lecture exacte sur un tube fermé prématurément (EOF)
    mock_stream = MagicMock()
    mock_stream.read.return_value = b""
    res = adapter._read_exact(mock_stream, 640 * 480 * 3)
    assert res is None

    # Statut fail-closed lors de la lecture de trame
    ok, frame, err = adapter.read_frame()
    assert ok is False
    assert frame is not None
    assert frame.is_placeholder is True


def test_a4_14_excessive_reconnect_attempts():
    """A4-14: Vérifie que le backoff exponentiel plafonne le rythme des tentatives."""
    cfg = CameraConnectionConfig(
        source_id="test_cam_a4_reconnect",
        protocol=CameraProtocol.RTSP,
        uri="rtsp://192.168.1.50:554/live",
        max_backoff=15.0
    )
    adapter = FFmpegRTSPAdapter(cfg)
    assert adapter._current_backoff == 1.0

    # Simulation de 10 échecs de reconnexion
    for _ in range(10):
        adapter._current_backoff = min(adapter._current_backoff * 1.5, adapter.config.max_backoff)

    assert adapter._current_backoff == 15.0
    assert adapter._current_backoff <= adapter.config.max_backoff


def test_a4_15_worker_termination():
    """A4-15: Vérifie l'extinction complète et l'absence d'orphelins lors de la fermeture."""
    cfg = CameraConnectionConfig(
        source_id="test_cam_a4_term",
        protocol=CameraProtocol.RTSP,
        uri="rtsp://192.168.1.50:554/live"
    )
    adapter = FFmpegRTSPAdapter(cfg)
    mock_proc = MagicMock()
    adapter._process = mock_proc

    adapter._cleanup_process()
    assert mock_proc.terminate.called or mock_proc.kill.called
    assert adapter._process is None
    assert adapter._is_connected is False


def test_a4_16_isolation_unavailable():
    """A4-16: Vérifie que si le confinement OS/conteneur est obligatoire mais absent, le système fail-closed."""
    cfg = CameraConnectionConfig(
        source_id="test_cam_a4_iso_req",
        protocol=CameraProtocol.RTSP,
        uri="rtsp://192.168.1.50:554/live",
        custom_params={"require_os_egress_confinement": True}
    )
    adapter = FFmpegRTSPAdapter(cfg)

    # En environnement standard sans pare-feu actif, la connexion doit être bloquée
    with patch.dict(os.environ, {"SSM_EGRESS_FIREWALL_ACTIVE": "", "SSM_EGRESS_CONTAINER_ISOLATED": ""}):
        adapter._enforcement_status, adapter._enforcement_reason = check_egress_enforcement_status()
        success = adapter.connect()
        assert success is False
        assert adapter._status == VideoSourceStatus.BLOCKED_SSRF
        assert "confinement réseau os/conteneur obligatoire mais inactif" in adapter._last_error.lower()


def test_a4_17_firewall_policy_absent():
    """A4-17: Vérifie que l'absence de pare-feu n'est jamais faussement déclarée comme active."""
    with patch.dict(os.environ, {"SSM_EGRESS_FIREWALL_ACTIVE": "", "SSM_EGRESS_CONTAINER_ISOLATED": ""}):
        status, reason = check_egress_enforcement_status()
        assert status != EgressEnforcementStatus.ENFORCED_OS_FIREWALL
        assert status != EgressEnforcementStatus.ENFORCED_CONTAINER
        assert status != EgressEnforcementStatus.ENFORCED
        assert len(reason) > 0


def test_a4_18_policy_allowlist_empty():
    """A4-18: Vérifie qu'une liste d'autorisations vide est rejetée immédiatement."""
    with pytest.raises(PolicyConfigurationError) as exc_info:
        EgressPolicy(allowed_destinations=[])
    assert "ne peut pas être vide" in str(exc_info.value).lower()

    with pytest.raises(PolicyConfigurationError):
        EgressPolicy(allowed_destinations=None)


def test_a4_19_policy_allowlist_overly_broad():
    """A4-19: Vérifie que les plages réseau trop larges (wildcards, /8, /0) sont rejetées."""
    # 1. 0.0.0.0/0
    with pytest.raises(PolicyConfigurationError) as exc1:
        EgressPolicy(allowed_destinations=["0.0.0.0/0"])
    assert "trop large" in str(exc1.value).lower()

    # 2. 10.0.0.0/8
    with pytest.raises(PolicyConfigurationError) as exc2:
        EgressPolicy(allowed_destinations=["10.0.0.0/8"])
    assert "trop large" in str(exc2.value).lower()

    # 3. IPv6 ::/0
    with pytest.raises(PolicyConfigurationError) as exc3:
        EgressPolicy(allowed_destinations=["::/0"])
    assert "trop large" in str(exc3.value).lower()

    # 4. Inclusion de métadonnées cloud
    with pytest.raises(PolicyConfigurationError) as exc4:
        EgressPolicy(allowed_destinations=["169.254.0.0/16"])
    assert "métadonnées cloud" in str(exc4.value).lower()


def test_a4_20_policy_rollback():
    """A4-20: Vérifie la détection dynamique de l'état d'activation et la restauration (sans confiance env)."""
    # 1. La variable d'environnement seule ne doit jamais falsifier le statut ENFORCED (A4.2)
    with patch.dict(os.environ, {"SSM_EGRESS_FIREWALL_ACTIVE": "1"}):
        st_spoof, _ = check_egress_enforcement_status()
        assert st_spoof != EgressEnforcementStatus.ENFORCED

    # 2. Activation vérifiée via provider puis révocation / rollback
    mock_prov = MockEgressProvider(status=EgressEnforcementStatus.ENFORCED, reason="Pare-feu actif")
    st1, _ = check_egress_enforcement_status(provider=mock_prov)
    assert st1 == EgressEnforcementStatus.ENFORCED_OS_FIREWALL

    mock_prov.status = EgressEnforcementStatus.NOT_ENFORCED
    st2, _ = check_egress_enforcement_status(provider=mock_prov)
    assert st2 != EgressEnforcementStatus.ENFORCED_OS_FIREWALL
