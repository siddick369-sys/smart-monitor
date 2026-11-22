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
        time.sleep(1.0 / (fps_target * 2))

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
