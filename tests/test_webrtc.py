import time
import pytest
from unittest.mock import MagicMock

from monitoring.webrtc_manager import WebRTCManager

def test_webrtc_session_creation_and_lifecycle():
    """Vérifie le cycle de vie d'une session de signalisation WebRTC."""
    mgr = WebRTCManager()
    
    # 1. Création de session
    session = mgr.create_session("dev_salon_01", client_ip="192.168.1.15")
    assert session["session_id"].startswith("rtc_")
    assert session["device_id"] == "dev_salon_01"
    assert session["state"] == "NEW"
    assert mgr.get_status()["active_sessions_count"] == 1
    
    # 2. Ajout de candidat ICE
    ok_ice = mgr.add_ice_candidate(session["session_id"], {"candidate": "candidate:1 1 UDP ..."})
    assert ok_ice is True
    assert len(session["ice_candidates"]) == 1
    
    # 3. Fermeture de session
    ok_close = mgr.close_session(session["session_id"])
    assert ok_close is True
    assert mgr.get_status()["active_sessions_count"] == 0

def test_webrtc_offer_and_mjpeg_fallback():
    """Vérifie la réception d'une offre SDP et la directive explicite de fallback MJPEG si requis."""
    mgr = WebRTCManager()
    session = mgr.create_session("dev_entree_02")
    
    dummy_offer = "v=0\r\no=- 12345 2 IN IP4 127.0.0.1\r\ns=-\r\nt=0 0\r\nm=video 9 UDP/TLS/RTP/SAVPF 96\r\n"
    
    success, sdp_answer, meta = mgr.handle_offer(session["session_id"], dummy_offer, "dev_entree_02")
    
    if not mgr.is_available():
        # Sans aiortc, le système ordonne explicitement le fallback MJPEG
        assert success is False
        assert meta["action"] == "FALLBACK_MJPEG"
        assert "/api/devices/dev_entree_02/stream" in meta["fallback_url"]
    else:
        assert success is True
        assert sdp_answer is not None

def test_webrtc_stale_sessions_cleanup():
    """Vérifie le nettoyage des sessions orphelines sans fuite de descripteurs."""
    mgr = WebRTCManager()
    s1 = mgr.create_session("dev_1")
    s2 = mgr.create_session("dev_2")
    
    # Rendre s1 obsolète (idle depuis 300s)
    mgr.sessions[s1["session_id"]]["last_active"] = time.time() - 300
    
    mgr.cleanup_stale_sessions(max_idle_seconds=60)
    
    assert s1["session_id"] not in mgr.sessions
    assert s2["session_id"] in mgr.sessions
