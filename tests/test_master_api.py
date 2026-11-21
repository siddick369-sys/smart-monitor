import time
import json
import pytest
import numpy as np
import cv2
from app import create_app
import config
from database import get_db_session
from monitoring.models import User

@pytest.fixture
def auth_client():
    app, coordinator = create_app()
    app.config["TESTING"] = True

    admin_pwd = config.ADMIN_DEFAULT_PASSWORD or "AdminSecurity2026!"
    with app.test_client() as client:
        # Se connecter en tant qu'admin
        client.post('/api/auth/login', json={
            "username": config.ADMIN_DEFAULT_USERNAME,
            "password": admin_pwd
        })
        yield client, coordinator
    coordinator.stop()

def test_tamper_endpoints(auth_client):
    client, coordinator = auth_client

    # 1. Status
    res = client.get('/api/tamper/status')
    assert res.status_code == 200
    data = res.get_json()
    assert data["status"] == "ok"
    assert "tamper" in data

    # 2. Resolve
    res = client.post('/api/tamper/resolve', json={"device_id": "cam_salon"})
    assert res.status_code == 200
    assert "acquitté" in res.get_json()["message"]

def test_audio_endpoints(auth_client):
    client, coordinator = auth_client

    # 1. Status
    res = client.get('/api/audio/status')
    assert res.status_code == 200
    data = res.get_json()
    assert data["status"] == "ok"
    assert data["audio_ai"]["enabled"] is True

    # 2. Classify simulated scream
    res = client.post('/api/audio/classify_test', json={"simulated_sound": "SCREAM"})
    assert res.status_code == 200
    pred = res.get_json()["prediction"]
    assert pred["predicted_class"] in ["SCREAM", "ALARM_SIREN", "ABNORMAL_NOISE", "GLASS_BREAK"]

def test_semantic_search_endpoints(auth_client):
    client, coordinator = auth_client

    # 1. Query without query param -> 400
    res = client.get('/api/search/semantic')
    assert res.status_code == 400

    # 2. Query with valid text
    res = client.get('/api/search/semantic?q=personne+rouge')
    assert res.status_code == 200
    data = res.get_json()
    assert data["status"] == "ok"
    assert "results" in data["data"]
    assert "total_results" in data["data"]

    # 3. Reindex
    res = client.post('/api/search/reindex')
    assert res.status_code == 200
    assert "indexed_frames" in res.get_json()

def test_forensic_and_privacy_endpoints(auth_client):
    client, coordinator = auth_client

    # 1. Créer une fausse alerte pour tester le rapport forensique
    fake_alert = {
        "id": "alert_forensic_test_01",
        "timestamp": time.time(),
        "datetime": time.strftime("%Y-%m-%d %H:%M:%S"),
        "type": "MOUVEMENT DÉTECTÉ",
        "category": "INTRUSION",
        "severity": "CRITIQUE",
        "device_id": "cam_01",
        "device_name": "Camera Hall",
        "details": "Test détection suspecte",
        "screenshot": None,
        "video_file": None
    }
    with coordinator.recording_manager._lock:
        coordinator.recording_manager.alerts.insert(0, fake_alert)

    # 2. Générer rapport forensique PDF
    res = client.post('/api/forensic/generate_pdf/alert_forensic_test_01')
    assert res.status_code == 200
    data = res.get_json()
    assert data["status"] == "ok"
    assert "filename" in data

    # 3. Privacy status
    res = client.get('/api/privacy/status')
    assert res.status_code == 200
    assert res.get_json()["status"] == "ok"

    # 4. Two-man rule request & approve (respect strict de la séparation des identités demandeur/approbateur)
    res_req = client.post('/api/privacy/request_decryption', json={
        "resource_id": "video_hall_inc01.mp4",
        "reason": "Réquisition judiciaire officielle"
    })
    assert res_req.status_code == 200
    req_id = res_req.get_json()["request"]["id"]

    # Changement d'identité vers un second administrateur distinct pour l'approbation
    with client.session_transaction() as sess:
        sess["username"] = "admin_supervisor"
        sess["role"] = "ADMIN"

    res_app = client.post('/api/privacy/approve_decryption', json={
        "request_id": req_id
    })
    assert res_app.status_code == 200
    assert "Approbation" in res_app.get_json()["message"]

def test_spatial_and_pose_endpoints(auth_client):
    client, coordinator = auth_client

    coordinator.spatial_tracker.add_camera("cam_01", "Camera Hall", 10.0, 5.0)

    # 1. Floorplan
    res = client.get('/api/spatial/floorplan')
    assert res.status_code == 200
    assert "floorplan" in res.get_json()

    # 2. Record detection
    res = client.post('/api/spatial/record_detection', json={
        "camera_id": "cam_01",
        "bbox_center_x": 0.5,
        "distance_meters": 3.0
    })
    assert res.status_code == 200
    assert "track" in res.get_json()

    # 3. Active tracks
    res = client.get('/api/spatial/tracks')
    assert res.status_code == 200
    assert len(res.get_json()["tracks"]) >= 1

    # 4. Pose status
    res = client.get('/api/pose/status')
    assert res.status_code == 200
    assert "engine" in res.get_json()["pose"]

def test_p2p_and_intercom_endpoints(auth_client):
    client, coordinator = auth_client

    # 1. P2P status
    res = client.get('/api/p2p/status')
    assert res.status_code == 200
    assert res.get_json()["status"] == "ok"

    # 2. P2P sync batch with auth
    device_id = "device_phone_01"
    token = "secret_tok_test_456"
    coordinator.p2p_sync_mgr.register_device(device_id, token)

    res_sync = client.post(
        '/api/p2p/sync_batch',
        json={"events": [{"event_id": "ev_p2p_01", "event_type": "ALERTE_P2P", "timestamp": time.time()}]},
        headers={
            "X-Device-ID": device_id,
            "X-Device-Token": token
        }
    )
    assert res_sync.status_code == 200
    assert res_sync.get_json()["synced_count"] == 1

    # 3. Intercom status
    res = client.get('/api/intercom/status')
    assert res.status_code == 200
    assert "intercom" in res.get_json()

    # 4. Voice announcement
    res = client.post('/api/intercom/voice_announcement', json={
        "device_id": "cam_01",
        "phrase_id": "WARNING_ZONE"
    })
    assert res.status_code == 200
    assert res.get_json()["status"] == "ok"

    # 5. Strobe trigger
    res = client.post('/api/intercom/strobe', json={
        "duration": 5,
        "device_id": "cam_01"
    })
    assert res.status_code == 200
    assert res.get_json()["status"] == "ok"
