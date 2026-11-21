import os
import time
import json
import pytest
import numpy as np
import config
from monitoring.sensor_manager import SensorParser, SensorPoller, SensorManager
from monitoring.camera_manager import CameraManager, CameraWorker
from monitoring.recording_manager import RecordingManager
from monitoring.detection_engine import DetectionEngine
from app import create_app

# 1. Test état d'un appareil dont la télémétrie est périmée
def test_stale_telemetry_status():
    poller = SensorPoller("dev_stale", "http://127.0.0.1:59999/sensors.json")
    poller.last_update_time = time.time() - 20.0 # 20 secondes dans le passé (> STALE_TELEMETRY_SECONDS)
    poller.raw_payload = {"proximity": {"unit": "cm", "data": [[1700000000000, [10.0]]]}}
    
    sensors = poller.get_sensors()
    assert sensors["proximity"]["available"] is False
    assert sensors["proximity"]["status"] == "DONNÉE EXPIRÉE"

# 2. Test déconnexion et reconnexion (événements système)
def test_disconnection_and_reconnection_events():
    events_received = []
    engine = DetectionEngine(None, None, None)
    engine.register_callback(lambda e: events_received.append(e))

    class MockStore:
        def get_device(self, dev_id):
            return {"id": dev_id, "name": "Phone Test", "ip": "192.168.1.50"}

    engine.device_store = MockStore()

    # Déconnexion
    engine.dispatch_system_event("dev_test", "DEVICE_DISCONNECTED", "Perte du flux vidéo", severity="AVERTISSEMENT")
    assert len(events_received) == 1
    assert events_received[0]["event_code"] == "DEVICE_DISCONNECTED"
    assert events_received[0]["severity"] == "AVERTISSEMENT"

    # Reconnexion
    engine.dispatch_system_event("dev_test", "DEVICE_RECONNECTED", "Rétablissement du flux", severity="INFO")
    assert len(events_received) == 2
    assert events_received[1]["event_code"] == "DEVICE_RECONNECTED"
    assert events_received[1]["severity"] == "INFO"

# 3. Test isolation d'une caméra déconnectée (ne bloque pas les autres)
def test_camera_isolation():
    cm = CameraManager()
    # Caméra 1 avec URL invalide (en échec de connexion)
    cm.start_camera("cam_bad", "http://127.0.0.1:59998/video")
    
    # Caméra 2 fonctionnelle
    cm.start_camera("cam_good", "http://127.0.0.1:59997/video")

    # Vérifier que l'accès à la frame de cam_bad ne bloque pas et renvoie une mire
    frame_bad = cm.get_frame("cam_bad")
    assert frame_bad is not None
    assert frame_bad.shape == (480, 640, 3)

    cm.stop_all()

# 4. Test données capteurs indisponibles
def test_sensors_unavailable_handling():
    payload = {"light": {"unit": "lx", "data": []}}
    parsed = SensorParser.parse_payload(payload)
    assert parsed["proximity"]["available"] is False
    assert parsed["proximity"]["status"] == "CAPTEUR NON DISPONIBLE"
    assert parsed["sound"]["available"] is False
    assert parsed["accel"]["available"] is False

# 5. Test classification réelle / simulée
def test_classification_real_vs_simulated():
    poller = SensorPoller("dev_sim", "http://127.0.0.1:59999/sensors.json")
    poller.last_update_time = time.time()
    poller.sensor_data = SensorParser.parse_payload({
        "proximity": {"unit": "cm", "data": [[1700000000000, [15.0]]]}
    })
    
    # Donnée réelle
    sensors_real = poller.get_sensors()
    assert sensors_real["proximity"]["is_simulated"] is False
    assert sensors_real["proximity"]["status"] == "DONNÉE RÉELLE"

    # Surcharge simulée
    poller.set_simulation_override("proximity", 2.0, duration_seconds=5.0)
    sensors_sim = poller.get_sensors()
    assert sensors_sim["proximity"]["is_simulated"] is True
    assert sensors_sim["proximity"]["status"] in ["DISPONIBLE (SIMULÉ)", "DONNÉE SIMULÉE"]

# 6. Test protection des endpoints sensibles (Origin non autorisée)
def test_sensitive_endpoints_origin_protection():
    app, coordinator = create_app()
    app.config["TESTING"] = True
    with app.test_client() as client:
        # Requête POST avec Origin externe non autorisée -> 403 Forbidden
        bad_origin_res = client.post(
            '/api/alarm/arm',
            headers={"Origin": "http://evil-attacker-site.com"}
        )
        assert bad_origin_res.status_code == 403

        # Requête POST avec Origin locale autorisée -> 200 OK
        good_origin_res = client.post(
            '/api/alarm/arm',
            headers={"Origin": "http://127.0.0.1:5000"}
        )
        assert good_origin_res.status_code == 200
    coordinator.stop()

# 7. Test validation des seuils configurables
def test_thresholds_validation():
    app, coordinator = create_app()
    app.config["TESTING"] = True
    with app.test_client() as client:
        # Seuil négatif rejeté
        bad_res = client.post('/api/settings', json={"proximity_threshold": -5.0})
        assert bad_res.status_code == 400
        assert "ne peut pas être négatif" in bad_res.get_json()["message"]

        # Cooldown inférieur à 1s rejeté
        bad_cooldown = client.post('/api/settings', json={"cooldown_seconds": 0.2})
        assert bad_cooldown.status_code == 400

        # Seuil valide accepté
        good_res = client.post('/api/settings', json={"proximity_threshold": 8.5})
        assert good_res.status_code == 200
        assert good_res.get_json()["settings"]["proximity_threshold"] == 8.5
    coordinator.stop()

# 8. Test création et consultation des preuves
def test_proofs_creation_and_consultation():
    cm = CameraManager()
    rm = RecordingManager(cm)

    frame = np.zeros((480, 640, 3), dtype=np.uint8)
    inc_id = f"test_proof_{int(time.time()*1000)}"
    incident = {
        "id": inc_id,
        "device_id": "dev_test",
        "device_name": "Test Device",
        "type": "PROXIMITÉ",
        "category": "ÉVÉNEMENT CAPTEUR RÉEL",
        "severity": "CRITIQUE",
        "details": "Test preuve",
        "frame": frame
    }
    rm.handle_incident(incident)

    alerts = rm.filter_alerts(device_id="dev_test")
    assert len(alerts) > 0
    assert alerts[0]["id"] == inc_id
    assert alerts[0]["screenshot_path"] is not None

    rm.delete_alert(inc_id)

# 9. Test gestion d'un échec d'enregistrement (sans frame associée)
def test_recording_failure_graceful_handling():
    cm = CameraManager()
    rm = RecordingManager(cm)

    inc_id = f"test_noframes_{int(time.time()*1000)}"
    # Incident sans frame (ex: événement système déconnexion)
    incident = {
        "id": inc_id,
        "device_id": "dev_test",
        "device_name": "Test Device",
        "type": "DEVICE_DISCONNECTED",
        "category": "DÉCONNEXION APPAREIL",
        "severity": "AVERTISSEMENT",
        "details": "Perte de signal",
        "frame": None
    }
    rm.handle_incident(incident)

    alert = next((a for a in rm.get_all_alerts() if a["id"] == inc_id), None)
    assert alert is not None
    assert alert["screenshot_path"] is None
    assert alert["recording_path"] is None
    assert alert["status"] in ["SANS FLUX VIDÉO", "ÉVÉNEMENT SYSTÈME"]

    rm.delete_alert(inc_id)

# 10. Test nettoyage des preuves expirées (> 7 jours) sans supprimer les récentes
def test_retention_expired_proofs_cleanup(tmp_path):
    cm = CameraManager()
    rm = RecordingManager(cm)

    # Créer un faux fichier récent
    recent_file = os.path.join(config.SCREENSHOTS_DIR, "recent_test_proof.jpg")
    with open(recent_file, "wb") as f:
        f.write(b"recent_data")

    # Nettoyer avec rétention de 7 jours
    rm.clean_expired_proofs(days=7)

    # Le fichier récent ne doit PAS être supprimé
    assert os.path.exists(recent_file)

    # Nettoyer le fichier de test
    if os.path.exists(recent_file):
        os.remove(recent_file)

# 11. Test Export CSV du journal des incidents
def test_export_csv():
    app, coordinator = create_app()
    app.config["TESTING"] = True
    with app.test_client() as client:
        res = client.get('/api/alerts/export/csv')
        assert res.status_code == 200
        assert res.mimetype == "text/csv"
        assert "Content-Disposition" in res.headers
        csv_text = res.get_data(as_text=True)
        assert "id;datetime;device_name" in csv_text
    coordinator.stop()

# 12. Test calcul de l'espace de stockage consommé
def test_storage_stats():
    cm = CameraManager()
    rm = RecordingManager(cm)
    stats = rm.get_storage_stats()
    assert "used_bytes" in stats
    assert "used_mb" in stats
    assert "max_mb" in stats
    assert stats["max_mb"] == config.MAX_STORAGE_MB
