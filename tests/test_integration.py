import os
import time
import threading
import numpy as np
import pytest
import config
from monitoring.camera_manager import CameraManager
from monitoring.recording_manager import RecordingManager
from monitoring.sensor_manager import SensorPoller
from tests.mock_ipwebcam import app as mock_app

def test_incident_screenshot_and_video_recording():
    """Vérifie la création réelle d'une capture d'écran et d'un clip vidéo sur incident."""
    cm = CameraManager()
    rm = RecordingManager(cm)

    # Créer une frame de test synthétique
    test_frame = np.zeros((480, 640, 3), dtype=np.uint8)
    test_frame[:, :] = (40, 40, 40)

    # Déclencher un incident
    incident_id = f"test_inc_{int(time.time()*1000)}"
    incident = {
        "id": incident_id,
        "device_id": "dev_test",
        "device_name": "Test Phone",
        "type": "MOUVEMENT_VIDÉO",
        "category": "ÉVÉNEMENT DÉTECTÉ PAR VIDÉO",
        "details": "Test enregistrement",
        "timestamp": time.time(),
        "frame": test_frame
    }

    # Traiter l'incident
    rm.handle_incident(incident)

    # Vérifier la capture instantanée
    screenshot_path = os.path.join(config.SCREENSHOTS_DIR, f"screenshot_{incident_id}.jpg")
    assert os.path.exists(screenshot_path)
    assert os.path.getsize(screenshot_path) > 0

    # Attendre que le thread d'enregistrement vidéo termine le post-roll
    # On laisse 6 secondes pour le post-roll (config.POST_RECORD_SECONDS = 5)
    time.sleep(6.5)

    # Vérifier l'alerte dans l'historique
    alerts = rm.get_all_alerts()
    matched = next((a for a in alerts if a["id"] == incident_id), None)
    assert matched is not None
    assert matched["status"] in ["DISPONIBLE", "ENREGISTREMENT EN COURS"]
    if matched.get("recording_path"):
        full_rec_path = os.path.join(config.BASE_DIR, matched["recording_path"])
        assert os.path.exists(full_rec_path)
        assert os.path.getsize(full_rec_path) > 0

    # Nettoyage
    rm.delete_alert(incident_id)


def test_mock_ipwebcam_endpoints():
    """Vérifie le bon fonctionnement du simulateur IP Webcam Android."""
    client = mock_app.test_client()

    # 1. Vérification index
    res = client.get('/')
    assert res.status_code == 200

    # 2. Vérification /sensors.json format IP Webcam
    sensors_res = client.get('/sensors.json')
    assert sensors_res.status_code == 200
    s_data = sensors_res.get_json()
    assert "proximity" in s_data
    assert "sound" in s_data
    assert "accel" in s_data
    assert isinstance(s_data["proximity"]["data"], list)

    # 3. Vérification torche
    torch_res = client.get('/enabletorch')
    assert torch_res.status_code == 200
    assert torch_res.get_json()["torch"] is True

    torch_off = client.get('/disabletorch')
    assert torch_off.status_code == 200
    assert torch_off.get_json()["torch"] is False

    # 4. Vérification simulation d'événement sur le mock
    sim_res = client.get('/simulate_trigger?type=sound&val=99.0')
    assert sim_res.status_code == 200
    s_after = client.get('/sensors.json').get_json()
    # Le son doit être supérieur à 95 dB
    assert s_after["sound"]["data"][0][1][0] > 95.0


def test_resilience_to_disconnection():
    """Vérifie qu'un smartphone inaccessible ne provoque pas de crash."""
    poller = SensorPoller("dev_offline", "http://127.0.0.1:59999/sensors.json", poll_interval=0.1)
    # Démarre le thread
    poller.start()
    time.sleep(0.5)

    data = poller.get_sensors()
    assert poller.status in ["DÉCONNECTÉ", "ERREUR DE CONNEXION"]
    assert data["proximity"]["available"] is False
    assert data["proximity"]["status"] == "CAPTEUR NON DISPONIBLE"

    # Arrêt propre
    poller.stop()
    poller.join(timeout=1.0)
