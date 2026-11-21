import pytest
import numpy as np
import time
import cv2
from monitoring.detection_engine import DetectionEngine
from monitoring.device_store import DeviceStore
from monitoring.camera_manager import CameraManager
from monitoring.sensor_manager import SensorManager

class DummyDeviceStore:
    def __init__(self):
        self.devices = [{"id": "dev_test", "name": "Phone Test", "enabled": True}]
        self.settings = {
            "proximity_threshold": 5.0,
            "sound_threshold": 75.0,
            "accel_shock_threshold": 4.5,
            "motion_area_threshold": 2.0,
            "cooldown_seconds": 2.0,
            "enable_motion": True,
            "enable_proximity": True,
            "enable_sound": True,
            "enable_accel": True
        }

    def get_all_devices(self):
        return self.devices

    def get_device(self, dev_id):
        return self.devices[0]

    def get_settings(self):
        return self.settings


class DummyCameraManager:
    def __init__(self):
        self.frame = np.zeros((480, 640, 3), dtype=np.uint8)

    def get_frame(self, dev_id):
        return self.frame.copy()


class DummySensorManager:
    def __init__(self):
        self.sensors = {}

    def get_device_sensors(self, dev_id):
        return {"status": "CONNECTÉ", "sensors": self.sensors}


def test_opencv_video_motion_detection():
    """Vérifie la détection de mouvement par analyse différentielle OpenCV."""
    ds = DummyDeviceStore()
    cm = DummyCameraManager()
    sm = DummySensorManager()
    engine = DetectionEngine(cm, sm, ds)

    frame1 = np.zeros((480, 640, 3), dtype=np.uint8)
    frame2 = np.zeros((480, 640, 3), dtype=np.uint8)

    # 1. Deux images identiques : aucun mouvement
    is_motion, pct = engine.check_video_motion("dev_test", frame1, threshold_area_pct=2.0)
    assert is_motion is False
    assert pct == 0.0

    is_motion, pct = engine.check_video_motion("dev_test", frame2, threshold_area_pct=2.0)
    assert is_motion is False
    assert pct == 0.0

    # 2. Dessiner un rectangle blanc significatif pour créer un mouvement
    frame3 = frame2.copy()
    cv2.rectangle(frame3, (100, 100), (350, 350), (255, 255, 255), -1)

    is_motion, pct = engine.check_video_motion("dev_test", frame3, threshold_area_pct=2.0)
    assert is_motion is True
    assert pct > 2.0


def test_detection_cooldown_anti_rebond():
    """Vérifie que l'anti-rebond empêche le mitraillage d'alertes consécutives."""
    ds = DummyDeviceStore()
    cm = DummyCameraManager()
    sm = DummySensorManager()
    engine = DetectionEngine(cm, sm, ds)

    assert engine._is_cooling_down("dev_test", "PROXIMITÉ", cooldown_seconds=2.0) is False
    engine._record_trigger("dev_test", "PROXIMITÉ")
    assert engine._is_cooling_down("dev_test", "PROXIMITÉ", cooldown_seconds=2.0) is True

    # Après expiration du délai
    time.sleep(2.1)
    assert engine._is_cooling_down("dev_test", "PROXIMITÉ", cooldown_seconds=2.0) is False


def test_simulated_incident_categorization():
    """Exigence : qualification stricte de l'événement comme ÉVÉNEMENT SIMULÉ."""
    ds = DummyDeviceStore()
    cm = DummyCameraManager()
    sm = DummySensorManager()
    engine = DetectionEngine(cm, sm, ds)

    dispatched = []
    engine.register_callback(lambda inc: dispatched.append(inc))

    inc = engine.trigger_simulated_incident("dev_test", "MOUVEMENT_VIDÉO")
    assert len(dispatched) == 1
    assert dispatched[0]["category"] == "ÉVÉNEMENT SIMULÉ"
    assert dispatched[0]["type"] == "MOUVEMENT_VIDÉO"
    assert dispatched[0]["device_name"] == "Phone Test"
