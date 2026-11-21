"""
Bancs de Tests pour PRO-07 : Anti-Sabotage et Classification Acoustique
Valide les fonctionnalités :
- Détection d'obstruction optique (TamperDetector)
- Détection de flou sévère et surexposition
- Détection de déplacement physique et bascule d'orientation
- Détection de perte de flux et télémétrie obsolète
- Classification acoustique (AudioClassifier)
- Corrélation multi-vectorielle audio/vidéo
"""

import time
import numpy as np
import pytest
from monitoring.tamper_detection import TamperDetector, TamperState, TamperType
from monitoring.audio_classifier import AudioClassifier, AudioEventClass


def test_tamper_detection_optical_obstruction():
    detector = TamperDetector(consecutive_frames_required=2, dark_threshold=10.0)

    # 1. Frame normale (bruit texturé bien éclairé)
    np.random.seed(42)
    normal_frame = np.random.randint(50, 200, (480, 640, 3), dtype=np.uint8)
    ev1 = detector.analyze_frame("dev_cam1", normal_frame)
    assert ev1 is None

    # 2. Frame masquée / sombre (objectif couvert)
    dark_frame = np.zeros((480, 640, 3), dtype=np.uint8)
    ev_suspected = detector.analyze_frame("dev_cam1", dark_frame)
    assert ev_suspected is not None
    assert ev_suspected.anomaly_type == TamperType.OBSTRUCTION
    assert ev_suspected.status == TamperState.SUSPECTED

    # 3. Seconde frame consécutive -> Confirmation du sabotage
    ev_confirmed = detector.analyze_frame("dev_cam1", dark_frame)
    assert ev_confirmed is not None
    assert ev_confirmed.status == TamperState.CONFIRMED
    assert ev_confirmed.confidence >= 0.70


def test_tamper_detection_video_degradation_and_overexposure():
    detector = TamperDetector(blur_threshold=15.0, consecutive_frames_required=2)

    # Image très floue (gradient lisse sans contours)
    blurred_frame = np.ones((200, 200, 3), dtype=np.uint8) * 100
    for i in range(200):
        blurred_frame[i, :] = int(90 + (i / 10))
    ev = detector.analyze_frame("dev_cam2", blurred_frame)
    assert ev is not None
    assert ev.anomaly_type == TamperType.VIDEO_DEGRADATION

    # Image surexposée / aveuglement laser
    bright_frame = np.full((200, 200, 3), 255, dtype=np.uint8)
    ev_bright = detector.analyze_frame("dev_cam2", bright_frame)
    assert ev_bright is not None
    assert ev_bright.anomaly_type == TamperType.LIGHTING_ANOMALY


def test_tamper_detection_physical_displacement_and_tilt():
    detector = TamperDetector(accel_shock_threshold=4.0)

    # Télémétrie normale (smartphone au repos vertical az ≈ 9.81 m/s²)
    sensors_normal = {"accel": {"values": [0.0, 0.0, 9.81]}, "status": "RÉEL"}
    ev_norm = detector.analyze_telemetry("dev_phone1", sensors_normal)
    assert ev_norm is None

    # Choc brutal / arrachement (norme = 16.0 m/s², delta_g = 6.19)
    sensors_shock = {"accel": {"values": [6.0, 8.0, 12.0]}, "status": "RÉEL"}
    ev_shock = detector.analyze_telemetry("dev_phone1", sensors_shock)
    assert ev_shock is not None
    assert ev_shock.anomaly_type == TamperType.DISPLACEMENT
    assert ev_shock.status == TamperState.CONFIRMED

    # Bascule d'orientation (rotation de 90 degrés sur le support)
    sensors_tilted = {"accel": {"values": [9.81, 0.0, 0.0]}, "status": "RÉEL"}
    ev_tilt = detector.analyze_telemetry("dev_phone1", sensors_tilted)
    assert ev_tilt is not None
    assert ev_tilt.anomaly_type == TamperType.ORIENTATION_CHANGE
    assert ev_tilt.evidence["tilt_angle_deg"] > 35.0


def test_tamper_detection_stream_loss_and_recovery():
    detector = TamperDetector(stream_timeout_seconds=5.0)

    # Flux récent (< 5s)
    ev_ok = detector.check_stream_health("dev_cam3", last_frame_age=1.2)
    assert ev_ok is None

    # Flux perdu (> 5s)
    ev_lost = detector.check_stream_health("dev_cam3", last_frame_age=8.5)
    assert ev_lost is not None
    assert ev_lost.anomaly_type == TamperType.STREAM_LOSS
    assert ev_lost.status == TamperState.CONFIRMED

    # Résolution manuelle
    detector.resolve_tamper("dev_cam3")
    stat = detector.get_status("dev_cam3")
    assert stat["state"] == TamperState.NORMAL
    assert stat["active_anomaly"] is None


def test_audio_classifier_background_vs_threats():
    classifier = AudioClassifier(min_sound_db_threshold=65.0, confidence_threshold=0.50)

    # 1. Bruit de fond normal (45 dB)
    res_bg = classifier.classify_sound_event("dev_cam1", sound_level_db=45.0)
    assert res_bg.predicted_class == AudioEventClass.BACKGROUND_NORMAL
    assert not res_bg.is_threat

    # 2. Bris de vitre simulé (signal haute fréquence ZCR élevé + dB élevé)
    t = np.linspace(0, 1, 16000)
    high_freq_noise = np.sin(2 * np.pi * 4000 * t) + np.random.normal(0, 0.5, 16000)
    res_glass = classifier.classify_sound_event(
        "dev_cam1",
        sound_level_db=84.0,
        audio_samples=high_freq_noise.astype(np.float32)
    )
    assert res_glass.is_threat
    assert res_glass.predicted_class == AudioEventClass.GLASS_BREAK
    assert res_glass.confidence >= 0.70

    # 3. Cri simulé
    mid_freq = np.sin(2 * np.pi * 1200 * t) + np.random.normal(0, 0.2, 16000)
    res_scream = classifier.classify_sound_event(
        "dev_cam1",
        sound_level_db=86.0,
        audio_samples=mid_freq.astype(np.float32)
    )
    assert res_scream.is_threat
    assert res_scream.predicted_class in [AudioEventClass.SCREAM, AudioEventClass.GLASS_BREAK]


def test_audio_classifier_multivector_fusion():
    classifier = AudioClassifier()

    # Détection audio critique
    t = np.linspace(0, 1, 8000)
    high_freq_noise = np.sin(2 * np.pi * 3500 * t) + np.random.normal(0, 0.4, 8000)
    audio_res = classifier.classify_sound_event(
        "dev_cam1",
        sound_level_db=85.0,
        audio_samples=high_freq_noise.astype(np.float32)
    )

    # Fusion avec mouvement vidéo avéré
    fusion_corroborated = classifier.fuse_with_video_event(audio_res, video_motion=True)
    assert fusion_corroborated["corroborated"] is True
    assert fusion_corroborated["severity"] == "CRITIQUE"

    # Sans mouvement vidéo
    fusion_audio_only = classifier.fuse_with_video_event(audio_res, video_motion=False)
    assert fusion_audio_only["corroborated"] is False
    assert fusion_audio_only["severity"] == "AVERTISSEMENT"
