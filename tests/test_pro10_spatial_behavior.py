"""
Bancs de Tests pour PRO-10 : Jumeau Numérique Spatio-Temporel et Analyse Comportementale
Valide les fonctionnalités :
- Délimitation de zones et plan 2D (SpatialTracker)
- Passage de témoin inter-caméras (Handover multi-caméra)
- Détection de violation de zone sensible
- Détection de chute potentielle (PoseDetector)
- Détection de station prolongée (Loitering)
- Conformité éthique (États NEEDS_REVIEW sans préjugé criminel)
"""

import time
import pytest
from monitoring.spatial_tracker import SpatialTracker, SpatialZone
from monitoring.pose_detector import PoseDetector, BehavioralState


def test_spatial_zone_polygon_containment():
    # Zone rectangulaire (x: [10, 30], y: [10, 40])
    zone = SpatialZone(
        zone_id="zone_safe",
        name="Zone Sécurisée",
        polygon=[(10.0, 10.0), (30.0, 10.0), (30.0, 40.0), (10.0, 40.0)],
        is_restricted=True
    )

    assert zone.contains_point(20.0, 25.0) is True   # À l'intérieur
    assert zone.contains_point(5.0, 25.0) is False    # En dehors à gauche
    assert zone.contains_point(35.0, 25.0) is False   # En dehors à droite
    assert zone.contains_point(20.0, 50.0) is False   # En dehors en bas


def test_spatial_tracking_and_multicamera_handover():
    tracker = SpatialTracker(handover_max_delay=5.0, handover_max_dist=12.0)

    # Configuration de 2 caméras contiguës
    tracker.add_camera("cam_entree", "Entrée", x=5.0, y=10.0, orientation_deg=0.0)
    tracker.add_camera("cam_couloir", "Couloir", x=10.0, y=10.0, orientation_deg=0.0)

    # Zone sensible dans le couloir
    tracker.add_zone(
        "zone_coffre",
        "Coffre Fort",
        polygon=[(10.0, 5.0), (16.0, 5.0), (16.0, 15.0), (10.0, 15.0)],
        is_restricted=True
    )

    t0 = 1000.0
    # 1. Première détection sur caméra Entrée
    res1 = tracker.record_detection("cam_entree", bbox_center_x=0.5, distance_meters=3.0, timestamp=t0)
    assert res1["track_id"] is not None
    assert res1["is_handover"] is False
    assert "cam_entree" in res1["cameras_involved"]

    # 2. Deux secondes plus tard, détection sur caméra Couloir proche (Handover)
    t1 = t0 + 2.0
    res2 = tracker.record_detection("cam_couloir", bbox_center_x=0.5, distance_meters=2.0, timestamp=t1)
    assert res2["track_id"] == res1["track_id"]  # Même trajectoire conservée
    assert res2["is_handover"] is True
    assert "cam_couloir" in res2["cameras_involved"]
    assert res2["restricted_zone_alert"] == "Coffre Fort"  # Pénétration en zone sensible


def test_pose_detection_fall_and_ethical_qualification():
    detector = PoseDetector(fall_aspect_ratio_threshold=1.35)

    # 1. Posture debout normale (silhouette verticale w=60, h=160, aspect_ratio = 0.375)
    bbox_upright = (100, 100, 60, 160)
    res_normal = detector.analyze_person_posture("cam1", frame=None, bbox=bbox_upright)
    assert res_normal.state == BehavioralState.NORMAL
    assert res_normal.event_type == "NORMAL_UPRIGHT_POSTURE"

    # 2. Chute / position couchée au sol (silhouette horizontale w=150, h=60, aspect_ratio = 2.5)
    bbox_horizontal = (100, 200, 150, 60)
    res_fall = detector.analyze_person_posture("cam1", frame=None, bbox=bbox_horizontal)
    assert res_fall.state == BehavioralState.NEEDS_REVIEW
    assert res_fall.event_type == "POTENTIAL_FALL_DETECTED"
    assert res_fall.confidence >= 0.75
    assert "observation" in res_fall.evidence


def test_pose_detection_loitering():
    detector = PoseDetector(loitering_threshold_seconds=5.0)

    t0 = 2000.0
    # Première observation
    detector.analyze_person_posture("cam_door", frame=None, bbox=(50, 50, 50, 120), timestamp=t0)

    # 2 secondes plus tard (< 5s) -> Pas de rôdage
    ev_mid = detector.analyze_person_posture("cam_door", frame=None, bbox=(50, 50, 50, 120), timestamp=t0 + 2.0)
    assert ev_mid.event_type != "LOITERING_PROLONGED_PRESENCE"

    # 6 secondes plus tard (> 5s) -> Alerte rôdage
    ev_loitering = detector.analyze_person_posture("cam_door", frame=None, bbox=(50, 50, 50, 120), timestamp=t0 + 6.0)
    assert ev_loitering.event_type == "LOITERING_PROLONGED_PRESENCE"
    assert ev_loitering.state == BehavioralState.NEEDS_REVIEW
    assert ev_loitering.evidence["presence_duration_seconds"] >= 5.0
