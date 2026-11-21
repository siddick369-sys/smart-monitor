import os
import time
import pytest
import numpy as np
from unittest.mock import MagicMock, patch

from monitoring.edge_ai_detector import EdgeAIDetector, COCO_CLASSES

def test_edge_ai_model_absent():
    """Vérifie que l'absence de fichier modèle déclenche le statut MODEL_UNAVAILABLE sans crash."""
    detector = EdgeAIDetector(enabled=True, model_path="storage/models/non_existent_yolo.onnx")
    assert detector.status == EdgeAIDetector.STATUS_MODEL_UNAVAILABLE
    assert not detector.is_available()
    assert "introuvable" in detector.status_detail.lower()

def test_edge_ai_disabled():
    """Vérifie le comportement lorsque Edge AI est formellement désactivé."""
    detector = EdgeAIDetector(enabled=False)
    assert detector.status == EdgeAIDetector.STATUS_DISABLED
    assert not detector.is_available()
    
    # Appel de detect avec image valide
    img = np.zeros((480, 640, 3), dtype=np.uint8)
    res = detector.detect(img)
    assert res["status"] == EdgeAIDetector.STATUS_DISABLED
    assert res["has_target_object"] is False

def test_edge_ai_model_corrupted(tmp_path):
    """Vérifie la capture propre d'un fichier ONNX corrompu."""
    corrupted_file = tmp_path / "corrupted.onnx"
    corrupted_file.write_bytes(b"NOT_A_VALID_ONNX_FILE_RANDOM_BYTES")
    
    detector = EdgeAIDetector(enabled=True, model_path=str(corrupted_file))
    assert detector.status == EdgeAIDetector.STATUS_MODEL_CORRUPTED
    assert not detector.is_available()

def test_edge_ai_invalid_images():
    """Vérifie le rejet propre des entrées d'images non conformes."""
    detector = EdgeAIDetector(enabled=True, model_path="storage/models/dummy.onnx")
    
    # Image None
    res_none = detector.detect(None)
    assert res_none["status"] == EdgeAIDetector.STATUS_ERROR
    assert "invalide" in res_none["reason"]
    
    # Image vide (taille 0)
    res_empty = detector.detect(np.array([]))
    assert res_empty["status"] == EdgeAIDetector.STATUS_ERROR
    
    # Image 2D (pas 3 canaux)
    res_2d = detector.detect(np.zeros((100, 100), dtype=np.uint8))
    assert res_2d["status"] == EdgeAIDetector.STATUS_ERROR

def test_edge_ai_preprocessing_and_letterbox():
    """Vérifie le redimensionnement letterbox et la préservation du ratio d'aspect."""
    detector = EdgeAIDetector(enabled=False)
    orig_img = np.zeros((300, 600, 3), dtype=np.uint8)
    
    padded, ratio, (pad_w, pad_h) = detector.letterbox(orig_img, (640, 640))
    assert padded.shape == (640, 640, 3)
    assert ratio == 640 / 600
    
    tensor, r, p = detector.preprocess(orig_img)
    assert tensor.shape == (1, 3, 640, 640)
    assert tensor.dtype == np.float32
    assert tensor.max() <= 1.0

def test_edge_ai_detection_and_threshold_with_mock():
    """Vérifie l'inférence, le filtrage par seuil et l'extraction de classe via mock ONNX."""
    detector = EdgeAIDetector(
        enabled=True,
        confidence_threshold=0.5,
        target_classes={"person", "car"}
    )
    
    # Injection d'une fausse session ONNX fonctionnelle
    mock_session = MagicMock()
    mock_input = MagicMock()
    mock_input.name = "images"
    mock_input.shape = [1, 3, 640, 640]
    mock_output = MagicMock()
    mock_output.name = "output0"
    
    mock_session.get_inputs.return_value = [mock_input]
    mock_session.get_outputs.return_value = [mock_output]
    
    # Tenseur de sortie YOLOv8 [1, 84, 8400]
    # 84 = [cx, cy, w, h] + 80 classes
    fake_output = np.zeros((1, 84, 8400), dtype=np.float32)
    
    # Détection 1 : 'person' (index 0) avec score 0.85 (>= 0.5)
    fake_output[0, 0, 10] = 320.0  # cx
    fake_output[0, 1, 10] = 320.0  # cy
    fake_output[0, 2, 10] = 100.0  # w
    fake_output[0, 3, 10] = 200.0  # h
    fake_output[0, 4, 10] = 0.85   # score 'person' (classe 0)
    
    # Détection 2 : 'car' (index 2) avec score 0.30 (< 0.5 -> DOIT ÊTRE FILTRÉ)
    fake_output[0, 0, 20] = 100.0
    fake_output[0, 1, 20] = 100.0
    fake_output[0, 2, 20] = 80.0
    fake_output[0, 3, 20] = 80.0
    fake_output[0, 4 + 2, 20] = 0.30 # score 'car'
    
    mock_session.run.return_value = [fake_output]
    
    detector.session = mock_session
    detector.status = EdgeAIDetector.STATUS_READY
    detector.input_name = "images"
    detector.output_names = ["output0"]
    
    frame = np.zeros((480, 640, 3), dtype=np.uint8)
    res = detector.detect(frame, force=True)
    
    assert res["status"] == "SUCCESS"
    assert res["count"] == 1
    assert res["detections"][0]["class"] == "person"
    assert res["detections"][0]["confidence"] == 0.85
    assert res["has_target_object"] is True
    assert "person" in res["target_objects"]
    assert res["latency_ms"] >= 0.0

def test_edge_ai_decision_policies():
    """Vérifie les 3 modes de décision : OPENCV_ONLY, EDGE_AI_ASSISTED, EDGE_AI_REQUIRED."""
    # 1. Mode OPENCV_ONLY
    det_opencv = EdgeAIDetector(mode=EdgeAIDetector.MODE_OPENCV_ONLY)
    eval1 = det_opencv.evaluate_detection_policy(opencv_motion_detected=True)
    assert eval1["alert"] is True
    assert eval1["mode"] == EdgeAIDetector.MODE_OPENCV_ONLY
    
    eval1_no = det_opencv.evaluate_detection_policy(opencv_motion_detected=False)
    assert eval1_no["alert"] is False
    
    # 2. Mode EDGE_AI_ASSISTED avec modèle indisponible -> Fallback actif
    det_assisted = EdgeAIDetector(mode=EdgeAIDetector.MODE_ASSISTED)
    det_assisted.status = EdgeAIDetector.STATUS_MODEL_UNAVAILABLE
    eval2 = det_assisted.evaluate_detection_policy(opencv_motion_detected=True)
    assert eval2["alert"] is True
    assert eval2["fallback"] is True
    
    # 3. Mode EDGE_AI_REQUIRED avec modèle prêt mais AUCUN objet détecté -> Alerte rejetée
    det_required = EdgeAIDetector(mode=EdgeAIDetector.MODE_REQUIRED)
    det_required.is_available = MagicMock(return_value=True)
    det_required.detect = MagicMock(return_value={
        "status": "SUCCESS",
        "has_target_object": False,
        "target_objects": [],
        "detections": []
    })
    
    eval3 = det_required.evaluate_detection_policy(opencv_motion_detected=True, image=np.zeros((10,10,3), dtype=np.uint8))
    assert eval3["alert"] is False  # Rejeté en mode REQUIRED car aucun objet cible n'est confirmé
    assert "rejeté" in eval3["reason"]
    
    # 4. Mode EDGE_AI_REQUIRED avec personne confirmée -> Alerte validée
    det_required.detect = MagicMock(return_value={
        "status": "SUCCESS",
        "has_target_object": True,
        "target_objects": ["person"],
        "detections": [{"class": "person", "confidence": 0.89}]
    })
    eval4 = det_required.evaluate_detection_policy(opencv_motion_detected=True, image=np.zeros((10,10,3), dtype=np.uint8))
    assert eval4["alert"] is True
    assert eval4["confirmed"] is True
    assert "person" in eval4["target_objects"]
