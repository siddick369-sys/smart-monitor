import time
import json
import pytest
import numpy as np
import requests
from unittest.mock import patch, MagicMock
from monitoring.qwen_vision_manager import QwenVisionManager

def test_free_tier_catalog_filtering():
    """Vérifie la sélection exclusive d'un modèle Qwen Vision vérifié Free Tier et le rejet des payants."""
    # 1. Clé absente -> OPENCV_ONLY
    mgr_no_key = QwenVisionManager(enabled=True, api_key="")
    assert mgr_no_key.status == QwenVisionManager.STATUS_OPENCV_ONLY
    assert mgr_no_key.verification_level == "NONE"
    mgr_no_key.stop()

    # 2. Mock du catalogue xKiro avec mélange de modèles
    mock_catalog = {
        "data": [
            # Modèle 1 : Qwen textuel uniquement (pas vision) -> Rejeté
            {"id": "qwen2.5-7b-chat:free", "free": True},
            # Modèle 2 : Modèle Vision non-Qwen -> Rejeté
            {"id": "llama-3.2-vision:free", "free": True},
            # Modèle 3 : Qwen Vision PAYANT -> REJET STRICT
            {"id": "qwen2.5-vl-72b-instruct", "free": False, "pricing": {"prompt": 0.002, "completion": 0.005}},
            # Modèle 4 : Qwen Vision GRATUIT VÉRIFIÉ -> DOIT ÊTRE ACCEPTÉ
            {"id": "qwen2.5-vl-7b-instruct:free", "free": True, "pricing": {"prompt": 0, "completion": 0}}
        ]
    }

    with patch("requests.get") as mock_get:
        mock_res = MagicMock()
        mock_res.status_code = 200
        mock_res.json.return_value = mock_catalog
        mock_get.return_value = mock_res

        mgr = QwenVisionManager(enabled=True, api_key="sk-test-xkiro-free-key")
        
        assert mgr.status == QwenVisionManager.STATUS_FREE_TIER_VERIFIED
        assert mgr.selected_model == "qwen2.5-vl-7b-instruct:free"
        assert mgr.verification_level == "CATALOG_VERIFIED_FREE"
        mgr.stop()

def test_rejection_when_no_free_vision_model():
    """Vérifie le repli sur OpenCV lorsque aucun modèle Qwen Vision n'est gratuit."""
    mock_catalog_only_paid = {
        "data": [
            {"id": "qwen2.5-vl-72b", "free": False, "pricing": {"prompt": 0.01}},
            {"id": "gpt-4o", "free": False}
        ]
    }

    with patch("requests.get") as mock_get:
        mock_res = MagicMock()
        mock_res.status_code = 200
        mock_res.json.return_value = mock_catalog_only_paid
        mock_get.return_value = mock_res

        mgr = QwenVisionManager(enabled=True, api_key="sk-test-key")
        assert mgr.status == QwenVisionManager.STATUS_FREE_TIER_NOT_VERIFIED
        assert mgr.selected_model is None
        assert mgr.verification_level == "NONE"
        mgr.stop()

@patch("requests.post")
def test_structured_json_classification_and_429(mock_post):
    """Vérifie l'analyse d'image, le parsing du JSON et la gestion du quota 429."""
    # Simulation réponse Qwen Vision valide
    valid_ai_json = json.dumps({
        "detected": True,
        "primary_object": "PERSON",
        "objects": ["PERSON"],
        "activity": "Intrusion suspecte devant la caméra",
        "event_type": "INTRUSION",
        "risk_level": "CRITICAL",
        "confidence": 0.94,
        "description": "Silhouette humaine détectée",
        "suggested_action": "DÉCLENCHER_ALARME",
        "uncertain": False
    })

    mock_res_200 = MagicMock()
    mock_res_200.status_code = 200
    mock_res_200.json.return_value = {
        "choices": [{"message": {"content": f"```json\n{valid_ai_json}\n```"}}]
    }
    mock_post.return_value = mock_res_200

    mgr = QwenVisionManager(enabled=True, api_key="sk-test", min_interval=0.0)
    mgr.status = QwenVisionManager.STATUS_FREE_TIER_VERIFIED
    mgr.selected_model = "qwen2.5-vl-7b-instruct:free"

    dummy_frame = np.zeros((480, 640, 3), dtype=np.uint8)
    result = mgr.analyze_frame_sync(dummy_frame)

    assert result["detected"] is True
    assert result["primary_object"] == "PERSON"
    assert result["risk_level"] == "CRITICAL"
    assert result["risk_level_fr"] == "CRITIQUE"
    assert result["confidence"] == 0.94
    assert result["event_type"] == "INTRUSION"
    assert result["suggested_action"] == "DÉCLENCHER_ALARME"
    assert result["uncertain"] is False

    # Test de réponse 429 Quota Reached
    mock_res_429 = MagicMock()
    mock_res_429.status_code = 429
    mock_post.return_value = mock_res_429

    res_quota = mgr.analyze_frame_sync(dummy_frame)
    assert mgr.status == QwenVisionManager.STATUS_FREE_TIER_QUOTA_REACHED
    assert res_quota["uncertain"] is True
    mgr.stop()

@patch("requests.post")
def test_circuit_breaker_mechanism(mock_post):
    """Vérifie le déclenchement du Circuit Breaker après 3 échecs consécutifs."""
    mock_err_res = MagicMock()
    mock_err_res.status_code = 500
    mock_post.return_value = mock_err_res

    mgr = QwenVisionManager(enabled=True, api_key="sk-test", min_interval=0.0)
    mgr.status = QwenVisionManager.STATUS_FREE_TIER_VERIFIED
    mgr.selected_model = "qwen2.5-vl-7b-instruct:free"

    dummy_frame = np.zeros((480, 640, 3), dtype=np.uint8)

    # 1ère erreur
    mgr.analyze_frame_sync(dummy_frame)
    assert mgr.consecutive_errors == 1
    assert mgr.status == QwenVisionManager.STATUS_FREE_TIER_VERIFIED

    # 2ème erreur
    mgr.analyze_frame_sync(dummy_frame)
    assert mgr.consecutive_errors == 2

    # 3ème erreur -> Disjoncteur déclenché !
    res3 = mgr.analyze_frame_sync(dummy_frame)
    assert mgr.consecutive_errors == 3
    assert mgr.status == QwenVisionManager.STATUS_ERROR
    assert res3["model_used"] == "OPENCV_LOCAL_FALLBACK"

    # Vérification que is_available() retourne False
    assert mgr.is_available() is False
    mgr.stop()

def test_insufficient_metadata_and_network_errors():
    """Vérifie le rejet des modèles sans métadonnées explicites de gratuité et les erreurs réseau."""
    # 1. Modèle avec nom vision mais aucune indication de gratuité -> Rejeté
    mock_incomplete_catalog = {
        "data": [
            {"id": "qwen-vl-max"}  # Pas de champ free, pas de pricing, pas de :free
        ]
    }
    with patch("requests.get") as mock_get:
        mock_res = MagicMock()
        mock_res.status_code = 200
        mock_res.json.return_value = mock_incomplete_catalog
        mock_get.return_value = mock_res

        mgr = QwenVisionManager(enabled=True, api_key="sk-test-key")
        assert mgr.status == QwenVisionManager.STATUS_FREE_TIER_NOT_VERIFIED
        assert mgr.selected_model is None
        mgr.stop()

    # 2. Erreur réseau / Timeout lors de l'appel au catalogue
    with patch("requests.get", side_effect=requests.exceptions.Timeout("Timeout xKiro")):
        mgr_timeout = QwenVisionManager(enabled=True, api_key="sk-test-key")
        assert mgr_timeout.status == QwenVisionManager.STATUS_XKIRO_UNAVAILABLE
        assert "Erreur de communication" in mgr_timeout.status_detail
        mgr_timeout.stop()

def test_startup_without_key_makes_zero_network_calls():
    """Vérifie que sans clé API xKiro configurée, aucune requête réseau n'est émise et OpenCV reste actif."""
    with patch("requests.get") as mock_get, patch("requests.post") as mock_post:
        mgr = QwenVisionManager(enabled=True, api_key="")
        assert mgr.status == QwenVisionManager.STATUS_OPENCV_ONLY
        assert not mgr.is_available()
        assert mgr.verification_level == "NONE"

        # Vérification qu'aucun appel réseau n'a été effectué
        mock_get.assert_not_called()
        mock_post.assert_not_called()

        # Inférence locale de repli
        frame = np.zeros((100, 100, 3), dtype=np.uint8)
        res = mgr.analyze_frame_sync(frame)
        assert res["model_used"] == "OPENCV_LOCAL_FALLBACK"
        assert res["event_type"] == "MOUVEMENT_OPENCV"

        mock_post.assert_not_called()
        mgr.stop()
