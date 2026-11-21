import time
import pytest
from unittest.mock import patch, MagicMock
from monitoring.telegram_notifier import TelegramNotifier
from app import create_app

def test_telegram_configuration_and_masking():
    """Vérifie la détection de configuration et le masquage strict du token."""
    # 1. Non configuré
    t_unconf = TelegramNotifier(enabled=False, bot_token="", chat_id="")
    assert t_unconf.is_configured() is False
    assert t_unconf.get_masked_token() == "NON_CONFIGURÉ"
    t_unconf.stop()

    # 2. Configuré avec masquage
    token = "123456789:AAEFGHIJKLMNOPQRSTUVWXYZ12345"
    t_conf = TelegramNotifier(enabled=True, bot_token=token, chat_id="987654321")
    assert t_conf.is_configured() is True
    masked = t_conf.get_masked_token()
    assert "123456789:" in masked
    assert "AAEF" not in masked  # Le corps du secret est masqué
    assert "2345" in masked       # Seuls les 4 derniers caractères sont visibles
    t_conf.stop()

@patch("requests.post")
def test_telegram_test_message_mock(mock_post):
    """Vérifie l'envoi d'un message de test via mock HTTP."""
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.text = '{"ok": true}'
    mock_post.return_value = mock_resp

    notifier = TelegramNotifier(enabled=True, bot_token="123:TOKEN", chat_id="456")
    success, msg = notifier.send_test_message(test_by="AdminTest")
    
    assert success is True
    assert "succès" in msg.lower()
    assert mock_post.called
    assert "sendMessage" in mock_post.call_args[0][0]
    notifier.stop()

@patch("requests.post")
def test_telegram_incident_dispatch(mock_post, tmp_path):
    """Vérifie la transmission asynchrone d'une alerte CRITICAL avec photo."""
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.text = '{"ok": true}'
    mock_post.return_value = mock_resp

    test_photo = str(tmp_path / "intruder.jpg")
    with open(test_photo, "wb") as f:
        f.write(b"\xFF\xD8\xFF\xE0" + b"\x00" * 100)

    notifier = TelegramNotifier(enabled=True, bot_token="123:TOKEN", chat_id="456")
    
    incident = {
        "id": "alert_tg_test",
        "severity": "CRITICAL",
        "device_name": "Camera Salon",
        "event_code": "INTRUSION_DETECTED",
        "details": "Personne détectée dans la zone porte"
    }

    # Envoi asynchrone
    notifier.send_incident_notification(incident, photo_path=test_photo)
    time.sleep(0.3)  # Laisse le worker thread traiter

    assert mock_post.called
    notifier.stop()
