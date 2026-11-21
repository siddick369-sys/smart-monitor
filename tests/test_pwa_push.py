import os
import json
import pytest

from monitoring.push_manager import PushManager

def test_pwa_manifest_validity():
    """Vérifie la présence et la conformité W3C du manifest.json."""
    manifest_path = "static/manifest.json"
    assert os.path.exists(manifest_path)
    
    with open(manifest_path, "r", encoding="utf-8") as f:
        manifest = json.load(f)
        
    assert manifest["name"] == "Smart Security Monitor - TP4"
    assert manifest["short_name"] == "SecurityMonitor"
    assert manifest["display"] == "standalone"
    assert manifest["start_url"] == "/"
    assert len(manifest["icons"]) >= 1
    assert manifest["icons"][0]["src"] == "/static/icons/icon.svg"

def test_service_worker_security_blacklist():
    """Vérifie que le Service Worker interdit formellement la mise en cache des routes sensibles."""
    sw_path = "static/sw.js"
    assert os.path.exists(sw_path)
    
    with open(sw_path, "r", encoding="utf-8") as f:
        content = f.read()
        
    assert "CACHE_NAME" in content
    # Vérification des motifs sensibles interdits de mise en cache
    assert "api" in content
    assert "video" in content
    assert "stream" in content
    assert "recordings" in content
    assert "screenshots" in content
    assert "login" in content

def test_push_manager_subscription_lifecycle(tmp_path):
    """Vérifie l'enregistrement, la déduplication et la révocation des abonnements Web Push."""
    sub_file = str(tmp_path / "subscriptions.json")
    mgr = PushManager(subscriptions_file=sub_file)
    
    sample_sub = {
        "endpoint": "https://fcm.googleapis.com/fcm/send/sample_token_123",
        "keys": {
            "p256dh": "BLcl_sample_key",
            "auth": "auth_sample_key"
        }
    }
    
    # 1. Ajout abonnement
    ok = mgr.add_subscription(sample_sub, user_id="admin_01")
    assert ok is True
    assert len(mgr.get_subscriptions()) == 1
    assert os.path.exists(sub_file)
    
    # 2. Déduplication (ré-enregistrement du même endpoint met à jour sans doublon)
    mgr.add_subscription(sample_sub, user_id="admin_01")
    assert len(mgr.get_subscriptions()) == 1
    
    # 3. Émission de notification sécurisée
    delivery = mgr.send_notification("Alerte Intrusion", "Mouvement détecté caméra entrée")
    assert delivery["success"] is True
    assert delivery["total_subscribers"] == 1
    assert delivery["payload"]["title"] == "Alerte Intrusion"
    
    # 4. Révocation / suppression
    removed = mgr.remove_subscription(sample_sub["endpoint"])
    assert removed is True
    assert len(mgr.get_subscriptions()) == 0
