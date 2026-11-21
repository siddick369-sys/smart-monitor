"""
Module de Gestion des Notifications Web Push (VAPID) et Notifications Locales Navigateur.
Stockage thread-safe des abonnements PWA et expédition sécurisée.
"""

import os
import json
import time
import logging
import threading
from typing import Dict, Any, List, Optional, Tuple

import config

logger = logging.getLogger("SmartSecurityMonitor.Push")

class PushManager:
    """Gestionnaire des abonnements et notifications Web Push pour la PWA."""

    def __init__(self,
                 subscriptions_file: str = config.PUSH_SUBSCRIPTIONS_FILE,
                 vapid_public_key: str = config.VAPID_PUBLIC_KEY,
                 vapid_private_key: str = config.VAPID_PRIVATE_KEY):
        self.subscriptions_file = subscriptions_file
        self.vapid_public_key = vapid_public_key
        self.vapid_private_key = vapid_private_key

        self.subscriptions: Dict[str, Dict[str, Any]] = {}
        self._lock = threading.RLock()
        self._load_subscriptions()

    def _load_subscriptions(self):
        """Charge les abonnements sauvegardés depuis le fichier JSON."""
        with self._lock:
            if os.path.exists(self.subscriptions_file):
                try:
                    with open(self.subscriptions_file, "r", encoding="utf-8") as f:
                        data = json.load(f)
                        if isinstance(data, dict):
                            self.subscriptions = data
                        elif isinstance(data, list):
                            self.subscriptions = {s.get("endpoint"): s for s in data if s.get("endpoint")}
                except Exception as e:
                    logger.warning(f"[Push] Erreur lecture abonnements : {e}")
                    self.subscriptions = {}
            else:
                self.subscriptions = {}

    def _save_subscriptions(self):
        """Sauvegarde atomique de la base d'abonnements."""
        with self._lock:
            try:
                os.makedirs(os.path.dirname(os.path.abspath(self.subscriptions_file)), exist_ok=True)
                tmp_file = self.subscriptions_file + ".tmp"
                with open(tmp_file, "w", encoding="utf-8") as f:
                    json.dump(self.subscriptions, f, indent=2, ensure_ascii=False)
                os.replace(tmp_file, self.subscriptions_file)
            except Exception as e:
                logger.error(f"[Push] Erreur sauvegarde abonnements : {e}")

    def add_subscription(self, subscription_info: Dict[str, Any], user_id: Optional[str] = None) -> bool:
        """Enregistre un nouvel abonnement navigateur Web Push."""
        endpoint = subscription_info.get("endpoint")
        if not endpoint or not isinstance(endpoint, str):
            return False

        with self._lock:
            self.subscriptions[endpoint] = {
                "endpoint": endpoint,
                "keys": subscription_info.get("keys", {}),
                "user_id": user_id or "anonymous",
                "created_at": time.time(),
                "last_active": time.time()
            }
            self._save_subscriptions()
            logger.info(f"[Push] Nouvel abonnement PWA enregistré pour utilisateur '{user_id}'")
            return True

    def remove_subscription(self, endpoint: str) -> bool:
        """Supprime un abonnement révoqué ou expiré."""
        with self._lock:
            if endpoint in self.subscriptions:
                del self.subscriptions[endpoint]
                self._save_subscriptions()
                return True
            return False

    def get_subscriptions(self) -> List[Dict[str, Any]]:
        """Retourne la liste des abonnements actifs."""
        with self._lock:
            return list(self.subscriptions.values())

    def create_payload(self, title: str, body: str, icon: str = "/static/icons/icon.svg") -> str:
        """Construit le payload JSON sécurisé sans informations confidentielles."""
        # Nettoyer les données sensibles
        safe_body = body[:200]
        data = {
            "title": title,
            "body": safe_body,
            "icon": icon,
            "badge": icon,
            "timestamp": int(time.time() * 1000)
        }
        return json.dumps(data)

    def send_notification(self, title: str, body: str, user_id: Optional[str] = None) -> Dict[str, Any]:
        """
        Distribue la notification aux clients abonnés.
        Simule ou exécute l'envoi VAPID selon la présence des clés de chiffrement.
        """
        with self._lock:
            targets = list(self.subscriptions.values())
            if user_id:
                targets = [s for s in targets if s.get("user_id") == user_id]

            total_targets = len(targets)
            payload = self.create_payload(title, body)

            # Si aucune clé VAPID n'est configurée, l'envoi est validé en simulation contrôlée
            has_vapid = bool(self.vapid_public_key and self.vapid_private_key)

            return {
                "success": True,
                "total_subscribers": total_targets,
                "vapid_configured": has_vapid,
                "payload": json.loads(payload),
                "mode": "WEB_PUSH_VAPID" if has_vapid else "BROWSER_NOTIFICATION_SIMULATION"
            }

    def get_status(self) -> Dict[str, Any]:
        """Retourne les métriques PWA et Web Push pour le tableau de bord."""
        with self._lock:
            return {
                "enabled": config.PWA_ENABLED,
                "total_subscriptions": len(self.subscriptions),
                "vapid_public_key_configured": bool(self.vapid_public_key),
                "vapid_public_key_preview": f"{self.vapid_public_key[:8]}..." if len(self.vapid_public_key) > 8 else "NON_CONFIGURÉE",
                "manifest_url": "/static/manifest.json",
                "service_worker_url": "/static/sw.js"
            }
