import os
import time
import queue
import threading
import requests
from typing import Optional, Dict, Any, Tuple
import config

class TelegramNotifier:
    """Gestionnaire de notifications Telegram asynchrone, non bloquant et sécurisé."""

    def __init__(self,
                 enabled: bool = config.TELEGRAM_ENABLED,
                 bot_token: str = config.TELEGRAM_BOT_TOKEN,
                 chat_id: str = config.TELEGRAM_CHAT_ID,
                 timeout: float = config.TELEGRAM_TIMEOUT,
                 max_retries: int = config.TELEGRAM_MAX_RETRIES):
        self.enabled = enabled
        self.bot_token = bot_token
        self.chat_id = chat_id
        self.timeout = timeout
        self.max_retries = max_retries

        self._queue = queue.Queue(maxsize=100)
        self._stop_event = threading.Event()
        self._lock = threading.Lock()
        
        self.last_sent: Optional[dict] = None
        self.last_error: Optional[str] = None
        self.sent_count = 0
        self.error_count = 0

        # Démarrage du thread d'envoi en arrière-plan
        self._worker_thread = threading.Thread(target=self._worker_loop, daemon=True, name="TelegramNotifierWorker")
        self._worker_thread.start()

    def get_masked_token(self) -> str:
        """Retourne une version masquée du token pour l'affichage et les logs sécurisés."""
        if not self.bot_token:
            return "NON_CONFIGURÉ"
        if ":" in self.bot_token:
            prefix, secret = self.bot_token.split(":", 1)
            return f"{prefix}:{'*' * (len(secret) - 4)}{secret[-4:]}" if len(secret) > 4 else f"{prefix}:****"
        return "CONFIGURÉ (MASQUÉ)"

    def is_configured(self) -> bool:
        return bool(self.bot_token and self.chat_id)

    def send_incident_notification(self, incident: dict, photo_path: Optional[str] = None):
        """Met en file d'attente une alerte d'incident de façon asynchrone (non-bloquante)."""
        if not self.enabled or not self.is_configured():
            return

        severity = incident.get("severity", "INFO")
        # Filtrer : envoyer uniquement pour HIGH et CRITICAL
        if severity not in ["HIGH", "CRITICAL"]:
            return

        try:
            self._queue.put_nowait({
                "type": "incident",
                "incident": incident,
                "photo_path": photo_path,
                "timestamp": time.time()
            })
        except queue.Full:
            print("[Telegram] File de notifications saturée, alerte ignorée pour préserver les ressources.")

    def send_test_message(self, test_by: str = "Admin") -> Tuple[bool, str]:
        """Envoie immédiatement un message de test synchrone réservé à l'administrateur."""
        if not self.is_configured():
            return False, "Telegram n'est pas configuré (token ou chat_id manquant)."

        text = (
            "🛡️ *SMART SECURITY MONITOR*\n\n"
            "✅ *TEST DE CONNEXION RÉUSSI*\n"
            f"👤 Déclenché par : `{test_by}`\n"
            f"🕒 Horodatage : `{time.strftime('%Y-%m-%d %H:%M:%S')}`\n"
            "Ce canal est désormais actif pour la transmission des alertes prioritaires."
        )

        return self._send_text_direct(text)

    def _send_text_direct(self, text: str) -> Tuple[bool, str]:
        url = f"https://api.telegram.org/bot{self.bot_token}/sendMessage"
        payload = {
            "chat_id": self.chat_id,
            "text": text,
            "parse_mode": "Markdown"
        }
        try:
            res = requests.post(url, json=payload, timeout=self.timeout)
            if res.status_code == 200:
                with self._lock:
                    self.sent_count += 1
                    self.last_sent = {"type": "test", "time": time.time()}
                return True, "Message de test transmis avec succès à Telegram."
            else:
                err_msg = f"Erreur HTTP {res.status_code} : {res.text}"
                with self._lock:
                    self.error_count += 1
                    self.last_error = err_msg
                return False, err_msg
        except Exception as e:
            err_msg = f"Exception réseau Telegram : {e}"
            with self._lock:
                self.error_count += 1
                self.last_error = err_msg
            return False, err_msg

    def _worker_loop(self):
        """Boucle d'arrière-plan traitant les notifications en continu sans bloquer l'alarme."""
        while not self._stop_event.is_set():
            try:
                task = self._queue.get(timeout=1.0)
            except queue.Empty:
                continue

            try:
                self._process_notification(task)
            except Exception as e:
                print(f"[Telegram] Erreur traitement notification : {e}")
            finally:
                self._queue.task_done()

    def _process_notification(self, task: dict):
        incident = task.get("incident", {})
        photo_path = task.get("photo_path")
        
        severity = incident.get("severity", "CRITICAL")
        device_name = incident.get("device_name", "Inconnu")
        event_code = incident.get("event_code", incident.get("type", "ALERTE"))
        details = incident.get("details", "Détection dans une zone surveillée.")
        date_str = incident.get("datetime") or time.strftime("%Y-%m-%d %H:%M:%S")

        caption = (
            "🚨 *SMART SECURITY MONITOR // ALERTE*\n\n"
            f"⚠️ *Gravité :* `{severity}`\n"
            f"📹 *Appareil :* {device_name}\n"
            f"⚡ *Événement :* `{event_code}`\n"
            f"🕒 *Heure :* `{date_str}`\n"
            f"📝 *Détails :* {details}\n"
        )

        success = False
        retries = 0

        while retries < self.max_retries and not success and not self._stop_event.is_set():
            try:
                if photo_path and os.path.exists(photo_path) and os.path.getsize(photo_path) > 0:
                    # Envoi avec photo
                    url = f"https://api.telegram.org/bot{self.bot_token}/sendPhoto"
                    with open(photo_path, "rb") as f:
                        files = {"photo": f}
                        data = {"chat_id": self.chat_id, "caption": caption, "parse_mode": "Markdown"}
                        res = requests.post(url, data=data, files=files, timeout=self.timeout)
                    if res.status_code == 200:
                        success = True
                    else:
                        print(f"[Telegram] Échec sendPhoto ({res.status_code})")
                else:
                    # Envoi texte simple
                    success, _ = self._send_text_direct(caption)

                if success:
                    with self._lock:
                        self.sent_count += 1
                        self.last_sent = {
                            "incident_id": incident.get("id"),
                            "severity": severity,
                            "time": time.time()
                        }
                    break
            except Exception as e:
                print(f"[Telegram] Tentative {retries+1}/{self.max_retries} échouée : {e}")

            retries += 1
            if not success and retries < self.max_retries:
                time.sleep(1.0 * retries)

        if not success:
            with self._lock:
                self.error_count += 1
                self.last_error = f"Échec d'envoi après {self.max_retries} tentatives."

    def get_status(self) -> Dict[str, Any]:
        """Retourne l'état de configuration et de fonctionnement de Telegram."""
        with self._lock:
            return {
                "enabled": self.enabled,
                "configured": self.is_configured(),
                "bot_token_masked": self.get_masked_token(),
                "chat_id_set": bool(self.chat_id),
                "sent_count": self.sent_count,
                "error_count": self.error_count,
                "last_sent": self.last_sent,
                "last_error": self.last_error,
                "queue_size": self._queue.qsize()
            }

    def stop(self):
        self._stop_event.set()
