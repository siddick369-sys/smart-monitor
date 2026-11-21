import os
import threading
import time
import requests
from typing import Optional, Dict
import config

try:
    import winsound
    HAS_WINSOUND = True
except ImportError:
    HAS_WINSOUND = False

class AlarmManager:
    """Gestionnaire de l'état d'armement, de la sirène sonore et du pilotage des torches."""

    def __init__(self, device_store):
        self.device_store = device_store
        self._lock = threading.RLock()
        
        self.is_armed = self.device_store.get_settings().get("system_armed", True)
        self.in_alarm = False
        self.siren_active = False
        
        self.current_incident: Optional[dict] = None
        self._siren_thread: Optional[threading.Thread] = None
        self._stop_siren_event = threading.Event()
        
        self.siren_wav_path = os.path.join(config.BASE_DIR, "static", "audio", "siren.wav")

    def arm(self):
        with self._lock:
            self.is_armed = True
            self.device_store.update_settings({"system_armed": True})
            print("[AlarmManager] Système ARMÉ.")

    def disarm(self):
        with self._lock:
            self.is_armed = False
            self.device_store.update_settings({"system_armed": False})
            self.stop_siren()
            self.in_alarm = False
            print("[AlarmManager] Système DÉSARMÉ.")

    def trigger_alarm(self, incident: dict):
        """Déclenché par le DetectionEngine lors d'un incident avéré."""
        with self._lock:
            if not self.is_armed:
                print(f"[AlarmManager] Détection ignorée pour alerte (système désarmé) : {incident['type']}")
                return

            self.in_alarm = True
            self.current_incident = {k: v for k, v in incident.items() if k != "frame" and not hasattr(v, "shape")}
            print(f"[AlarmManager] ALARME DÉCLENCHÉE ! [{incident['category']}] {incident['type']} - {incident['device_name']}")

            settings = self.device_store.get_settings()
            if settings.get("siren_enabled", True):
                self.start_siren()

            # Activer la torche si activée globalement ou pour cet appareil
            device_id = incident.get("device_id")
            device = self.device_store.get_device(device_id)
            if device and (settings.get("torch_on_alarm", False) or device.get("enable_torch", False)):
                self.set_torch(device_id, True)

    def start_siren(self):
        """Démarre la sirène sonore sur le PC de manière asynchrone non bloquante."""
        with self._lock:
            if self.siren_active:
                return
            self.siren_active = True
            self._stop_siren_event.clear()

            if HAS_WINSOUND:
                try:
                    if os.path.exists(self.siren_wav_path):
                        winsound.PlaySound(self.siren_wav_path, winsound.SND_FILENAME | winsound.SND_ASYNC | winsound.SND_LOOP)
                    else:
                        self._siren_thread = threading.Thread(target=self._beep_siren_loop, name="WinsoundBeepSiren", daemon=True)
                        self._siren_thread.start()
                except Exception as e:
                    print(f"[AlarmManager] Erreur lecture sonore : {e}")
                    self._siren_thread = threading.Thread(target=self._beep_siren_loop, name="WinsoundBeepSiren", daemon=True)
                    self._siren_thread.start()

    def stop_siren(self):
        """Arrête immédiatement la sirène sonore sans couper le serveur."""
        with self._lock:
            self.siren_active = False
            self._stop_siren_event.set()
            if HAS_WINSOUND:
                try:
                    winsound.PlaySound(None, winsound.SND_PURGE)
                except Exception:
                    pass
            print("[AlarmManager] Sirène arrêtée.")

    def reset_alarm_state(self):
        """Réinitialise l'état d'alerte en cours."""
        with self._lock:
            self.stop_siren()
            self.in_alarm = False
            self.current_incident = None

    def _beep_siren_loop(self):
        """Boucle sonore de secours utilisant winsound.Beep modulant."""
        while not self._stop_siren_event.is_set() and self.siren_active:
            try:
                winsound.Beep(850, 200)
                if self._stop_siren_event.is_set():
                    break
                winsound.Beep(1200, 200)
            except Exception:
                break

    def test_siren(self, duration_seconds: float = 3.0):
        """Effectue un test sonore limité dans le temps."""
        def _test_worker():
            self.start_siren()
            time.sleep(duration_seconds)
            self.stop_siren()

        threading.Thread(target=_test_worker, daemon=True).start()

    def set_torch(self, device_id: str, enable: bool):
        """Envoie la commande d'activation ou de désactivation de la torche du smartphone."""
        device = self.device_store.get_device(device_id)
        if not device:
            return

        ip = device["ip"]
        port = device["port"]
        ok, reason = config.is_allowed_camera_target(ip, port)
        if not ok:
            print(f"[AlarmManager] Envoi torche bloqué (SSRF): {reason}")
            return

        endpoint = "enabletorch" if enable else "disabletorch"
        url = f"http://{ip}:{port}/{endpoint}"

        def _send():
            try:
                requests.get(url, timeout=config.HTTP_TIMEOUT, allow_redirects=False)
                print(f"[AlarmManager] Torche {endpoint} envoyée à {device['name']}")
            except Exception as e:
                print(f"[AlarmManager] Erreur torche {endpoint} sur {device['name']} : {e}")

        threading.Thread(target=_send, daemon=True).start()

    def get_status(self) -> dict:
        with self._lock:
            return {
                "is_armed": self.is_armed,
                "in_alarm": self.in_alarm,
                "siren_active": self.siren_active,
                "current_incident": self.current_incident
            }
