"""
Module de Détection de Présence Réseau et Armement Intelligent (Geofencing Wi-Fi).

Gère les appareils autorisés (smartphones/ordinateurs des occupants),
la détection de présence non intrusive (ARP / Ping contrôlé) et la machine
à états d'armement automatique sécurisée.
"""

import os
import json
import time
import socket
import logging
import threading
import subprocess
from typing import Dict, Any, List, Optional, Tuple, Callable

import config

logger = logging.getLogger("SmartSecurityMonitor.Presence")


class PresenceManager:
    """Gestionnaire de présence réseau et d'armement intelligent."""

    # États de la machine à états d'armement
    STATE_MANUAL = "MANUAL"
    STATE_HOME = "HOME"
    STATE_AWAY_PENDING = "AWAY_PENDING"
    STATE_ARMED_AWAY = "ARMED_AWAY"
    STATE_RETURN_PENDING = "RETURN_PENDING"
    STATE_UNKNOWN = "UNKNOWN"

    # Statuts de présence unitaire d'un appareil
    PRESENCE_PRESENT = "PRESENT"
    PRESENCE_ABSENT = "ABSENT"
    PRESENCE_UNKNOWN = "UNKNOWN"

    def __init__(self,
                 alarm_manager=None,
                 notification_manager=None,
                 enabled: bool = config.PRESENCE_ENABLED,
                 auto_arm: bool = config.PRESENCE_AUTO_ARM,
                 auto_disarm_on_return: bool = False,
                 grace_period_seconds: int = config.PRESENCE_GRACE_PERIOD_SECONDS,
                 check_interval: int = config.PRESENCE_CHECK_INTERVAL_SECONDS,
                 devices_file: str = config.PRESENCE_DEVICES_FILE):
        self.alarm_manager = alarm_manager
        self.notification_manager = notification_manager
        self.enabled = enabled
        self.auto_arm = auto_arm
        self.auto_disarm_on_return = auto_disarm_on_return
        self.grace_period_seconds = max(1, grace_period_seconds)
        self.check_interval = max(1, check_interval)
        self.devices_file = devices_file

        self.current_state = self.STATE_MANUAL if not self.auto_arm else self.STATE_UNKNOWN
        self.state_entered_time = time.time()
        self.state_reason = "Initialisation du gestionnaire de présence."

        self.devices: Dict[str, Dict[str, Any]] = {}
        self._consecutive_misses: Dict[str, int] = {}
        self.miss_threshold = 3  # Tolérance au sommeil Wi-Fi des smartphones

        self._lock = threading.RLock()
        self._stop_event = threading.Event()
        self._worker_thread: Optional[threading.Thread] = None
        self._state_callbacks: List[Callable[[str, str], None]] = []

        self._load_devices()

        if self.enabled:
            self.start()

    def register_state_callback(self, cb: Callable[[str, str], None]):
        """Enregistre un écouteur de changement d'état (old_state, new_state)."""
        with self._lock:
            self._state_callbacks.append(cb)

    def _load_devices(self):
        """Charge la liste des appareils de confiance depuis le fichier JSON."""
        with self._lock:
            if os.path.exists(self.devices_file):
                try:
                    with open(self.devices_file, "r", encoding="utf-8") as f:
                        data = json.load(f)
                        if isinstance(data, dict):
                            self.devices = data
                        elif isinstance(data, list):
                            self.devices = {d["id"]: d for d in data if "id" in d}
                except Exception as e:
                    logger.warning(f"[Presence] Erreur lecture {self.devices_file} : {e}")
                    self.devices = {}
            else:
                self.devices = {}

    def _save_devices(self):
        """Sauvegarde atomique de la configuration des appareils."""
        with self._lock:
            try:
                os.makedirs(os.path.dirname(os.path.abspath(self.devices_file)), exist_ok=True)
                tmp_file = self.devices_file + ".tmp"
                with open(tmp_file, "w", encoding="utf-8") as f:
                    json.dump(self.devices, f, indent=2, ensure_ascii=False)
                os.replace(tmp_file, self.devices_file)
            except Exception as e:
                logger.error(f"[Presence] Erreur sauvegarde {self.devices_file} : {e}")

    def add_trusted_device(self,
                           name: str,
                           ip: str,
                           mac: Optional[str] = None,
                           device_type: str = "smartphone",
                           authorized: bool = True) -> Dict[str, Any]:
        """Ajoute ou met à jour un appareil autorisé pour la présence réseau."""
        clean_ip = ip.strip() if ip else ""
        if not config.is_allowed_ip(clean_ip):
            raise ValueError(f"Adresse IP de périphérique de confiance refusée (anti-SSRF) : '{ip}'")

        with self._lock:
            dev_id = f"pres_{int(time.time() * 1000)}"
            device_entry = {
                "id": dev_id,
                "name": name.strip(),
                "ip": clean_ip,
                "mac": mac.strip().lower() if mac else "",
                "type": device_type,
                "authorized": bool(authorized),
                "status": self.PRESENCE_UNKNOWN,
                "last_seen": 0.0,
                "last_checked": 0.0,
                "created_at": time.time()
            }
            self.devices[dev_id] = device_entry
            self._consecutive_misses[dev_id] = 0
            self._save_devices()
            logger.info(f"[Presence] Appareil de confiance ajouté : {name} ({clean_ip})")
            return device_entry

    def remove_trusted_device(self, device_id: str) -> bool:
        """Supprime un appareil autorisé."""
        with self._lock:
            if device_id in self.devices:
                del self.devices[device_id]
                self._consecutive_misses.pop(device_id, None)
                self._save_devices()
                return True
            return False

    def get_trusted_devices(self) -> List[Dict[str, Any]]:
        """Retourne la liste de tous les appareils enregistrés."""
        with self._lock:
            return list(self.devices.values())

    def ping_check(self, ip: str, timeout_ms: int = 400) -> bool:
        """Effectue un test de présence réseau non agressif (ICMP ping unitaire ou socket)."""
        if not ip or not config.is_allowed_ip(ip):
            return False

        # 1. Tentative rapide via socket UDP/TCP vers ports standards
        for test_port in [5353, 80, 443]:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(timeout_ms / 1000.0)
                res = s.connect_ex((ip, test_port))
                s.close()
                if res == 0:
                    return True
            except Exception:
                pass

        # 2. Ping unitaire sous Windows
        try:
            cmd = ["ping", "-n", "1", "-w", str(timeout_ms), ip]
            res = subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            return res.returncode == 0
        except Exception:
            return False

    def check_device_presence(self, device: Dict[str, Any]) -> str:
        """Évalue la présence d'un appareil donné sans saturer le réseau."""
        ip = device.get("ip", "")
        if not ip:
            return self.PRESENCE_UNKNOWN

        is_alive = self.ping_check(ip)
        now = time.time()
        dev_id = device["id"]

        with self._lock:
            device["last_checked"] = now
            if is_alive:
                device["status"] = self.PRESENCE_PRESENT
                device["last_seen"] = now
                self._consecutive_misses[dev_id] = 0
                return self.PRESENCE_PRESENT
            else:
                misses = self._consecutive_misses.get(dev_id, 0) + 1
                self._consecutive_misses[dev_id] = misses
                if misses >= self.miss_threshold:
                    device["status"] = self.PRESENCE_ABSENT
                    return self.PRESENCE_ABSENT
                else:
                    return device.get("status", self.PRESENCE_UNKNOWN)

    def evaluate_state_machine(self) -> Tuple[str, str]:
        """
        Exécute une itération de la machine à états de présence.
        Gère les transitions sécurisées HOME, AWAY_PENDING, ARMED_AWAY, RETURN_PENDING.
        """
        with self._lock:
            if not self.enabled:
                return self.current_state, "Présence désactivée"

            if not self.auto_arm and self.current_state != self.STATE_MANUAL:
                self._transition_to(self.STATE_MANUAL, "Mode manuel actif (Armement auto désactivé).")
                return self.current_state, self.state_reason

            # Sondage de tous les appareils autorisés
            authorized_devs = [d for d in self.devices.values() if d.get("authorized", True)]
            if not authorized_devs:
                if self.current_state != self.STATE_MANUAL:
                    self._transition_to(self.STATE_MANUAL, "Aucun appareil autorisé configuré.")
                return self.current_state, self.state_reason

            present_count = 0
            absent_count = 0
            for d in authorized_devs:
                st = self.check_device_presence(d)
                if st == self.PRESENCE_PRESENT:
                    present_count += 1
                elif st == self.PRESENCE_ABSENT:
                    absent_count += 1

            now = time.time()
            all_absent = (absent_count == len(authorized_devs))
            at_least_one_present = (present_count > 0)

            # Machine à états
            if self.current_state in [self.STATE_UNKNOWN, self.STATE_MANUAL]:
                if at_least_one_present:
                    self._transition_to(self.STATE_HOME, f"{present_count} appareil(s) autorisé(s) détecté(s) à domicile.")
                elif all_absent:
                    self._transition_to(self.STATE_AWAY_PENDING, "Tous les appareils autorisés sont absents. Délai de grâce initié.")

            elif self.current_state == self.STATE_HOME:
                if all_absent:
                    self._transition_to(self.STATE_AWAY_PENDING, f"Départ confirmé. Période de grâce de {self.grace_period_seconds}s avant armement.")

            elif self.current_state == self.STATE_AWAY_PENDING:
                if at_least_one_present:
                    self._transition_to(self.STATE_HOME, "Appareil revenu pendant la période de grâce. Armement annulé.")
                elif all_absent:
                    elapsed = now - self.state_entered_time
                    if elapsed >= self.grace_period_seconds:
                        self._transition_to(self.STATE_ARMED_AWAY, "Période de grâce écoulée. Armement automatique activé.")
                        # Armement effectif du système
                        if self.alarm_manager:
                            try:
                                self.alarm_manager.arm()
                                logger.info("[Presence] Système armé automatiquement par départ des occupants.")
                            except Exception as e:
                                logger.error(f"[Presence] Erreur lors de l'armement : {e}")

            elif self.current_state == self.STATE_ARMED_AWAY:
                if at_least_one_present:
                    # Règle de sécurité : un appareil qui réapparaît ne doit pas désarmer silencieusement
                    if self.auto_disarm_on_return:
                        self._transition_to(self.STATE_HOME, "Retour d'un appareil autorisé : désarmement automatique autorisé.")
                        if self.alarm_manager:
                            try:
                                self.alarm_manager.disarm()
                            except Exception as e:
                                logger.error(f"[Presence] Erreur désarmement : {e}")
                    else:
                        self._transition_to(self.STATE_RETURN_PENDING, "Appareil autorisé détecté. Désarmement en attente de validation.")

            elif self.current_state == self.STATE_RETURN_PENDING:
                # En attente de désarmement explicite ou retour à HOME si désarmé manuellement
                if self.alarm_manager and not getattr(self.alarm_manager, "is_armed", lambda: False)():
                    self._transition_to(self.STATE_HOME, "Système désarmé par l'utilisateur.")
                elif all_absent:
                    self._transition_to(self.STATE_ARMED_AWAY, "Les appareils sont repartis. Réactivation armement.")

            self._save_devices()
            return self.current_state, self.state_reason

    def _transition_to(self, new_state: str, reason: str):
        """Effectue une transition d'état et déclenche les notifications."""
        old_state = self.current_state
        self.current_state = new_state
        self.state_entered_time = time.time()
        self.state_reason = reason
        logger.info(f"[Presence] Transition d'état : {old_state} -> {new_state} ({reason})")

        # Notification au centre de supervision si disponible
        if self.notification_manager:
            try:
                sev = "WARNING" if new_state == self.STATE_AWAY_PENDING else "INFO"
                self.notification_manager.add_notification(
                    title="GÉOFENCING RÉSEAU",
                    message=f"État : {new_state} — {reason}",
                    severity=sev,
                    source="PresenceManager"
                )
            except Exception:
                pass

        # Exécution des callbacks enregistrés
        for cb in self._state_callbacks:
            try:
                cb(old_state, new_state)
            except Exception as e:
                logger.error(f"[Presence] Erreur callback transition : {e}")

    def manual_override(self, target_state: str, reason: str = "Intervention manuelle utilisateur"):
        """Permet à l'administrateur de forcer l'état de présence (priorité manuelle absolue)."""
        with self._lock:
            valid_states = [self.STATE_MANUAL, self.STATE_HOME, self.STATE_ARMED_AWAY]
            if target_state in valid_states:
                self._transition_to(target_state, f"Dérogation manuelle : {reason}")
                return True
            return False

    def _worker_loop(self):
        """Boucle d'évaluation périodique d'arrière-plan."""
        while not self._stop_event.is_set():
            try:
                self.evaluate_state_machine()
            except Exception as e:
                logger.error(f"[Presence] Erreur dans la boucle travailleur : {e}")

            self._stop_event.wait(self.check_interval)

    def start(self):
        """Démarre le thread d'arrière-plan."""
        with self._lock:
            if self._worker_thread is None or not self._worker_thread.is_alive():
                self._stop_event.clear()
                self._worker_thread = threading.Thread(target=self._worker_loop, daemon=True, name="PresenceWorker")
                self._worker_thread.start()
                logger.info("[Presence] Service de détection de présence démarré.")

    def stop(self):
        """Arrête proprement le thread."""
        with self._lock:
            self._stop_event.set()
            if self._worker_thread:
                self._worker_thread.join(timeout=2.0)
                self._worker_thread = None

    def get_status(self) -> Dict[str, Any]:
        """Retourne l'état complet du gestionnaire pour l'API et l'IHM."""
        with self._lock:
            now = time.time()
            elapsed_in_state = int(now - self.state_entered_time)
            remaining_grace = max(0, self.grace_period_seconds - elapsed_in_state) if self.current_state == self.STATE_AWAY_PENDING else 0

            return {
                "enabled": self.enabled,
                "auto_arm": self.auto_arm,
                "auto_disarm_on_return": self.auto_disarm_on_return,
                "current_state": self.current_state,
                "state_reason": self.state_reason,
                "state_entered_time": self.state_entered_time,
                "elapsed_seconds": elapsed_in_state,
                "remaining_grace_seconds": remaining_grace,
                "grace_period_seconds": self.grace_period_seconds,
                "check_interval": self.check_interval,
                "devices_count": len(self.devices),
                "devices": list(self.devices.values())
            }
