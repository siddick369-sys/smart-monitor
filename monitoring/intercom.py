"""
Module d'Interphonie Défensive, Sommations Vocales et Contrôle Stroboscopique — PRO-11
Gère la communication bidirectionnelle et les contre-mesures physiques :
- Sessions d'interphonie audio WebRTC contrôlées par l'opérateur
- Diffusion de sommations vocales neutres et conformes (sans fausses déclarations)
- Déclenchement sécurisé du stroboscope LED avec temporisation stricte anti-photosensibilité
- Coupe-circuit d'urgence (kill-switch) et journalisation d'audit
"""

import time
import uuid
import threading
from typing import Dict, List, Optional, Tuple, Any


class IntercomSessionState:
    IDLE = "IDLE"
    CONNECTING = "CONNECTING"
    ACTIVE = "ACTIVE"
    MUTED = "MUTED"
    TERMINATED = "TERMINATED"


class VoiceAnnouncementType:
    ZONE_SURVEILLEE = "ZONE_SURVEILLEE"
    PRESENCE_DETECTEE = "PRESENCE_DETECTEE"
    EVACUATION_SECURITE = "EVACUATION_SECURITE"


NEUTRAL_VOICE_MESSAGES = {
    VoiceAnnouncementType.ZONE_SURVEILLEE: "Zone surveillée. Veuillez quitter cette zone.",
    VoiceAnnouncementType.PRESENCE_DETECTEE: "Votre présence a été détectée. Veuillez contacter le responsable du site.",
    VoiceAnnouncementType.EVACUATION_SECURITE: "Incident de sécurité signalé. Veuillez vous éloigner de l'accès."
}


class IntercomManager:
    def __init__(
        self,
        max_strobe_duration_seconds: float = 8.0,
        strobe_cooldown_seconds: float = 15.0
    ):
        self.max_strobe_duration_seconds = max_strobe_duration_seconds
        self.strobe_cooldown_seconds = strobe_cooldown_seconds

        self._lock = threading.RLock()
        self._active_sessions: Dict[str, dict] = {}
        self._last_strobe_time: Dict[str, float] = {}
        self._strobe_active: Dict[str, bool] = {}
        self._audit_log: List[dict] = []

    # =========================================================================
    # 1. Gestion des Sessions d'Interphonie Audio
    # =========================================================================

    def start_intercom_session(self, device_id: str, operator_username: str) -> dict:
        """Démarre une session d'interphonie bidirectionnelle pour un opérateur habilité."""
        now = time.time()
        session_id = f"icom_{uuid.uuid4().hex[:10]}"

        with self._lock:
            # Clôture d'une éventuelle session active préexistante sur cet appareil
            for s_id, s in list(self._active_sessions.items()):
                if s["device_id"] == device_id and s["state"] != IntercomSessionState.TERMINATED:
                    s["state"] = IntercomSessionState.TERMINATED
                    s["ended_at"] = now

            session = {
                "session_id": session_id,
                "device_id": device_id,
                "operator": operator_username,
                "state": IntercomSessionState.ACTIVE,
                "started_at": now,
                "ended_at": None,
                "audio_muted": False
            }
            self._active_sessions[session_id] = session

            self._audit_log.append({
                "action": "INTERCOM_START",
                "session_id": session_id,
                "device_id": device_id,
                "operator": operator_username,
                "timestamp": now
            })

            return session

    def stop_intercom_session(self, session_id: str, operator_username: str) -> bool:
        """Clôture une session d'interphonie."""
        now = time.time()
        with self._lock:
            session = self._active_sessions.get(session_id)
            if not session:
                return False

            session["state"] = IntercomSessionState.TERMINATED
            session["ended_at"] = now

            self._audit_log.append({
                "action": "INTERCOM_STOP",
                "session_id": session_id,
                "device_id": session["device_id"],
                "operator": operator_username,
                "timestamp": now
            })
            return True

    def set_mute(self, session_id: str, muted: bool) -> bool:
        """Active ou coupe le micro de l'opérateur."""
        with self._lock:
            session = self._active_sessions.get(session_id)
            if not session or session["state"] == IntercomSessionState.TERMINATED:
                return False
            session["audio_muted"] = muted
            session["state"] = IntercomSessionState.MUTED if muted else IntercomSessionState.ACTIVE
            return True

    # =========================================================================
    # 2. Sommations Vocales Neutres & Déclaratives
    # =========================================================================

    def trigger_voice_announcement(
        self,
        device_id: str,
        announcement_type: str,
        operator_username: str = "system"
    ) -> dict:
        """Émet une sommation vocale préenregistrée neutre sur le haut-parleur de l'appareil."""
        text = NEUTRAL_VOICE_MESSAGES.get(announcement_type, NEUTRAL_VOICE_MESSAGES[VoiceAnnouncementType.ZONE_SURVEILLEE])
        now = time.time()

        with self._lock:
            event = {
                "announcement_id": f"voc_{uuid.uuid4().hex[:8]}",
                "device_id": device_id,
                "type": announcement_type,
                "text": text,
                "operator": operator_username,
                "timestamp": now,
                "status": "DISPATCHED"
            }

            self._audit_log.append({
                "action": "VOICE_ANNOUNCEMENT",
                "device_id": device_id,
                "type": announcement_type,
                "text": text,
                "operator": operator_username,
                "timestamp": now
            })

            return event

    # =========================================================================
    # 3. Commande Stroboscopique Sécurisée (Flash LED)
    # =========================================================================

    def trigger_strobe(
        self,
        device_id: str,
        duration_seconds: float = 5.0,
        operator_username: str = "admin"
    ) -> Tuple[bool, str]:
        """Déclenche la torche stroboscopique avec respect strict du temps de repos anti-photosensibilité."""
        now = time.time()

        with self._lock:
            # Vérification du délai de repos (cooldown)
            last = self._last_strobe_time.get(device_id, 0.0)
            if now - last < self.strobe_cooldown_seconds:
                remaining = round(self.strobe_cooldown_seconds - (now - last), 1)
                return False, f"Temporisation de sécurité active. Veuillez patienter {remaining}s."

            # Plafonnement strict de la durée
            capped_duration = min(self.max_strobe_duration_seconds, max(1.0, float(duration_seconds)))
            self._last_strobe_time[device_id] = now
            self._strobe_active[device_id] = True

            self._audit_log.append({
                "action": "STROBE_TRIGGERED",
                "device_id": device_id,
                "duration_seconds": capped_duration,
                "operator": operator_username,
                "timestamp": now
            })

            return True, f"Stroboscope activé pour {capped_duration}s sur {device_id}."

    def abort_strobe(self, device_id: str) -> bool:
        """Coupe-circuit immédiat d'urgence pour le stroboscope."""
        with self._lock:
            self._strobe_active[device_id] = False
            self._audit_log.append({
                "action": "STROBE_ABORTED",
                "device_id": device_id,
                "timestamp": time.time()
            })
            return True

    def get_status(self) -> dict:
        with self._lock:
            active_list = [s for s in self._active_sessions.values() if s["state"] != IntercomSessionState.TERMINATED]
            return {
                "active_sessions_count": len(active_list),
                "active_sessions": active_list,
                "strobe_active": dict(self._strobe_active),
                "available_announcements": list(NEUTRAL_VOICE_MESSAGES.keys()),
                "recent_audit_events": self._audit_log[-15:]
            }
