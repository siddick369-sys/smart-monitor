import time
import threading
from collections import deque
from typing import List, Optional, Dict
from database import get_db_session
from monitoring.models import Notification

class NotificationManager:
    """Gestionnaire intelligent, thread-safe et non bloquant du centre de notifications."""

    def __init__(self, max_notifications: int = 200, dedup_window_seconds: float = 20.0):
        self.max_notifications = max_notifications
        self.dedup_window_seconds = dedup_window_seconds
        self._lock = threading.RLock()
        self._notifications: deque = deque(maxlen=max_notifications)
        self._last_dedup_keys: Dict[str, float] = {}

    def add_notification(self, level: str, title: str, message: str,
                         device_id: Optional[str] = None, device_name: Optional[str] = None,
                         alert_id: Optional[str] = None, category: Optional[str] = None,
                         user_id: Optional[str] = None) -> Optional[dict]:
        """Ajoute une notification avec filtrage anti-doublons automatique et rattachement utilisateur optionnel."""
        now = time.time()
        
        # Normalisation du niveau : INFO, WARNING, HIGH, CRITICAL
        level_clean = level.upper()
        if level_clean not in ["INFO", "WARNING", "HIGH", "CRITICAL"]:
            if level_clean in ["CRITIQUE", "DANGER"]:
                level_clean = "CRITICAL"
            elif level_clean in ["AVERTISSEMENT", "ALERTE"]:
                level_clean = "HIGH"
            elif level_clean in ["WARN"]:
                level_clean = "WARNING"
            else:
                level_clean = "INFO"

        # Protection anti-doublons : clé basée sur l'appareil et le titre de l'alerte
        dedup_key = f"{device_id or 'sys'}_{title}_{category or 'gen'}_{user_id or 'all'}"
        with self._lock:
            last_ts = self._last_dedup_keys.get(dedup_key, 0.0)
            if (now - last_ts) < self.dedup_window_seconds:
                # Doublon ignoré dans la fenêtre temporelle
                return None
            self._last_dedup_keys[dedup_key] = now

            notif_id = f"notif_{int(now*1000)}"
            notif = {
                "id": notif_id,
                "timestamp": now,
                "datetime": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(now)),
                "level": level_clean,
                "title": title,
                "message": message,
                "device_id": device_id,
                "device_name": device_name or "Système",
                "alert_id": alert_id,
                "category": category,
                "read": False,
                "user_id": user_id
            }
            self._notifications.appendleft(notif)
            try:
                with get_db_session() as db:
                    db.add(Notification(
                        id=notif_id,
                        timestamp=now,
                        datetime=notif["datetime"],
                        title=title,
                        message=message,
                        level=level_clean,
                        category=category or "SYSTEM",
                        read=False,
                        user_id=user_id
                    ))
            except Exception:
                pass
            return notif

    def get_notifications(self, unread_only: bool = False, limit: int = 50,
                          user_id: Optional[str] = None, role: Optional[str] = None) -> dict:
        """Retourne la liste des notifications filtrées selon l'utilisateur et son rôle."""
        with self._lock:
            all_list = list(self._notifications)
            # Filtrage selon l'appartenance utilisateur
            if user_id:
                if role in ["ADMIN", "OPERATOR"]:
                    filtered = [n for n in all_list if n.get("user_id") is None or n.get("user_id") == user_id]
                else:
                    filtered = [n for n in all_list if n.get("user_id") == user_id or n.get("user_id") is None]
            else:
                filtered = all_list

            unread_count = sum(1 for n in filtered if not n["read"])
            if unread_only:
                items = [n for n in filtered if not n["read"]]
            else:
                items = filtered
            return {
                "notifications": items[:limit],
                "unread_count": unread_count,
                "total_count": len(filtered)
            }

    def mark_as_read(self, notif_id: str, user_id: Optional[str] = None, role: Optional[str] = None) -> bool:
        """Marque une notification spécifique comme lue en validant la propriété et les droits RBAC."""
        with self._lock:
            for n in self._notifications:
                if n["id"] == notif_id:
                    # Contrôle de propriété
                    notif_owner = n.get("user_id")
                    if notif_owner is not None:
                        if user_id is not None and user_id != notif_owner and role != "ADMIN":
                            return False  # Accès inter-utilisateur refusé
                    else:
                        # Notification globale / système
                        if role is not None and role not in ["ADMIN", "OPERATOR"]:
                            return False  # Seuls ADMIN et OPERATOR peuvent altérer les notifications système

                    n["read"] = True
                    try:
                        with get_db_session() as db:
                            db_n = db.query(Notification).filter(Notification.id == notif_id).first()
                            if db_n:
                                db_n.read = True
                    except Exception:
                        pass
                    return True
            return False

    def mark_all_as_read(self, user_id: Optional[str] = None, role: Optional[str] = None) -> int:
        """Marque comme lues exclusivement les notifications accessibles à l'utilisateur."""
        with self._lock:
            count = 0
            for n in self._notifications:
                notif_owner = n.get("user_id")
                can_modify = False
                if notif_owner is not None:
                    if user_id == notif_owner or role == "ADMIN" or (user_id is None and role is None):
                        can_modify = True
                else:
                    if (role in ["ADMIN", "OPERATOR"]) or (user_id is None and role is None):
                        can_modify = True

                if can_modify and not n["read"]:
                    n["read"] = True
                    count += 1

            try:
                with get_db_session() as db:
                    query = db.query(Notification).filter(Notification.read == False)
                    if user_id and role not in ["ADMIN"]:
                        if role == "OPERATOR":
                            query = query.filter((Notification.user_id == user_id) | (Notification.user_id.is_(None)))
                        else:
                            query = query.filter((Notification.user_id == user_id))
                    for db_n in query.all():
                        db_n.read = True
            except Exception:
                pass
            return count

    def delete_notification(self, notif_id: str, user_id: Optional[str] = None, role: Optional[str] = None) -> bool:
        """Supprime une notification de l'historique en vérifiant la propriété."""
        with self._lock:
            for i, n in enumerate(self._notifications):
                if n["id"] == notif_id:
                    notif_owner = n.get("user_id")
                    if notif_owner is not None:
                        if user_id is not None and user_id != notif_owner and role != "ADMIN":
                            return False  # IDOR bloqué
                    else:
                        if role is not None and role not in ["ADMIN", "OPERATOR"]:
                            return False  # Suppression système réservée

                    del self._notifications[i]
                    try:
                        with get_db_session() as db:
                            db_n = db.query(Notification).filter(Notification.id == notif_id).first()
                            if db_n:
                                db.delete(db_n)
                    except Exception:
                        pass
                    return True
            return False

    def clear_all(self):
        """Efface toutes les notifications."""
        with self._lock:
            self._notifications.clear()
            self._last_dedup_keys.clear()
            try:
                with get_db_session() as db:
                    db.query(Notification).delete()
            except Exception:
                pass
