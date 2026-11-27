import os
import io
import csv
import json
import re
import threading
import time
import shutil
import cv2
import numpy as np
from typing import List, Optional, Dict
import config
from database import get_db_session
from monitoring.models import Alert, Device

class RecordingManager:
    """Gestionnaire professionnel des preuves, clips vidéo d'incidents, rétention, intégrité et historique."""

    def __init__(self, camera_manager, alerts_file: str = config.ALERTS_FILE, integrity_manager=None, telegram_notifier=None):
        self.camera_manager = camera_manager
        self.alerts_file = alerts_file
        self.integrity_manager = integrity_manager
        self.telegram_notifier = telegram_notifier
        self._lock = threading.RLock()
        self.alerts: List[dict] = []
        self.load_alerts()

    def load_alerts(self):
        with self._lock:
            # 1. Tenter le chargement depuis SQLite
            loaded_from_db = False
            try:
                with get_db_session() as db:
                    db_alerts = db.query(Alert).order_by(Alert.timestamp.desc()).limit(200).all()
                    if db_alerts:
                        self.alerts = [a.to_dict() for a in db_alerts]
                        loaded_from_db = True
            except Exception as sqle:
                print(f"[RecordingManager] Info lecture SQLite : {sqle}")

            # 2. Si SQLite vide, charger depuis alerts.json
            if not loaded_from_db:
                if os.path.exists(self.alerts_file):
                    try:
                        with open(self.alerts_file, "r", encoding="utf-8") as f:
                            self.alerts = json.load(f)
                    except Exception as e:
                        print(f"[RecordingManager] Erreur chargement alerts.json : {e}")
                        self.alerts = []
                else:
                    self.alerts = []

    def save_alerts(self):
        with self._lock:
            # 1. Sauvegarde SQLite
            try:
                with get_db_session() as db:
                    for a in self.alerts[:200]:
                        a_id = a.get("id")
                        if not a_id:
                            continue
                        db_alert = db.query(Alert).filter(Alert.id == a_id).first()
                        if not db_alert:
                            target_dev_id = a.get("device_id")
                            if target_dev_id and not db.query(Device).filter(Device.id == target_dev_id).first():
                                target_dev_id = None
                            db_alert = Alert(
                                id=a_id,
                                timestamp=float(a.get("timestamp", time.time())),
                                datetime=str(a.get("datetime", "")),
                                device_id=target_dev_id,
                                device_name=str(a.get("device_name", "Inconnu")),
                                device_ip=str(a.get("device_ip", "")),
                                type=str(a.get("type", "INCIDENT")),
                                event_code=str(a.get("event_code", "SIMULATED_EVENT")),
                                category=str(a.get("category", "Événement")),
                                severity=str(a.get("severity", "INFO")),
                                details=str(a.get("details", "")),
                                measured_value=a.get("measured_value"),
                                threshold=a.get("threshold"),
                                status=str(a.get("status", "TERMINÉ")),
                                screenshot_path=a.get("screenshot_path"),
                                recording_path=a.get("recording_path"),
                                sha256_hash=a.get("sha256_hash")
                            )
                            db.add(db_alert)
                        else:
                            db_alert.status = str(a.get("status", db_alert.status))
                            if a.get("recording_path"):
                                db_alert.recording_path = a.get("recording_path")
                            if a.get("sha256_hash"):
                                db_alert.sha256_hash = a.get("sha256_hash")
            except Exception as sqle:
                pass

            # 2. Sauvegarde JSON miroir
            try:
                self.alerts = self.alerts[:200]
                with open(self.alerts_file, "w", encoding="utf-8") as f:
                    json.dump(self.alerts, f, indent=2, ensure_ascii=False)
            except Exception as e:
                print(f"[RecordingManager] Erreur sauvegarde alerts.json : {e}")

    def get_all_alerts(self) -> List[dict]:
        """Retourne la liste des alertes directement depuis la source de vérité SQLite."""
        with self._lock:
            try:
                with get_db_session() as db:
                    db_alerts = db.query(Alert).order_by(Alert.timestamp.desc()).limit(200).all()
                    if db_alerts is not None:
                        return [a.to_dict() for a in db_alerts]
            except Exception:
                pass
            return list(self.alerts)

    def filter_alerts(self, device_id: Optional[str] = None, event_type: Optional[str] = None,
                      period: Optional[str] = None, query: Optional[str] = None) -> List[dict]:
        """Filtre les alertes selon les critères demandés (appareil, type, période, recherche)."""
        with self._lock:
            filtered = list(self.alerts)
            now = time.time()

            if device_id:
                filtered = [a for a in filtered if a.get("device_id") == device_id]

            if event_type:
                filtered = [a for a in filtered if a.get("type") == event_type or a.get("event_code") == event_type]

            if period:
                if period == "today":
                    today_str = time.strftime("%Y-%m-%d")
                    filtered = [a for a in filtered if a.get("datetime", "").startswith(today_str)]
                elif period == "24h":
                    filtered = [a for a in filtered if (now - a.get("timestamp", 0)) <= 86400]
                elif period == "7d":
                    filtered = [a for a in filtered if (now - a.get("timestamp", 0)) <= 86400 * 7]

            if query:
                q = query.lower()
                filtered = [
                    a for a in filtered
                    if q in a.get("device_name", "").lower()
                    or q in a.get("details", "").lower()
                    or q in a.get("id", "").lower()
                    or q in a.get("category", "").lower()
                ]

            return filtered

    def _safe_remove_proof(self, rel_path: Optional[str], allowed_dirs: list):
        """Supprime de manière sécurisée un fichier de preuve en empêchant le Path Traversal."""
        if not rel_path or not isinstance(rel_path, str):
            return
        full_p = os.path.normpath(os.path.abspath(os.path.join(config.BASE_DIR, rel_path)))
        for d in allowed_dirs:
            norm_d = os.path.normpath(os.path.abspath(d))
            if full_p.startswith(norm_d + os.sep) and os.path.isfile(full_p):
                try:
                    os.remove(full_p)
                    return
                except Exception as e:
                    print(f"[RecordingManager] Erreur suppression {full_p} : {e}")
                    return
        # Si le fichier tente de sortir du dossier de preuves
        if os.path.exists(full_p):
            print(f"[RecordingManager] Sécurité : rejet suppression preuve hors répertoire autorisé : {rel_path}")

    def delete_alert(self, alert_id: str) -> bool:
        """Supprime une alerte et ses fichiers de preuves associés sur disque de manière sécurisée."""
        with self._lock:
            alert = next((a for a in self.alerts if a["id"] == alert_id), None)
            if alert:
                self._safe_remove_proof(alert.get("screenshot_path"), [config.SCREENSHOTS_DIR])
                self._safe_remove_proof(alert.get("recording_path"), [config.RECORDINGS_DIR])
                
                try:
                    with get_db_session() as db:
                        db_a = db.query(Alert).filter(Alert.id == alert_id).first()
                        if db_a:
                            db.delete(db_a)
                except Exception as sqle:
                    pass

                self.alerts = [a for a in self.alerts if a["id"] != alert_id]
                self.save_alerts()
                return True
            return False

    def clear_all(self):
        """Purge toutes les alertes et supprime les fichiers de preuves associés de manière sécurisée."""
        with self._lock:
            for alert in self.alerts:
                self._safe_remove_proof(alert.get("screenshot_path"), [config.SCREENSHOTS_DIR])
                self._safe_remove_proof(alert.get("recording_path"), [config.RECORDINGS_DIR])
            try:
                with get_db_session() as db:
                    db.query(Alert).delete()
            except Exception as sqle:
                pass
            self.alerts = []
            self.save_alerts()

    def handle_incident(self, incident: dict):
        """Prend en charge un incident : sauvegarde photo instantanée et clip vidéo."""
        alert_id = incident.get("id") or f"alert_{int(time.time()*1000)}"
        device_id = incident.get("device_id")
        frame = incident.get("frame")
        now = time.time()

        # Nettoyage automatique des preuves expirées et contrôle d'espace disque lors d'un nouvel incident
        try:
            self.clean_expired_proofs(days=config.RETENTION_DAYS)
            self.check_disk_space()
        except Exception:
            pass

        # 1. Capture instantanée (Screenshot)
        screenshot_filename = f"screenshot_{alert_id}.jpg"
        screenshot_full_path = os.path.join(config.SCREENSHOTS_DIR, screenshot_filename)
        screenshot_rel_path = os.path.join("storage", "screenshots", screenshot_filename).replace("\\", "/")

        saved_screenshot = False
        sha256_val = None
        if frame is not None:
            try:
                cv2.imwrite(screenshot_full_path, frame)
                if os.path.exists(screenshot_full_path) and os.path.getsize(screenshot_full_path) > 0:
                    saved_screenshot = True
                    if self.integrity_manager:
                        ev = self.integrity_manager.register_evidence(screenshot_full_path, "IMAGE", alert_id=alert_id)
                        if ev:
                            sha256_val = ev.get("sha256_hash")
            except Exception as e:
                print(f"[RecordingManager] Erreur sauvegarde capture : {e}")

        # 2. Préparation métadonnées d'alerte
        alert_entry = {
            "id": alert_id,
            "timestamp": now,
            "datetime": incident.get("datetime") or time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(now)),
            "device_id": device_id,
            "device_name": incident.get("device_name", "Inconnu"),
            "device_ip": incident.get("device_ip", ""),
            "type": incident.get("type", "INTRUSION"),
            "event_code": incident.get("event_code", "REAL_SENSOR_EVENT"),
            "category": incident.get("category", "ÉVÉNEMENT SIMULÉ"),
            "severity": incident.get("severity", "AVERTISSEMENT"),
            "details": incident.get("details", ""),
            "measured_value": incident.get("measured_value"),
            "threshold": incident.get("threshold"),
            "screenshot_path": screenshot_rel_path if saved_screenshot else None,
            "recording_path": None,
            "sha256_hash": sha256_val,
            "status": "ENREGISTREMENT EN COURS" if frame is not None else "ÉVÉNEMENT SYSTÈME"
        }

        with self._lock:
            self.alerts.insert(0, alert_entry)
            self.save_alerts()

        # Envoi de la notification Telegram si activée
        if self.telegram_notifier:
            try:
                self.telegram_notifier.send_incident_notification(
                    alert_entry,
                    photo_path=screenshot_full_path if saved_screenshot else None
                )
            except Exception as te:
                print(f"[RecordingManager] Erreur notification Telegram : {te}")

        # 3. Lancer l'enregistrement vidéo en thread dédié uniquement si une frame est associée
        if frame is not None and device_id:
            threading.Thread(
                target=self._record_incident_video,
                args=(alert_id, device_id, now),
                name=f"VideoRecorder-{alert_id}",
                daemon=True
            ).start()
        else:
            self._update_alert_recording(alert_id, None, "SANS FLUX VIDÉO")

    def _record_incident_video(self, alert_id: str, device_id: str, trigger_time: float):
        """Enregistre le pré-roll (3s) et le post-roll (5s) dans un clip vidéo MP4/AVI."""
        video_filename = f"incident_{alert_id}.mp4"
        video_full_path = os.path.join(config.RECORDINGS_DIR, video_filename)
        video_rel_path = os.path.join("storage", "recordings", video_filename).replace("\\", "/")

        # Récupérer les frames pré-roll
        pre_frames_with_time = self.camera_manager.get_recent_frames(device_id, seconds=config.PRE_RECORD_SECONDS)
        all_frames = [f for (_, f) in pre_frames_with_time]

        # Capturer les frames post-roll
        end_time = trigger_time + config.POST_RECORD_SECONDS
        while time.time() < end_time:
            time.sleep(1.0 / config.CAMERA_FPS)
            frame = self.camera_manager.get_frame(device_id)
            if frame is not None:
                all_frames.append(frame)

        if not all_frames:
            print(f"[RecordingManager] Aucune frame disponible pour l'incident {alert_id}")
            self._update_alert_recording(alert_id, None, "AUCUNE FRAME")
            return

        h, w = all_frames[0].shape[:2]

        written = False
        try:
            fourcc = cv2.VideoWriter_fourcc(*'mp4v')
            out = cv2.VideoWriter(video_full_path, fourcc, float(config.CAMERA_FPS), (w, h))
            if out.isOpened():
                for f in all_frames:
                    if f.shape[:2] != (h, w):
                        f = cv2.resize(f, (w, h))
                    out.write(f)
                out.release()
                if os.path.exists(video_full_path) and os.path.getsize(video_full_path) > 0:
                    written = True
        except Exception as e:
            print(f"[RecordingManager] Échec écriture MP4 : {e}")

        if not written:
            # Fallback AVI XVID
            video_filename = f"incident_{alert_id}.avi"
            video_full_path = os.path.join(config.RECORDINGS_DIR, video_filename)
            video_rel_path = os.path.join("storage", "recordings", video_filename).replace("\\", "/")
            try:
                fourcc = cv2.VideoWriter_fourcc(*'XVID')
                out = cv2.VideoWriter(video_full_path, fourcc, float(config.CAMERA_FPS), (w, h))
                if out.isOpened():
                    for f in all_frames:
                        if f.shape[:2] != (h, w):
                            f = cv2.resize(f, (w, h))
                        out.write(f)
                    out.release()
                    if os.path.exists(video_full_path) and os.path.getsize(video_full_path) > 0:
                        written = True
            except Exception as e:
                print(f"[RecordingManager] Échec écriture AVI de secours : {e}")

        # Vérification finale de lisibilité
        final_status = "ÉCHEC ENREGISTREMENT"
        final_path = None
        if written and os.path.exists(video_full_path) and os.path.getsize(video_full_path) > 0:
            final_status = "DISPONIBLE"
            final_path = video_rel_path
            if self.integrity_manager:
                try:
                    self.integrity_manager.register_evidence(video_full_path, "VIDEO", alert_id=alert_id)
                except Exception as ie:
                    print(f"[RecordingManager] Enregistrement intégrité vidéo : {ie}")

        self._update_alert_recording(alert_id, final_path, final_status)

    def _update_alert_recording(self, alert_id: str, rec_path: Optional[str], status: str):
        with self._lock:
            for a in self.alerts:
                if a["id"] == alert_id:
                    a["recording_path"] = rec_path
                    a["status"] = status
                    break
            self.save_alerts()

    def clean_expired_proofs(self, days: int = config.RETENTION_DAYS):
        """Nettoie les fichiers de captures et vidéos plus anciens que le délai de rétention avec protection des preuves récentes."""
        with self._lock:
            cutoff = time.time() - (days * 86400)
            active_paths = set()
            
            # 1. Identifier et protéger tous les fichiers activement référencés récents
            for a in self.alerts:
                if a.get("timestamp", 0) >= cutoff:
                    if a.get("screenshot_path"):
                        active_paths.add(os.path.normpath(os.path.join(config.BASE_DIR, a["screenshot_path"])))
                    if a.get("recording_path"):
                        active_paths.add(os.path.normpath(os.path.join(config.BASE_DIR, a["recording_path"])))

            # 2. Supprimer les fichiers physiques expirés non protégés
            for directory in [config.SCREENSHOTS_DIR, config.RECORDINGS_DIR]:
                if not os.path.exists(directory):
                    continue
                for fname in os.listdir(directory):
                    fpath = os.path.normpath(os.path.join(directory, fname))
                    # Ne JAMAIS supprimer un fichier protégé dans la période active
                    if fpath not in active_paths:
                        try:
                            mtime = os.path.getmtime(fpath)
                            if mtime < cutoff:
                                os.remove(fpath)
                                print(f"[RecordingManager] Preuve expirée purgée : {fname}")
                        except Exception:
                            pass

            # 3. Assurer la cohérence de l'historique alerts.json (détection des preuves archivées)
            modified = False
            for a in self.alerts:
                if a.get("timestamp", 0) < cutoff:
                    has_scr = False
                    if a.get("screenshot_path"):
                        full_scr = os.path.join(config.BASE_DIR, a["screenshot_path"])
                        has_scr = os.path.exists(full_scr)
                    has_rec = False
                    if a.get("recording_path"):
                        full_rec = os.path.join(config.BASE_DIR, a["recording_path"])
                        has_rec = os.path.exists(full_rec)

                    if not has_scr and not has_rec and a.get("status") not in ["ARCHIVÉ / PREUVES PURGÉES", "ÉVÉNEMENT SYSTÈME"]:
                        a["status"] = "ARCHIVÉ / PREUVES PURGÉES"
                        modified = True

            if modified:
                self.save_alerts()

    def check_disk_space(self) -> bool:
        """Vérifie la disponibilité de l'espace disque pour éviter la saturation du système."""
        try:
            total, used, free = shutil.disk_usage(config.STORAGE_DIR)
            free_mb = free / (1024 * 1024)
            if free_mb < 50.0: # Moins de 50 Mo disponibles
                print(f"[RecordingManager] ALERTE DISQUE : Espace libre critique ({round(free_mb, 1)} Mo restants).")
                self.clean_expired_proofs(days=1)
                return False
            return True
        except Exception:
            return True

    def get_storage_stats(self) -> dict:
        """Calcule l'espace disque consommé par les captures et vidéos."""
        total_bytes = 0
        rec_count = 0
        scr_count = 0

        for f in os.listdir(config.RECORDINGS_DIR):
            p = os.path.join(config.RECORDINGS_DIR, f)
            if os.path.isfile(p):
                total_bytes += os.path.getsize(p)
                rec_count += 1

        for f in os.listdir(config.SCREENSHOTS_DIR):
            p = os.path.join(config.SCREENSHOTS_DIR, f)
            if os.path.isfile(p):
                total_bytes += os.path.getsize(p)
                scr_count += 1

        used_mb = round(total_bytes / (1024 * 1024), 2)
        return {
            "used_bytes": total_bytes,
            "used_mb": used_mb,
            "max_mb": config.MAX_STORAGE_MB,
            "pct_used": round((used_mb / config.MAX_STORAGE_MB) * 100, 1),
            "recordings_count": rec_count,
            "screenshots_count": scr_count
        }

    def export_csv(self, alerts: Optional[List[dict]] = None) -> str:
        """Génère un export CSV structuré de l'historique des incidents avec neutralisation des injections de formules."""
        with self._lock:
            target_alerts = alerts if alerts is not None else self.alerts
            output = io.StringIO()
            fieldnames = [
                "id", "datetime", "device_name", "device_id", "device_ip",
                "type", "event_code", "category", "severity", "details",
                "measured_value", "threshold", "status", "screenshot_path", "recording_path"
            ]
            writer = csv.DictWriter(output, fieldnames=fieldnames, extrasaction='ignore', delimiter=';')
            writer.writeheader()
            for a in target_alerts:
                sanitized_row = {}
                for k in fieldnames:
                    v = a.get(k)
                    if isinstance(v, str):
                        # Neutralisation CSV formula injection: =, +, -, @, \t, \r, \n
                        stripped = v.lstrip(' \t\r\n')
                        starts_dangerous = (len(v) > 0 and v[0] in ('=', '+', '-', '@', '\t', '\r', '\n')) or (len(stripped) > 0 and stripped[0] in ('=', '+', '-', '@'))
                        if starts_dangerous:
                            # Préserver les valeurs purement numériques dans les colonnes de mesure (ex: "-5.0", "+3")
                            is_pure_num = False
                            if k in ("measured_value", "threshold") and re.match(r'^[+-]?\d+(\.\d+)?$', v.strip()):
                                is_pure_num = True
                            if not is_pure_num:
                                sanitized_row[k] = "'" + v
                            else:
                                sanitized_row[k] = v
                        else:
                            sanitized_row[k] = v
                    else:
                        sanitized_row[k] = v
                writer.writerow(sanitized_row)
            return output.getvalue()

    def get_statistics(self) -> dict:
        """Calcule les statistiques temporelles et analytiques réelles à partir de l'historique."""
        with self._lock:
            now = time.time()
            total = len(self.alerts)
            
            by_severity = {"CRITIQUE": 0, "AVERTISSEMENT": 0, "INFO": 0}
            by_category = {}
            by_device = {}
            hourly = [0] * 24
            
            # 7 derniers jours
            days_map = {}
            for i in range(6, -1, -1):
                day_ts = now - (i * 86400)
                day_str = time.strftime("%Y-%m-%d", time.localtime(day_ts))
                days_map[day_str] = {"date": day_str, "total": 0, "real": 0, "video": 0, "simulated": 0, "system": 0}

            today_str = time.strftime("%Y-%m-%d", time.localtime(now))
            count_today = 0
            count_24h = 0
            count_7d = 0

            for a in self.alerts:
                # Sévérité
                sev = a.get("severity", "INFO")
                by_severity[sev] = by_severity.get(sev, 0) + 1

                # Catégorie
                cat = a.get("event_code") or a.get("category", "AUTRE")
                by_category[cat] = by_category.get(cat, 0) + 1

                # Appareil
                dev = a.get("device_name", "Inconnu")
                by_device[dev] = by_device.get(dev, 0) + 1

                # Horodatage
                ts = a.get("timestamp", 0)
                if ts:
                    dt = time.localtime(ts)
                    hourly[dt.tm_hour] += 1
                    d_str = time.strftime("%Y-%m-%d", dt)
                    if d_str in days_map:
                        days_map[d_str]["total"] += 1
                        code = a.get("event_code", "")
                        if code == "REAL_SENSOR_EVENT":
                            days_map[d_str]["real"] += 1
                        elif code == "VIDEO_MOTION_EVENT":
                            days_map[d_str]["video"] += 1
                        elif code == "SIMULATED_EVENT":
                            days_map[d_str]["simulated"] += 1
                        else:
                            days_map[d_str]["system"] += 1

                # Périodes
                dt_str = a.get("datetime", "")
                if dt_str.startswith(today_str):
                    count_today += 1
                if (now - ts) <= 86400:
                    count_24h += 1
                if (now - ts) <= 86400 * 7:
                    count_7d += 1

            return {
                "total_incidents": total,
                "count_today": count_today,
                "count_24h": count_24h,
                "count_7d": count_7d,
                "by_severity": by_severity,
                "by_category": by_category,
                "by_device": by_device,
                "hourly_distribution": hourly,
                "daily_stats": list(days_map.values())
            }

    def get_timeline(self, device_id: Optional[str] = None, event_type: Optional[str] = None,
                     period: Optional[str] = None, query: Optional[str] = None, limit: int = 100) -> List[dict]:
        """Retourne la chronologie ordonnée et filtrée des incidents."""
        alerts = self.filter_alerts(device_id=device_id, event_type=event_type, period=period, query=query)
        alerts.sort(key=lambda x: x.get("timestamp", 0), reverse=True)
        return alerts[:limit]
