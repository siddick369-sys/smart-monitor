import os
import json
import time
import shutil
from typing import Dict, Any, Tuple
import config
from database import init_db, get_db_session
from monitoring.models import Device, Alert, Notification, Evidence, IntegrityLogEntry

class MigrationManager:
    """Gestionnaire de migration idempotente des données JSON vers SQLite avec sauvegardes et restaurations."""

    def __init__(self):
        init_db()

    def backup_json_files(self) -> Dict[str, str]:
        """Crée une copie de sauvegarde horodatée des fichiers JSON avant toute modification."""
        ts = int(time.time())
        backups = {}
        os.makedirs(config.BACKUPS_DIR, exist_ok=True)
        
        for name, src in [("devices", config.DEVICES_FILE), ("alerts", config.ALERTS_FILE)]:
            if os.path.exists(src):
                dst = os.path.join(config.BACKUPS_DIR, f"{name}_{ts}.json")
                shutil.copy2(src, dst)
                backups[name] = dst
        return backups

    def migrate_json_to_sqlite(self) -> Dict[str, Any]:
        """Exécute la migration transactionnelle idempotente des fichiers JSON vers SQLite."""
        report = {
            "status": "pending",
            "timestamp": time.time(),
            "backups": {},
            "devices": {"read": 0, "inserted": 0, "skipped": 0},
            "alerts": {"read": 0, "inserted": 0, "skipped": 0},
            "errors": []
        }

        # 1. Sauvegarde préventive
        try:
            report["backups"] = self.backup_json_files()
        except Exception as e:
            report["status"] = "error"
            report["errors"].append(f"Échec création sauvegardes JSON : {e}")
            return report

        # 2. Lecture et validation JSON
        devices_data = {}
        if os.path.exists(config.DEVICES_FILE):
            try:
                with open(config.DEVICES_FILE, "r", encoding="utf-8") as f:
                    content = f.read().strip()
                    if content:
                        devices_data = json.loads(content)
            except Exception as e:
                report["errors"].append(f"Erreur lecture devices.json : {e}")

        alerts_data = []
        if os.path.exists(config.ALERTS_FILE):
            try:
                with open(config.ALERTS_FILE, "r", encoding="utf-8") as f:
                    content = f.read().strip()
                    if content:
                        alerts_data = json.loads(content)
            except Exception as e:
                report["errors"].append(f"Erreur lecture alerts.json : {e}")

        report["devices"]["read"] = len(devices_data) if isinstance(devices_data, dict) else 0
        report["alerts"]["read"] = len(alerts_data) if isinstance(alerts_data, list) else 0

        # 3. Transaction atomique
        try:
            with get_db_session() as session:
                # A. Migration des appareils
                if isinstance(devices_data, dict):
                    for dev_id, dev_info in devices_data.items():
                        existing = session.query(Device).filter(Device.id == dev_id).first()
                        if existing:
                            report["devices"]["skipped"] += 1
                            continue

                        zones = dev_info.get("zones", [])
                        new_dev = Device(
                            id=dev_id,
                            name=dev_info.get("name", f"Camera {dev_id}"),
                            ip=dev_info.get("ip", "127.0.0.1"),
                            port=int(dev_info.get("port", 8080)),
                            zones_json=json.dumps(zones),
                            created_at=float(dev_info.get("created_at", time.time())),
                            updated_at=float(dev_info.get("updated_at", time.time()))
                        )
                        session.add(new_dev)
                        report["devices"]["inserted"] += 1

                # Flush pour s'assurer que les clés étrangères fonctionnent
                session.flush()

                # B. Migration des alertes
                if isinstance(alerts_data, list):
                    for a in alerts_data:
                        a_id = a.get("id")
                        if not a_id:
                            continue

                        existing = session.query(Alert).filter(Alert.id == a_id).first()
                        if existing:
                            report["alerts"]["skipped"] += 1
                            continue

                        # Vérifier si l'appareil associé existe
                        target_dev_id = a.get("device_id")
                        if target_dev_id:
                            dev_exists = session.query(Device).filter(Device.id == target_dev_id).first()
                            if not dev_exists:
                                target_dev_id = None

                        new_alert = Alert(
                            id=a_id,
                            timestamp=float(a.get("timestamp", time.time())),
                            datetime=str(a.get("datetime", "")),
                            device_id=target_dev_id,
                            device_name=str(a.get("device_name", "Inconnu")),
                            device_ip=str(a.get("device_ip", "127.0.0.1")),
                            type=str(a.get("type", "INCIDENT")),
                            event_code=str(a.get("event_code", "SIMULATED_EVENT")),
                            category=str(a.get("category", "Événement")),
                            severity=str(a.get("severity", "INFO")),
                            details=str(a.get("details", "")),
                            measured_value=float(a["measured_value"]) if a.get("measured_value") is not None else None,
                            threshold=float(a["threshold"]) if a.get("threshold") is not None else None,
                            status=str(a.get("status", "TERMINÉ")),
                            screenshot_path=a.get("screenshot_path"),
                            recording_path=a.get("recording_path"),
                            sha256_hash=a.get("sha256_hash")
                        )
                        session.add(new_alert)
                        report["alerts"]["inserted"] += 1

            report["status"] = "success"
        except Exception as e:
            report["status"] = "error"
            report["errors"].append(f"Erreur durant la transaction SQLite : {e}")

        return report

    def export_sqlite_to_json(self) -> Dict[str, Any]:
        """Exporte l'état complet de la base SQLite sous forme de dictionnaire JSON pour sauvegarde."""
        with get_db_session() as session:
            devices = [d.to_dict() for d in session.query(Device).all()]
            alerts = [a.to_dict() for a in session.query(Alert).order_by(Alert.timestamp.desc()).all()]
            notifications = [n.to_dict() for n in session.query(Notification).order_by(Notification.timestamp.desc()).all()]
            evidences = [e.to_dict() for e in session.query(Evidence).all()]
            
            return {
                "exported_at": time.time(),
                "devices": devices,
                "alerts": alerts,
                "notifications": notifications,
                "evidences": evidences
            }

    def restore_from_json_backup(self, backup_filepath: str) -> Tuple[bool, str]:
        """Restaure la base de données depuis un fichier JSON d'export vérifié."""
        if not os.path.exists(backup_filepath):
            return False, "Fichier de sauvegarde introuvable."

        try:
            with open(backup_filepath, "r", encoding="utf-8") as f:
                data = json.load(f)
        except Exception as e:
            return False, f"Fichier de sauvegarde invalide : {e}"

        if not isinstance(data, dict):
            return False, "Format de sauvegarde non reconnu."

        try:
            with get_db_session() as session:
                # Importer devices
                for d in data.get("devices", []):
                    d_id = d.get("id")
                    if d_id and not session.query(Device).filter(Device.id == d_id).first():
                        session.add(Device(
                            id=d_id,
                            name=d.get("name", "Camera"),
                            ip=d.get("ip", "127.0.0.1"),
                            port=int(d.get("port", 8080)),
                            zones_json=json.dumps(d.get("zones", [])),
                            created_at=float(d.get("created_at", time.time())),
                            updated_at=float(d.get("updated_at", time.time()))
                        ))
                session.flush()

                # Importer alertes
                for a in data.get("alerts", []):
                    a_id = a.get("id")
                    if a_id and not session.query(Alert).filter(Alert.id == a_id).first():
                        target_dev_id = a.get("device_id")
                        if target_dev_id and not session.query(Device).filter(Device.id == target_dev_id).first():
                            target_dev_id = None
                        session.add(Alert(
                            id=a_id,
                            timestamp=float(a.get("timestamp", time.time())),
                            datetime=str(a.get("datetime", "")),
                            device_id=target_dev_id,
                            device_name=str(a.get("device_name", "Inconnu")),
                            device_ip=str(a.get("device_ip", "127.0.0.1")),
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
                        ))
            return True, "Restauration terminée avec succès."
        except Exception as e:
            return False, f"Erreur lors de la restauration : {e}"
