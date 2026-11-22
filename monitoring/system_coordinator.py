import os
import threading
import time
from typing import Dict, List, Optional
import config
from monitoring.device_store import DeviceStore
from monitoring.camera_manager import CameraManager
from monitoring.sensor_manager import SensorManager
from monitoring.detection_engine import DetectionEngine
from monitoring.alarm_manager import AlarmManager
from monitoring.recording_manager import RecordingManager
from monitoring.notification_manager import NotificationManager
from monitoring.diagnostic_manager import DiagnosticManager
from monitoring.pdf_report_generator import PDFReportGenerator
from monitoring.auth_manager import AuthManager
from monitoring.integrity_manager import IntegrityManager
from monitoring.telegram_notifier import TelegramNotifier
from monitoring.qwen_vision_manager import QwenVisionManager
from monitoring.edge_ai_detector import EdgeAIDetector
from monitoring.presence_manager import PresenceManager
from monitoring.totp_manager import TOTPManager
from monitoring.security_audit import SecurityAudit
from monitoring.webrtc_manager import WebRTCManager
from monitoring.push_manager import PushManager
# PRO-07 à PRO-11
from monitoring.tamper_detection import TamperDetector
from monitoring.audio_classifier import AudioClassifier
from monitoring.semantic_search import SemanticSearchEngine
from monitoring.evidence_integrity import EvidenceIntegrityManager
from monitoring.privacy_shield import PrivacyShield
from monitoring.forensic_engine import ForensicReportEngine
from monitoring.spatial_tracker import SpatialTracker
from monitoring.pose_detector import PoseDetector
from monitoring.p2p_sync import P2PSyncManager
from monitoring.intercom import IntercomManager
from monitoring.acquisition.discovery import UnifiedDiscoveryManager

class SystemCoordinator:
    """Coordinateur central orchestrant l'ensemble des modules du Monitoring Host."""

    def __init__(self):
        self.auth_manager = AuthManager()
        self.integrity_manager = IntegrityManager()
        self.telegram_notifier = TelegramNotifier()
        self.qwen_vision_manager = QwenVisionManager()
        self.edge_ai_detector = EdgeAIDetector()
        self.totp_manager = TOTPManager()
        self.security_audit = SecurityAudit()
        self.push_manager = PushManager()

        self.device_store = DeviceStore()
        self.recording_manager = RecordingManager(
            camera_manager=None,
            integrity_manager=self.integrity_manager,
            telegram_notifier=self.telegram_notifier
        )
        self.alarm_manager = AlarmManager(self.device_store)
        self.notification_manager = NotificationManager()
        self.diagnostic_manager = DiagnosticManager(self)
        self.pdf_report_generator = PDFReportGenerator()
        
        # Initialisation avec callbacks d'état et fournisseur de zones
        self.camera_manager = CameraManager(
            on_state_change=self._on_camera_state_change,
            zone_provider=self.device_store.get_device_zones
        )
        self.recording_manager.camera_manager = self.camera_manager
        self.webrtc_manager = WebRTCManager(camera_manager=self.camera_manager)
        
        self.sensor_manager = SensorManager(on_state_change=self._on_sensor_state_change)
        
        self.detection_engine = DetectionEngine(
            self.camera_manager,
            self.sensor_manager,
            self.device_store,
            edge_ai_detector=self.edge_ai_detector
        )

        # Liaison des événements de détection aux gestionnaires d'alarme et d'enregistrement
        self.detection_engine.register_callback(self._on_detection_event)

        # Gestionnaire de présence et armement automatique intelligent
        self.presence_manager = PresenceManager(
            alarm_manager=self.alarm_manager,
            notification_manager=self.notification_manager
        )

        # =====================================================================
        # Évolutions PRO-07 à PRO-11
        # =====================================================================
        self.tamper_detector = TamperDetector(
            dark_threshold=getattr(config, "TAMPER_DARK_THRESHOLD", 25.0),
            blur_threshold=getattr(config, "TAMPER_BLUR_THRESHOLD", 40.0),
            stream_timeout_seconds=getattr(config, "TAMPER_STREAM_TIMEOUT", 6.0)
        )
        self.audio_classifier = AudioClassifier(
            confidence_threshold=getattr(config, "AUDIO_AI_CONFIDENCE_THRESHOLD", 0.50)
        )
        self.semantic_search_engine = SemanticSearchEngine(
            db_path=getattr(config, "SEMANTIC_DB_PATH", os.path.join(config.STORAGE_DIR, "semantic_index.db"))
        )
        self.evidence_integrity_mgr = EvidenceIntegrityManager(
            secret_key=getattr(config, "EVIDENCE_HMAC_KEY", None) or getattr(config, "INTEGRITY_SECRET_KEY", None),
            tsa_server_url=getattr(config, "TSA_URL", None)
        )
        self.privacy_shield = PrivacyShield(
            key_file_path=getattr(config, "PRIVACY_KEY_FILE", None)
        )
        self.forensic_engine = ForensicReportEngine(output_dir=os.path.join(config.STORAGE_DIR, "reports"))
        self.spatial_tracker = SpatialTracker()
        self.pose_detector = PoseDetector()
        self.p2p_sync_mgr = P2PSyncManager(
            cluster_secret=getattr(config, "P2P_CLUSTER_SECRET", None)
        )
        self.intercom_mgr = IntercomManager(
            max_strobe_duration_seconds=getattr(config, "INTERCOM_MAX_STROBE_DURATION", 8.0)
        )
        self.discovery_manager = UnifiedDiscoveryManager()

        self._started = False
        self._lock = threading.RLock()
        self._device_last_seen: Dict[str, float] = {}

    def _on_camera_state_change(self, device_id: str, old_status: str, new_status: str):
        if old_status == "CONNECTÉ" and new_status != "CONNECTÉ":
            dev = self.device_store.get_device(device_id)
            name = dev["name"] if dev else device_id
            self.detection_engine.dispatch_system_event(
                device_id, "DEVICE_DISCONNECTED",
                f"Perte du flux vidéo pour {name} (état: {new_status})", severity="AVERTISSEMENT"
            )
            self.notification_manager.add_notification(
                level="WARNING",
                title=f"Perte flux vidéo : {name}",
                message=f"Le signal vidéo du smartphone {name} a été interrompu.",
                device_id=device_id,
                device_name=name,
                category="DEVICE_DISCONNECTED"
            )
        elif old_status != "CONNECTÉ" and new_status == "CONNECTÉ":
            dev = self.device_store.get_device(device_id)
            name = dev["name"] if dev else device_id
            self.detection_engine.dispatch_system_event(
                device_id, "DEVICE_RECONNECTED",
                f"Rétablissement du flux vidéo pour {name}", severity="INFO"
            )
            self.notification_manager.add_notification(
                level="INFO",
                title=f"Vidéo rétablie : {name}",
                message=f"Le signal vidéo du smartphone {name} est à nouveau opérationnel.",
                device_id=device_id,
                device_name=name,
                category="DEVICE_RECONNECTED"
            )

    def _on_sensor_state_change(self, device_id: str, old_status: str, new_status: str):
        if old_status == "CONNECTÉ" and new_status != "CONNECTÉ":
            dev = self.device_store.get_device(device_id)
            name = dev["name"] if dev else device_id
            self.detection_engine.dispatch_system_event(
                device_id, "DEVICE_DISCONNECTED",
                f"Interruption télémétrie capteurs pour {name}", severity="AVERTISSEMENT"
            )
            self.notification_manager.add_notification(
                level="WARNING",
                title=f"Perte capteurs : {name}",
                message=f"La télémétrie des capteurs pour {name} ne répond plus.",
                device_id=device_id,
                device_name=name,
                category="DEVICE_DISCONNECTED"
            )
        elif old_status != "CONNECTÉ" and new_status == "CONNECTÉ":
            dev = self.device_store.get_device(device_id)
            name = dev["name"] if dev else device_id
            self.detection_engine.dispatch_system_event(
                device_id, "DEVICE_RECONNECTED",
                f"Rétablissement télémétrie capteurs pour {name}", severity="INFO"
            )
            self.notification_manager.add_notification(
                level="INFO",
                title=f"Capteurs rétablis : {name}",
                message=f"La télémétrie des capteurs pour {name} est rétablie.",
                device_id=device_id,
                device_name=name,
                category="DEVICE_RECONNECTED"
            )

    def _on_detection_event(self, incident: dict):
        """Déclenche la sirène si armé, démarre la capture/enregistrement et notifie le centre d'alerte."""
        # Seuls les incidents d'intrusion déclenchent la sirène
        if incident.get("severity") in ["CRITIQUE", "AVERTISSEMENT"] or incident.get("event_code") in ["REAL_SENSOR_EVENT", "VIDEO_MOTION_EVENT", "SIMULATED_EVENT"]:
            self.alarm_manager.trigger_alarm(incident)
        self.recording_manager.handle_incident(incident)

        # Déclenchement de l'analyse visuelle Qwen Vision asynchrone si une frame est disponible
        frame = incident.get("frame")
        device_id = incident.get("device_id")
        if frame is not None and self.qwen_vision_manager.status == self.qwen_vision_manager.STATUS_FREE_TIER_VERIFIED:
            def _ai_callback(analysis):
                incident_id = incident.get("id")
                if incident_id and analysis:
                    with self.recording_manager._lock:
                        for a in self.recording_manager.alerts:
                            if a.get("id") == incident_id:
                                a["ai_analysis"] = analysis
                                if analysis.get("primary_object") in ["PERSON", "VEHICLE"]:
                                    a["details"] = f"{a.get('details', '')} [IA: {analysis.get('visual_description')}]"
                                break
                        self.recording_manager.save_alerts()

            self.qwen_vision_manager.analyze_motion_frame_async(frame, device_id, callback=_ai_callback)

        # Dispatch dans le centre de notifications
        sev = incident.get("severity", "INFO")
        lvl = "CRITICAL" if sev == "CRITIQUE" else ("HIGH" if sev == "AVERTISSEMENT" else "INFO")
        self.notification_manager.add_notification(
            level=lvl,
            title=incident.get("type", "Incident Détecté"),
            message=incident.get("details", "Détection suspecte"),
            device_id=incident.get("device_id"),
            device_name=incident.get("device_name"),
            alert_id=incident.get("id"),
            category=incident.get("category")
        )

        # Indexation sémantique (PRO-08) et analyse posturale (PRO-10)
        if frame is not None:
            try:
                if hasattr(self, "semantic_search_engine") and self.semantic_search_engine.enabled:
                    self.semantic_search_engine.index_video(
                        event_id=incident.get("id", f"inc_{int(time.time())}"),
                        device_id=incident.get("device_id", "unknown"),
                        video_path=incident.get("video_file", ""),
                        keyframes=[frame],
                        labels=[incident.get("type", ""), incident.get("category", "")],
                        timestamp=incident.get("timestamp")
                    )
            except Exception as e:
                print(f"[SystemCoordinator] Erreur indexation sémantique : {e}")

            try:
                if hasattr(self, "pose_detector"):
                    pose_res = self.pose_detector.analyze_frame(frame, timestamp=incident.get("timestamp"))
                    if pose_res.get("potential_fall"):
                        incident["details"] = f"{incident.get('details', '')} [CHUTE POTENTIELLE: {pose_res.get('aspect_ratio')}]"
            except Exception as e:
                print(f"[SystemCoordinator] Erreur analyse posturale : {e}")

        # Enregistrement dans la file P2P hors-ligne (PRO-11)
        try:
            if hasattr(self, "p2p_sync_mgr"):
                safe_event = {k: v for k, v in incident.items() if k != "frame" and not hasattr(v, "shape")}
                self.p2p_sync_mgr.enqueue_local_event(
                    device_id=incident.get("device_id", "host_01"),
                    event_type=incident.get("type", "INCIDENT"),
                    payload=safe_event
                )
        except Exception as e:
            print(f"[SystemCoordinator] Erreur file d'attente P2P : {e}")

    def start(self):
        with self._lock:
            if self._started:
                return
            self._started = True

            devices = self.device_store.get_all_devices()
            for dev in devices:
                if dev.get("enabled", True):
                    self.camera_manager.start_camera(dev["id"], dev["video_url"])
                    self.sensor_manager.start_sensor_polling(dev["id"], dev["sensors_url"])

            self.detection_engine.start()
            print("[SystemCoordinator] Monitoring Host démarré avec succès.")

    def stop(self):
        with self._lock:
            if not self._started:
                return
            self._started = False
            self.detection_engine.stop()
            self.camera_manager.stop_all()
            self.sensor_manager.stop_all()
            self.alarm_manager.stop_siren()
            self.telegram_notifier.stop()
            self.qwen_vision_manager.stop()
            self.presence_manager.stop()
            if hasattr(self, "semantic_search_engine"):
                self.semantic_search_engine.close()
            print("[SystemCoordinator] Monitoring Host arrêté.")

    def add_device(self, name: str, ip: str, port: int, enable_torch: bool = False, protocol: str = "ANDROID_IPWEBCAM", rtsp_uri: Optional[str] = None) -> dict:
        with self._lock:
            device = self.device_store.add_device(name, ip, port, enable_torch, protocol=protocol, rtsp_uri=rtsp_uri)
            if self._started and device.get("enabled", True):
                self.camera_manager.start_camera(device["id"], device["video_url"])
                if device.get("sensors_url"):
                    self.sensor_manager.start_sensor_polling(device["id"], device["sensors_url"])
            return device

    def update_device(self, device_id: str, **kwargs) -> Optional[dict]:
        with self._lock:
            device = self.device_store.update_device(device_id, **kwargs)
            if device and self._started:
                if device.get("enabled", True):
                    self.camera_manager.start_camera(device["id"], device["video_url"])
                    self.sensor_manager.start_sensor_polling(device["id"], device["sensors_url"])
                else:
                    self.camera_manager.stop_camera(device["id"])
                    self.sensor_manager.stop_sensor_polling(device["id"])
            return device

    def delete_device(self, device_id: str) -> bool:
        with self._lock:
            self.camera_manager.stop_camera(device_id)
            self.sensor_manager.stop_sensor_polling(device_id)
            return self.device_store.delete_device(device_id)

    def get_system_status(self) -> dict:
        """Agrège l'état global et les statistiques professionnelles pour le tableau de bord."""
        devices = self.device_store.get_all_devices()
        connected_count = 0
        disconnected_count = 0
        degraded_count = 0
        total_available_sensors = 0

        now = time.time()
        devices_status = []
        for dev in devices:
            dev_id = dev["id"]
            cam_stat = self.camera_manager.get_status(dev_id)
            sens_stat = self.sensor_manager.get_device_sensors(dev_id)

            cam_s = cam_stat.get("status", "DÉCONNECTÉ")
            sens_s = sens_stat.get("status", "DÉCONNECTÉ")

            # Synthèse globale de l'appareil
            if cam_s == "CONNECTÉ" and sens_s == "CONNECTÉ":
                overall = "OPÉRATIONNEL"
                connected_count += 1
            elif cam_s in ["CONNECTÉ", "DÉGRADÉ"] or sens_s in ["CONNECTÉ", "DÉGRADÉ"]:
                overall = "DÉGRADÉ"
                degraded_count += 1
            else:
                overall = "DÉCONNECTÉ"
                disconnected_count += 1

            sensors = sens_stat.get("sensors", {})
            for s_name, s_data in sensors.items():
                if s_data.get("available") and s_data.get("status") in ["DONNÉE RÉELLE", "DONNÉE SIMULÉE", "DISPONIBLE", "DISPONIBLE (SIMULÉ)"]:
                    total_available_sensors += 1

            # Calcul du temps de dernière communication
            last_comm_age = None
            if cam_stat.get("last_frame_age") is not None and sens_stat.get("last_update_age") is not None:
                last_comm_age = min(cam_stat["last_frame_age"], sens_stat["last_update_age"])
            elif cam_stat.get("last_frame_age") is not None:
                last_comm_age = cam_stat["last_frame_age"]
            elif sens_stat.get("last_update_age") is not None:
                last_comm_age = sens_stat["last_update_age"]

            devices_status.append({
                "id": dev_id,
                "name": dev["name"],
                "ip": dev["ip"],
                "port": dev["port"],
                "enabled": dev.get("enabled", True),
                "enable_torch": dev.get("enable_torch", False),
                "overall_status": overall,
                "camera_status": cam_s,
                "sensor_status": sens_s,
                "last_communication_age": last_comm_age,
                "last_frame_time": cam_stat.get("last_frame_time"),
                "sensors": sensors,
                "zones": dev.get("zones", []),
                "zones_count": len(dev.get("zones", [])),
                "history": sens_stat.get("history", {"sound": [], "accel": []}),
                "video_url": f"/video_feed/{dev_id}"
            })

        alarm_stat = self.alarm_manager.get_status()
        alerts = self.recording_manager.get_all_alerts()
        notifs_data = self.notification_manager.get_notifications(limit=5)
        
        # Calcul alertes du jour
        today_prefix = time.strftime("%Y-%m-%d")
        alerts_today = sum(1 for a in alerts if a.get("datetime", "").startswith(today_prefix))

        # État général de surveillance
        if alarm_stat["in_alarm"]:
            general_state = "INCIDENT"
        elif degraded_count > 0 or (len(devices) > 0 and connected_count < len(devices)):
            general_state = "DÉGRADÉ"
        elif len(devices) > 0 and connected_count == len(devices):
            general_state = "OPÉRATIONNEL"
        else:
            general_state = "VEILLE"

        last_incident = alerts[0] if alerts else None
        storage_stats = self.recording_manager.get_storage_stats()
        settings = self.device_store.get_settings()

        curr_inc = alarm_stat.get("current_incident")
        if curr_inc and isinstance(curr_inc, dict):
            curr_inc = {k: v for k, v in curr_inc.items() if k != "frame" and not hasattr(v, "shape")}

        return {
            "is_armed": alarm_stat["is_armed"],
            "in_alarm": alarm_stat["in_alarm"],
            "siren_active": alarm_stat["siren_active"],
            "current_incident": curr_inc,
            "general_state": general_state,
            "connected_devices_count": connected_count,
            "disconnected_devices_count": disconnected_count,
            "degraded_devices_count": degraded_count,
            "total_devices_count": len(devices),
            "available_sensors_count": total_available_sensors,
            "alerts_count": len(alerts),
            "alerts_today_count": alerts_today,
            "notifications_unread_count": notifs_data["unread_count"],
            "recent_notifications": notifs_data["notifications"],
            "last_incident": {
                "id": last_incident["id"],
                "type": last_incident.get("type"),
                "device_name": last_incident.get("device_name"),
                "datetime": last_incident.get("datetime"),
                "severity": last_incident.get("severity", "AVERTISSEMENT")
            } if last_incident else None,
            "storage_stats": storage_stats,
            "devices": devices_status,
            "settings": settings,
            "demo_mode": settings.get("demo_mode", False),
            "telegram": self.telegram_notifier.get_status(),
            "qwen_vision": self.qwen_vision_manager.get_status(),
            "edge_ai": self.edge_ai_detector.get_status() if self.edge_ai_detector else {"status": "UNAVAILABLE"},
            "presence": self.presence_manager.get_status() if self.presence_manager else {"status": "DISABLED"},
            "webrtc": self.webrtc_manager.get_status() if self.webrtc_manager else {"status": "UNAVAILABLE"},
            "pwa": self.push_manager.get_status() if self.push_manager else {"enabled": True},
            "tamper": self.tamper_detector.get_status() if hasattr(self, "tamper_detector") else {"status": "UNAVAILABLE"},
            "audio_ai": self.audio_classifier.get_status() if hasattr(self, "audio_classifier") else {"status": "UNAVAILABLE"},
            "semantic_search": self.semantic_search_engine.get_status() if hasattr(self, "semantic_search_engine") else {"status": "UNAVAILABLE"},
            "privacy_shield": self.privacy_shield.get_status() if hasattr(self, "privacy_shield") else {"status": "UNAVAILABLE"},
            "spatial_tracker": self.spatial_tracker.get_status() if hasattr(self, "spatial_tracker") else {"status": "UNAVAILABLE"},
            "pose_detector": self.pose_detector.get_status() if hasattr(self, "pose_detector") else {"status": "UNAVAILABLE"},
            "p2p_sync": self.p2p_sync_mgr.get_status() if hasattr(self, "p2p_sync_mgr") else {"status": "UNAVAILABLE"},
            "intercom": self.intercom_mgr.get_status() if hasattr(self, "intercom_mgr") else {"status": "UNAVAILABLE"},
            "database": {"engine": "SQLite 3", "status": "active"},
            "server_time": time.strftime("%Y-%m-%d %H:%M:%S")
        }
