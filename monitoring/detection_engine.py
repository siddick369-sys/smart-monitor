import cv2
import numpy as np
import threading
import time
import math
from typing import Dict, List, Callable, Optional, Tuple
import config

class DetectionEngine:
    """Moteur de détection multi-vectorielle intelligent avec filtrage d'artefacts et classification normalisée."""

    def __init__(self, camera_manager, sensor_manager, device_store, edge_ai_detector=None):
        self.camera_manager = camera_manager
        self.sensor_manager = sensor_manager
        self.device_store = device_store
        
        if edge_ai_detector is None:
            try:
                from monitoring.edge_ai_detector import EdgeAIDetector
                self.edge_ai_detector = EdgeAIDetector()
            except Exception:
                self.edge_ai_detector = None
        else:
            self.edge_ai_detector = edge_ai_detector

        self._callbacks: List[Callable[[dict], None]] = []
        self._prev_frames_gray: Dict[str, np.ndarray] = {}
        self._last_triggers: Dict[Tuple[str, str], float] = {} # (device_id, event_type) -> timestamp
        self._last_triggered_zone: Dict[str, Optional[str]] = {}
        
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._lock = threading.RLock()

    def register_callback(self, cb: Callable[[dict], None]):
        """Enregistre une fonction de rappel déclenchée lors d'un incident avéré."""
        with self._lock:
            self._callbacks.append(cb)

    def start(self):
        with self._lock:
            if self._thread is None or not self._thread.is_alive():
                self._stop_event.clear()
                self._thread = threading.Thread(target=self._run_loop, name="DetectionEngineLoop", daemon=True)
                self._thread.start()

    def stop(self):
        with self._lock:
            self._stop_event.set()
            if self._thread:
                self._thread.join(timeout=2.0)

    def _is_cooling_down(self, device_id: str, event_type: str, cooldown_seconds: float) -> bool:
        key = (device_id, event_type)
        last_time = self._last_triggers.get(key, 0.0)
        return (time.time() - last_time) < cooldown_seconds

    def _record_trigger(self, device_id: str, event_type: str):
        key = (device_id, event_type)
        self._last_triggers[key] = time.time()

    def _dispatch_incident(self, incident: dict):
        """Notifie tous les gestionnaires abonnés (AlarmManager, RecordingManager)."""
        for cb in self._callbacks:
            try:
                cb(incident)
            except Exception as e:
                print(f"[DetectionEngine] Erreur callback incident : {e}")

    def dispatch_system_event(self, device_id: str, event_code: str, details: str, severity: str = "INFO"):
        """Émet un événement système (ex: déconnexion, reconnexion, erreur)."""
        device = self.device_store.get_device(device_id) or {"id": device_id, "name": f"Appareil {device_id}", "ip": "127.0.0.1"}
        now = time.time()
        category = config.EVENT_CODES.get(event_code, "ÉVÉNEMENT SYSTÈME")
        
        event_dict = {
            "id": f"event_{int(now*1000)}",
            "timestamp": now,
            "datetime": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(now)),
            "device_id": device_id,
            "device_name": device["name"],
            "device_ip": device.get("ip", ""),
            "type": event_code,
            "event_code": event_code,
            "category": category,
            "severity": severity,
            "details": details,
            "frame": None
        }
        self._dispatch_incident(event_dict)

    def trigger_simulated_incident(self, device_id: str, event_type: str, custom_label: str = None) -> dict:
        """Déclenche immédiatement un événement qualifié de SIMULÉ."""
        device = self.device_store.get_device(device_id) or {"id": device_id, "name": f"Device {device_id}", "ip": "127.0.0.1"}
        frame = self.camera_manager.get_frame(device_id)
        now = time.time()
        
        incident = {
            "id": f"alert_{int(now*1000)}",
            "device_id": device_id,
            "device_name": device["name"],
            "device_ip": device.get("ip", ""),
            "type": event_type,
            "event_code": "SIMULATED_EVENT",
            "category": config.EVENT_CODES["SIMULATED_EVENT"],
            "severity": "INFO",
            "details": custom_label or f"Déclenchement manuel simulé : {event_type}",
            "timestamp": now,
            "datetime": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(now)),
            "frame": frame
        }
        self._record_trigger(device_id, event_type)
        self._dispatch_incident(incident)
        return incident

    def get_last_triggered_zone(self, device_id: str) -> Optional[str]:
        return self._last_triggered_zone.get(device_id)

    def check_video_motion(self, device_id: str, frame: np.ndarray, threshold_area_pct: float) -> Tuple[bool, float]:
        """Détection de mouvement OpenCV basée sur le calcul de surface différentielle avec support des zones ROI et rejet des flashs lumineux."""
        if frame is None:
            return False, 0.0

        try:
            h, w = frame.shape[:2]
            gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
            gray = cv2.GaussianBlur(gray, (21, 21), 0)

            prev_gray = self._prev_frames_gray.get(device_id)
            self._prev_frames_gray[device_id] = gray

            if prev_gray is None or prev_gray.shape != gray.shape:
                return False, 0.0

            # Calcul de différence absolue
            delta = cv2.absdiff(prev_gray, gray)
            thresh = cv2.threshold(delta, 25, 255, cv2.THRESH_BINARY)[1]
            thresh = cv2.dilate(thresh, None, iterations=2)

            # Vérifier si des zones de surveillance sont configurées pour cet appareil
            zones = []
            if hasattr(self.device_store, "get_device_zones"):
                zones = self.device_store.get_device_zones(device_id)
            elif hasattr(self.device_store, "get_device"):
                dev = self.device_store.get_device(device_id)
                if dev and isinstance(dev, dict):
                    zones = dev.get("zones", [])

            active_zones = [z for z in zones if z.get("enabled", True)]

            if active_zones:
                # 1. Rejet préalable des variations lumineuses globales (> 85%)
                global_contours, _ = cv2.findContours(thresh.copy(), cv2.RETR_EXTERNAL, cv2.CHAIN_APPROX_SIMPLE)
                global_motion_area = sum(cv2.contourArea(c) for c in global_contours)
                global_pct = (global_motion_area / (w * h)) * 100.0
                if global_pct > 85.0:
                    self._last_triggered_zone[device_id] = None
                    return False, round(global_pct, 2)

                # 2. Analyse spécifique pour chaque zone active
                for zone in active_zones:
                    zx = max(0.0, min(1.0, float(zone.get("x", 0.0))))
                    zy = max(0.0, min(1.0, float(zone.get("y", 0.0))))
                    zw = max(0.01, min(1.0 - zx, float(zone.get("w", 1.0))))
                    zh = max(0.01, min(1.0 - zy, float(zone.get("h", 1.0))))

                    x1 = int(zx * w)
                    y1 = int(zy * h)
                    x2 = int((zx + zw) * w)
                    y2 = int((zy + zh) * h)

                    if x2 > x1 and y2 > y1:
                        zone_thresh = thresh[y1:y2, x1:x2]
                        zone_motion_px = cv2.countNonZero(zone_thresh)
                        zone_area_px = (x2 - x1) * (y2 - y1)
                        zone_motion_pct = (zone_motion_px / zone_area_px) * 100.0

                        if zone_motion_pct >= threshold_area_pct:
                            zone_name = zone.get("name", "Zone")
                            self._last_triggered_zone[device_id] = zone_name
                            return True, round(zone_motion_pct, 2)

                self._last_triggered_zone[device_id] = None
                return False, 0.0
            else:
                # 3. Détection générale sur l'intégralité de l'image (si aucune zone configurée)
                contours, _ = cv2.findContours(thresh.copy(), cv2.RETR_EXTERNAL, cv2.CHAIN_APPROX_SIMPLE)
                total_motion_area = sum(cv2.contourArea(c) for c in contours)
                total_area = w * h
                motion_pct = (total_motion_area / total_area) * 100.0

                # Rejet des faux positifs de variation d'éclairage globale
                if motion_pct > 85.0:
                    self._last_triggered_zone[device_id] = None
                    return False, round(motion_pct, 2)

                is_motion = motion_pct >= threshold_area_pct
                self._last_triggered_zone[device_id] = None
                return is_motion, round(motion_pct, 2)
        except Exception as e:
            print(f"[DetectionEngine] Erreur analyse vidéo {device_id} : {e}")
            self._last_triggered_zone[device_id] = None
            return False, 0.0

    def _run_loop(self):
        """Boucle principale d'évaluation continue des flux et des données de capteurs."""
        while not self._stop_event.is_set():
            settings = self.device_store.get_settings()
            cooldown = settings.get("cooldown_seconds", 8.0)
            devices = self.device_store.get_all_devices()

            for dev in devices:
                if not dev.get("enabled", True):
                    continue

                dev_id = dev["id"]
                dev_name = dev["name"]
                dev_ip = dev.get("ip", "")
                
                # Récupérer frame et données de capteurs
                frame = self.camera_manager.get_frame(dev_id)
                sensor_info = self.sensor_manager.get_device_sensors(dev_id)
                sensors = sensor_info.get("sensors", {})

                # 1. Analyse Détection Mouvement Vidéo (OpenCV)
                if settings.get("enable_motion", True):
                    thresh_motion = settings.get("motion_area_threshold", 1.5)
                    is_motion, motion_pct = self.check_video_motion(dev_id, frame, thresh_motion)
                    
                    if is_motion and not self._is_cooling_down(dev_id, "MOUVEMENT_VIDÉO", cooldown):
                        # Arbitrage décisionnel par Edge AI
                        ai_eval = {"alert": True, "confirmed": False}
                        if self.edge_ai_detector:
                            try:
                                ai_eval = self.edge_ai_detector.evaluate_detection_policy(is_motion, frame)
                            except Exception as e:
                                ai_eval = {"alert": True, "confirmed": False, "error": str(e)}

                        if ai_eval.get("alert", True):
                            self._record_trigger(dev_id, "MOUVEMENT_VIDÉO")
                            now = time.time()
                            zone_triggered = self.get_last_triggered_zone(dev_id)
                            if zone_triggered:
                                motion_details = f"Mouvement détecté dans la zone '{zone_triggered}' : {motion_pct}% (seuil: {thresh_motion}%)"
                            else:
                                motion_details = f"Mouvement vidéo détecté : {motion_pct}% de l'image (seuil: {thresh_motion}%)"

                            if ai_eval.get("confirmed"):
                                motion_details += f" | IA: {ai_eval.get('reason')}"

                            self._dispatch_incident({
                                "id": f"alert_{int(now*1000)}",
                                "device_id": dev_id,
                                "device_name": dev_name,
                                "device_ip": dev_ip,
                                "type": "MOUVEMENT_VIDÉO",
                                "event_code": "VIDEO_MOTION_EVENT",
                                "category": config.EVENT_CODES["VIDEO_MOTION_EVENT"],
                                "severity": "AVERTISSEMENT",
                                "details": motion_details,
                                "measured_value": motion_pct,
                                "threshold": thresh_motion,
                                "frame": frame,
                                "edge_ai": ai_eval
                            })

                # 2. Analyse Capteur de Proximité
                if settings.get("enable_proximity", True):
                    prox = sensors.get("proximity", {})
                    if prox.get("available") and prox.get("value") is not None:
                        val = prox["value"]
                        thresh_prox = settings.get("proximity_threshold", 5.0)
                        is_sim = prox.get("is_simulated", False)
                        
                        # Alerte si proximité <= seuil
                        if isinstance(val, (int, float)) and not math.isnan(val) and val <= thresh_prox:
                            if not self._is_cooling_down(dev_id, "PROXIMITÉ", cooldown):
                                self._record_trigger(dev_id, "PROXIMITÉ")
                                now = time.time()
                                event_code = "SIMULATED_EVENT" if is_sim else "REAL_SENSOR_EVENT"
                                self._dispatch_incident({
                                    "id": f"alert_{int(now*1000)}",
                                    "device_id": dev_id,
                                    "device_name": dev_name,
                                    "device_ip": dev_ip,
                                    "type": "PROXIMITÉ",
                                    "event_code": event_code,
                                    "category": config.EVENT_CODES[event_code],
                                    "severity": "AVERTISSEMENT",
                                    "details": f"Obstacle à proximité : {val} cm (seuil: <= {thresh_prox} cm)",
                                    "timestamp": now,
                                    "datetime": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(now)),
                                    "measured_value": val,
                                    "threshold": thresh_prox,
                                    "frame": frame
                                })

                # 3. Analyse Capteur Acoustique (Niveau Sonore / Bris de verre)
                if settings.get("enable_sound", True):
                    sound = sensors.get("sound", {})
                    if sound.get("available") and sound.get("value") is not None:
                        val = sound["value"]
                        thresh_sound = settings.get("sound_threshold", 75.0)
                        is_sim = sound.get("is_simulated", False)

                        if isinstance(val, (int, float)) and not math.isnan(val) and val >= thresh_sound:
                            if not self._is_cooling_down(dev_id, "ACOUSTIQUE", cooldown):
                                self._record_trigger(dev_id, "ACOUSTIQUE")
                                now = time.time()
                                event_code = "SIMULATED_EVENT" if is_sim else "REAL_SENSOR_EVENT"
                                self._dispatch_incident({
                                    "id": f"alert_{int(now*1000)}",
                                    "device_id": dev_id,
                                    "device_name": dev_name,
                                    "device_ip": dev_ip,
                                    "type": "ACOUSTIQUE",
                                    "event_code": event_code,
                                    "category": config.EVENT_CODES[event_code],
                                    "severity": "CRITIQUE",
                                    "details": f"Bruit suspect / Bris de vitre : {val} dB (seuil relatif: >= {thresh_sound} dB)",
                                    "timestamp": now,
                                    "datetime": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(now)),
                                    "measured_value": val,
                                    "threshold": thresh_sound,
                                    "frame": frame
                                })

                # 4. Analyse Accéléromètre (Secousse, Choc, Déplacement)
                if settings.get("enable_accel", True):
                    accel = sensors.get("accel", {})
                    if accel.get("available") and accel.get("norm") is not None:
                        norm = accel["norm"]
                        if isinstance(norm, (int, float)) and not math.isnan(norm) and not math.isinf(norm):
                            delta_gravity = abs(norm - 9.81)
                            thresh_shock = settings.get("accel_shock_threshold", 4.5)
                            is_sim = accel.get("is_simulated", False)

                            if delta_gravity >= thresh_shock and not self._is_cooling_down(dev_id, "CHOC_ACCÉLÉROMÈTRE", cooldown):
                                self._record_trigger(dev_id, "CHOC_ACCÉLÉROMÈTRE")
                                now = time.time()
                                event_code = "SIMULATED_EVENT" if is_sim else "REAL_SENSOR_EVENT"
                                self._dispatch_incident({
                                    "id": f"alert_{int(now*1000)}",
                                    "device_id": dev_id,
                                    "device_name": dev_name,
                                    "device_ip": dev_ip,
                                    "type": "CHOC_ACCÉLÉROMÈTRE",
                                    "event_code": event_code,
                                    "category": config.EVENT_CODES[event_code],
                                    "severity": "CRITIQUE",
                                    "details": f"Choc / Secousse détectée : variation de {round(delta_gravity, 2)} m/s² (seuil: >= {thresh_shock})",
                                    "timestamp": now,
                                    "datetime": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(now)),
                                    "measured_value": round(delta_gravity, 2),
                                    "threshold": thresh_shock,
                                    "frame": frame
                                })

            time.sleep(0.1) # 10 Hz cycle d'évaluation
