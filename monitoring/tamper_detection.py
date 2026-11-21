"""
Module de Détection Anti-Sabotage (Tamper Detection) — PRO-07
Surveille l'intégrité physique et optique des nœuds caméras et de leurs capteurs :
- Obstruction optique (masquage d'objectif, spray, carton)
- Changement brutal d'orientation ou déplacement physique (accéléromètre)
- Dégradation anormale de la netteté (flou, défocalisation)
- Perte ou gel de flux vidéo
- Anomalies extrêmes d'éclairage
- Anomalies de télémétrie et déconnexion inattendue
"""

import time
import uuid
import threading
from typing import Dict, List, Optional, Any
import numpy as np
import cv2


class TamperState:
    NORMAL = "NORMAL"
    SUSPECTED = "SUSPECTED"
    CONFIRMED = "CONFIRMED"
    RECOVERED = "RECOVERED"
    UNKNOWN = "UNKNOWN"


class TamperType:
    OBSTRUCTION = "OBSTRUCTION"
    ORIENTATION_CHANGE = "ORIENTATION_CHANGE"
    DISPLACEMENT = "DISPLACEMENT"
    STREAM_LOSS = "STREAM_LOSS"
    VIDEO_DEGRADATION = "VIDEO_DEGRADATION"
    LIGHTING_ANOMALY = "LIGHTING_ANOMALY"
    DISCONNECT = "DISCONNECT"
    TELEMETRY_ANOMALY = "TELEMETRY_ANOMALY"


class TamperEvent:
    def __init__(
        self,
        event_id: str,
        device_id: str,
        anomaly_type: str,
        confidence: float,
        status: str,
        data_source: str,
        evidence: Dict[str, Any],
        timestamp: Optional[float] = None
    ):
        self.id = event_id
        self.device_id = device_id
        self.anomaly_type = anomaly_type
        self.confidence = max(0.0, min(1.0, float(confidence)))
        self.status = status
        self.data_source = data_source
        self.evidence = evidence or {}
        self.timestamp = timestamp or time.time()

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "device_id": self.device_id,
            "anomaly_type": self.anomaly_type,
            "confidence": round(self.confidence, 3),
            "status": self.status,
            "data_source": self.data_source,
            "evidence": self.evidence,
            "timestamp": self.timestamp,
            "datetime": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(self.timestamp))
        }


class TamperDetector:
    def __init__(
        self,
        blur_threshold: float = 15.0,
        dark_threshold: float = 8.0,
        consecutive_frames_required: int = 3,
        accel_shock_threshold: float = 4.0,
        stream_timeout_seconds: float = 6.0
    ):
        self.blur_threshold = blur_threshold
        self.dark_threshold = dark_threshold
        self.consecutive_frames_required = consecutive_frames_required
        self.accel_shock_threshold = accel_shock_threshold
        self.stream_timeout_seconds = stream_timeout_seconds

        self._lock = threading.RLock()
        # Suivi par device_id
        self._device_state: Dict[str, str] = {}
        self._consecutive_anomalies: Dict[str, Dict[str, int]] = {}
        self._reference_accel: Dict[str, List[float]] = {}
        self._recent_events: List[TamperEvent] = []
        self._active_events: Dict[str, TamperEvent] = {}

    def _get_consecutive(self, device_id: str, anomaly_type: str) -> int:
        if device_id not in self._consecutive_anomalies:
            self._consecutive_anomalies[device_id] = {}
        return self._consecutive_anomalies[device_id].get(anomaly_type, 0)

    def _increment_consecutive(self, device_id: str, anomaly_type: str) -> int:
        if device_id not in self._consecutive_anomalies:
            self._consecutive_anomalies[device_id] = {}
        cnt = self._consecutive_anomalies[device_id].get(anomaly_type, 0) + 1
        self._consecutive_anomalies[device_id][anomaly_type] = cnt
        return cnt

    def _reset_consecutive(self, device_id: str, anomaly_type: str):
        if device_id in self._consecutive_anomalies and anomaly_type in self._consecutive_anomalies[device_id]:
            self._consecutive_anomalies[device_id][anomaly_type] = 0

    def analyze_frame(self, device_id: str, frame: np.ndarray, timestamp: Optional[float] = None) -> Optional[TamperEvent]:
        """Analyse une frame vidéo pour détecter obstruction, flou sévère ou éclairage anormal."""
        if frame is None or not isinstance(frame, np.ndarray) or frame.size == 0:
            return None

        now = timestamp or time.time()

        try:
            if len(frame.shape) == 3:
                gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
            else:
                gray = frame

            mean_val = float(np.mean(gray))
            std_val = float(np.std(gray))
            laplacian_var = float(cv2.Laplacian(gray, cv2.CV_64F).var())
        except Exception:
            return None

        with self._lock:
            # 1. Obstruction optique (image quasi-uniforme et sombre / masquée)
            is_obstructed = (mean_val < self.dark_threshold) or (std_val < 2.0 and mean_val < 35.0)
            if is_obstructed:
                count = self._increment_consecutive(device_id, TamperType.OBSTRUCTION)
                status = TamperState.CONFIRMED if count >= self.consecutive_frames_required else TamperState.SUSPECTED
                conf = min(0.95, 0.5 + (count * 0.15))
                event = TamperEvent(
                    event_id=f"tamp_{uuid.uuid4().hex[:10]}",
                    device_id=device_id,
                    anomaly_type=TamperType.OBSTRUCTION,
                    confidence=conf,
                    status=status,
                    data_source="VIDEO_ANALYSIS",
                    evidence={
                        "mean_luminance": round(mean_val, 2),
                        "std_deviation": round(std_val, 2),
                        "consecutive_count": count
                    },
                    timestamp=now
                )
                self._record_event(event)
                return event
            else:
                self._reset_consecutive(device_id, TamperType.OBSTRUCTION)

            # 2. Dégradation anormale de netteté (flou extrême / défocalisation)
            if self.dark_threshold <= mean_val <= 245.0 and laplacian_var < self.blur_threshold:
                count = self._increment_consecutive(device_id, TamperType.VIDEO_DEGRADATION)
                status = TamperState.CONFIRMED if count >= self.consecutive_frames_required else TamperState.SUSPECTED
                event = TamperEvent(
                    event_id=f"tamp_{uuid.uuid4().hex[:10]}",
                    device_id=device_id,
                    anomaly_type=TamperType.VIDEO_DEGRADATION,
                    confidence=0.75,
                    status=status,
                    data_source="VIDEO_ANALYSIS",
                    evidence={
                        "laplacian_var": round(laplacian_var, 2),
                        "threshold": self.blur_threshold,
                        "consecutive_count": count
                    },
                    timestamp=now
                )
                self._record_event(event)
                return event
            else:
                self._reset_consecutive(device_id, TamperType.VIDEO_DEGRADATION)

            # 3. Anomalie brutale d'éclairage (surexposition totale / flash éblouissant)
            if mean_val > 250.0:
                count = self._increment_consecutive(device_id, TamperType.LIGHTING_ANOMALY)
                status = TamperState.CONFIRMED if count >= 2 else TamperState.SUSPECTED
                event = TamperEvent(
                    event_id=f"tamp_{uuid.uuid4().hex[:10]}",
                    device_id=device_id,
                    anomaly_type=TamperType.LIGHTING_ANOMALY,
                    confidence=0.85,
                    status=status,
                    data_source="VIDEO_ANALYSIS",
                    evidence={
                        "mean_luminance": round(mean_val, 2),
                        "type": "OVEREXPOSURE_BLINDING"
                    },
                    timestamp=now
                )
                self._record_event(event)
                return event
            else:
                self._reset_consecutive(device_id, TamperType.LIGHTING_ANOMALY)

            # Si aucune anomalie, vérifier s'il faut passer à RECOVERED
            if self._device_state.get(device_id) in [TamperState.SUSPECTED, TamperState.CONFIRMED]:
                # Tout est redevenu normal
                self._device_state[device_id] = TamperState.RECOVERED

        return None

    def analyze_telemetry(self, device_id: str, sensors_dict: dict, timestamp: Optional[float] = None) -> Optional[TamperEvent]:
        """Analyse la télémétrie physique pour détecter chocs, déplacement ou orientation altérée."""
        if not sensors_dict or not isinstance(sensors_dict, dict):
            return None

        now = timestamp or time.time()

        with self._lock:
            # 1. Vérification de l'accéléromètre
            accel = sensors_dict.get("accel") or sensors_dict.get("accelerometer")
            if accel and isinstance(accel, dict) and "values" in accel:
                vals = accel["values"]
                if isinstance(vals, list) and len(vals) >= 3:
                    ax, ay, az = float(vals[0]), float(vals[1]), float(vals[2])
                    norm = (ax**2 + ay**2 + az**2) ** 0.5
                    delta_g = abs(norm - 9.81)

                    # Déplacement ou choc violent
                    if delta_g >= self.accel_shock_threshold:
                        event = TamperEvent(
                            event_id=f"tamp_{uuid.uuid4().hex[:10]}",
                            device_id=device_id,
                            anomaly_type=TamperType.DISPLACEMENT,
                            confidence=min(0.98, 0.6 + (delta_g / 10.0)),
                            status=TamperState.CONFIRMED,
                            data_source="IMU_SENSOR",
                            evidence={
                                "norm": round(norm, 2),
                                "delta_g": round(delta_g, 2),
                                "raw_accel": [round(ax, 2), round(ay, 2), round(az, 2)]
                            },
                            timestamp=now
                        )
                        self._record_event(event)
                        return event

                    # Changement d'orientation continu (tilt)
                    ref = self._reference_accel.get(device_id)
                    if ref:
                        # Angle entre le vecteur de référence et le vecteur actuel
                        dot = ax * ref[0] + ay * ref[1] + az * ref[2]
                        norm_ref = (ref[0]**2 + ref[1]**2 + ref[2]**2) ** 0.5
                        if norm > 0.1 and norm_ref > 0.1:
                            cos_angle = max(-1.0, min(1.0, dot / (norm * norm_ref)))
                            angle_deg = np.degrees(np.arccos(cos_angle))
                            if angle_deg > 35.0:  # Déviation de plus de 35 degrés
                                event = TamperEvent(
                                    event_id=f"tamp_{uuid.uuid4().hex[:10]}",
                                    device_id=device_id,
                                    anomaly_type=TamperType.ORIENTATION_CHANGE,
                                    confidence=0.88,
                                    status=TamperState.CONFIRMED,
                                    data_source="IMU_SENSOR",
                                    evidence={
                                        "tilt_angle_deg": round(float(angle_deg), 1),
                                        "current_accel": [round(ax, 2), round(ay, 2), round(az, 2)],
                                        "reference_accel": [round(ref[0], 2), round(ref[1], 2), round(ref[2], 2)]
                                    },
                                    timestamp=now
                                )
                                self._record_event(event)
                                return event
                    else:
                        # Enregistrement du premier vecteur stable comme référence
                        self._reference_accel[device_id] = [ax, ay, az]

            # 2. Vérification de l'obsolescence télémétrique
            if sensors_dict.get("status") == "DONNÉE EXPIRÉE" or sensors_dict.get("last_update_age", 0) > 8.0:
                event = TamperEvent(
                    event_id=f"tamp_{uuid.uuid4().hex[:10]}",
                    device_id=device_id,
                    anomaly_type=TamperType.TELEMETRY_ANOMALY,
                    confidence=0.70,
                    status=TamperState.SUSPECTED,
                    data_source="TELEMETRY_PARSER",
                    evidence={"last_update_age": sensors_dict.get("last_update_age")},
                    timestamp=now
                )
                self._record_event(event)
                return event

        return None

    def check_stream_health(self, device_id: str, last_frame_age: Optional[float], is_enabled: bool = True) -> Optional[TamperEvent]:
        """Vérifie la continuité du flux vidéo et signale une perte de flux prolongée."""
        if not is_enabled:
            return None

        now = time.time()
        with self._lock:
            if last_frame_age is not None and last_frame_age > self.stream_timeout_seconds:
                # Perte de flux prolongée
                event = TamperEvent(
                    event_id=f"tamp_{uuid.uuid4().hex[:10]}",
                    device_id=device_id,
                    anomaly_type=TamperType.STREAM_LOSS,
                    confidence=0.90,
                    status=TamperState.CONFIRMED,
                    data_source="STREAM_MONITOR",
                    evidence={
                        "last_frame_age": round(last_frame_age, 2),
                        "timeout_seconds": self.stream_timeout_seconds
                    },
                    timestamp=now
                )
                self._record_event(event)
                return event
        return None

    def _record_event(self, event: TamperEvent):
        self._device_state[event.device_id] = event.status
        self._active_events[event.device_id] = event
        self._recent_events.append(event)
        if len(self._recent_events) > 100:
            self._recent_events = self._recent_events[-100:]

    def resolve_tamper(self, device_id: str):
        """Réinitialise manuellement l'état d'un appareil à NORMAL."""
        with self._lock:
            self._device_state[device_id] = TamperState.NORMAL
            if device_id in self._active_events:
                del self._active_events[device_id]
            self._consecutive_anomalies[device_id] = {}

    def get_status(self, device_id: Optional[str] = None) -> dict:
        """Retourne l'état anti-sabotage d'un appareil ou l'ensemble du système."""
        with self._lock:
            if device_id:
                state = self._device_state.get(device_id, TamperState.NORMAL)
                active = self._active_events.get(device_id)
                return {
                    "device_id": device_id,
                    "state": state,
                    "active_anomaly": active.to_dict() if active else None
                }

            return {
                "states": dict(self._device_state),
                "active_tamper_count": sum(1 for s in self._device_state.values() if s == TamperState.CONFIRMED),
                "recent_events": [ev.to_dict() for ev in reversed(self._recent_events[-15:])]
            }
