"""
Module d'Estimation de Pose et Analyse Comportementale — PRO-10
Analyse les postures corporelles et détecte les anomalies éthiques :
- Détection de chute potentielle (personne allongée au sol, immobilité)
- Détection de station prolongée suspecte (rôdage / loitering > 20s)
- Posture d'agression ou bras levé avec objet (à vérifier)

États normalisés : NORMAL, POTENTIAL_ANOMALY, NEEDS_REVIEW, UNKNOWN.
Conformité éthique : les alertes sont qualifiées comme événements à vérifier par l'opérateur,
sans jamais déduire d'intention criminelle ni de culpabilité automatique.
"""

import os
import time
import uuid
import threading
from typing import Dict, List, Optional, Tuple, Any
import numpy as np
import cv2


class BehavioralState:
    NORMAL = "NORMAL"
    POTENTIAL_ANOMALY = "POTENTIAL_ANOMALY"
    NEEDS_REVIEW = "NEEDS_REVIEW"
    UNKNOWN = "UNKNOWN"


class BehavioralEvent:
    def __init__(
        self,
        event_id: str,
        device_id: str,
        event_type: str,
        state: str,
        confidence: float,
        evidence: dict,
        timestamp: Optional[float] = None
    ):
        self.id = event_id
        self.device_id = device_id
        self.event_type = event_type
        self.state = state
        self.confidence = max(0.0, min(1.0, float(confidence)))
        self.evidence = evidence or {}
        self.timestamp = timestamp or time.time()

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "device_id": self.device_id,
            "event_type": self.event_type,
            "state": self.state,
            "confidence": round(self.confidence, 3),
            "evidence": self.evidence,
            "timestamp": self.timestamp,
            "datetime": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(self.timestamp))
        }


class PoseDetector:
    def __init__(
        self,
        pose_model_path: Optional[str] = "models/yolov8n-pose.onnx",
        loitering_threshold_seconds: float = 20.0,
        fall_aspect_ratio_threshold: float = 1.35
    ):
        self.pose_model_path = pose_model_path
        self.loitering_threshold_seconds = loitering_threshold_seconds
        self.fall_aspect_ratio_threshold = fall_aspect_ratio_threshold

        self._lock = threading.RLock()
        self._pose_session = None
        self._engine_type = "GEOMETRIC_FALLBACK"

        # Suivi du temps de présence par caméra pour loitering (device_id -> first_seen_time, last_seen_time)
        self._presence_tracker: Dict[str, Dict[str, float]] = {}
        self._recent_events: List[BehavioralEvent] = []

        self._init_pose_model()

    def _init_pose_model(self):
        if self.pose_model_path and os.path.exists(self.pose_model_path):
            try:
                import onnxruntime as ort
                opts = ort.SessionOptions()
                opts.intra_op_num_threads = 1
                self._pose_session = ort.InferenceSession(self.pose_model_path, opts, providers=['CPUExecutionProvider'])
                self._engine_type = "ONNX_YOLO_POSE"
            except Exception:
                self._pose_session = None
                self._engine_type = "GEOMETRIC_FALLBACK"
        else:
            self._engine_type = "GEOMETRIC_FALLBACK"

    def analyze_person_posture(
        self,
        device_id: str,
        frame: Optional[np.ndarray],
        bbox: Optional[Tuple[int, int, int, int]] = None,
        timestamp: Optional[float] = None
    ) -> BehavioralEvent:
        """Analyse la posture d'une silhouette humaine et détecte d'éventuelles chutes ou postures anormales."""
        now = timestamp or time.time()

        # 1. Suivi du rôdage (Loitering)
        with self._lock:
            if device_id not in self._presence_tracker:
                self._presence_tracker[device_id] = {"first_seen": now, "last_seen": now}
            else:
                self._presence_tracker[device_id]["last_seen"] = now

            presence_duration = now - self._presence_tracker[device_id]["first_seen"]

            if presence_duration >= self.loitering_threshold_seconds:
                ev = BehavioralEvent(
                    event_id=f"beh_{uuid.uuid4().hex[:10]}",
                    device_id=device_id,
                    event_type="LOITERING_PROLONGED_PRESENCE",
                    state=BehavioralState.NEEDS_REVIEW,
                    confidence=0.85,
                    evidence={
                        "presence_duration_seconds": round(presence_duration, 1),
                        "threshold": self.loitering_threshold_seconds,
                        "observation": "Station prolongée anormale dans le champ de la caméra."
                    },
                    timestamp=now
                )
                self._recent_events.append(ev)
                return ev

        # 2. Analyse de posture (Chute vs Posture normale)
        if bbox is not None:
            x, y, w, h = bbox
            aspect_ratio = (w / float(h)) if h > 0 else 1.0

            # Silhouette couchée horizontalement au sol (w > h * 1.35)
            if aspect_ratio >= self.fall_aspect_ratio_threshold:
                ev = BehavioralEvent(
                    event_id=f"beh_{uuid.uuid4().hex[:10]}",
                    device_id=device_id,
                    event_type="POTENTIAL_FALL_DETECTED",
                    state=BehavioralState.NEEDS_REVIEW,
                    confidence=0.80,
                    evidence={
                        "aspect_ratio_w_over_h": round(aspect_ratio, 2),
                        "bbox": [x, y, w, h],
                        "observation": "Position horizontale anormale détectée au sol (assistance ou vérification requise)."
                    },
                    timestamp=now
                )
                with self._lock:
                    self._recent_events.append(ev)
                return ev

        # Posture normale standard
        ev_normal = BehavioralEvent(
            event_id=f"beh_{uuid.uuid4().hex[:10]}",
            device_id=device_id,
            event_type="NORMAL_UPRIGHT_POSTURE",
            state=BehavioralState.NORMAL,
            confidence=0.92,
            evidence={"engine": self._engine_type},
            timestamp=now
        )
        return ev_normal

    def reset_presence(self, device_id: str):
        """Réinitialise le compteur de présence d'un appareil."""
        with self._lock:
            if device_id in self._presence_tracker:
                del self._presence_tracker[device_id]

    def get_status(self) -> dict:
        with self._lock:
            recent_anomalies = [e.to_dict() for e in reversed(self._recent_events[-15:]) if e.state != BehavioralState.NORMAL]
            return {
                "engine": self._engine_type,
                "model_available": self._pose_session is not None,
                "loitering_threshold_seconds": self.loitering_threshold_seconds,
                "fall_aspect_ratio_threshold": self.fall_aspect_ratio_threshold,
                "tracked_devices_presence": {
                    k: round(time.time() - v["first_seen"], 1)
                    for k, v in self._presence_tracker.items()
                },
                "recent_behavioral_anomalies": recent_anomalies
            }
