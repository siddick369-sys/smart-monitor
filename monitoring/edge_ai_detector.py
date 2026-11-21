"""
Module de Détection Locale d'Objets par IA Embarquée (Edge AI).
Utilise YOLOv8-Nano au format ONNX via ONNX Runtime CPU.

Information de Licence :
- L'architecture YOLOv8 est développée par Ultralytics sous licence AGPL-3.0.
- Dans le cadre de ce projet universitaire (TP4 - Démonstration & Recherche),
  l'exécution locale d'un modèle ONNX exporté respecte les conditions d'usage pédagogique.
- Pour une distribution commerciale fermée, une licence commerciale Ultralytics ou
  un modèle sous licence permissive (ex: MobileNet SSD Apache-2.0) est requis.
"""

import os
import time
import logging
import threading
from typing import Dict, Any, List, Optional, Tuple, Set
import numpy as np
import cv2

try:
    import onnxruntime as ort
    HAS_ONNX = True
except ImportError:
    ort = None
    HAS_ONNX = False

import config

logger = logging.getLogger("SmartSecurityMonitor.EdgeAI")

# 80 classes du jeu de données COCO (standard YOLO)
COCO_CLASSES = [
    "person", "bicycle", "car", "motorcycle", "airplane", "bus", "train", "truck", "boat",
    "traffic light", "fire hydrant", "stop sign", "parking meter", "bench", "bird", "cat",
    "dog", "horse", "sheep", "cow", "elephant", "bear", "zebra", "giraffe", "backpack",
    "umbrella", "handbag", "tie", "suitcase", "frisbee", "skis", "snowboard", "sports ball",
    "kite", "baseball bat", "baseball glove", "skateboard", "surfboard", "tennis racket",
    "bottle", "wine glass", "cup", "fork", "knife", "spoon", "bowl", "banana", "apple",
    "sandwich", "orange", "broccoli", "carrot", "hot dog", "pizza", "donut", "cake", "chair",
    "couch", "potted plant", "bed", "dining table", "toilet", "tv", "laptop", "mouse",
    "remote", "keyboard", "cell phone", "microwave", "oven", "toaster", "sink", "refrigerator",
    "book", "clock", "vase", "scissors", "teddy bear", "hair drier", "toothbrush"
]

# Classes prioritaires pour la sécurité et la surveillance
DEFAULT_SECURITY_CLASSES: Set[str] = {
    "person", "car", "motorcycle", "bicycle", "bus", "truck", "dog", "cat"
}


class EdgeAIDetector:
    """Détecteur d'objets local temps réel via ONNX Runtime (YOLOv8-Nano)."""

    STATUS_READY = "READY"
    STATUS_MODEL_UNAVAILABLE = "MODEL_UNAVAILABLE"
    STATUS_MODEL_CORRUPTED = "MODEL_CORRUPTED"
    STATUS_DISABLED = "DISABLED"
    STATUS_ERROR = "ERROR"

    MODE_OPENCV_ONLY = "OPENCV_ONLY"
    MODE_ASSISTED = "EDGE_AI_ASSISTED"
    MODE_REQUIRED = "EDGE_AI_REQUIRED"

    def __init__(self,
                 enabled: bool = config.EDGE_AI_ENABLED,
                 model_path: str = config.EDGE_AI_MODEL_PATH,
                 mode: str = config.EDGE_AI_MODE,
                 confidence_threshold: float = config.EDGE_AI_CONFIDENCE_THRESHOLD,
                 iou_threshold: float = config.EDGE_AI_IOU_THRESHOLD,
                 inference_interval: float = config.EDGE_AI_INFERENCE_INTERVAL,
                 target_classes: Optional[Set[str]] = None):
        self.enabled = enabled
        self.model_path = model_path
        self.mode = mode if mode in [self.MODE_OPENCV_ONLY, self.MODE_ASSISTED, self.MODE_REQUIRED] else self.MODE_ASSISTED
        self.confidence_threshold = max(0.05, min(0.95, confidence_threshold))
        self.iou_threshold = max(0.1, min(0.9, iou_threshold))
        self.inference_interval = max(0.0, inference_interval)
        self.target_classes = target_classes or DEFAULT_SECURITY_CLASSES

        self.status = self.STATUS_DISABLED if not self.enabled else self.STATUS_MODEL_UNAVAILABLE
        self.status_detail = "Initialisation..."
        self.session: Optional[Any] = None
        self.input_name: Optional[str] = None
        self.input_shape: Tuple[int, int] = (640, 640)
        self.output_names: List[str] = []

        self.last_inference_time = 0.0
        self.last_result: Optional[Dict[str, Any]] = None
        self.inference_count = 0
        self.error_count = 0
        self._lock = threading.Lock()

        # Tentative de chargement du modèle
        if self.enabled:
            self.load_model()
        else:
            self.status = self.STATUS_DISABLED
            self.status_detail = "Edge AI désactivé par configuration."

    def load_model(self) -> Tuple[bool, str]:
        """Charge la session ONNX Runtime de manière thread-safe."""
        with self._lock:
            if not self.enabled:
                self.status = self.STATUS_DISABLED
                self.status_detail = "Edge AI désactivé par configuration."
                return False, self.status_detail

            if not HAS_ONNX:
                self.status = self.STATUS_ERROR
                self.status_detail = "Module onnxruntime non installé dans l'environnement Python."
                return False, self.status_detail

            if not os.path.isfile(self.model_path):
                self.status = self.STATUS_MODEL_UNAVAILABLE
                model_name = os.path.basename(self.model_path)
                self.status_detail = f"Fichier modèle ONNX introuvable ({model_name}). Fallback OpenCV actif."
                self.session = None
                return False, self.status_detail

            try:
                # Configuration des options de session CPU optimisées pour Windows
                opts = ort.SessionOptions()
                opts.intra_op_num_threads = 2
                opts.graph_optimization_level = ort.GraphOptimizationLevel.ORT_ENABLE_ALL

                self.session = ort.InferenceSession(
                    self.model_path,
                    sess_options=opts,
                    providers=["CPUExecutionProvider"]
                )

                # Extraction des métadonnées d'entrée et de sortie
                inputs = self.session.get_inputs()
                outputs = self.session.get_outputs()

                self.input_name = inputs[0].name
                shape = inputs[0].shape
                # Format attendu : [batch, 3, height, width]
                h = shape[2] if len(shape) > 2 and isinstance(shape[2], int) else 640
                w = shape[3] if len(shape) > 3 and isinstance(shape[3], int) else 640
                self.input_shape = (h, w)
                self.output_names = [o.name for o in outputs]

                self.status = self.STATUS_READY
                self.status_detail = f"Modèle ONNX chargé ({os.path.basename(self.model_path)} sur CPU)."
                logger.info(f"[EdgeAI] {self.status_detail}")
                return True, self.status_detail

            except Exception as e:
                self.status = self.STATUS_MODEL_CORRUPTED
                self.status_detail = f"Erreur chargement ONNX ({e}). Fallback OpenCV actif."
                self.session = None
                logger.warning(f"[EdgeAI] {self.status_detail}")
                return False, self.status_detail

    def is_available(self) -> bool:
        """Indique si l'inférence locale est immédiatement utilisable."""
        return self.enabled and self.status == self.STATUS_READY and self.session is not None

    def letterbox(self,
                  image: np.ndarray,
                  target_shape: Tuple[int, int] = (640, 640),
                  color: Tuple[int, int, int] = (114, 114, 114)) -> Tuple[np.ndarray, float, Tuple[int, int]]:
        """Redimensionne l'image en préservant le ratio d'aspect avec padding."""
        shape = image.shape[:2]  # [height, width]
        target_h, target_w = target_shape

        # Calcul du ratio d'échelle
        r = min(target_h / shape[0], target_w / shape[1])
        new_unpad = (int(round(shape[1] * r)), int(round(shape[0] * r)))
        dw, dh = target_w - new_unpad[0], target_h - new_unpad[1]
        dw /= 2
        dh /= 2

        if shape[::-1] != new_unpad:
            image = cv2.resize(image, new_unpad, interpolation=cv2.INTER_LINEAR)

        top, bottom = int(round(dh - 0.1)), int(round(dh + 0.1))
        left, right = int(round(dw - 0.1)), int(round(dw + 0.1))
        padded = cv2.copyMakeBorder(image, top, bottom, left, right, cv2.BORDER_CONSTANT, value=color)
        return padded, r, (int(round(dw)), int(round(dh)))

    def preprocess(self, image: np.ndarray) -> Tuple[np.ndarray, float, Tuple[int, int]]:
        """Prépare le tenseur normalisé pour l'inférence YOLO."""
        padded, ratio, (pad_w, pad_h) = self.letterbox(image, self.input_shape)
        # BGR vers RGB, transposition [H, W, C] -> [C, H, W]
        rgb = cv2.cvtColor(padded, cv2.COLOR_BGR2RGB)
        tensor = rgb.transpose((2, 0, 1)).astype(np.float32) / 255.0
        tensor = np.expand_dims(tensor, axis=0)  # [1, 3, 640, 640]
        return tensor, ratio, (pad_w, pad_h)

    def postprocess(self,
                    outputs: np.ndarray,
                    orig_shape: Tuple[int, int],
                    ratio: float,
                    padding: Tuple[int, int]) -> List[Dict[str, Any]]:
        """Décode la sortie YOLOv8 [1, 84, 8400] avec NMS et reprojection."""
        orig_h, orig_w = orig_shape
        pad_w, pad_h = padding

        # YOLOv8 standard sort [1, 84, 8400] où 84 = [cx, cy, w, h] + 80 classes
        if outputs.ndim == 3:
            if outputs.shape[1] == 84:
                # Transposer vers [8400, 84]
                preds = outputs[0].transpose()
            else:
                preds = outputs[0]
        else:
            preds = outputs

        boxes = []
        confidences = []
        class_ids = []

        for row in preds:
            cx, cy, w, h = row[:4]
            scores = row[4:]
            if len(scores) == 0:
                continue
            class_id = int(np.argmax(scores))
            max_conf = float(scores[class_id])

            if max_conf >= self.confidence_threshold:
                # Conversion du format centre-taille vers coordonnées absolues
                x1 = cx - w / 2.0
                y1 = cy - h / 2.0

                # Dépaddage et remise à l'échelle originale
                x1 = (x1 - pad_w) / ratio
                y1 = (y1 - pad_h) / ratio
                w_orig = w / ratio
                h_orig = h / ratio

                # Bornage dans les dimensions de l'image
                x1 = max(0, min(orig_w - 1, int(round(x1))))
                y1 = max(0, min(orig_h - 1, int(round(y1))))
                w_orig = max(1, min(orig_w - x1, int(round(w_orig))))
                h_orig = max(1, min(orig_h - y1, int(round(h_orig))))

                boxes.append([x1, y1, w_orig, h_orig])
                confidences.append(max_conf)
                class_ids.append(class_id)

        if not boxes:
            return []

        # Application de la suppression des non-maximaux (NMS)
        indices = cv2.dnn.NMSBoxes(boxes, confidences, self.confidence_threshold, self.iou_threshold)

        detections = []
        if len(indices) > 0:
            for idx in indices.flatten():
                box = boxes[idx]
                cid = class_ids[idx]
                class_name = COCO_CLASSES[cid] if cid < len(COCO_CLASSES) else f"class_{cid}"
                conf = confidences[idx]
                is_target = class_name in self.target_classes

                detections.append({
                    "class": class_name,
                    "class_id": cid,
                    "confidence": round(conf, 3),
                    "bbox": [box[0], box[1], box[0] + box[2], box[1] + box[3]],  # [x1, y1, x2, y2]
                    "is_target": is_target
                })

        return detections

    def detect(self, image: Optional[np.ndarray], force: bool = False) -> Dict[str, Any]:
        """
        Exécute la détection locale d'objets sur une image.
        Ne bloque jamais la capture en cas d'erreur ou d'indisponibilité.
        """
        # Validation de l'image
        if image is None or not isinstance(image, np.ndarray) or image.size == 0 or image.ndim != 3:
            return {
                "status": self.STATUS_ERROR,
                "reason": "Image d'entrée invalide ou vide.",
                "detections": [],
                "has_target_object": False,
                "target_objects": [],
                "confirmed": False
            }

        if not self.is_available():
            return {
                "status": self.status,
                "reason": self.status_detail,
                "detections": [],
                "has_target_object": False,
                "target_objects": [],
                "confirmed": False
            }

        # Limitation de la fréquence d'inférence pour préserver le CPU
        now = time.time()
        if not force and (now - self.last_inference_time < self.inference_interval):
            if self.last_result:
                cached = dict(self.last_result)
                cached["cached"] = True
                return cached

        t_start = time.time()
        try:
            with self._lock:
                tensor, ratio, padding = self.preprocess(image)
                outputs = self.session.run(self.output_names, {self.input_name: tensor})
                raw_out = outputs[0]

            detections = self.postprocess(raw_out, image.shape[:2], ratio, padding)
            target_objects = [d["class"] for d in detections if d["is_target"]]
            has_target = len(target_objects) > 0

            elapsed = time.time() - t_start
            self.last_inference_time = now
            self.inference_count += 1

            result = {
                "status": "SUCCESS",
                "model": os.path.basename(self.model_path),
                "mode": self.mode,
                "detections": detections,
                "count": len(detections),
                "has_target_object": has_target,
                "target_objects": list(set(target_objects)),
                "confirmed": has_target,
                "latency_ms": round(elapsed * 1000, 1),
                "timestamp": now,
                "cached": False
            }
            self.last_result = result
            return result

        except Exception as e:
            self.error_count += 1
            logger.error(f"[EdgeAI] Erreur d'inférence ONNX : {e}")
            return {
                "status": self.STATUS_ERROR,
                "reason": f"Erreur d'inférence : {e}",
                "detections": [],
                "has_target_object": False,
                "target_objects": [],
                "confirmed": False
            }

    def evaluate_detection_policy(self,
                                  opencv_motion_detected: bool,
                                  image: Optional[np.ndarray] = None) -> Dict[str, Any]:
        """
        Arbitre la décision finale d'alerte selon la politique configurée
        (OPENCV_ONLY, EDGE_AI_ASSISTED, EDGE_AI_REQUIRED).
        """
        # Mode 1 : OpenCV pur (comportement historique garanti)
        if self.mode == self.MODE_OPENCV_ONLY:
            return {
                "alert": opencv_motion_detected,
                "confirmed": opencv_motion_detected,
                "mode": self.MODE_OPENCV_ONLY,
                "edge_ai_status": self.status,
                "reason": "Décision basée sur OpenCV uniquement (Mode OPENCV_ONLY)."
            }

        # Pas de mouvement OpenCV détecté
        if not opencv_motion_detected:
            return {
                "alert": False,
                "confirmed": False,
                "mode": self.mode,
                "edge_ai_status": self.status,
                "reason": "Aucun mouvement OpenCV détecté."
            }

        # Mouvement OpenCV avéré : consultation d'Edge AI
        if not self.is_available():
            # Si le modèle est indisponible : Fallback sécurisé vers OpenCV
            return {
                "alert": True,
                "confirmed": False,
                "fallback": True,
                "mode": self.mode,
                "edge_ai_status": self.status,
                "reason": f"Mouvement OpenCV détecté (Edge AI indisponible: {self.status_detail}). Fallback actif."
            }

        detection_res = self.detect(image)
        has_target = detection_res.get("has_target_object", False)
        targets = detection_res.get("target_objects", [])

        # Mode 2 : EDGE_AI_ASSISTED (Le mouvement déclenche l'alarme, enrichi par la confirmation objet)
        if self.mode == self.MODE_ASSISTED:
            if has_target:
                reason = f"Mouvement OpenCV confirmé par Edge AI ({', '.join(targets)})."
            else:
                reason = "Mouvement OpenCV détecté (non confirmé par objet cible Edge AI)."
            return {
                "alert": True,
                "confirmed": has_target,
                "mode": self.MODE_ASSISTED,
                "edge_ai_status": self.status,
                "target_objects": targets,
                "detections": detection_res.get("detections", []),
                "reason": reason
            }

        # Mode 3 : EDGE_AI_REQUIRED (L'alarme n'est déclenchée QUE si un objet cible est formellement identifié)
        if self.mode == self.MODE_REQUIRED:
            if has_target:
                return {
                    "alert": True,
                    "confirmed": True,
                    "mode": self.MODE_REQUIRED,
                    "edge_ai_status": self.status,
                    "target_objects": targets,
                    "detections": detection_res.get("detections", []),
                    "reason": f"Mouvement et objet cible validés par Edge AI ({', '.join(targets)})."
                }
            else:
                return {
                    "alert": False,
                    "confirmed": False,
                    "mode": self.MODE_REQUIRED,
                    "edge_ai_status": self.status,
                    "detections": detection_res.get("detections", []),
                    "reason": "Mouvement OpenCV rejeté : aucun objet cible identifié par Edge AI (mode requis)."
                }

        # Cas par défaut : conservation de la décision OpenCV
        return {
            "alert": opencv_motion_detected,
            "confirmed": False,
            "mode": self.mode,
            "reason": "Politique par défaut appliquée."
        }

    def get_status(self) -> Dict[str, Any]:
        """Retourne l'état complet du composant pour les APIs et le Dashboard."""
        return {
            "enabled": self.enabled,
            "status": self.status,
            "status_detail": self.status_detail,
            "mode": self.mode,
            "model_path": self.model_path,
            "model_name": os.path.basename(self.model_path),
            "is_available": self.is_available(),
            "confidence_threshold": self.confidence_threshold,
            "iou_threshold": self.iou_threshold,
            "inference_interval": self.inference_interval,
            "target_classes": sorted(list(self.target_classes)),
            "inference_count": self.inference_count,
            "error_count": self.error_count,
            "last_inference_time": self.last_inference_time
        }
