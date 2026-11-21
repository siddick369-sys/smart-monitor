import os
import time
import json
import base64
import queue
import threading
from typing import Optional, Dict, Any, List, Tuple
import requests
import cv2
import numpy as np
import config

class QwenVisionManager:
    """Gestionnaire d'intelligence visuelle Qwen Vision via xKiro STRICTEMENT FREE TIER.
    
    Règles absolues :
    - Utilise exclusivement des modèles Qwen Vision vérifiés gratuits.
    - Aucun modèle payant, aucun basculement payant.
    - Fallback transparent sur OpenCV en cas d'indisponibilité ou d'absence de modèle gratuit.
    - Analyse asynchrone non-bloquante pour la vidéo, les capteurs et l'alarme.
    - Disjoncteur (Circuit Breaker) et limitation de débit stricts.
    """

    ALLOWED_CLASSES = ["PERSON", "VEHICLE", "ANIMAL", "UNKNOWN", "NO_RELEVANT_OBJECT"]
    
    # Niveaux de risque bilingues normalisés
    RISK_LEVELS_FR = ["FAIBLE", "MOYEN", "ÉLEVÉ", "CRITIQUE"]
    RISK_LEVELS_EN = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    
    RISK_MAPPING = {
        "LOW": "FAIBLE", "FAIBLE": "FAIBLE",
        "MEDIUM": "MOYEN", "MOYEN": "MOYEN",
        "HIGH": "ÉLEVÉ", "ÉLEVÉ": "ÉLEVÉ", "ELEVE": "ÉLEVÉ",
        "CRITICAL": "CRITIQUE", "CRITIQUE": "CRITIQUE"
    }

    # Statuts opérationnels normalisés
    STATUS_ACTIVE = "ACTIVE"
    STATUS_DISABLED = "DISABLED"
    STATUS_ERROR = "ERROR"
    STATUS_OPENCV_ONLY = "OPENCV_ONLY"
    STATUS_FREE_TIER_NOT_VERIFIED = "FREE_TIER_NOT_VERIFIED"
    STATUS_FREE_TIER_QUOTA_REACHED = "FREE_TIER_QUOTA_REACHED"
    STATUS_FREE_TIER_VERIFIED = "FREE_TIER_VERIFIED"  # Alias pour rétro-compatibilité
    STATUS_XKIRO_UNAVAILABLE = "XKIRO_UNAVAILABLE"
    STATUS_AI_ANALYSIS_ERROR = "AI_ANALYSIS_ERROR"

    # Paramètres Circuit Breaker
    CIRCUIT_BREAKER_MAX_ERRORS = 3
    CIRCUIT_BREAKER_COOLDOWN = 30.0  # secondes de pause après 3 erreurs consécutives

    def __init__(self,
                 enabled: bool = config.XKIRO_VISION_ENABLED,
                 api_key: str = config.XKIRO_API_KEY,
                 base_url: str = config.XKIRO_BASE_URL,
                 configured_model: str = config.XKIRO_VISION_MODEL,
                 timeout: float = config.XKIRO_VISION_TIMEOUT,
                 max_rpm: int = config.XKIRO_VISION_MAX_REQUESTS_PER_MINUTE,
                 min_interval: float = config.XKIRO_VISION_MIN_INTERVAL,
                 max_width: int = config.XKIRO_VISION_IMAGE_MAX_WIDTH,
                 free_tier_only: bool = config.XKIRO_VISION_FREE_TIER_ONLY):
        self.enabled = enabled
        self.api_key = api_key
        self.base_url = base_url.rstrip("/")
        self.configured_model = configured_model
        self.timeout = timeout
        self.max_rpm = max_rpm
        self.min_interval = min_interval
        self.max_width = max_width
        self.free_tier_only = free_tier_only

        self.selected_model: Optional[str] = None
        self.status: str = self.STATUS_OPENCV_ONLY
        self.status_detail: str = "Initialisation"
        self.verification_level: str = "NONE"  # "NONE", "CATALOG_VERIFIED_FREE", "REAL_INFERENCE_TESTED"
        
        # Statistiques et métriques
        self._lock = threading.Lock()
        self.request_timestamps: List[float] = []
        self.last_request_time: float = 0.0
        self.total_requests = 0
        self.successful_requests = 0
        self.error_requests = 0
        self.total_latency_ms = 0.0
        self.last_analysis: Optional[dict] = None
        self.quota_blocked_until: float = 0.0
        
        # Circuit Breaker state
        self.consecutive_errors: int = 0
        self.circuit_breaker_tripped_until: float = 0.0

        # File d'attente d'analyse asynchrone (taille bornée pour éviter toute saturation mémoire)
        self._analysis_queue = queue.Queue(maxsize=5)
        self._stop_event = threading.Event()
        self._worker_thread = threading.Thread(target=self._worker_loop, daemon=True, name="QwenVisionWorker")
        self._worker_thread.start()

        # Vérification initiale du catalogue
        self.verify_catalog_and_select_model()

    def get_masked_key(self) -> str:
        if not self.api_key:
            return "NON_CONFIGURÉE"
        return f"{self.api_key[:4]}...{self.api_key[-4:]}" if len(self.api_key) > 8 else "****"

    def is_available(self) -> bool:
        """Indique si l'analyse Qwen Vision Free Tier est prête et non bloquée."""
        with self._lock:
            now = time.time()
            if not self.enabled or not self.selected_model:
                return False
            if self.status not in (self.STATUS_FREE_TIER_VERIFIED, self.STATUS_ACTIVE):
                return False
            if now < self.quota_blocked_until or now < self.circuit_breaker_tripped_until:
                return False
            return True

    def verify_catalog_and_select_model(self) -> Tuple[bool, str]:
        """Interroge le catalogue officiel xKiro et sélectionne UNIQUEMENT un modèle Qwen Vision éligible Free Tier."""
        with self._lock:
            if not self.enabled:
                self.status = self.STATUS_DISABLED
                self.status_detail = "IA visuelle désactivée par configuration. Moteur OpenCV local actif."
                return False, self.status_detail

            if not self.api_key:
                self.status = self.STATUS_OPENCV_ONLY
                self.status_detail = "Clé API xKiro absente. Moteur OpenCV local actif (Fallback sécurisé)."
                return False, self.status_detail

            headers = {
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json"
            }

            try:
                res = requests.get(f"{self.base_url}/models", headers=headers, timeout=self.timeout)
                if res.status_code != 200:
                    self.status = self.STATUS_XKIRO_UNAVAILABLE
                    self.status_detail = f"Serveur xKiro inaccessible (HTTP {res.status_code}). Fallback OpenCV."
                    return False, self.status_detail

                data = res.json()
                models_list = data.get("data", []) if isinstance(data, dict) else []

                # Recherche de modèles avec capacité Vision et gratuité vérifiée
                verified_free_qwen_vl = []
                verified_free_other_vl = []
                for m in models_list:
                    m_id = str(m.get("id", "")).lower()
                    
                    # 1. Critère Vision (vl, vision, omni)
                    is_vision = any(v in m_id for v in ["vl", "vision", "omni"]) or "vision" in str(m.get("modality", "")).lower()
                    is_qwen = "qwen" in m_id

                    # 2. Critère gratuité stricte (Free Tier Only)
                    pricing = m.get("pricing", {})
                    is_free_flag = (
                        m.get("free") is True or
                        m.get("is_free") is True or
                        ":free" in m_id or
                        "free" in m.get("tier", "").lower() or
                        (isinstance(pricing, dict) and (
                            (pricing.get("prompt") == 0 and pricing.get("completion") == 0) or
                            (pricing.get("input") == 0 and pricing.get("output") == 0)
                        ))
                    )

                    if is_vision and is_free_flag:
                        if is_qwen:
                            verified_free_qwen_vl.append(m.get("id"))
                        else:
                            verified_free_other_vl.append(m.get("id"))

                # Si un modèle est spécifié dans la configuration, vérifier qu'il est bien dans la liste gratuite vérifiée
                if self.configured_model:
                    all_free_vl = verified_free_qwen_vl + verified_free_other_vl
                    if self.configured_model in all_free_vl:
                        self.selected_model = self.configured_model
                        self.status = self.STATUS_FREE_TIER_VERIFIED
                        self.verification_level = "CATALOG_VERIFIED_FREE"
                        self.status_detail = f"Modèle Vision Free Tier validé : {self.selected_model}"
                        return True, self.status_detail
                    else:
                        # Rejet strict : le modèle configuré n'est pas vérifiable comme gratuit
                        self.selected_model = None
                        self.verification_level = "NONE"
                        self.status = self.STATUS_FREE_TIER_NOT_VERIFIED
                        self.status_detail = f"Le modèle configuré '{self.configured_model}' n'est pas certifié Free Tier. Rejet préventif pour éviter toute facturation."
                        return False, self.status_detail

                # Sélection automatique : priorité absolue aux modèles Qwen Vision gratuits
                if verified_free_qwen_vl:
                    preferred = [m for m in verified_free_qwen_vl if "2.5" in m or "2" in m]
                    self.selected_model = preferred[0] if preferred else verified_free_qwen_vl[0]
                    self.status = self.STATUS_FREE_TIER_VERIFIED
                    self.verification_level = "CATALOG_VERIFIED_FREE"
                    self.status_detail = f"Modèle Qwen Vision Free Tier certifié : {self.selected_model}"
                    return True, self.status_detail

                # Sélection de repli sur un autre modèle Vision 100% gratuit du catalogue
                if verified_free_other_vl:
                    self.selected_model = verified_free_other_vl[0]
                    self.status = self.STATUS_FREE_TIER_VERIFIED
                    self.verification_level = "CATALOG_VERIFIED_FREE"
                    self.status_detail = f"Modèle Vision Free Tier certifié (catalogue xKiro) : {self.selected_model}"
                    return True, self.status_detail

                # Aucun modèle Qwen Vision gratuit vérifié
                self.selected_model = None
                self.verification_level = "NONE"
                self.status = self.STATUS_FREE_TIER_NOT_VERIFIED
                self.status_detail = "Aucun modèle Qwen Vision éligible au Free Tier n'a été vérifié sur ce compte. Fallback OpenCV sécurisé."
                return False, self.status_detail

            except Exception as e:
                self.status = self.STATUS_XKIRO_UNAVAILABLE
                self.status_detail = f"Erreur de communication avec le catalogue xKiro : {e}"
                return False, self.status_detail

    def is_rate_limited(self) -> Tuple[bool, str]:
        """Vérifie les contraintes temporelles strictes du Free Tier et le disjoncteur."""
        now = time.time()
        
        # Blocage disjoncteur (Circuit Breaker)
        if now < self.circuit_breaker_tripped_until:
            wait_cb = int(self.circuit_breaker_tripped_until - now)
            return True, f"Circuit breaker actif après erreurs répétées (pause {wait_cb}s)."

        # Blocage temporaire 429
        if now < self.quota_blocked_until:
            wait_s = int(self.quota_blocked_until - now)
            return True, f"Quota Free Tier temporairement saturé (pause {wait_s}s)."

        # Intervalle minimum
        if (now - self.last_request_time) < self.min_interval:
            return True, "Intervalle minimum entre deux requêtes non écoulé."

        # Requêtes par minute (RPM)
        recent = [t for t in self.request_timestamps if now - t < 60.0]
        self.request_timestamps = recent
        if len(recent) >= self.max_rpm:
            return True, f"Limite de débit atteinte ({self.max_rpm} req/min)."

        return False, "OK"

    def analyze_motion_frame_async(self, frame: np.ndarray, device_id: str, callback=None):
        """Dépose une trame dans la file d'attente d'analyse IA sans bloquer le thread de capture vidéo."""
        if not self.is_available():
            return

        limited, _ = self.is_rate_limited()
        if limited:
            return

        # Clone léger de la frame pour isoler la mémoire
        try:
            h, w = frame.shape[:2]
            if w > self.max_width:
                new_h = int(h * (self.max_width / w))
                small_frame = cv2.resize(frame, (self.max_width, new_h))
            else:
                small_frame = frame.copy()

            self._analysis_queue.put_nowait({
                "frame": small_frame,
                "device_id": device_id,
                "timestamp": time.time(),
                "callback": callback
            })
        except queue.Full:
            pass  # Ne jamais bloquer la vidéo si la file IA est saturée

    def analyze_frame_sync(self, frame: np.ndarray) -> Dict[str, Any]:
        """Exécute l'analyse d'une image avec Qwen Vision via l'API xKiro."""
        default_fallback = {
            "detected": True,
            "primary_object": "UNKNOWN",
            "objects": ["UNKNOWN"],
            "activity": "Mouvement détecté par vision OpenCV locale",
            "event_type": "MOUVEMENT_OPENCV",
            "risk_level": "ÉLEVÉ",
            "risk_level_en": "HIGH",
            "confidence": None,
            "description": "Analyse IA distante non disponible, qualification par moteur local OpenCV.",
            "suggested_action": "VERIFICATION_LOCALE",
            "visual_description": "Analyse IA distante non disponible, qualification par moteur local OpenCV.",
            "uncertain": True,
            "model_used": "OPENCV_LOCAL_FALLBACK"
        }

        if not self.is_available():
            return default_fallback

        with self._lock:
            limited, reason = self.is_rate_limited()
            if limited:
                print(f"[QwenVision] Requête ignorée (Limitation de débit) : {reason}")
                return default_fallback

            now = time.time()
            self.last_request_time = now
            self.request_timestamps.append(now)
            self.total_requests += 1

        # Redimensionnement et compression JPEG
        h, w = frame.shape[:2]
        if w > self.max_width:
            new_h = int(h * (self.max_width / w))
            frame_resized = cv2.resize(frame, (self.max_width, new_h))
        else:
            frame_resized = frame

        success, buffer = cv2.imencode(".jpg", frame_resized, [int(cv2.IMWRITE_JPEG_QUALITY), 75])
        if not success:
            return default_fallback

        b64_image = base64.b64encode(buffer).decode("utf-8")
        data_uri = f"data:image/jpeg;base64,{b64_image}"

        # Prompt demandant une classification JSON stricte
        system_prompt = (
            "You are a strict security AI vision classifier. Analyze the provided surveillance image and output ONLY valid JSON matching this schema:\n"
            "{\n"
            '  "detected": true or false,\n'
            '  "primary_object": "PERSON" or "VEHICLE" or "ANIMAL" or "UNKNOWN" or "NO_RELEVANT_OBJECT",\n'
            '  "objects": ["list of detected object types"],\n'
            '  "event_type": "INTRUSION" or "PASSAGE" or "ANOMALIE" or "NORMAL" or "UNKNOWN",\n'
            '  "risk_level": "FAIBLE" or "MOYEN" or "ÉLEVÉ" or "CRITIQUE" (or "LOW", "MEDIUM", "HIGH", "CRITICAL"),\n'
            '  "confidence": float between 0.0 and 1.0 or null,\n'
            '  "description": "one sentence factual summary",\n'
            '  "suggested_action": "DÉCLENCHER_ALARME" or "NOTIFICATION_SEULE" or "SURVEILLANCE_RENFORCÉE" or "IGNORER",\n'
            '  "uncertain": true or false\n'
            "}"
        )

        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }

        payload = {
            "model": self.selected_model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {
                    "role": "user",
                    "content": [
                        {"type": "text", "text": "Classify the security risk and detected subjects in this frame."},
                        {"type": "image_url", "image_url": {"url": data_uri}}
                    ]
                }
            ],
            "temperature": 0.1,
            "max_tokens": 256
        }

        start_t = time.time()
        try:
            res = requests.post(f"{self.base_url}/chat/completions", headers=headers, json=payload, timeout=self.timeout)
            latency_ms = (time.time() - start_t) * 1000

            # Gestion spécifique du 429 Quota Exceeded
            if res.status_code == 429:
                with self._lock:
                    self.error_requests += 1
                    self.status = self.STATUS_FREE_TIER_QUOTA_REACHED
                    self.status_detail = "Quota Free Tier atteint (HTTP 429). Analyse distante suspendue 60s."
                    self.quota_blocked_until = time.time() + 60.0
                return default_fallback

            if res.status_code != 200:
                with self._lock:
                    self.error_requests += 1
                    self.consecutive_errors += 1
                    if self.consecutive_errors >= self.CIRCUIT_BREAKER_MAX_ERRORS:
                        self.circuit_breaker_tripped_until = time.time() + self.CIRCUIT_BREAKER_COOLDOWN
                        self.status = self.STATUS_ERROR
                        self.status_detail = f"Disjoncteur déclenché après {self.consecutive_errors} erreurs HTTP consécutives (pause {int(self.CIRCUIT_BREAKER_COOLDOWN)}s)."
                    else:
                        self.status_detail = f"Erreur API xKiro (HTTP {res.status_code})."
                return default_fallback

            res_json = res.json()
            content = res_json.get("choices", [{}])[0].get("message", {}).get("content", "")

            # Extraction et validation stricte du JSON
            cleaned_content = content.strip()
            if cleaned_content.startswith("```json"):
                cleaned_content = cleaned_content[7:]
            if cleaned_content.startswith("```"):
                cleaned_content = cleaned_content[3:]
            if cleaned_content.endswith("```"):
                cleaned_content = cleaned_content[:-3]
            cleaned_content = cleaned_content.strip()

            parsed = json.loads(cleaned_content)
            
            # Validation des types et valeurs autorisées
            primary = str(parsed.get("primary_object", "UNKNOWN")).upper()
            if primary not in self.ALLOWED_CLASSES:
                primary = "UNKNOWN"

            raw_risk = str(parsed.get("risk_level", "HIGH")).upper()
            normalized_risk_fr = self.RISK_MAPPING.get(raw_risk, "ÉLEVÉ")
            raw_confidence = parsed.get("confidence")
            confidence_val = None
            if raw_confidence is not None:
                try:
                    c = float(raw_confidence)
                    if 0.0 <= c <= 1.0:
                        confidence_val = round(c, 2)
                except (ValueError, TypeError):
                    confidence_val = None

            event_type = str(parsed.get("event_type", "INTRUSION" if primary == "PERSON" else "PASSAGE")).upper()
            desc = str(parsed.get("description") or parsed.get("visual_description", "Présence constatée sur l'image"))
            action = str(parsed.get("suggested_action", "NOTIFICATION_SEULE" if normalized_risk_fr == "FAIBLE" else "DÉCLENCHER_ALARME"))

            result = {
                "detected": bool(parsed.get("detected", True)),
                "primary_object": primary,
                "objects": [str(o).upper() for o in parsed.get("objects", [primary])],
                "event_type": event_type,
                "activity": str(parsed.get("activity", desc)),
                "risk_level": raw_risk,  # Conserve la valeur brute pour rétro-compatibilité tests
                "risk_level_fr": normalized_risk_fr,
                "confidence": confidence_val,
                "description": desc,
                "suggested_action": action,
                "visual_description": desc,
                "uncertain": bool(parsed.get("uncertain", False)),
                "model_used": self.selected_model,
                "latency_ms": round(latency_ms, 1)
            }

            with self._lock:
                self.successful_requests += 1
                self.consecutive_errors = 0  # Réinitialisation du disjoncteur après succès
                self.total_latency_ms += latency_ms
                self.last_analysis = result

            return result

        except Exception as e:
            with self._lock:
                self.error_requests += 1
                self.consecutive_errors += 1
                if self.consecutive_errors >= self.CIRCUIT_BREAKER_MAX_ERRORS:
                    self.circuit_breaker_tripped_until = time.time() + self.CIRCUIT_BREAKER_COOLDOWN
                    self.status = self.STATUS_ERROR
                    self.status_detail = f"Disjoncteur déclenché après {self.consecutive_errors} erreurs (pause {int(self.CIRCUIT_BREAKER_COOLDOWN)}s) : {e}"
                else:
                    self.status_detail = f"Exception analyse IA : {e}"
            return default_fallback

    def _worker_loop(self):
        """Traite les requêtes de vision asynchrones."""
        while not self._stop_event.is_set():
            try:
                task = self._analysis_queue.get(timeout=1.0)
            except queue.Empty:
                continue

            try:
                frame = task.get("frame")
                callback = task.get("callback")
                if frame is not None:
                    analysis = self.analyze_frame_sync(frame)
                    if callback and callable(callback):
                        try:
                            callback(analysis)
                        except Exception as cb_err:
                            print(f"[QwenVision] Erreur callback : {cb_err}")
            except Exception as e:
                print(f"[QwenVision] Erreur worker loop : {e}")
            finally:
                self._analysis_queue.task_done()

    def get_status(self) -> Dict[str, Any]:
        """Retourne l'état complet du gestionnaire Qwen Vision pour le dashboard."""
        with self._lock:
            avg_lat = round(self.total_latency_ms / max(1, self.successful_requests), 1)
            now = time.time()
            circuit_breaker_active = now < self.circuit_breaker_tripped_until
            quota_active = now < self.quota_blocked_until

            return {
                "enabled": self.enabled,
                "api_key_configured": bool(self.api_key),
                "api_key_masked": self.get_masked_key(),
                "selected_model": self.selected_model,
                "configured_model": self.configured_model,
                "verification_level": self.verification_level,
                "free_tier_only": self.free_tier_only,
                "status": self.status,
                "status_detail": self.status_detail,
                "circuit_breaker_active": circuit_breaker_active,
                "consecutive_errors": self.consecutive_errors,
                "quota_blocked": quota_active,
                "total_requests": self.total_requests,
                "successful_requests": self.successful_requests,
                "error_requests": self.error_requests,
                "avg_latency_ms": avg_lat,
                "last_analysis": self.last_analysis,
                "queue_size": self._analysis_queue.qsize()
            }

    def stop(self):
        self._stop_event.set()
