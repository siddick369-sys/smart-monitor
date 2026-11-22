import cv2
import numpy as np
import threading
import time
from collections import deque
from typing import Dict, Optional, Tuple, List, Callable, Any
import config

class CameraWorker(threading.Thread):
    """Thread dédié à l'acquisition vidéo indépendante, avec backoff progressif et tampon circulaire."""

    def __init__(self, device_id: str, video_url: str, buffer_size: int = config.CIRCULAR_BUFFER_SIZE,
                 on_state_change: Optional[Callable[[str, str, str], None]] = None,
                 video_source: Optional[Any] = None):
        super().__init__(name=f"CameraWorker-{device_id}", daemon=True)
        self.device_id = device_id
        self.video_url = video_url
        self.buffer_size = buffer_size
        self.on_state_change = on_state_change
        self.video_source = video_source

        # Initialisation automatique de l'adaptateur RTSP FFmpeg pour les flux RTSP
        if self.video_source is None and isinstance(video_url, str) and video_url.startswith("rtsp://"):
            try:
                from monitoring.acquisition.ffmpeg_adapter import FFmpegRTSPAdapter
                from monitoring.acquisition.interfaces import CameraConnectionConfig, CameraProtocol
                cfg = CameraConnectionConfig(
                    source_id=device_id,
                    protocol=CameraProtocol.RTSP,
                    uri=video_url,
                    allow_loopback=getattr(config, "ALLOW_LOOPBACK_SIMULATOR", False)
                )
                self.video_source = FFmpegRTSPAdapter(cfg)
            except Exception as e:
                print(f"[CameraWorker-{device_id}] Info initialisation FFmpegRTSPAdapter : {e}")

        self._stop_event = threading.Event()
        self._lock = threading.Lock()
        
        self.status = "DÉCONNECTÉ"  # "CONNECTÉ", "DÉCONNECTÉ", "ERREUR DE CONNEXION"
        self.last_error = ""
        self.last_frame_time = 0.0
        self.reconnect_attempts = 0
        self.current_backoff = 1.0
        
        self.latest_frame: Optional[np.ndarray] = None
        self.circular_buffer: deque = deque(maxlen=buffer_size) # (timestamp, frame)

        # Générer une frame de substitution par défaut
        self._placeholder_frame = self._create_placeholder("INITIALISATION DU FLUX...", (120, 120, 120))

    def _set_status(self, new_status: str, error_msg: str = ""):
        old_status = self.status
        self.status = new_status
        self.last_error = error_msg
        if old_status != new_status and self.on_state_change:
            try:
                self.on_state_change(self.device_id, old_status, new_status)
            except Exception as e:
                print(f"[CameraWorker-{self.device_id}] Erreur callback état : {e}")

    def _create_placeholder(self, message: str, color=(0, 0, 255)) -> np.ndarray:
        """Génère une mire professionnelle stylisée lors de perte ou tentative de connexion."""
        img = np.zeros((480, 640, 3), dtype=np.uint8)
        # Quadrillage sobre haute technologie
        img[::40, :, :] = (20, 20, 24)
        img[:, ::40, :] = (20, 20, 24)
        
        # En-tête de surveillance
        cv2.putText(img, "SMART SECURITY MONITOR // CCTV HOST", (25, 45), cv2.FONT_HERSHEY_DUPLEX, 0.6, (0, 200, 255), 1)
        cv2.putText(img, f"SOURCE: {self.device_id} ({self.video_url})", (25, 75), cv2.FONT_HERSHEY_SIMPLEX, 0.45, (160, 160, 160), 1)
        
        # Message central encadré
        text_size = cv2.getTextSize(message, cv2.FONT_HERSHEY_SIMPLEX, 0.75, 2)[0]
        text_x = max(10, (640 - text_size[0]) // 2)
        text_y = 240
        cv2.rectangle(img, (text_x - 15, text_y - 30), (text_x + text_size[0] + 15, text_y + 15), (35, 35, 45), -1)
        cv2.rectangle(img, (text_x - 15, text_y - 30), (text_x + text_size[0] + 15, text_y + 15), color, 1)
        cv2.putText(img, message, (text_x, text_y), cv2.FONT_HERSHEY_SIMPLEX, 0.75, color, 2)
        
        # Horodatage et état
        ts_str = time.strftime("%Y-%m-%d %H:%M:%S")
        cv2.putText(img, f"HORODATAGE LOCAL: {ts_str}", (25, 435), cv2.FONT_HERSHEY_SIMPLEX, 0.45, (120, 120, 120), 1)
        status_txt = f"ETAT: {self.status} | TENTATIVES: {self.reconnect_attempts}"
        cv2.putText(img, status_txt, (25, 455), cv2.FONT_HERSHEY_SIMPLEX, 0.42, (100, 100, 100), 1)
        return img

    def run(self):
        if self.video_source is not None:
            self._run_video_source_loop()
            return

        from urllib.parse import urlparse
        while not self._stop_event.is_set():
            cap = None
            try:
                self.reconnect_attempts += 1

                # Validation anti-SSRF au point de connexion effectif
                if isinstance(self.video_url, str) and "://" in self.video_url:
                    parsed = urlparse(self.video_url)
                    if parsed.hostname:
                        port = parsed.port or (80 if parsed.scheme == "http" else 554)
                        ok_target, reason = config.is_allowed_camera_target(parsed.hostname, port)
                        if not ok_target:
                            self._set_status("ERREUR DE CONNEXION", f"SSRF bloqué : {reason}")
                            self._placeholder_frame = self._create_placeholder("CONNEXION BLOQUÉE (SSRF)", (0, 0, 255))
                            time.sleep(self.current_backoff)
                            continue

                cap = cv2.VideoCapture(self.video_url)
                cap.set(cv2.CAP_PROP_BUFFERSIZE, 1)

                if not cap.isOpened():
                    self._set_status("ERREUR DE CONNEXION", f"Impossible d'ouvrir le flux {self.video_url}")
                    self._placeholder_frame = self._create_placeholder(f"CONNEXION IMPOSSIBLE (REESSAI DANS {int(self.current_backoff)}S)", (0, 140, 255))
                    time.sleep(self.current_backoff)
                    self.current_backoff = min(self.current_backoff * 1.5, config.CAMERA_MAX_BACKOFF)
                    continue

                # Réinitialisation du backoff lors de l'établissement réussi
                self.current_backoff = 1.0
                self.reconnect_attempts = 0
                self._set_status("CONNECTÉ", "")

                while not self._stop_event.is_set():
                    ret, frame = cap.read()
                    now = time.time()
                    if not ret or frame is None:
                        self._set_status("ERREUR DE CONNEXION", "Perte de signal vidéo (frame vide)")
                        self._placeholder_frame = self._create_placeholder("SIGNAL PERDU - RECONNEXION EN COURS...", (0, 0, 255))
                        break

                    with self._lock:
                        self.latest_frame = frame
                        self.last_frame_time = now
                        self.circular_buffer.append((now, frame.copy()))
                        if self.status != "CONNECTÉ":
                            self._set_status("CONNECTÉ", "")

                    elapsed = time.time() - now
                    target_delay = 1.0 / config.CAMERA_FPS
                    if elapsed < target_delay:
                        time.sleep(target_delay - elapsed)

            except Exception as e:
                self._set_status("ERREUR DE CONNEXION", str(e))
                self._placeholder_frame = self._create_placeholder("ERREUR FLUX VIDEO", (0, 0, 255))
            finally:
                if cap is not None:
                    try:
                        cap.release()
                    except Exception:
                        pass
                
            if not self._stop_event.is_set():
                time.sleep(self.current_backoff)
                self.current_backoff = min(self.current_backoff * 1.5, config.CAMERA_MAX_BACKOFF)

    def _run_video_source_loop(self):
        """Boucle d'acquisition s'appuyant sur une source abstraite VideoSource."""
        self._set_status("CONNECTÉ", "")
        connected = self.video_source.connect()
        if not connected:
            self._set_status("ERREUR DE CONNEXION", "Échec de connexion VideoSource")
            self._placeholder_frame = self._create_placeholder("CONNEXION IMPOSSIBLE (NVR)", (0, 0, 255))

        while not self._stop_event.is_set():
            success, vframe, err = self.video_source.read_frame()
            now = time.time()
            if success and vframe is not None and not vframe.is_placeholder:
                with self._lock:
                    self.latest_frame = vframe.data
                    self.last_frame_time = vframe.timestamp_utc
                    self.circular_buffer.append((vframe.timestamp_utc, vframe.data.copy()))
                    if self.status != "CONNECTÉ":
                        self._set_status("CONNECTÉ", "")
            else:
                if vframe and vframe.is_placeholder:
                    self._placeholder_frame = vframe.data
                self._set_status("ERREUR DE CONNEXION", err or "Flux indisponible")

            target_delay = 1.0 / config.CAMERA_FPS
            time.sleep(target_delay)

        try:
            self.video_source.close()
        except Exception:
            pass

    def stop(self):
        self._stop_event.set()
        if self.video_source is not None:
            try:
                self.video_source.close()
            except Exception:
                pass

    def get_frame(self) -> np.ndarray:
        """Retourne la dernière frame reçue ou la mire de substitution si le flux est périmé."""
        with self._lock:
            now = time.time()
            if self.latest_frame is not None and (now - self.last_frame_time) < config.STALE_TELEMETRY_SECONDS:
                return self.latest_frame.copy()
            return self._placeholder_frame.copy()

    def get_recent_frames(self, seconds: float) -> List[Tuple[float, np.ndarray]]:
        """Extrait les frames du tampon circulaire correspondant aux N dernières secondes."""
        now = time.time()
        start_time = now - seconds
        with self._lock:
            return [(t, f.copy()) for (t, f) in self.circular_buffer if t >= start_time]


class CameraManager:
    """Gestionnaire centralisé des flux vidéo avec isolation complète entre caméras et incrustation des zones."""

    def __init__(self, on_state_change: Optional[Callable[[str, str, str], None]] = None,
                 zone_provider: Optional[Callable[[str], List[dict]]] = None):
        self._workers: Dict[str, CameraWorker] = {}
        self._lock = threading.RLock()
        self.on_state_change = on_state_change
        self.zone_provider = zone_provider

    def start_camera(self, device_id: str, video_url: str, video_source: Optional[Any] = None):
        with self._lock:
            self.stop_camera(device_id)
            worker = CameraWorker(device_id, video_url, on_state_change=self.on_state_change, video_source=video_source)
            self._workers[device_id] = worker
            worker.start()

    def stop_camera(self, device_id: str):
        with self._lock:
            if device_id in self._workers:
                worker = self._workers.pop(device_id)
                worker.stop()
                if worker.is_alive():
                    worker.join(timeout=1.0)

    def stop_all(self):
        with self._lock:
            for dev_id, worker in list(self._workers.items()):
                worker.stop()
            for dev_id, worker in list(self._workers.items()):
                if worker.is_alive():
                    worker.join(timeout=1.0)
            self._workers.clear()

    def get_status(self, device_id: str) -> dict:
        with self._lock:
            worker = self._workers.get(device_id)
            if not worker:
                return {"status": "DÉCONNECTÉ", "error": "Non démarré", "last_frame_age": None, "last_frame_time": None}
            
            now = time.time()
            age = round(now - worker.last_frame_time, 1) if worker.last_frame_time else None
            status = worker.status
            if status == "CONNECTÉ" and age is not None and age > config.STALE_TELEMETRY_SECONDS:
                status = "DÉGRADÉ"

            return {
                "status": status,
                "error": worker.last_error,
                "last_frame_age": age,
                "last_frame_time": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(worker.last_frame_time)) if worker.last_frame_time else None,
                "reconnect_attempts": worker.reconnect_attempts
            }

    def get_frame(self, device_id: str) -> np.ndarray:
        with self._lock:
            worker = self._workers.get(device_id)
            if worker:
                return worker.get_frame()
            img = np.zeros((480, 640, 3), dtype=np.uint8)
            cv2.putText(img, "APPAREIL INCONNU", (180, 240), cv2.FONT_HERSHEY_SIMPLEX, 0.8, (0, 0, 255), 2)
            return img

    def get_recent_frames(self, device_id: str, seconds: float) -> List[Tuple[float, np.ndarray]]:
        with self._lock:
            worker = self._workers.get(device_id)
            if worker:
                return worker.get_recent_frames(seconds)
            return []

    def generate_mjpeg_stream(self, device_id: str):
        """Générateur de flux MJPEG multipart pour Flask avec incrustation des zones configurées."""
        while True:
            frame = self.get_frame(device_id)
            display_frame = frame.copy()

            # Incrustation visuelle des zones de surveillance si disponibles
            if self.zone_provider:
                try:
                    zones = self.zone_provider(device_id) or []
                    h, w = display_frame.shape[:2]
                    for z in zones:
                        zx = max(0.0, min(1.0, float(z.get("x", 0.0))))
                        zy = max(0.0, min(1.0, float(z.get("y", 0.0))))
                        zw = max(0.01, min(1.0 - zx, float(z.get("w", 1.0))))
                        zh = max(0.01, min(1.0 - zy, float(z.get("h", 1.0))))

                        x1 = int(zx * w)
                        y1 = int(zy * h)
                        x2 = int((zx + zw) * w)
                        y2 = int((zy + zh) * h)

                        is_active = bool(z.get("enabled", True))
                        color = (0, 220, 0) if is_active else (120, 120, 120)
                        label = f"[{'ACTIF' if is_active else 'OFF'}] {z.get('name', 'Zone')}"
                        
                        cv2.rectangle(display_frame, (x1, y1), (x2, y2), color, 2 if is_active else 1)
                        # Étiquette de la zone
                        text_sz = cv2.getTextSize(label, cv2.FONT_HERSHEY_SIMPLEX, 0.45, 1)[0]
                        lbl_y1 = max(0, y1 - text_sz[1] - 8)
                        cv2.rectangle(display_frame, (x1, lbl_y1), (x1 + text_sz[0] + 8, y1), color, -1)
                        cv2.putText(display_frame, label, (x1 + 4, y1 - 4), cv2.FONT_HERSHEY_SIMPLEX, 0.45, (0, 0, 0) if is_active else (255, 255, 255), 1)
                except Exception:
                    pass

            ret, jpeg = cv2.imencode('.jpg', display_frame, [int(cv2.IMWRITE_JPEG_QUALITY), 70])
            if ret:
                frame_bytes = jpeg.tobytes()
                yield (b'--frame\r\n'
                       b'Content-Type: image/jpeg\r\n\r\n' + frame_bytes + b'\r\n')
            time.sleep(1.0 / config.CAMERA_FPS)
