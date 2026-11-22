"""
Adaptateur de flux vidéo RTSP supervisé basé sur FFmpeg.
Architecture NVR universelle PRO-13.
"""

import os
import sys
import time
import shutil
import atexit
import signal
import logging
import threading
import subprocess
from collections import deque
from typing import Optional, Tuple, List, Dict, Any
import numpy as np
import cv2

from monitoring.acquisition.interfaces import (
    VideoSource, VideoFrame, VideoSourceHealth, VideoSourceMetadata,
    CameraProtocol, VideoSourceStatus, CameraConnectionConfig,
    SSRFBlockedError, ConnectionTimeoutError, StreamStalledError, CodecError
)
from monitoring.acquisition.security import validate_video_target, sanitize_uri

logger = logging.getLogger("SmartSecurityMonitor.NVR.FFmpeg")


class FFmpegRTSPAdapter(VideoSource):
    """Adaptateur RTSP robuste supervisant un sous-processus FFmpeg indépendant."""

    def __init__(self, config_obj: CameraConnectionConfig, ffmpeg_bin: Optional[str] = None):
        self.config = config_obj
        self.source_id = config_obj.source_id
        self.uri = config_obj.uri
        self.sanitized_uri = sanitize_uri(self.uri)
        self.ffmpeg_bin = ffmpeg_bin or getattr(self.config, "custom_params", {}).get("ffmpeg_path", "ffmpeg")

        self._width = config_obj.target_width
        self._height = config_obj.target_height
        self._target_fps = max(1, config_obj.target_fps)
        self._frame_bytes = self._width * self._height * 3

        # État et synchronisation
        self._status = VideoSourceStatus.DISCONNECTED
        self._is_connected = False
        self._lock = threading.RLock()
        self._stop_event = threading.Event()
        self._worker_thread: Optional[threading.Thread] = None
        self._process: Optional[subprocess.Popen] = None

        # Télémétrie de santé
        self._latest_frame: Optional[VideoFrame] = None
        self._frame_sequence = 0
        self._fps_measured = 0.0
        self._dropped_frames = 0
        self._reconnect_count = 0
        self._last_error = ""
        self._connect_time = 0.0
        self._last_frame_time = 0.0
        self._consecutive_read_failures = 0
        self._current_backoff = 1.0

        # Détection de disponibilité du binaire FFmpeg
        self._has_ffmpeg_binary = bool(shutil.which(self.ffmpeg_bin))

        # Enregistrement pour nettoyage d'urgence à l'arrêt du programme (anti-processus orphelins)
        atexit.register(self.close)

    def is_healthy(self) -> bool:
        with self._lock:
            now = time.time()
            is_recent = (now - self._last_frame_time) <= (self.config.read_timeout * 1.5)
            return self._is_connected and is_recent and self._status == VideoSourceStatus.CONNECTED

    def get_health(self) -> VideoSourceHealth:
        with self._lock:
            now = time.time()
            uptime = (now - self._connect_time) if self._is_connected else 0.0
            latency = (now - self._last_frame_time) * 1000.0 if (self._last_frame_time > 0) else 0.0
            return VideoSourceHealth(
                status=self._status,
                is_connected=self._is_connected,
                fps_measured=round(self._fps_measured, 2),
                dropped_frames=self._dropped_frames,
                reconnect_count=self._reconnect_count,
                latency_ms=round(latency, 1),
                last_error=self._last_error,
                uptime_seconds=round(uptime, 1),
                consecutive_read_failures=self._consecutive_read_failures
            )

    def get_metadata(self) -> VideoSourceMetadata:
        with self._lock:
            return VideoSourceMetadata(
                source_id=self.source_id,
                protocol=CameraProtocol.RTSP,
                sanitized_uri=self.sanitized_uri,
                codec="H.264/RAW",
                width=self._width,
                height=self._height,
                nominal_fps=float(self._target_fps),
                manufacturer="ONVIF/RTSP Compatible",
                model="Universal RTSP Stream",
                firmware="N/A"
            )

    def connect(self) -> bool:
        """Démarre le thread de supervision et la connexion au flux."""
        with self._lock:
            if self._worker_thread and self._worker_thread.is_alive():
                return True

            # 1. Validation Anti-SSRF stricte avant toute tentative de socket
            valid, reason, resolved_ip = validate_video_target(
                self.uri,
                allow_loopback=self.config.allow_loopback
            )
            if not valid:
                self._status = VideoSourceStatus.BLOCKED_SSRF
                self._last_error = f"SSRF bloqué : {reason}"
                logger.warning(f"[{self.source_id}] Connexion refusée par la sécurité anti-SSRF ({self.sanitized_uri}) : {reason}")
                return False

            self._stop_event.clear()
            self._worker_thread = threading.Thread(
                target=self._supervision_loop,
                name=f"FFmpegWorker-{self.source_id}",
                daemon=True
            )
            self._worker_thread.start()
            return True

    def _build_ffmpeg_cmd(self) -> List[str]:
        """Construit les arguments structurés pour exécuter FFmpeg sans injection shell."""
        timeout_us = int(self.config.connect_timeout * 1_000_000)
        cmd = [
            self.ffmpeg_bin,
            "-hide_banner",
            "-loglevel", "error",
            "-nostdin",
            "-rtsp_transport", "tcp",
            "-stimeout", str(timeout_us),
            "-i", self.uri,
            "-an",
            "-sn",
            "-vf", f"scale={self._width}:{self._height}",
            "-r", str(self._target_fps),
            "-f", "rawvideo",
            "-pix_fmt", "bgr24",
            "pipe:1"
        ]
        return cmd

    def _supervision_loop(self):
        """Boucle de supervision continue avec redémarrage contrôlé et backoff exponentiel."""
        while not self._stop_event.is_set():
            try:
                # Si le binaire FFmpeg n'est pas disponible sur le système hôte
                if not self._has_ffmpeg_binary:
                    # Repli gracieux via VideoCapture OpenCV avec transport RTSP
                    self._run_cv2_fallback_loop()
                else:
                    self._run_ffmpeg_subprocess_loop()
            except Exception as e:
                self._last_error = f"Exception supervision : {str(e)}"
                logger.error(f"[{self.source_id}] Erreur supervision FFmpeg : {e}")

            if self._stop_event.is_set():
                break

            # Application du backoff exponentiel avant reconnexion
            self._reconnect_count += 1
            self._status = VideoSourceStatus.CONNECTING
            logger.info(f"[{self.source_id}] Tentative de reconnexion dans {self._current_backoff:.1f}s...")
            self._stop_event.wait(self._current_backoff)
            self._current_backoff = min(self._current_backoff * 1.5, self.config.max_backoff)

        self._cleanup_process()
        self._status = VideoSourceStatus.CLOSED

    def _run_ffmpeg_subprocess_loop(self):
        """Lance et supervise le sous-processus FFmpeg structuré."""
        cmd = self._build_ffmpeg_cmd()
        self._status = VideoSourceStatus.CONNECTING

        try:
            # Création du sous-processus sans shell (shell=False impératif contre l'injection de commandes)
            self._process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                stdin=subprocess.DEVNULL,
                bufsize=self._frame_bytes * 2,
                shell=False
            )
        except FileNotFoundError:
            self._has_ffmpeg_binary = False
            self._last_error = "Binaire FFmpeg introuvable sur le système hôte."
            return
        except Exception as e:
            self._last_error = f"Impossible de lancer FFmpeg : {e}"
            return

        self._status = VideoSourceStatus.CONNECTED
        self._is_connected = True
        self._connect_time = time.time()
        self._current_backoff = 1.0  # Réinitialisation du backoff lors du succès

        fps_timer = time.time()
        frame_counter = 0

        # Lecture continue depuis stdout
        while not self._stop_event.is_set():
            if self._process.poll() is not None:
                # Le sous-processus s'est terminé inopinément
                rc = self._process.returncode
                err_bytes = self._process.stderr.read() if self._process.stderr else b""
                err_msg = err_bytes.decode('utf-8', errors='ignore').strip()
                self._last_error = f"FFmpeg terminé (code {rc}) : {err_msg[:200]}"
                break

            # Lecture exacte d'une trame BGR24 brute
            try:
                raw_frame = self._process.stdout.read(self._frame_bytes)
            except Exception as e:
                self._last_error = f"Erreur lecture pipe stdout : {e}"
                break

            if not raw_frame or len(raw_frame) != self._frame_bytes:
                # Fin de flux ou trame tronquée
                self._consecutive_read_failures += 1
                if self._consecutive_read_failures > 5:
                    self._status = VideoSourceStatus.STALLED
                    self._last_error = "Flux vidéo interrompu ou trames incomplètes."
                    break
                time.sleep(0.05)
                continue

            now = time.time()
            self._consecutive_read_failures = 0
            self._last_frame_time = now
            self._frame_sequence += 1

            # Conversion du buffer brut en tableau NumPy
            img = np.frombuffer(raw_frame, dtype=np.uint8).reshape((self._height, self._width, 3))

            frame_obj = VideoFrame(
                data=img,
                timestamp_utc=now,
                sequence_num=self._frame_sequence,
                width=self._width,
                height=self._height,
                channels=3,
                is_placeholder=False
            )

            with self._lock:
                self._latest_frame = frame_obj

            frame_counter += 1
            if now - fps_timer >= 1.0:
                self._fps_measured = frame_counter / (now - fps_timer)
                frame_counter = 0
                fps_timer = now

        self._cleanup_process()

    def _run_cv2_fallback_loop(self):
        """Mode de repli utilisant le décodeur FFmpeg interne d'OpenCV si le binaire FFmpeg CLI est absent."""
        self._status = VideoSourceStatus.CONNECTING
        cap = cv2.VideoCapture(self.uri)
        cap.set(cv2.CAP_PROP_BUFFERSIZE, 1)

        if not cap.isOpened():
            self._status = VideoSourceStatus.ERROR
            self._last_error = f"Impossible d'ouvrir le flux RTSP ({self.sanitized_uri})"
            cap.release()
            return

        self._status = VideoSourceStatus.CONNECTED
        self._is_connected = True
        self._connect_time = time.time()
        self._current_backoff = 1.0

        fps_timer = time.time()
        frame_counter = 0

        while not self._stop_event.is_set():
            ret, frame = cap.read()
            if not ret or frame is None:
                self._consecutive_read_failures += 1
                if self._consecutive_read_failures > 10:
                    self._status = VideoSourceStatus.STALLED
                    self._last_error = "Perte de signal vidéo RTSP."
                    break
                time.sleep(0.05)
                continue

            now = time.time()
            self._consecutive_read_failures = 0
            self._last_frame_time = now
            self._frame_sequence += 1

            if frame.shape[0] != self._height or frame.shape[1] != self._width:
                frame = cv2.resize(frame, (self._width, self._height))

            frame_obj = VideoFrame(
                data=frame,
                timestamp_utc=now,
                sequence_num=self._frame_sequence,
                width=self._width,
                height=self._height,
                channels=3,
                is_placeholder=False
            )

            with self._lock:
                self._latest_frame = frame_obj

            frame_counter += 1
            if now - fps_timer >= 1.0:
                self._fps_measured = frame_counter / (now - fps_timer)
                frame_counter = 0
                fps_timer = now

            # Régulation de cadence
            sleep_time = max(0.001, (1.0 / self._target_fps) - 0.01)
            time.sleep(sleep_time)

        cap.release()
        self._is_connected = False

    def _cleanup_process(self):
        """Arrêt strict et propre du sous-processus FFmpeg et fermeture des descripteurs."""
        with self._lock:
            self._is_connected = False
            proc = self._process
            self._process = None

        if proc:
            try:
                # Fermeture des flux pour libérer les buffers
                if proc.stdin:
                    proc.stdin.close()
                if proc.stdout:
                    proc.stdout.close()
                if proc.stderr:
                    proc.stderr.close()
            except Exception:
                pass

            try:
                # Tentative d'arrêt gracieux
                proc.terminate()
                proc.wait(timeout=1.5)
            except (subprocess.TimeoutExpired, Exception):
                try:
                    # Arrêt forcé si non répondant
                    proc.kill()
                    proc.wait(timeout=1.0)
                except Exception:
                    pass

    def read_frame(self, timeout: Optional[float] = None) -> Tuple[bool, Optional[VideoFrame], str]:
        """Lit la dernière frame disponible de manière non-bloquante avec contrôle d'obsolescence."""
        with self._lock:
            if not self._is_connected or self._latest_frame is None:
                # Si le flux est indisponible, renvoyer une mire stylisée tout en indiquant l'erreur
                placeholder = self._generate_placeholder(self._last_error or "FLUX EN ATTENTE")
                return False, placeholder, self._last_error or "Source déconnectée."

            now = time.time()
            age = now - self._latest_frame.timestamp_utc
            effective_timeout = timeout or self.config.read_timeout

            if age > effective_timeout:
                self._dropped_frames += 1
                placeholder = self._generate_placeholder(f"FLUX FIGÉ ({age:.1f}S)")
                return False, placeholder, f"Trame périmée ({age:.2f}s > {effective_timeout:.2f}s)."

            return True, self._latest_frame, ""

    def _generate_placeholder(self, message: str) -> VideoFrame:
        """Produit une mire sobre et professionnelle lors des interruptions."""
        img = np.zeros((self._height, self._width, 3), dtype=np.uint8)
        img[::40, :, :] = (20, 20, 25)
        img[:, ::40, :] = (20, 20, 25)
        cv2.putText(img, "SMART SECURITY MONITOR // NVR RTSP", (20, 35),
                    cv2.FONT_HERSHEY_DUPLEX, 0.55, (0, 200, 255), 1)
        cv2.putText(img, f"SOURCE: {self.source_id}", (20, 60),
                    cv2.FONT_HERSHEY_SIMPLEX, 0.4, (160, 160, 160), 1)

        txt_size = cv2.getTextSize(message, cv2.FONT_HERSHEY_SIMPLEX, 0.6, 2)[0]
        tx = max(10, (self._width - txt_size[0]) // 2)
        ty = self._height // 2
        cv2.putText(img, message, (tx, ty), cv2.FONT_HERSHEY_SIMPLEX, 0.6, (0, 140, 255), 2)

        return VideoFrame(
            data=img,
            timestamp_utc=time.time(),
            sequence_num=0,
            width=self._width,
            height=self._height,
            channels=3,
            is_placeholder=True
        )

    def close(self) -> None:
        """Arrête définitivement la supervision et libère toutes les ressources."""
        self._stop_event.set()
        self._cleanup_process()
        if self._worker_thread and self._worker_thread.is_alive():
            if threading.current_thread() != self._worker_thread:
                self._worker_thread.join(timeout=3.0)
        self._status = VideoSourceStatus.CLOSED
        self._is_connected = False
