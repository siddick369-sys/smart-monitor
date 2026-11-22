"""
Adaptateur pour smartphone Android (application IP Webcam).
Assure la compatibilité ascendante PRO-01 à PRO-12 dans l'architecture NVR universelle PRO-13.
"""

import time
import logging
import threading
from typing import Optional, Tuple
import cv2

from monitoring.acquisition.interfaces import (
    VideoSource, VideoFrame, VideoSourceHealth, VideoSourceMetadata,
    CameraProtocol, VideoSourceStatus, CameraConnectionConfig
)
from monitoring.acquisition.security import validate_video_target, sanitize_uri

logger = logging.getLogger("SmartSecurityMonitor.NVR.Android")


class AndroidIPWebcamAdapter(VideoSource):
    """Adaptateur HTTP MJPEG pour caméra smartphone Android."""

    def __init__(self, config_obj: CameraConnectionConfig):
        self.config = config_obj
        self.source_id = config_obj.source_id
        self.uri = config_obj.uri
        self.sanitized_uri = sanitize_uri(self.uri)

        self._width = config_obj.target_width
        self._height = config_obj.target_height
        self._fps = max(1, config_obj.target_fps)

        self._status = VideoSourceStatus.DISCONNECTED
        self._is_connected = False
        self._lock = threading.RLock()
        self._cap: Optional[cv2.VideoCapture] = None
        self._sequence = 0
        self._connect_time = 0.0
        self._last_frame_time = 0.0
        self._reconnect_count = 0
        self._dropped_frames = 0
        self._last_error = ""

    def connect(self) -> bool:
        with self._lock:
            # Validation anti-SSRF stricte
            valid, reason, _ = validate_video_target(
                self.uri,
                allow_loopback=self.config.allow_loopback
            )
            if not valid:
                self._status = VideoSourceStatus.BLOCKED_SSRF
                self._last_error = f"SSRF bloqué : {reason}"
                logger.warning(f"[{self.source_id}] Connexion rejetée par l'anti-SSRF : {reason}")
                return False

            self._cap = cv2.VideoCapture(self.uri)
            self._cap.set(cv2.CAP_PROP_BUFFERSIZE, 1)

            if not self._cap.isOpened():
                self._status = VideoSourceStatus.ERROR
                self._last_error = f"Impossible d'ouvrir le flux Android ({self.sanitized_uri})"
                self._is_connected = False
                return False

            self._status = VideoSourceStatus.CONNECTED
            self._is_connected = True
            self._connect_time = time.time()
            self._last_frame_time = self._connect_time
            self._last_error = ""
            return True

    def read_frame(self, timeout: Optional[float] = None) -> Tuple[bool, Optional[VideoFrame], str]:
        with self._lock:
            if not self._is_connected or not self._cap:
                return False, None, "Adaptateur Android non connecté."

            ret, frame = self._cap.read()
            if not ret or frame is None:
                self._dropped_frames += 1
                return False, None, "Échec de lecture d'image depuis le flux Android."

            now = time.time()
            self._sequence += 1
            self._last_frame_time = now

            if frame.shape[0] != self._height or frame.shape[1] != self._width:
                frame = cv2.resize(frame, (self._width, self._height))

            video_frame = VideoFrame(
                data=frame,
                timestamp_utc=now,
                sequence_num=self._sequence,
                width=self._width,
                height=self._height,
                channels=3,
                is_placeholder=False,
                metadata={"protocol": "ANDROID_IPWEBCAM"}
            )
            return True, video_frame, ""

    def get_health(self) -> VideoSourceHealth:
        with self._lock:
            now = time.time()
            uptime = (now - self._connect_time) if self._is_connected else 0.0
            return VideoSourceHealth(
                status=self._status,
                is_connected=self._is_connected,
                fps_measured=float(self._fps),
                dropped_frames=self._dropped_frames,
                reconnect_count=self._reconnect_count,
                latency_ms=0.0,
                last_error=self._last_error,
                uptime_seconds=uptime
            )

    def get_metadata(self) -> VideoSourceMetadata:
        with self._lock:
            return VideoSourceMetadata(
                source_id=self.source_id,
                protocol=CameraProtocol.ANDROID_IPWEBCAM,
                sanitized_uri=self.sanitized_uri,
                codec="MJPEG",
                width=self._width,
                height=self._height,
                nominal_fps=float(self._fps),
                manufacturer="Android IP Webcam",
                model="Smartphone Stream",
                firmware="N/A"
            )

    def close(self) -> None:
        with self._lock:
            if self._cap:
                self._cap.release()
                self._cap = None
            self._status = VideoSourceStatus.CLOSED
            self._is_connected = False

    def is_healthy(self) -> bool:
        with self._lock:
            return self._is_connected and self._status == VideoSourceStatus.CONNECTED
