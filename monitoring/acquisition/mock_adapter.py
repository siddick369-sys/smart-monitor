"""
Source vidéo synthétique et déterministe pour tests unitaires, d'intégration et adversariaux.
Architecture NVR universelle PRO-13.
"""

import time
import threading
from typing import Optional, Tuple, Dict, Any
import numpy as np
import cv2

from monitoring.acquisition.interfaces import (
    VideoSource, VideoFrame, VideoSourceHealth, VideoSourceMetadata,
    CameraProtocol, VideoSourceStatus, CameraConnectionConfig
)


class MockVideoSource(VideoSource):
    """Source vidéo simulée haute performance et hautement paramétrable."""

    def __init__(
        self,
        config_obj: CameraConnectionConfig,
        simulate_network_delay: float = 0.0,
        fail_connect: bool = False,
        stall_after_frames: int = 0
    ):
        self.config = config_obj
        self.source_id = config_obj.source_id
        self.simulate_network_delay = simulate_network_delay
        self.fail_connect = fail_connect
        self.stall_after_frames = stall_after_frames

        self._width = config_obj.target_width
        self._height = config_obj.target_height
        self._fps = max(1, config_obj.target_fps)

        self._status = VideoSourceStatus.DISCONNECTED
        self._is_connected = False
        self._lock = threading.RLock()
        self._sequence = 0
        self._connect_time = 0.0
        self._last_frame_time = 0.0
        self._reconnect_count = 0
        self._dropped_frames = 0
        self._last_error = ""

    def connect(self) -> bool:
        with self._lock:
            if self.fail_connect:
                self._status = VideoSourceStatus.ERROR
                self._last_error = "Échec simulé de connexion"
                self._is_connected = False
                return False

            self._status = VideoSourceStatus.CONNECTED
            self._is_connected = True
            self._connect_time = time.time()
            self._last_frame_time = self._connect_time
            self._sequence = 0
            self._last_error = ""
            return True

    def read_frame(self, timeout: Optional[float] = None) -> Tuple[bool, Optional[VideoFrame], str]:
        with self._lock:
            if not self._is_connected:
                return False, None, "Source non connectée."

            now = time.time()
            if self.stall_after_frames > 0 and self._sequence >= self.stall_after_frames:
                self._status = VideoSourceStatus.STALLED
                self._last_error = "Flux simulé figé/bloqué."
                return False, None, self._last_error

            if self.simulate_network_delay > 0:
                time.sleep(self.simulate_network_delay)

            self._sequence += 1
            self._last_frame_time = now

            # Génération d'une image de test synthétique avec mire et informations
            img = np.zeros((self._height, self._width, 3), dtype=np.uint8)
            # Motif géométrique sobre
            color = (int((self._sequence * 15) % 255), 180, 200)
            cv2.rectangle(img, (20, 20), (self._width - 20, self._height - 20), color, 2)
            cv2.circle(img, (int(self._width / 2), int(self._height / 2)), 40, (0, 200, 255), -1)

            cv2.putText(
                img, f"MOCK FEED: {self.source_id} | SEQ: {self._sequence}",
                (30, 50), cv2.FONT_HERSHEY_SIMPLEX, 0.55, (255, 255, 255), 1
            )
            cv2.putText(
                img, f"TIME: {time.strftime('%H:%M:%S', time.localtime(now))}",
                (30, 80), cv2.FONT_HERSHEY_SIMPLEX, 0.45, (180, 180, 180), 1
            )

            frame = VideoFrame(
                data=img,
                timestamp_utc=now,
                sequence_num=self._sequence,
                width=self._width,
                height=self._height,
                channels=3,
                is_placeholder=False,
                metadata={"mock": True}
            )
            return True, frame, ""

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
                latency_ms=self.simulate_network_delay * 1000.0,
                last_error=self._last_error,
                uptime_seconds=uptime
            )

    def get_metadata(self) -> VideoSourceMetadata:
        with self._lock:
            return VideoSourceMetadata(
                source_id=self.source_id,
                protocol=CameraProtocol.MOCK,
                sanitized_uri="mock://loopback",
                codec="RAW_SYNTHETIC",
                width=self._width,
                height=self._height,
                nominal_fps=float(self._fps),
                manufacturer="SSM_SIMULATION",
                model="VirtualTestCamera",
                firmware="1.0-mock"
            )

    def close(self) -> None:
        with self._lock:
            self._status = VideoSourceStatus.CLOSED
            self._is_connected = False

    def is_healthy(self) -> bool:
        with self._lock:
            return self._is_connected and self._status == VideoSourceStatus.CONNECTED
