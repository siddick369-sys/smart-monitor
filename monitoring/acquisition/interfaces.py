"""
Contrats d'interface universels et structures de données pour l'acquisition vidéo.
Architecture NVR universelle PRO-13.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional, Tuple, Dict, Any
import numpy as np


class CameraProtocol(str, Enum):
    """Protocoles d'acquisition pris en charge."""
    RTSP = "RTSP"
    ONVIF = "ONVIF"
    ANDROID_IPWEBCAM = "ANDROID_IPWEBCAM"
    USB = "USB"
    MOCK = "MOCK"


class VideoSourceStatus(str, Enum):
    """États du cycle de vie d'une source vidéo."""
    DISCONNECTED = "DÉCONNECTÉ"
    CONNECTING = "CONNEXION_EN_COURS"
    CONNECTED = "CONNECTÉ"
    ERROR = "ERREUR"
    STALLED = "FLUX_BLOQUÉ"
    BLOCKED_SSRF = "BLOQUÉ_SSRF"
    CLOSED = "FERMÉ"


@dataclass(frozen=True)
class VideoFrame:
    """Représentation immuable d'une image vidéo décodée."""
    data: np.ndarray
    timestamp_utc: float
    sequence_num: int
    width: int
    height: int
    channels: int = 3
    is_placeholder: bool = False
    metadata: Dict[str, Any] = field(default_factory=dict)

    def __repr__(self) -> str:
        return (f"<VideoFrame seq={self.sequence_num} {self.width}x{self.height}x{self.channels} "
                f"ts={self.timestamp_utc:.3f} placeholder={self.is_placeholder}>")


@dataclass
class VideoSourceHealth:
    """Télémétrie de santé opérationnelle du flux d'acquisition."""
    status: VideoSourceStatus
    is_connected: bool
    fps_measured: float
    dropped_frames: int
    reconnect_count: int
    latency_ms: float
    last_error: str
    uptime_seconds: float
    consecutive_read_failures: int = 0


@dataclass
class VideoSourceMetadata:
    """Métadonnées descriptives de la source vidéo."""
    source_id: str
    protocol: CameraProtocol
    sanitized_uri: str
    codec: str = "UNKNOWN"
    width: int = 0
    height: int = 0
    nominal_fps: float = 0.0
    manufacturer: str = "GENERIC"
    model: str = "GENERIC_CAMERA"
    firmware: str = "N/A"
    ptz_supported: bool = False


@dataclass
class CameraConnectionConfig:
    """Configuration de connexion normalisée et sécurisée pour toute caméra."""
    source_id: str
    protocol: CameraProtocol
    uri: str
    username: Optional[str] = None
    password: Optional[str] = None
    connect_timeout: float = 5.0
    read_timeout: float = 5.0
    max_backoff: float = 30.0
    target_fps: int = 10
    target_width: int = 640
    target_height: int = 480
    allow_loopback: bool = False
    custom_params: Dict[str, Any] = field(default_factory=dict)


# =============================================================================
# EXCEPTIONS TYPÉES D'ACQUISITION
# =============================================================================

class VideoSourceError(Exception):
    """Exception de base pour les erreurs de source vidéo."""
    pass


class SSRFBlockedError(VideoSourceError):
    """Levée lorsqu'une cible réseau est interdite par la politique de sécurité."""
    pass


class ConnectionTimeoutError(VideoSourceError):
    """Levée lors d'un dépassement de délai de connexion."""
    pass


class StreamStalledError(VideoSourceError):
    """Levée lorsqu'un flux ne transmet plus d'images dans le délai imparti."""
    pass


class CodecError(VideoSourceError):
    """Levée lors d'une défaillance de décodage vidéo."""
    pass


class AuthenticationFailedError(VideoSourceError):
    """Levée lors d'un échec d'authentification caméra (401/403)."""
    pass


# =============================================================================
# CONTRAT D'INTERFACE ABSTRAIT
# =============================================================================

class VideoSource(ABC):
    """Contrat d'interface abstrait pour toute source de flux vidéo NVR."""

    @abstractmethod
    def connect(self) -> bool:
        """Établit la connexion avec la source vidéo (avec backoff exponentiel).
        Retourne True si la connexion est établie, False sinon.
        """
        pass

    @abstractmethod
    def read_frame(self, timeout: Optional[float] = None) -> Tuple[bool, Optional[VideoFrame], str]:
        """Lit la dernière frame disponible de manière non-bloquante ou avec timeout.
        Retourne : (succès, VideoFrame ou None, message_erreur)
        Ne doit JAMAIS renvoyer une frame ancienne sans indiquer son statut.
        """
        pass

    @abstractmethod
    def get_health(self) -> VideoSourceHealth:
        """Retourne la télémétrie de santé temps réel du flux."""
        pass

    @abstractmethod
    def get_metadata(self) -> VideoSourceMetadata:
        """Retourne les métadonnées de la caméra et du flux."""
        pass

    @abstractmethod
    def close(self) -> None:
        """Libère proprement les ressources (processus enfants, sockets, descripteurs)."""
        pass

    @abstractmethod
    def is_healthy(self) -> bool:
        """Indique si la source produit activement des images saines."""
        pass
