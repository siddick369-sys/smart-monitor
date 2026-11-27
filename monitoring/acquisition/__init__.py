"""
Package d'acquisition vidéo universelle NVR — Programme PRO-13.
"""

from monitoring.acquisition.interfaces import (
    VideoSource,
    VideoFrame,
    VideoSourceHealth,
    VideoSourceMetadata,
    CameraConnectionConfig,
    CameraProtocol,
    VideoSourceStatus,
    VideoSourceError,
    SSRFBlockedError,
    ConnectionTimeoutError,
    StreamStalledError,
    CodecError,
    AuthenticationFailedError,
)
from monitoring.acquisition.security import (
    sanitize_uri,
    validate_video_target,
    extract_uri_credentials,
    pin_uri_to_ip,
)
from monitoring.acquisition.egress_policy import (
    EgressPolicy,
    EgressEnforcementStatus,
    PolicyConfigurationError,
    check_egress_enforcement_status,
    classify_ip,
)
from monitoring.acquisition.ffmpeg_adapter import FFmpegRTSPAdapter
from monitoring.acquisition.onvif_adapter import (
    ONVIFDiscoveryService,
    ONVIFCandidate,
)
from monitoring.acquisition.discovery import (
    SSDPDiscoveryService,
    DiscoveredDeviceCandidate,
    UnifiedDiscoveryManager,
)
from monitoring.acquisition.android_adapter import AndroidIPWebcamAdapter
from monitoring.acquisition.mock_adapter import MockVideoSource

__all__ = [
    "VideoSource",
    "VideoFrame",
    "VideoSourceHealth",
    "VideoSourceMetadata",
    "CameraConnectionConfig",
    "CameraProtocol",
    "VideoSourceStatus",
    "VideoSourceError",
    "SSRFBlockedError",
    "ConnectionTimeoutError",
    "StreamStalledError",
    "CodecError",
    "AuthenticationFailedError",
    "sanitize_uri",
    "validate_video_target",
    "extract_uri_credentials",
    "pin_uri_to_ip",
    "EgressPolicy",
    "EgressEnforcementStatus",
    "PolicyConfigurationError",
    "check_egress_enforcement_status",
    "classify_ip",
    "FFmpegRTSPAdapter",
    "ONVIFDiscoveryService",
    "ONVIFCandidate",
    "SSDPDiscoveryService",
    "DiscoveredDeviceCandidate",
    "UnifiedDiscoveryManager",
    "AndroidIPWebcamAdapter",
    "MockVideoSource",
]
