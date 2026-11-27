"""
Services de découverte réseau SSDP et intégration WS-Discovery pour caméras IP.
Architecture NVR universelle PRO-13.

NOTE PROTOCOLE (A1-005) :
Le protocole mDNS / Zeroconf n'est PAS implémenté dans cette version (NOT_IMPLEMENTED).
Seuls les protocoles SSDP (UPnP) et ONVIF WS-Discovery sont pris en charge.
Tout équipement découvert est consigné à l'état DISCOVERED_PENDING_APPROVAL (zéro auto-enrôlement).
"""

import socket
import time
import uuid
import logging
from typing import List, Dict, Optional, Any
from dataclasses import dataclass, field

from monitoring.acquisition.security import validate_video_target, sanitize_uri

logger = logging.getLogger("SmartSecurityMonitor.NVR.Discovery")

# Constantes SSDP
SSDP_ADDR = "239.255.255.250"
SSDP_PORT = 1900
SSDP_SEARCH_MSG = (
    "M-SEARCH * HTTP/1.1\r\n"
    "HOST: 239.255.255.250:1900\r\n"
    "MAN: \"ssdp:discover\"\r\n"
    "MX: 2\r\n"
    "ST: urn:schemas-upnp-org:device:Basic:1\r\n\r\n"
)


@dataclass
class DiscoveredDeviceCandidate:
    """Représentation d'un équipement découvert par WS-Discovery ou SSDP (mDNS non implémenté)."""
    candidate_id: str
    discovery_protocol: str  # "SSDP", "WS_DISCOVERY" (mDNS: "NOT_IMPLEMENTED")
    ip: str
    port: int
    name: str
    location_url: Optional[str]
    server_info: str
    discovered_at: float
    status: str = "DISCOVERED_PENDING_APPROVAL"
    metadata: Dict[str, Any] = field(default_factory=dict)


class SSDPDiscoveryService:
    """Service de détection de caméras et passerelles IP via SSDP / UPnP."""

    def __init__(self, timeout_seconds: float = 2.0, max_responses: int = 50):
        self.timeout_seconds = timeout_seconds
        self.max_responses = max_responses

    def search(self, allow_loopback: bool = False) -> List[DiscoveredDeviceCandidate]:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
        sock.settimeout(self.timeout_seconds)

        candidates = []
        seen_ids = set()

        try:
            sock.sendto(SSDP_SEARCH_MSG.encode('utf-8'), (SSDP_ADDR, SSDP_PORT))
            start_time = time.time()

            while (time.time() - start_time) < self.timeout_seconds and len(candidates) < self.max_responses:
                try:
                    data, addr = sock.recvfrom(4096)
                    ip, port = addr[0], addr[1]

                    valid, reason, _ = validate_video_target(ip, port, allow_loopback=allow_loopback)
                    if not valid:
                        continue

                    response_text = data.decode('utf-8', errors='ignore')
                    headers = self._parse_headers(response_text)

                    usn = headers.get("USN", f"ssdp_{ip}_{port}")
                    if usn in seen_ids:
                        continue
                    seen_ids.add(usn)

                    cand = DiscoveredDeviceCandidate(
                        candidate_id=f"ssdp_{ip.replace('.', '_')}_{port}",
                        discovery_protocol="SSDP",
                        ip=ip,
                        port=port,
                        name=headers.get("SERVER", f"IP Device ({ip})"),
                        location_url=headers.get("LOCATION"),
                        server_info=headers.get("SERVER", "UPnP Device"),
                        discovered_at=time.time(),
                        metadata={"headers": headers}
                    )
                    candidates.append(cand)
                except socket.timeout:
                    break
                except Exception as e:
                    logger.debug(f"Exception SSDP : {e}")
                    break
        finally:
            sock.close()

        return candidates

    def _parse_headers(self, response: str) -> Dict[str, str]:
        headers = {}
        for line in response.splitlines():
            if ":" in line:
                key, val = line.split(":", 1)
                headers[key.strip().upper()] = val.strip()
        return headers


class UnifiedDiscoveryManager:
    """Gestionnaire centralisé de découverte réseau multi-protocoles avec approbation obligatoire."""

    def __init__(self, onvif_service=None, ssdp_service=None):
        from monitoring.acquisition.onvif_adapter import ONVIFDiscoveryService
        self.onvif_service = onvif_service or ONVIFDiscoveryService()
        self.ssdp_service = ssdp_service or SSDPDiscoveryService()
        self._all_candidates: Dict[str, DiscoveredDeviceCandidate] = {}

    def scan_network(self, allow_loopback: bool = False) -> List[Dict[str, Any]]:
        """Lance une analyse multi-vectorielle et retourne les candidats consolidés dédupliqués."""
        # 1. Découverte ONVIF WS-Discovery
        try:
            onvif_cands = self.onvif_service.discover(allow_loopback=allow_loopback)
            for oc in onvif_cands:
                cand = DiscoveredDeviceCandidate(
                    candidate_id=oc.candidate_id,
                    discovery_protocol="WS_DISCOVERY",
                    ip=oc.ip,
                    port=oc.port,
                    name=f"{oc.manufacturer} {oc.model}",
                    location_url=oc.xaddrs[0] if oc.xaddrs else None,
                    server_info=f"ONVIF Device ({oc.manufacturer})",
                    discovered_at=oc.discovered_at,
                    metadata={
                        "rtsp_uri": oc.rtsp_uri,
                        "sanitized_rtsp_uri": oc.sanitized_rtsp_uri,
                        "profiles": oc.profiles
                    }
                )
                self._all_candidates[cand.candidate_id] = cand
        except Exception as e:
            logger.warning(f"Erreur scan ONVIF : {e}")

        # 2. Découverte SSDP
        try:
            ssdp_cands = self.ssdp_service.search(allow_loopback=allow_loopback)
            for sc in ssdp_cands:
                if sc.candidate_id not in self._all_candidates:
                    self._all_candidates[sc.candidate_id] = sc
        except Exception as e:
            logger.warning(f"Erreur scan SSDP : {e}")

        return [
            {
                "candidate_id": c.candidate_id,
                "protocol": c.discovery_protocol,
                "ip": c.ip,
                "port": c.port,
                "name": c.name,
                "server_info": c.server_info,
                "discovered_at": c.discovered_at,
                "status": c.status,
                "metadata": c.metadata
            }
            for c in self._all_candidates.values()
        ]

    def get_candidate(self, candidate_id: str) -> Optional[DiscoveredDeviceCandidate]:
        return self._all_candidates.get(candidate_id)

    def approve_candidate(self, candidate_id: str, operator_username: str) -> Optional[DiscoveredDeviceCandidate]:
        """Approbation explicite d'un équipement découvert par un opérateur authentifié.
        RÈGLE NON NÉGOCIABLE : Aucun appareil n'est enrôlé automatiquement.
        """
        cand = self._all_candidates.get(candidate_id)
        if not cand:
            return None
        cand.status = "APPROVED"
        logger.info(f"[Discovery] Équipement candidat {candidate_id} ({cand.ip}:{cand.port}) formellement approuvé par '{operator_username}'.")
        return cand

    def reject_candidate(self, candidate_id: str, operator_username: str) -> bool:
        """Rejet et suppression d'un équipement découvert."""
        if candidate_id in self._all_candidates:
            del self._all_candidates[candidate_id]
            logger.info(f"[Discovery] Équipement {candidate_id} rejeté et supprimé par '{operator_username}'.")
            return True
        return False
