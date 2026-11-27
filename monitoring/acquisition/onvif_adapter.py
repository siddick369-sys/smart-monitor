"""
Module d'intégration ONVIF WS-Discovery.
Architecture NVR universelle PRO-13.

NOTE ARCHITECTURALE & PÉRIMÈTRE DE SÉCURITÉ (A1-004) :
Ce module implémente EXCLUSIVEMENT la découverte réseau WS-Discovery (SOAP/UDP).
Les services SOAP Media (ONVIF Profile S / Profile T, GetStreamUri, GetProfiles, PTZ)
ne sont PAS implémentés dans cette version. L'URI RTSP par défaut est une inférence indicative
(gabarit 'rtsp://{ip}:554/live/ch0') et DOIT faire l'objet d'une validation et approbation explicite
par l'opérateur avant tout raccordement effectif.
"""

import socket
import uuid
import time
import logging
import xml.etree.ElementTree as ET
from urllib.parse import urlparse
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple, Any

from monitoring.acquisition.security import validate_video_target, sanitize_uri
from monitoring.acquisition.interfaces import CameraProtocol

logger = logging.getLogger("SmartSecurityMonitor.NVR.ONVIF")

# Constantes WS-Discovery
WS_DISCOVERY_ADDR = "239.255.255.250"
WS_DISCOVERY_PORT = 3702
WS_DISCOVERY_PROBE_XML = """<?xml version="1.0" encoding="utf-8"?>
<Envelope xmlns:tds="http://www.onvif.org/ver10/device/wsdl" 
          xmlns="http://www.w3.org/2003/05/soap-envelope">
  <Header xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing">
    <wsa:MessageID>urn:uuid:{message_id}</wsa:MessageID>
    <wsa:To>urn:schemas-xmlsoap-org:ws:2004:08:addressing</wsa:To>
    <wsa:Action>http://schemas.xmlsoap.org/ws/2004/08/addressing/probe</wsa:Action>
  </Header>
  <Body>
    <Probe xmlns:dn="http://www.onvif.org/ver10/network/wsdl" 
           xmlns="http://schemas.xmlsoap.org/ws/2005/04/discovery">
      <Types>dn:NetworkVideoTransmitter tds:Device</Types>
    </Probe>
  </Body>
</Envelope>"""


@dataclass
class ONVIFCandidate:
    """Représentation d'une caméra découverte en attente d'approbation opérateur."""
    candidate_id: str
    ip: str
    port: int
    xaddrs: List[str]
    scopes: List[str]
    discovered_at: float
    manufacturer: str = "GENERIC_ONVIF"
    model: str = "ONVIF_CAMERA"
    firmware: str = "N/A"
    rtsp_uri: Optional[str] = None
    sanitized_rtsp_uri: Optional[str] = None
    profiles: List[str] = field(default_factory=lambda: ["WS_DISCOVERY_SUPPORTED"])
    capabilities: Dict[str, str] = field(default_factory=lambda: {
        "ws_discovery": "WS_DISCOVERY_SUPPORTED",
        "soap_media": "SOAP_MEDIA_NOT_IMPLEMENTED",
        "profile_s": "PROFILE_S_NOT_VERIFIED",
        "profile_t": "PROFILE_T_NOT_VERIFIED"
    })
    status: str = "DISCOVERED_PENDING_APPROVAL"  # "DISCOVERED_PENDING_APPROVAL", "APPROVED", "REJECTED"


class ONVIFDiscoveryService:
    """Service de découverte réseau passive et active via WS-Discovery (SOAP/UDP)."""

    def __init__(self, bind_ip: str = "0.0.0.0", timeout_seconds: float = 3.0, max_responses: int = 50):
        self.bind_ip = bind_ip
        self.timeout_seconds = timeout_seconds
        self.max_responses = max_responses
        self._pending_candidates: Dict[str, ONVIFCandidate] = {}

    def discover(self, allow_loopback: bool = False) -> List[ONVIFCandidate]:
        """Émet une sonde WS-Discovery et collecte les caméras répondantes."""
        msg_id = str(uuid.uuid4())
        probe_payload = WS_DISCOVERY_PROBE_XML.format(message_id=msg_id).encode('utf-8')

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
        sock.settimeout(self.timeout_seconds)

        candidates = []
        try:
            sock.sendto(probe_payload, (WS_DISCOVERY_ADDR, WS_DISCOVERY_PORT))
            start_time = time.time()

            while (time.time() - start_time) < self.timeout_seconds and len(candidates) < self.max_responses:
                try:
                    data, addr = sock.recvfrom(65535)
                    sender_ip, sender_port = addr[0], addr[1]

                    # Validation anti-SSRF sur l'émetteur de la réponse
                    valid, reason, _ = validate_video_target(sender_ip, sender_port, allow_loopback=allow_loopback)
                    if not valid:
                        logger.warning(f"Réponse WS-Discovery rejetée par la sécurité anti-SSRF ({sender_ip}) : {reason}")
                        continue

                    candidate = self._parse_probe_match(data.decode('utf-8', errors='ignore'), sender_ip, sender_port)
                    if candidate:
                        # Déduplication
                        if candidate.candidate_id not in self._pending_candidates:
                            self._pending_candidates[candidate.candidate_id] = candidate
                            candidates.append(candidate)
                except socket.timeout:
                    break
                except Exception as e:
                    logger.debug(f"Erreur réception paquet WS-Discovery : {e}")
                    break
        finally:
            sock.close()

        return candidates

    def _parse_probe_match(self, xml_text: str, default_ip: str, default_port: int) -> Optional[ONVIFCandidate]:
        """Extrait en toute sécurité les métadonnées ONVIF sans vulnérabilité XXE."""
        if not xml_text or "ProbeMatch" not in xml_text:
            return None

        try:
            # Parsing XML défensif
            root = ET.fromstring(xml_text)
        except Exception:
            return None

        # Recherche des balises usuelles WS-Discovery
        xaddrs_raw = ""
        scopes_raw = ""
        for elem in root.iter():
            tag_name = elem.tag.split("}")[-1] if "}" in elem.tag else elem.tag
            if tag_name == "XAddrs" and elem.text:
                xaddrs_raw = elem.text.strip()
            elif tag_name == "Scopes" and elem.text:
                scopes_raw = elem.text.strip()

        xaddrs_list = xaddrs_raw.split() if xaddrs_raw else []
        scopes_list = scopes_raw.split() if scopes_raw else []

        # Extraction de la marque/modèle depuis les scopes
        manufacturer = "ONVIF_MANUFACTURER"
        model = "ONVIF_DEVICE"
        for s in scopes_list:
            if "hardware/" in s.lower():
                model = s.split("/")[-1]
            elif "name/" in s.lower():
                manufacturer = s.split("/")[-1]

        # Détermination de l'adresse principale
        ip = default_ip
        port = default_port
        if xaddrs_list:
            parsed = urlparse(xaddrs_list[0])
            if parsed.hostname:
                ip = parsed.hostname
            if parsed.port:
                port = parsed.port

        cand_id = f"onvif_{ip.replace('.', '_')}_{port}"

        # Construction de l'URI RTSP théorique déduite (à valider)
        rtsp_uri = f"rtsp://{ip}:554/live/ch0"

        return ONVIFCandidate(
            candidate_id=cand_id,
            ip=ip,
            port=port,
            xaddrs=xaddrs_list,
            scopes=scopes_list,
            discovered_at=time.time(),
            manufacturer=manufacturer,
            model=model,
            rtsp_uri=rtsp_uri,
            sanitized_rtsp_uri=sanitize_uri(rtsp_uri),
            profiles=["WS_DISCOVERY_SUPPORTED"],
            capabilities={
                "ws_discovery": "WS_DISCOVERY_SUPPORTED",
                "soap_media": "SOAP_MEDIA_NOT_IMPLEMENTED",
                "profile_s": "PROFILE_S_NOT_VERIFIED",
                "profile_t": "PROFILE_T_NOT_VERIFIED"
            },
            status="DISCOVERED_PENDING_APPROVAL"
        )

    def get_pending_candidates(self) -> List[Dict[str, Any]]:
        """Consulte les équipements découverts en attente d'approbation opérateur."""
        return [
            {
                "candidate_id": c.candidate_id,
                "ip": c.ip,
                "port": c.port,
                "manufacturer": c.manufacturer,
                "model": c.model,
                "sanitized_rtsp_uri": c.sanitized_rtsp_uri,
                "profiles": c.profiles,
                "capabilities": c.capabilities,
                "discovered_at": c.discovered_at,
                "status": c.status
            }
            for c in self._pending_candidates.values()
        ]

    def get_candidate(self, candidate_id: str) -> Optional[ONVIFCandidate]:
        return self._pending_candidates.get(candidate_id)

    def approve_candidate(self, candidate_id: str, operator_username: str) -> Optional[ONVIFCandidate]:
        """Approbation explicite par un opérateur. Règle absolue : aucun enrôlement automatique."""
        cand = self._pending_candidates.get(candidate_id)
        if not cand:
            return None
        cand.status = "APPROVED"
        logger.info(f"[ONVIF] Équipement {candidate_id} ({cand.ip}:{cand.port}) formellement approuvé par l'opérateur '{operator_username}'.")
        return cand

    def reject_candidate(self, candidate_id: str, operator_username: str) -> bool:
        """Rejet explicite d'un équipement découvert."""
        if candidate_id in self._pending_candidates:
            cand = self._pending_candidates[candidate_id]
            cand.status = "REJECTED"
            logger.info(f"[ONVIF] Équipement {candidate_id} rejeté par '{operator_username}'.")
            del self._pending_candidates[candidate_id]
            return True
        return False
