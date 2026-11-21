"""
Module de Journalisation d'Audit de Sécurité et Export SIEM.
Conforme aux standards :
- Syslog RFC 5424 (IETF Standard Syslog Protocol)
- Common Event Format (CEF - Standard ArcSight / Splunk / Wazuh / ELK)
"""

import os
import time
import socket
import logging
import threading
from typing import Dict, Any, Optional, List

import config

logger = logging.getLogger("SmartSecurityMonitor.SecurityAudit")

class SecurityAudit:
    """Gestionnaire d'événements de sécurité, d'audit cryptographique et de SIEM."""

    # Sévérités normalisées
    SEV_DEBUG = 7
    SEV_INFO = 6
    SEV_NOTICE = 5
    SEV_WARNING = 4
    SEV_ERROR = 3
    SEV_CRITICAL = 2
    SEV_ALERT = 1
    SEV_EMERGENCY = 0

    FACILITY_AUTH = 4  # Security / Authorization messages

    # Niveaux CEF (0 à 10)
    CEF_SEVERITY_MAP = {
        SEV_DEBUG: 1,
        SEV_INFO: 3,
        SEV_NOTICE: 4,
        SEV_WARNING: 6,
        SEV_ERROR: 7,
        SEV_CRITICAL: 8,
        SEV_ALERT: 9,
        SEV_EMERGENCY: 10
    }

    # Liste noire de clés sensibles à ne JAMAIS journaliser en clair
    SENSITIVE_KEYS = {
        "password", "passwd", "secret", "totp_secret", "token", "bot_token",
        "api_key", "secret_key", "private_key", "recovery_code", "authorization"
    }

    def __init__(self,
                 log_file: str = config.AUDIT_LOG_FILE,
                 export_enabled: bool = config.SIEM_EXPORT_ENABLED,
                 siem_host: str = config.SIEM_HOST,
                 siem_port: int = config.SIEM_PORT,
                 protocol: str = config.SIEM_PROTOCOL,
                 format_type: str = config.SIEM_FORMAT):
        self.log_file = log_file
        self.export_enabled = export_enabled
        self.siem_host = siem_host
        self.siem_port = siem_port
        self.protocol = protocol.upper()
        self.format_type = format_type.upper()

        self.hostname = socket.gethostname()
        self.app_name = "SmartSecurityMonitor"
        self._lock = threading.Lock()

        os.makedirs(os.path.dirname(os.path.abspath(self.log_file)), exist_ok=True)

    def sanitize_metadata(self, metadata: Dict[str, Any]) -> Dict[str, Any]:
        """Élimine ou masque systématiquement tout secret des métadonnées d'audit."""
        sanitized = {}
        for k, v in metadata.items():
            k_lower = str(k).lower()
            is_sensitive = False
            for s in self.SENSITIVE_KEYS:
                if s == k_lower or k_lower.startswith(s + "_") or k_lower.endswith("_" + s) or ("_" + s + "_") in k_lower:
                    is_sensitive = True
                    break
                if s in ["password", "passwd", "secret", "totp", "token", "api_key", "recovery_code"] and s in k_lower:
                    is_sensitive = True
                    break
            sanitized[k] = "[MASQUÉ]" if is_sensitive else v
        return sanitized

    def format_syslog_rfc5424(self,
                               event_id: str,
                               severity: int,
                               actor: str,
                               action: str,
                               outcome: str,
                               message: str,
                               metadata: Dict[str, Any],
                               timestamp: float) -> str:
        """Produit un enregistrement conforme à la RFC 5424."""
        pri = (self.FACILITY_AUTH * 8) + max(0, min(7, severity))
        version = 1
        ts_str = time.strftime("%Y-%m-%dT%H:%M:%S.000Z", time.gmtime(timestamp))
        proc_id = os.getpid()

        # Structured Data SD-ELEMENT
        sd_params = [
            f'action="{action}"',
            f'actor="{actor}"',
            f'outcome="{outcome}"'
        ]
        for k, v in sorted(metadata.items()):
            sd_params.append(f'{k}="{v}"')

        sd_text = f"[audit@48577 {' '.join(sd_params)}]"
        return f"<{pri}>{version} {ts_str} {self.hostname} {self.app_name} {proc_id} {event_id} {sd_text} {message}"

    def format_cef(self,
                   event_id: str,
                   name: str,
                   severity: int,
                   actor: str,
                   action: str,
                   outcome: str,
                   message: str,
                   metadata: Dict[str, Any]) -> str:
        """Produit un enregistrement Common Event Format (CEF)."""
        cef_sev = self.CEF_SEVERITY_MAP.get(severity, 5)

        # Construction des extensions clé=valeur
        extensions = [
            f"suser={actor}",
            f"act={action}",
            f"outcome={outcome}",
            f"msg={message}"
        ]

        if "src_ip" in metadata:
            extensions.append(f"src={metadata['src_ip']}")
        if "device_id" in metadata:
            extensions.append(f"deviceExternalId={metadata['device_id']}")

        for k, v in sorted(metadata.items()):
            if k not in ["src_ip", "device_id"]:
                clean_val = str(v).replace("\\", "\\\\").replace("=", "\\=")
                extensions.append(f"cs_{k}={clean_val}")

        ext_str = " ".join(extensions)
        return f"CEF:0|SmartSecurityMonitor|TP4|1.0|{event_id}|{name}|{cef_sev}|{ext_str}"

    def log_event(self,
                  event_id: str,
                  name: str,
                  actor: str = "SYSTEM",
                  action: str = "EXECUTE",
                  outcome: str = "SUCCESS",
                  message: str = "",
                  severity: int = SEV_INFO,
                  metadata: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Enregistre un événement de sécurité dans le journal local et l'exporte au SIEM si activé.
        """
        now = time.time()
        safe_meta = self.sanitize_metadata(metadata or {})

        syslog_line = self.format_syslog_rfc5424(event_id, severity, actor, action, outcome, message, safe_meta, now)
        cef_line = self.format_cef(event_id, name, severity, actor, action, outcome, message, safe_meta)

        entry_to_write = cef_line if self.format_type == "CEF" else syslog_line

        # Écriture locale persistante et thread-safe
        with self._lock:
            try:
                with open(self.log_file, "a", encoding="utf-8") as f:
                    f.write(entry_to_write + "\n")
            except Exception as e:
                logger.error(f"[Audit] Erreur écriture log local : {e}")

        # Export réseau vers SIEM (si configuré)
        if self.export_enabled:
            self._export_to_siem(entry_to_write)

        return {
            "timestamp": now,
            "event_id": event_id,
            "name": name,
            "actor": actor,
            "action": action,
            "outcome": outcome,
            "severity": severity,
            "syslog": syslog_line,
            "cef": cef_line
        }

    def _export_to_siem(self, raw_message: str):
        """Transmet le paquet au serveur SIEM configuré (UDP / TCP)."""
        payload = raw_message.encode("utf-8")
        try:
            if self.protocol == "TCP":
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(2.0)
                s.connect((self.siem_host, self.siem_port))
                s.sendall(payload + b"\n")
                s.close()
            else:
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.sendto(payload, (self.siem_host, self.siem_port))
                s.close()
        except Exception as e:
            logger.warning(f"[Audit] Échec export SIEM ({self.siem_host}:{self.siem_port}) : {e}")

    def get_recent_logs(self, limit: int = 50) -> List[str]:
        """Retourne les dernières lignes du journal d'audit."""
        with self._lock:
            if not os.path.exists(self.log_file):
                return []
            try:
                with open(self.log_file, "r", encoding="utf-8") as f:
                    lines = f.readlines()
                    return [l.strip() for l in lines[-limit:]]
            except Exception:
                return []
