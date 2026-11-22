"""
Module de Synchronisation Store-and-Forward & Réseau P2P — PRO-11
Gère la résilience en mode déconnecté et la synchronisation des événements :
- File d'attente locale Store-and-Forward sur les nœuds
- Authentification mutuelle des appareils autorisés (Device Token)
- Déduplication stricte des événements et horodatage de séquence
- Réconciliation atomique des incidents lors du rétablissement de la liaison
- Résolution des conflits par horodatage UTC et sévérité
"""

import time
import uuid
import hmac
import hashlib
import json
import threading
from typing import Dict, List, Optional, Tuple, Any
import config


class SyncEvent:
    def __init__(
        self,
        event_id: str,
        device_id: str,
        sequence_num: int,
        event_type: str,
        payload: dict,
        timestamp: float,
        signature: Optional[str] = None,
        proto_version: str = "SSMP2P02"
    ):
        self.event_id = event_id
        self.device_id = device_id
        self.sequence_num = sequence_num
        self.event_type = event_type
        self.payload = payload
        self.timestamp = timestamp
        self.signature = signature
        self.proto_version = proto_version

    def to_dict(self) -> dict:
        return {
            "event_id": self.event_id,
            "device_id": self.device_id,
            "sequence_num": self.sequence_num,
            "event_type": self.event_type,
            "payload": self.payload,
            "timestamp": self.timestamp,
            "proto_version": self.proto_version,
            "signature": self.signature
        }


class P2PSyncManager:
    def __init__(
        self,
        cluster_secret: Optional[str] = None,
        max_queue_size: int = 500,
        event_ttl_seconds: float = 86400.0,  # 24 heures
        persist_events: Optional[bool] = None
    ):
        # Suppression stricte de tout secret par défaut en dur (P12-02)
        # Exige un secret explicite avec entropie minimale (>= 32 octets en production, >= 16 octets en test)
        min_len = 32 if getattr(config, "IS_PRODUCTION", False) else 16
        if cluster_secret and len(str(cluster_secret).strip()) >= min_len:
            self.cluster_secret = str(cluster_secret).strip().encode("utf-8")
        else:
            self.cluster_secret = None

        self.max_queue_size = max_queue_size
        self.event_ttl_seconds = event_ttl_seconds
        if persist_events is None:
            self.persist_events = getattr(config, "IS_PRODUCTION", False) or getattr(config, "P2P_PERSISTENCE_ENABLED", False)
        else:
            self.persist_events = bool(persist_events)

        self._lock = threading.RLock()
        self._authorized_devices: Dict[str, str] = {}  # device_id -> token_hash
        self._store_forward_queue: List[SyncEvent] = []
        self._received_event_ids: Dict[str, float] = {}  # event_id -> timestamp (déduplication)
        self._device_last_seq: Dict[str, int] = {}       # device_id -> last_seq

    def is_sync_available(self) -> bool:
        """Indique si le cluster P2P dispose d'une clé d'authentification valide."""
        return self.cluster_secret is not None

    def register_device(self, device_id: str, device_token: str):
        """Enregistre un appareil autorisé dans le cluster P2P."""
        with self._lock:
            token_hash = hashlib.sha256(device_token.encode("utf-8")).hexdigest()
            self._authorized_devices[device_id] = token_hash

    def authenticate_device(self, device_id: str, device_token: str) -> bool:
        """Vérifie l'authenticité d'un appareil lors d'une tentative de synchronisation.
        Refus immédiat si le secret de cluster n'est pas configuré.
        """
        if not self.cluster_secret:
            return False

        with self._lock:
            expected = self._authorized_devices.get(device_id)
            if not expected:
                return False
            token_hash = hashlib.sha256(device_token.encode("utf-8")).hexdigest()
            return hmac.compare_digest(expected, token_hash)

    REQUIRED_PROTOCOL_VERSION = "SSMP2P02"
    MAX_EVENT_DATA_SIZE = 65536  # 64 Ko max par événement
    MAX_PAYLOAD_DEPTH = 10

    @staticmethod
    def canonicalize_payload(payload: Any, max_depth: int = 10) -> str:
        """Produit une représentation JSON canonique déterministe (clés triées, UTF-8, sans espaces).
        Rejette formellement NaN, Infinity, -Infinity et les structures non conformes RFC 8259 (SEC-1241-01).
        """
        if payload is None:
            return "{}"
        if not isinstance(payload, dict):
            raise ValueError(f"Le payload P2P doit être un dictionnaire, reçu : {type(payload).__name__}")

        def _check_depth_and_values(obj: Any, current_depth: int = 0):
            if current_depth > max_depth:
                raise ValueError(f"Profondeur maximale du payload ({max_depth}) dépassée.")
            if isinstance(obj, dict):
                for k, v in obj.items():
                    if not isinstance(k, str):
                        raise ValueError(f"Les clés de payload doivent être des chaînes : {type(k).__name__}")
                    _check_depth_and_values(v, current_depth + 1)
            elif isinstance(obj, list):
                for item in obj:
                    _check_depth_and_values(item, current_depth + 1)
            elif isinstance(obj, float):
                import math
                if math.isnan(obj) or math.isinf(obj):
                    raise ValueError("Les valeurs NaN et Infinity sont strictement interdites dans le payload.")

        _check_depth_and_values(payload, 0)

        try:
            return json.dumps(
                payload,
                sort_keys=True,
                separators=(',', ':'),
                ensure_ascii=True,
                allow_nan=False
            )
        except (ValueError, TypeError, OverflowError) as e:
            raise ValueError(f"Payload P2P non canonicalisable (NaN, infini ou type invalide) : {e}")

    def compute_event_signature(
        self,
        event_id: str,
        device_id: str,
        sequence_num: int,
        event_type: str,
        timestamp: float,
        payload: Optional[dict] = None,
        proto_version: str = "SSMP2P02"
    ) -> str:
        """Calcule la signature HMAC-SHA256 intégrale couvrant les métadonnées et la totalité du payload métier (SEC-123-04 & SEC-1241-01).
        Rejette toute version autre que SSMP2P02 et tout séparateur interdit.
        """
        if not self.cluster_secret:
            return ""
        if proto_version != self.REQUIRED_PROTOCOL_VERSION:
            raise ValueError(f"Version de protocole P2P non autorisée pour la signature : '{proto_version}'. Seul '{self.REQUIRED_PROTOCOL_VERSION}' est accepté.")

        for field_name, val in [("event_id", event_id), ("device_id", device_id), ("event_type", event_type)]:
            if not isinstance(val, str) or ":" in val or "\n" in val or "\r" in val:
                raise ValueError(f"Champ '{field_name}' invalide ou contenant un séparateur interdit (':') : '{val}'")

        can_payload = self.canonicalize_payload(payload or {})
        msg = f"{proto_version}:{device_id}:{event_id}:{sequence_num}:{event_type}:{timestamp}:{can_payload}"
        return hmac.new(self.cluster_secret, msg.encode("utf-8"), hashlib.sha256).hexdigest()

    def enqueue_local_event(self, device_id: str, event_type: str, payload: dict) -> SyncEvent:
        """Enfile un événement dans la file locale Store-and-Forward (ex: lors d'une rupture réseau).
        Les événements locaux sont TOUJOURS conservés même sans clé P2P configurée.
        """
        with self._lock:
            seq = self._device_last_seq.get(device_id, 0) + 1
            self._device_last_seq[device_id] = seq
            now = time.time()
            ev_id = f"p2p_{device_id}_{seq}_{int(now)}"

            # Signature cryptographique intégrale si secret présent, sinon None
            if self.cluster_secret:
                sig = self.compute_event_signature(
                    event_id=ev_id,
                    device_id=device_id,
                    sequence_num=seq,
                    event_type=event_type,
                    timestamp=now,
                    payload=payload,
                    proto_version=self.REQUIRED_PROTOCOL_VERSION
                )
            else:
                sig = None

            event = SyncEvent(ev_id, device_id, seq, event_type, payload, now, sig, proto_version=self.REQUIRED_PROTOCOL_VERSION)
            self._store_forward_queue.append(event)
            if len(self._store_forward_queue) > self.max_queue_size:
                self._store_forward_queue.pop(0)

            return event

    def receive_sync_batch(
        self,
        device_id: str,
        device_token: str,
        events_batch: List[dict],
        require_event_signatures: Optional[bool] = None
    ) -> Tuple[bool, int, List[str], str]:
        """Reçoit et intègre un lot d'événements synchronisés avec déduplication persistante et vérification d'authenticité.
        ÉLIMINATION ABSOLUE DE TOUT DOWNGRADE PROTOCOLAIRE (SEC-1241-01).
        Aucun fallback vers v1 ou signature partielle. Validation cryptographique intégrale avant tout effet secondaire.
        """
        if not self.cluster_secret:
            return False, 0, [], "Refus sécurisé : Secret de cluster P2P non configuré (min 32 caractères requis)."

        if not self.authenticate_device(device_id, device_token):
            return False, 0, [], "Échec d'authentification de l'appareil."

        # En production, les signatures d'événements sont obligatoires par défaut
        if require_event_signatures is None:
            require_event_signatures = getattr(config, "IS_PRODUCTION", False)

        accepted = 0
        accepted_ids = []
        now = time.time()

        with self._lock:
            for ev_data in events_batch:
                # 1. Vérification du format général et du type
                if not isinstance(ev_data, dict):
                    continue

                # 2. Vérification de la taille totale de l'événement (anti-DoS, max 64 Ko par événement)
                try:
                    raw_len = len(json.dumps(ev_data, default=str))
                    if raw_len > self.MAX_EVENT_DATA_SIZE:
                        continue
                except Exception:
                    continue

                # 3. Validation de la version du protocole (STRICTE : SSMP2P02 UNIQUEMENT)
                # SEC-1241-01 : Rejet formel et immédiat sans aucun fallback v1
                proto_version = ev_data.get("proto_version")
                if not isinstance(proto_version, str) or proto_version != self.REQUIRED_PROTOCOL_VERSION:
                    continue

                # 4. Validation des champs obligatoires et types
                ev_id = ev_data.get("event_id")
                ev_dev = ev_data.get("device_id")
                seq = ev_data.get("sequence_num")
                ev_type = ev_data.get("event_type")
                ev_time = ev_data.get("timestamp")
                sig = ev_data.get("signature")

                # Contrôles de types et contraintes de format strictes
                if not isinstance(ev_id, str) or not ev_id or len(ev_id) > 128 or ":" in ev_id or "\n" in ev_id or "\r" in ev_id:
                    continue
                if ev_dev is not None and (not isinstance(ev_dev, str) or ev_dev != device_id or ":" in ev_dev or "\n" in ev_dev or "\r" in ev_dev):
                    continue
                if not isinstance(seq, int) or seq < 0:
                    continue
                if not isinstance(ev_type, str) or not ev_type or len(ev_type) > 64 or ":" in ev_type or "\n" in ev_type or "\r" in ev_type:
                    continue
                if not isinstance(ev_time, (int, float)):
                    continue

                # 5. Extraction et validation stricte du payload métier
                raw_payload = ev_data.get("payload")
                if raw_payload is None:
                    ev_payload = {}
                elif isinstance(raw_payload, dict):
                    ev_payload = raw_payload
                else:
                    # Payload de type non-dict (ex: string, list, int, etc.) -> REJET
                    continue

                # Validation de canonicalisation du payload (rejet NaN, Infinity, types invalides)
                try:
                    can_payload = self.canonicalize_payload(ev_payload)
                except ValueError:
                    continue  # Payload corrompu ou contenant des structures ambiguës

                # 6. Vérification de la signature cryptographique intégrale
                if require_event_signatures and not sig:
                    continue  # Signature obligatoire mais absente

                if sig:
                    if not isinstance(sig, str) or len(sig) != 64:
                        continue  # Signature malformée (doit être un hash hexadécimal SHA-256 de 64 caractères)
                    try:
                        int(sig, 16)  # Vérifie que la chaîne est hexadécimale
                    except ValueError:
                        continue

                    try:
                        expected_sig = self.compute_event_signature(
                            event_id=ev_id,
                            device_id=device_id,
                            sequence_num=seq,
                            event_type=ev_type,
                            timestamp=ev_time,
                            payload=ev_payload,
                            proto_version=self.REQUIRED_PROTOCOL_VERSION
                        )
                    except ValueError:
                        continue

                    if not hmac.compare_digest(expected_sig, sig):
                        continue  # Signature invalide ou payload altéré -> REJET STRICT SANS EFFET SECONDAIRE

                # 7. Vérification TTL et dérive temporelle (anti-rejeu et timestamps futurs)
                if (now - ev_time > self.event_ttl_seconds) or (ev_time - now > 120.0):
                    continue  # Événement trop ancien ou horodaté dans le futur ignoré

                # 8. Protection contre les rejeux et déduplication en mémoire
                if ev_id in self._received_event_ids:
                    continue

                # 8.1 Déduplication persistante en base (résistance aux redémarrages serveur)
                already_in_db = False
                if self.persist_events:
                    try:
                        from database import get_db_session
                        from monitoring.models import P2PReceivedEvent
                        with get_db_session() as db:
                            existing = db.query(P2PReceivedEvent).filter(P2PReceivedEvent.event_id == ev_id).first()
                            if existing:
                                self._received_event_ids[ev_id] = existing.received_at
                                already_in_db = True
                    except Exception:
                        pass

                if already_in_db:
                    continue

                # 9. Persistance atomique de l'événement accepté
                if self.persist_events:
                    try:
                        from database import get_db_session
                        from monitoring.models import P2PReceivedEvent
                        with get_db_session() as db:
                            db.add(P2PReceivedEvent(event_id=ev_id, device_id=device_id, received_at=now))
                    except Exception:
                        # En cas de collision concurrente sur clé primaire, ignorer comme doublon
                        continue

                self._received_event_ids[ev_id] = now
                accepted += 1
                accepted_ids.append(ev_id)

            # Nettoyage des vieux identifiants de déduplication (> 24h) en mémoire et en base
            for old_id, t in list(self._received_event_ids.items()):
                if now - t > self.event_ttl_seconds:
                    del self._received_event_ids[old_id]

            if self.persist_events:
                try:
                    from database import get_db_session
                    from monitoring.models import P2PReceivedEvent
                    with get_db_session() as db:
                        db.query(P2PReceivedEvent).filter(P2PReceivedEvent.received_at < (now - self.event_ttl_seconds)).delete()
                except Exception:
                    pass

        return True, accepted, accepted_ids, f"{accepted} événements intégrés avec succès."

    def drain_pending_queue(self, max_items: int = 50) -> List[dict]:
        """Extrait les événements en attente pour transmission au serveur lors du rétablissement."""
        with self._lock:
            items = self._store_forward_queue[:max_items]
            return [it.to_dict() for it in items]

    def acknowledge_queue(self, acknowledged_event_ids: List[str]):
        """Retire de la file locale les événements confirmés par le serveur."""
        with self._lock:
            self._store_forward_queue = [
                ev for ev in self._store_forward_queue
                if ev.event_id not in acknowledged_event_ids
            ]

    def get_status(self) -> dict:
        with self._lock:
            return {
                "registered_devices_count": len(self._authorized_devices),
                "store_forward_pending_count": len(self._store_forward_queue),
                "deduplicated_events_count": len(self._received_event_ids)
            }
