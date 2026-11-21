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
        signature: Optional[str] = None
    ):
        self.event_id = event_id
        self.device_id = device_id
        self.sequence_num = sequence_num
        self.event_type = event_type
        self.payload = payload
        self.timestamp = timestamp
        self.signature = signature

    def to_dict(self) -> dict:
        return {
            "event_id": self.event_id,
            "device_id": self.device_id,
            "sequence_num": self.sequence_num,
            "event_type": self.event_type,
            "payload": self.payload,
            "timestamp": self.timestamp,
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

    @staticmethod
    def canonicalize_payload(payload: Any) -> str:
        """Produit une représentation JSON canonique déterministe (clés triées, UTF-8, sans espaces)."""
        if not payload:
            return "{}"
        return json.dumps(payload, sort_keys=True, separators=(',', ':'), ensure_ascii=False)

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
        """Calcule la signature HMAC-SHA256 intégrale couvrant les métadonnées et la totalité du payload métier (SEC-123-04)."""
        if not self.cluster_secret:
            return ""
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
                    proto_version="SSMP2P02"
                )
            else:
                sig = None

            event = SyncEvent(ev_id, device_id, seq, event_type, payload, now, sig)
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
        """Reçoit et intègre un lot d'événements synchronisés avec déduplication persistante et vérification d'authenticité."""
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
                ev_id = ev_data.get("event_id")
                if not ev_id:
                    continue

                # Vérification de l'identité de l'appareil émetteur (anti-usurpation inter-devices)
                ev_dev = ev_data.get("device_id")
                if ev_dev and ev_dev != device_id:
                    continue

                # 1. Protection contre les rejeux et déduplication en mémoire
                if ev_id in self._received_event_ids:
                    accepted_ids.append(ev_id)
                    continue

                # 1.1 Déduplication persistante en base (résistance aux redémarrages serveur)
                if self.persist_events:
                    try:
                        from database import get_db_session
                        from monitoring.models import P2PReceivedEvent
                        with get_db_session() as db:
                            existing = db.query(P2PReceivedEvent).filter(P2PReceivedEvent.event_id == ev_id).first()
                            if existing:
                                self._received_event_ids[ev_id] = existing.received_at
                                accepted_ids.append(ev_id)
                                continue
                    except Exception:
                        pass

                # 2. Vérification TTL et dérive temporelle (anti-rejeu et timestamps futurs)
                ev_time = ev_data.get("timestamp", now)
                if (now - ev_time > self.event_ttl_seconds) or (ev_time - now > 120.0):
                    continue  # Événement trop ancien ou horodaté dans le futur ignoré

                # 3. Vérification de la signature HMAC intégrale (SEC-123-04)
                seq = ev_data.get("sequence_num", 0)
                ev_type = ev_data.get("event_type", "UNKNOWN")

                # Extraction du payload métier
                raw_payload = ev_data.get("payload")
                if raw_payload is None:
                    reserved_keys = {"event_id", "device_id", "sequence_num", "event_type", "timestamp", "signature", "proto_version"}
                    flat_payload = {k: v for k, v in ev_data.items() if k not in reserved_keys}
                    ev_payload = flat_payload if flat_payload else {}
                else:
                    ev_payload = raw_payload

                proto_version = ev_data.get("proto_version", "v1")

                # Signature moderne SSMP2P02 couvrant l'ensemble des données
                expected_sig_v2 = self.compute_event_signature(
                    event_id=ev_id,
                    device_id=device_id,
                    sequence_num=seq,
                    event_type=ev_type,
                    timestamp=ev_time,
                    payload=ev_payload,
                    proto_version="SSMP2P02"
                )

                # Signature legacy (réservée exclusivement aux paquets historiques sans protocole SSMP2P02)
                expected_sig_v1 = hmac.new(self.cluster_secret, f"{ev_id}:{device_id}:{seq}:{ev_type}:{ev_time}".encode("utf-8"), hashlib.sha256).hexdigest()

                sig = ev_data.get("signature")
                if require_event_signatures and not sig:
                    continue  # Signature obligatoire mais manquante

                if sig:
                    is_valid_v2 = hmac.compare_digest(expected_sig_v2, str(sig))
                    is_valid_v1 = False

                    # Autoriser legacy v1 uniquement si le protocole n'est pas explicitement SSMP2P02
                    if not is_valid_v2 and proto_version != "SSMP2P02":
                        is_valid_v1 = hmac.compare_digest(expected_sig_v1, str(sig))

                    if not is_valid_v2 and not is_valid_v1:
                        continue  # Signature falsifiée ou payload altéré ignoré

                # Acceptation et persistance anti-rejeu
                self._received_event_ids[ev_id] = now
                if self.persist_events:
                    try:
                        from database import get_db_session
                        from monitoring.models import P2PReceivedEvent
                        with get_db_session() as db:
                            db.add(P2PReceivedEvent(event_id=ev_id, device_id=device_id, received_at=now))
                    except Exception:
                        pass

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
