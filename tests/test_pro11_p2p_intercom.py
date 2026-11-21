"""
Bancs de Tests pour PRO-11 : P2P Store-and-Forward et Interphonie Défensive
Valide les fonctionnalités :
- Enrôlement et authentification des appareils (P2PSyncManager)
- File d'attente Store-and-Forward en mode déconnecté
- Déduplication et signature cryptographique des lots
- Sessions d'interphonie audio bidirectionnelle (IntercomManager)
- Sommations vocales neutres et déclaratives
- Contrôle sécurisé du stroboscope avec cooldown anti-photosensibilité et coupe-circuit
"""

import time
import pytest
from monitoring.p2p_sync import P2PSyncManager
from monitoring.intercom import IntercomManager, IntercomSessionState, VoiceAnnouncementType, NEUTRAL_VOICE_MESSAGES


def test_p2p_device_auth_and_store_forward():
    sync_mgr = P2PSyncManager(cluster_secret="test_p2p_secret_key")

    # Enregistrement d'un smartphone autorisé
    sync_mgr.register_device("phone_living", "token_phone_secret_999")

    # Vérification authentification
    assert sync_mgr.authenticate_device("phone_living", "token_phone_secret_999") is True
    assert sync_mgr.authenticate_device("phone_living", "bad_token") is False
    assert sync_mgr.authenticate_device("unknown_phone", "token_phone_secret_999") is False

    # Enfilement d'événements hors-ligne (Store-and-Forward)
    ev1 = sync_mgr.enqueue_local_event("phone_living", "MOUVEMENT", {"motion_pct": 5.4})
    ev2 = sync_mgr.enqueue_local_event("phone_living", "ACOUSTIQUE", {"sound_db": 81.2})

    assert ev1.sequence_num == 1
    assert ev2.sequence_num == 2
    assert ev1.signature is not None

    pending = sync_mgr.drain_pending_queue()
    assert len(pending) == 2

    # Acquittement du premier événement
    sync_mgr.acknowledge_queue([ev1.event_id])
    remaining = sync_mgr.drain_pending_queue()
    assert len(remaining) == 1
    assert remaining[0]["event_id"] == ev2.event_id


def test_p2p_batch_deduplication_and_tampering():
    sync_mgr = P2PSyncManager(cluster_secret="test_p2p_secret_key")
    sync_mgr.register_device("phone_garden", "token_garden_123")

    ev1 = sync_mgr.enqueue_local_event("phone_garden", "MOUVEMENT", {"val": 1}).to_dict()
    ev2 = sync_mgr.enqueue_local_event("phone_garden", "MOUVEMENT", {"val": 2}).to_dict()

    # 1. Envoi du lot valide
    ok, count, accepted_ids, _ = sync_mgr.receive_sync_batch("phone_garden", "token_garden_123", [ev1, ev2])
    assert ok is True
    assert count == 2
    assert len(accepted_ids) == 2

    # 2. Renvoi du même lot (Tentative de rejeu / doublon) -> Déduplication (0 nouveaux acceptés)
    ok_dup, count_dup, _, _ = sync_mgr.receive_sync_batch("phone_garden", "token_garden_123", [ev1, ev2])
    assert ok_dup is True
    assert count_dup == 0  # Rejeté comme déjà reçu

    # 3. Lot avec signature altérée
    tampered_ev = dict(ev1)
    tampered_ev["event_id"] = "p2p_tampered_999"
    tampered_ev["signature"] = "forged_invalid_signature"
    ok_tamp, count_tamp, _, _ = sync_mgr.receive_sync_batch("phone_garden", "token_garden_123", [tampered_ev])
    assert ok_tamp is True
    assert count_tamp == 0


def test_intercom_session_lifecycle():
    intercom = IntercomManager()

    # Démarrage d'une session
    session = intercom.start_intercom_session("cam_entrance", operator_username="admin")
    assert session["state"] == IntercomSessionState.ACTIVE
    assert session["operator"] == "admin"

    s_id = session["session_id"]

    # Coupure micro (Mute)
    intercom.set_mute(s_id, muted=True)
    assert intercom._active_sessions[s_id]["state"] == IntercomSessionState.MUTED

    # Réactivation micro
    intercom.set_mute(s_id, muted=False)
    assert intercom._active_sessions[s_id]["state"] == IntercomSessionState.ACTIVE

    # Clôture session
    intercom.stop_intercom_session(s_id, operator_username="admin")
    assert intercom._active_sessions[s_id]["state"] == IntercomSessionState.TERMINATED


def test_neutral_voice_announcement():
    intercom = IntercomManager()

    # Diffusion sommation neutre
    ann = intercom.trigger_voice_announcement("cam_entrance", VoiceAnnouncementType.ZONE_SURVEILLEE, operator_username="operator1")
    assert ann["status"] == "DISPATCHED"
    assert ann["text"] == NEUTRAL_VOICE_MESSAGES[VoiceAnnouncementType.ZONE_SURVEILLEE]
    assert "quitter cette zone" in ann["text"]

    # Présence détectée
    ann2 = intercom.trigger_voice_announcement("cam_entrance", VoiceAnnouncementType.PRESENCE_DETECTEE)
    assert "responsable du site" in ann2["text"]


def test_strobe_safety_controls_and_abort():
    intercom = IntercomManager(max_strobe_duration_seconds=6.0, strobe_cooldown_seconds=10.0)

    # 1. Déclenchement initial normal
    ok1, msg1 = intercom.trigger_strobe("cam_hall", duration_seconds=5.0, operator_username="admin")
    assert ok1 is True
    assert "activé pour 5.0s" in msg1

    # 2. Déclenchement immédiat consécutif -> REFUSÉ (Cooldown actif)
    ok2, msg2 = intercom.trigger_strobe("cam_hall", duration_seconds=5.0)
    assert ok2 is False
    assert "Temporisation de sécurité" in msg2

    # 3. Coupe-circuit d'urgence (kill-switch)
    abort_ok = intercom.abort_strobe("cam_hall")
    assert abort_ok is True
    assert intercom._strobe_active["cam_hall"] is False
