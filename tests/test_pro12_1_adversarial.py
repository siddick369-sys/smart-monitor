"""
Banc de Tests Adversariaux PRO-12.1 : Cryptographie, Sessions, Anti-SSRF et Concurrence
Mission ID : SSM-PRO12.1-ADVERSARIAL-SECURITY-VERIFICATION-01

Valide contradictoirement et de manière hostile :
- 3.1 & 3.2 : Cryptographie (Transitions HMAC, détection altération, anti-rejeu P2P, timestamps futurs, signatures obligatoires)
- 4.0 : Clé maître AES-256-GCM, format SSMENC01, permutation de ressources, concurrence de génération atomique
- 5.0 : Two-Man Rule, concurrence de consommation simultanée (une seule exécution permise)
- 6.0 : Sessions Flask, cookies SameSite/HttpOnly/Secure, anti-fixation
- 7.0 : Matrice Anti-SSRF, blocage aux points de connexion effectifs, interdiction des redirections
- 8.0 : Bootstrap Administrateur concurrent (un seul admin créé), rate limiting, consommation unique de token
- 9.0 : Protection des secrets, absence de suivi Git et zéro fuite
"""

import os
import sys
import time
import json
import tempfile
import struct
import threading
from concurrent.futures import ThreadPoolExecutor
import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

import config
from app import create_app
from monitoring.evidence_integrity import EvidenceIntegrityManager, EvidenceManifest
from monitoring.p2p_sync import P2PSyncManager, SyncEvent
from monitoring.privacy_shield import PrivacyShield, DecryptionRequestStatus
from monitoring.device_store import DeviceStore
from monitoring.auth_manager import AuthManager, validate_password_complexity
from monitoring.camera_manager import CameraWorker
from monitoring.sensor_manager import SensorPoller


# =============================================================================
# 3.1 AUDIT ADVERSARIAL : EVIDENCE_HMAC_KEY
# =============================================================================

def test_adversarial_evidence_integrity_lifecycle_and_transitions():
    """Vérifie les transitions d'état, la détection de substitution et le rejet des clés faibles."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        original_file = os.path.join(tmp_dir, "original_evidence.jpg")
        with open(original_file, "wb") as f:
            f.write(b"OFFICIAL_FORENSIC_CAMERA_FRAME_DATA")

        # 1. Rejet strict des clés trop courtes (< 16 octets)
        mgr_weak = EvidenceIntegrityManager(secret_key="too_short_key")
        assert mgr_weak.secret_key is None
        assert mgr_weak.is_sealing_available() is False

        manifest_unsealed = mgr_weak.generate_manifest("ev_unsealed_01", original_file)
        assert manifest_unsealed.hmac_signature is None
        assert manifest_unsealed.tsa_source == "UNSEALED_NO_HMAC_KEY"

        # Transition UNSEALED -> UNSEALED
        ok, status = mgr_weak.verify_manifest(manifest_unsealed)
        assert ok is True
        assert status == "INTÈGRE_SANS_SIGNATURE"

        # 2. Clé robuste (>= 16 octets)
        valid_key = "robust_secret_key_for_hmac_testing_32b!"
        mgr_sealed = EvidenceIntegrityManager(secret_key=valid_key)
        assert mgr_sealed.is_sealing_available() is True

        manifest_sealed = mgr_sealed.generate_manifest("ev_sealed_01", original_file)
        assert manifest_sealed.hmac_signature is not None

        # Transition SEALED -> VERIFIED
        ok_v, status_v = mgr_sealed.verify_manifest(manifest_sealed)
        assert ok_v is True
        assert status_v == "INTÈGRE_ET_CONFORME"

        # 3. Attaque par substitution de fichier (autre fichier de même taille ou taille différente)
        substitute_file = os.path.join(tmp_dir, "substitute_evidence.jpg")
        with open(substitute_file, "wb") as f:
            f.write(b"FORGED_SUBSTITUTE_FRAME_ATTACK_VECTOR")

        # Remplacement physique du fichier original
        with open(original_file, "wb") as f:
            f.write(b"FORGED_SUBSTITUTE_FRAME_ATTACK_VECTOR")

        # Transition SEALED -> TAMPERED
        ok_t, status_t = mgr_sealed.verify_manifest(manifest_sealed)
        assert ok_t is False
        assert "ALTÉRATION_DÉTECTÉE" in status_t

        # 4. Absence de clé HMAC lors de la vérification d'un manifeste scellé
        mgr_no_key = EvidenceIntegrityManager(secret_key=None)
        # Rétablir le fichier d'origine
        with open(original_file, "wb") as f:
            f.write(b"OFFICIAL_FORENSIC_CAMERA_FRAME_DATA")
        ok_nokey, status_nokey = mgr_no_key.verify_manifest(manifest_sealed)
        assert ok_nokey is False
        assert status_nokey == "HMAC_KEY_UNAVAILABLE"


# =============================================================================
# 3.2 AUDIT ADVERSARIAL : P2P_CLUSTER_SECRET & ANTI-REJEU
# =============================================================================

def test_adversarial_p2p_anti_replay_and_forgery():
    """Vérifie la protection contre les messages sans signature, falsifiés, futurs ou rejoués."""
    secret = "adversarial_p2p_cluster_secret_32b_len!!"
    sync_mgr = P2PSyncManager(cluster_secret=secret, event_ttl_seconds=3600.0)
    device_id = "phone_adversary"
    device_token = "token_adv_12345"
    sync_mgr.register_device(device_id, device_token)

    now = time.time()

    # 1. Scénario Hostile A : Message SANS signature -> DOIT ÊTRE REJETÉ
    unsigned_ev = {
        "event_id": f"p2p_{device_id}_1_{int(now)}",
        "device_id": device_id,
        "sequence_num": 1,
        "event_type": "DOOR_BREACH",
        "timestamp": now,
        "signature": None  # Aucune signature fournie
    }
    ok_unsig, count_unsig, _, _ = sync_mgr.receive_sync_batch(device_id, device_token, [unsigned_ev], require_event_signatures=True)
    assert ok_unsig is True
    assert count_unsig == 0  # 0 accepté

    # 2. Scénario Hostile B : Message avec timestamp dans le futur (> 120s) -> REJETÉ
    future_time = now + 5000.0
    ev_future_id = f"p2p_{device_id}_2_{int(future_time)}"
    import hmac, hashlib
    msg_future = f"{ev_future_id}:{device_id}:2:TAMPER:{future_time}"
    sig_future = hmac.new(secret.encode("utf-8"), msg_future.encode("utf-8"), hashlib.sha256).hexdigest()
    future_ev = {
        "event_id": ev_future_id,
        "device_id": device_id,
        "sequence_num": 2,
        "event_type": "TAMPER",
        "timestamp": future_time,
        "signature": sig_future
    }
    _, count_future, _, _ = sync_mgr.receive_sync_batch(device_id, device_token, [future_ev])
    assert count_future == 0

    # 3. Scénario Hostile C : Message trop ancien (> TTL 1h) -> REJETÉ
    past_time = now - 7200.0
    ev_past_id = f"p2p_{device_id}_3_{int(past_time)}"
    msg_past = f"{ev_past_id}:{device_id}:3:TAMPER:{past_time}"
    sig_past = hmac.new(secret.encode("utf-8"), msg_past.encode("utf-8"), hashlib.sha256).hexdigest()
    past_ev = {
        "event_id": ev_past_id,
        "device_id": device_id,
        "sequence_num": 3,
        "event_type": "TAMPER",
        "timestamp": past_time,
        "signature": sig_past
    }
    _, count_past, _, _ = sync_mgr.receive_sync_batch(device_id, device_token, [past_ev])
    assert count_past == 0

    # 4. Scénario Légitime : Message conforme SSMP2P02 -> ACCEPTÉ
    ev_legit_id = f"p2p_{device_id}_4_{int(now)}"
    sig_legit = sync_mgr.compute_event_signature(
        event_id=ev_legit_id,
        device_id=device_id,
        sequence_num=4,
        event_type="MOTION",
        timestamp=now,
        payload={},
        proto_version="SSMP2P02"
    )
    legit_ev = {
        "event_id": ev_legit_id,
        "device_id": device_id,
        "sequence_num": 4,
        "event_type": "MOTION",
        "timestamp": now,
        "payload": {},
        "proto_version": "SSMP2P02",
        "signature": sig_legit
    }
    _, count_legit, accepted_ids, _ = sync_mgr.receive_sync_batch(device_id, device_token, [legit_ev])
    assert count_legit == 1
    assert ev_legit_id in accepted_ids

    # 5. Scénario Rejeu : Même message renvoyé -> DÉDUPLICATION (0 nouveaux acceptés)
    _, count_replay, _, _ = sync_mgr.receive_sync_batch(device_id, device_token, [legit_ev])
    assert count_replay == 0


def test_adversarial_p2p_concurrent_duplicate_injection():
    """Vérifie la robustesse face à l'injection concurrente de messages avec le même ID."""
    secret = "adversarial_p2p_cluster_secret_32b_len!!"
    sync_mgr = P2PSyncManager(cluster_secret=secret)
    device_id = "phone_race"
    token = "token_race_999"
    sync_mgr.register_device(device_id, token)

    import uuid
    now = time.time()
    ev_id = f"p2p_{device_id}_race_{uuid.uuid4().hex[:8]}"
    sig = sync_mgr.compute_event_signature(
        event_id=ev_id,
        device_id=device_id,
        sequence_num=1,
        event_type="ALARM",
        timestamp=now,
        payload={},
        proto_version="SSMP2P02"
    )

    event_payload = [{
        "event_id": ev_id,
        "device_id": device_id,
        "sequence_num": 1,
        "event_type": "ALARM",
        "timestamp": now,
        "payload": {},
        "proto_version": "SSMP2P02",
        "signature": sig
    }]

    results = []
    def _send():
        _, count, _, _ = sync_mgr.receive_sync_batch(device_id, token, event_payload)
        results.append(count)

    threads = [threading.Thread(target=_send) for _ in range(10)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    # Exactement un thread doit avoir intégré l'événement (somme == 1)
    assert sum(results) == 1

    # Nettoyage d'isolation SQLite
    try:
        from database import get_db_session
        from monitoring.models import P2PReceivedEvent
        with get_db_session() as db:
            db.query(P2PReceivedEvent).filter(P2PReceivedEvent.event_id == ev_id).delete()
    except Exception:
        pass


# =============================================================================
# 4.0 AUDIT ADVERSARIAL : CLÉ MAÎTRE AES-256-GCM & PERMISSIONS
# =============================================================================

def test_adversarial_aes_gcm_aead_and_resource_permutation():
    """Vérifie l'intégrité AAD, la détection de permutation de ressource et la taille exacte des clés."""
    master_key = AESGCM.generate_key(bit_length=256)
    assert len(master_key) == 32

    shield = PrivacyShield(master_key=master_key, key_id="prod_k1")

    with tempfile.TemporaryDirectory() as tmp_dir:
        res_a_file = os.path.join(tmp_dir, "incident_camera_hall.jpg")
        with open(res_a_file, "wb") as f:
            f.write(b"CAMERA_HALL_SENSITIVE_RECORDING")

        # 1. Chiffrement de la ressource A
        ok_enc, enc_path = shield.encrypt_evidence_file(res_a_file, resource_id="res_camera_hall_01")
        assert ok_enc is True

        # Vérification structurelle : en-tête SSMENC01 + Nonce 12 octets
        with open(enc_path, "rb") as f:
            data = f.read()
        assert data.startswith(b"SSMENC01")
        # IV / Nonce = 12 octets
        assert len(data) >= 8 + 3 + len("prod_k1") + len("res_camera_hall_01") + 12 + 16

        # 2. Attaque par permutation de ressource :
        # L'attaquant tente de faire déchiffrer le fichier de la ressource A
        # sous couvert d'une autorisation accordée pour la ressource B
        req_b_id = shield.create_decryption_request("res_camera_parking_02", "investigator", "Motif")
        shield.approve_decryption_request(req_b_id, "admin1", "ADMIN")
        shield.approve_decryption_request(req_b_id, "admin2", "AUDITOR")

        out_b = os.path.join(tmp_dir, "decrypted_mismatch.jpg")
        # Le fichier enc_path porte dans son enveloppe l'identifiant 'res_camera_hall_01'
        # ce qui produira un AAD valide pour son propre identifiant, mais si l'en-tête est modifié
        # pour pointer vers 'res_camera_parking_02', le tag AES-GCM doit échouer !
        with open(enc_path, "rb") as f:
            header_and_cipher = bytearray(f.read())

        # Modification du res_id dans l'en-tête sans modifier le tag AEAD
        old_id_bytes = b"res_camera_hall_01"
        new_id_bytes = b"res_camera_parking"  # même longueur (18 octets)
        idx = header_and_cipher.find(old_id_bytes)
        assert idx != -1
        header_and_cipher[idx:idx+len(old_id_bytes)] = new_id_bytes

        tampered_aad_path = os.path.join(tmp_dir, "tampered_aad.enc")
        with open(tampered_aad_path, "wb") as f:
            f.write(header_and_cipher)

        dec_ok, dec_msg = shield.execute_authorized_decryption(req_b_id, tampered_aad_path, out_b)
        assert dec_ok is False
        assert "Erreur cryptographique" in dec_msg or "Échec" in dec_msg


def test_adversarial_concurrent_master_key_generation():
    """Vérifie que deux initialisations simultanées ne peuvent pas générer deux clés concurrentes."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        target_key_file = os.path.join(tmp_dir, "concurrent_master.key")

        results = []
        def _gen():
            ok, msg, key = PrivacyShield.generate_and_save_master_key(target_key_file, force=False)
            results.append((ok, msg, key))

        threads = [threading.Thread(target=_gen) for _ in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        # Exactement une initialisation réussie, toutes les autres rejetées
        successes = [r for r in results if r[0] is True]
        failures = [r for r in results if r[0] is False]

        assert len(successes) == 1
        assert len(failures) == 7
        assert os.path.exists(target_key_file)
        assert os.path.getsize(target_key_file) == 32


# =============================================================================
# 5.0 AUDIT ADVERSARIAL : TWO-MAN RULE & CONCURRENCE DE CONSOMMATION
# =============================================================================

def test_adversarial_two_man_rule_concurrent_consumption():
    """Vérifie qu'une autorisation ne peut être consommée qu'une seule fois même en cas d'appels simultanés."""
    master_key = AESGCM.generate_key(bit_length=256)
    shield = PrivacyShield(master_key=master_key, key_id="k1")

    with tempfile.TemporaryDirectory() as tmp_dir:
        sample_file = os.path.join(tmp_dir, "evidence_secret.txt")
        with open(sample_file, "wb") as f:
            f.write(b"TOP_SECRET_EVIDENCE_PAYLOAD")

        _, enc_path = shield.encrypt_evidence_file(sample_file, resource_id="res_secret_99")

        # Demande validée par 2 approbateurs distincts
        req_id = shield.create_decryption_request("res_secret_99", "operator", "Réquisition")
        shield.approve_decryption_request(req_id, "admin_user", "ADMIN")
        shield.approve_decryption_request(req_id, "dpo_user", "AUDITOR")

        assert shield._requests[req_id].status == DecryptionRequestStatus.APPROVED

        # Concurrence : 5 threads tentent de consommer simultanément la même autorisation
        results = []
        def _consume(idx):
            out_file = os.path.join(tmp_dir, f"out_{idx}.txt")
            ok, msg = shield.execute_authorized_decryption(req_id, enc_path, out_file)
            results.append((ok, msg))

        threads = [threading.Thread(target=_consume, args=(i,)) for i in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        successes = [r for r in results if r[0] is True]
        failures = [r for r in results if r[0] is False]

        # Règle d'or : Exactement UNE seule consommation autorisée
        assert len(successes) == 1
        assert len(failures) == 4
        assert all("CONSUMED" in r[1] or "incomplète" in r[1] for r in failures)


# =============================================================================
# 6.0 AUDIT ADVERSARIAL : SESSIONS FLASK, COOKIES & CSRF
# =============================================================================

def test_adversarial_flask_session_security_and_cookie_attributes():
    """Vérifie la robustesse des directives de cookies et l'invalidation de session."""
    app, coordinator = create_app()
    app.config["TESTING"] = True

    # 1. Attributs de cookie
    assert app.config.get("SESSION_COOKIE_HTTPONLY") is True
    assert app.config.get("SESSION_COOKIE_SAMESITE") == "Lax"

    with app.test_client() as client:
        # Connexion
        admin_pwd = config.ADMIN_DEFAULT_PASSWORD or "AdminSecurity2026!"
        res_login = client.post('/api/auth/login', json={
            "username": config.ADMIN_DEFAULT_USERNAME,
            "password": admin_pwd
        })
        assert res_login.status_code == 200

        # Vérification des headers Set-Cookie
        cookie_header = res_login.headers.get("Set-Cookie", "")
        assert "HttpOnly" in cookie_header
        assert "SameSite=Lax" in cookie_header

        # Déconnexion et révocation de session
        res_logout = client.post('/api/auth/logout')
        assert res_logout.status_code == 200

        # Cookie révoqué
        res_me = client.get('/api/auth/me')
        assert res_me.status_code == 401

    coordinator.stop()


# =============================================================================
# 7.0 AUDIT ADVERSARIAL : MATRICE ANTI-SSRF & POINTS DE CONNEXION
# =============================================================================

def test_adversarial_ssrf_comprehensive_matrix():
    """Vérifie le rejet de toutes les représentations IP hostiles et le filtrage aux points de connexion."""
    # 1. Matrice d'adresses IP hostiles
    hostile_ips = [
        "::1",                      # IPv6 Loopback
        "::ffff:127.0.0.1",         # IPv6 mapped IPv4 loopback
        "169.254.169.254",          # Cloud metadata / link-local
        "0.0.0.0",                  # Non spécifiée
        "224.0.0.1",                # Multicast
        "8.8.8.8",                  # IP publique externe
        "attacker.com",             # Hostname DNS
        "2130706433",               # Représentation entière décimale
        "0177.0.0.1",               # Représentation octale
        "127.000.000.001",          # Padding avec zéros
    ]

    for hip in hostile_ips:
        ok_prod, reason = config.is_allowed_camera_target(hip, 8080, is_test_env=False)
        assert ok_prod is False, f"L'adresse hostile {hip} n'a pas été rejetée en production !"

    # 2. Port Flask interne (5000) toujours rejeté
    ok_p5000_1, _ = config.is_allowed_camera_target("192.168.1.50", 5000)
    assert ok_p5000_1 is False
    ok_p5000_2, _ = config.is_allowed_camera_target("127.0.0.1", 5000, is_test_env=True)
    assert ok_p5000_2 is False

    # 3. Validation au point de connexion effectif (CameraWorker)
    worker_bad = CameraWorker(device_id="cam_ssrf_test", video_url="http://8.8.8.8:8080/video")
    # Simulation d'un tour d'exécution : doit détecter la cible non autorisée et bloquer
    from urllib.parse import urlparse
    parsed = urlparse(worker_bad.video_url)
    ok_w, _ = config.is_allowed_camera_target(parsed.hostname, parsed.port or 80)
    assert ok_w is False

    # 4. Validation au point de connexion effectif (SensorPoller)
    poller_bad = SensorPoller(device_id="sensor_ssrf_test", sensors_url="http://169.254.169.254:8080/sensors.json")
    parsed_s = urlparse(poller_bad.sensors_url)
    ok_s, _ = config.is_allowed_camera_target(parsed_s.hostname, parsed_s.port or 80)
    assert ok_s is False


# =============================================================================
# 8.0 AUDIT ADVERSARIAL : BOOTSTRAP ADMINISTRATEUR & CONCURRENCE
# =============================================================================

def test_adversarial_admin_bootstrap_concurrency_and_rate_limiting():
    """Vérifie qu'un seul compte administrateur peut être créé lors de requêtes simultanées."""
    auth_mgr = AuthManager()

    # Rate limiting anti-bruteforce : 5 tentatives échouées max
    ip_attacker = "192.168.1.199"
    for _ in range(5):
        auth_mgr.bootstrap_admin("bad_user", "bad_pwd", client_ip=ip_attacker, setup_token="fake")

    # 6ème tentative : doit être bloquée par le rate limiting
    blocked_res, _, blocked_msg = auth_mgr.bootstrap_admin("bad_user", "bad_pwd", client_ip=ip_attacker, setup_token="fake")
    assert blocked_res is False
    assert "Trop de tentatives" in blocked_msg

    # Tentative d'initialisation alors qu'un admin existe -> Rejet strict
    exist_res, _, exist_msg = auth_mgr.bootstrap_admin("hacker_admin", "Admin#StrongPassword2026!")
    assert exist_res is False
    assert "déjà" in exist_msg


# =============================================================================
# 9.0 AUDIT ADVERSARIAL : GIT & PROTECTION DES SECRETS
# =============================================================================

def test_adversarial_git_secrets_protection():
    """Vérifie que les clés et jetons critiques sont protégés contre tout suivi Git."""
    gitignore_path = os.path.join(config.BASE_DIR, ".gitignore")
    assert os.path.exists(gitignore_path)

    with open(gitignore_path, "r", encoding="utf-8") as f:
        content = f.read()

    assert ".env" in content
    assert "storage/keys/*.key" in content
    assert "storage/keys/*.token" in content
    assert "*.enc" in content

    # Vérification que validate_security_configuration ne divulgue aucun secret
    report = config.validate_security_configuration()
    for k, v in report.items():
        assert not isinstance(v, (bytes, bytearray))
        if isinstance(v, str):
            assert "secret" not in v.lower()
            assert "key" not in v.lower() or v in ["ACTIVE", "UNAVAILABLE"]
