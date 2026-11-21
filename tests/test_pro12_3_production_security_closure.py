"""
SUITE ADVERSARIALE DE CERTIFICATION ET DE CLÔTURE DE PRODUCTION — PRO-12.3
Référence : SSM-PRO12.3-PRODUCTION-SECURITY-CLOSURE
Périmètre : P123-01 à P123-27 (HTTPS, Sessions, CSRF, Two-Man Rule, Bootstrap,
            Rate Limiting, P2P, AES-256-GCM, NTFS, Forensic & Intégrité).
"""

import os
import sys
import time
import json
import uuid
import hmac
import hashlib
import tempfile
import subprocess
import multiprocessing as mp
from urllib.parse import urlparse
import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

import config
from app import create_app
from database import init_db, get_db_session, SessionLocal, engine
from monitoring.models import (
    Base, User, UserSession, DecryptionRequestModel, DecryptionApprovalModel,
    SystemBootstrap, P2PReceivedEvent, FailedAuthAttempt
)
from monitoring.privacy_shield import PrivacyShield, DecryptionRequestStatus
from monitoring.auth_manager import AuthManager
from monitoring.p2p_sync import P2PSyncManager
from monitoring.evidence_integrity import EvidenceIntegrityManager


# =============================================================================
# HELPER & TOP-LEVEL WORKERS (WINDOWS MULTIPROCESSING SPAWN COMPLIANT)
# =============================================================================

def _rebind_test_db(db_path: str):
    """Rebinds SQLAlchemy engine to an isolated temporary database path."""
    import database
    database.SessionLocal.remove()
    database.engine.dispose()
    config.DB_PATH = db_path
    database.engine = database.create_engine(
        f"sqlite:///{db_path}",
        connect_args={"check_same_thread": False, "timeout": 15},
        echo=False
    )
    database.SessionLocal = database.scoped_session(
        database.sessionmaker(autocommit=False, autoflush=False, bind=database.engine)
    )


def _worker_two_man_process(db_path: str, key_file: str, req_id: str, enc_file: str, out_dir: str, queue: mp.Queue):
    """Travailleur OS pour le test de concurrence atomique Two-Man Rule."""
    try:
        _rebind_test_db(db_path)
        shield = PrivacyShield(key_file_path=key_file, key_id="k1")
        pid = os.getpid()
        out_file = os.path.join(out_dir, f"out_{pid}_{time.time_ns()}.txt")
        ok, msg = shield.execute_authorized_decryption(req_id, enc_file, out_file)
        queue.put((pid, ok, msg))
    except Exception as e:
        queue.put((os.getpid(), False, f"Exception: {e}"))
    finally:
        import database
        database.SessionLocal.remove()
        database.engine.dispose()


def _worker_bootstrap_process(db_path: str, username: str, password: str, client_ip: str, token_file: str, setup_token: str, queue: mp.Queue):
    """Travailleur OS pour le test de concurrence atomique Bootstrap."""
    try:
        _rebind_test_db(db_path)
        import config
        config.KEYS_DIR = os.path.dirname(token_file)
        auth_mgr = AuthManager()
        pid = os.getpid()
        ok, user_dict, msg = auth_mgr.bootstrap_admin(username, password, client_ip, setup_token=setup_token)
        queue.put((pid, username, ok, msg))
    except Exception as e:
        queue.put((os.getpid(), username, False, f"Exception: {e}"))
    finally:
        import database
        database.SessionLocal.remove()
        database.engine.dispose()


def _worker_p2p_sync_process(db_path: str, secret: str, device_id: str, token: str, batch: list, queue: mp.Queue):
    """Travailleur OS pour le test de rejeu concurrent P2P."""
    try:
        _rebind_test_db(db_path)
        mgr = P2PSyncManager(cluster_secret=secret, persist_events=True)
        mgr.register_device(device_id, token)
        ok, accepted, ids, msg = mgr.receive_sync_batch(device_id, token, batch, require_event_signatures=True)
        queue.put((os.getpid(), ok, accepted, ids))
    except Exception as e:
        queue.put((os.getpid(), False, 0, [str(e)]))
    finally:
        import database
        database.SessionLocal.remove()
        database.engine.dispose()


# =============================================================================
# LOT A : SESSIONS & HTTPS COOKIES (P123-01 À P123-04)
# =============================================================================

def test_p123_01_cookie_secure_production_enforced():
    """P123-01: Vérifie qu'en production, SESSION_COOKIE_SECURE=False provoque un refus explicite."""
    import importlib
    old_env = os.environ.get("APP_ENV")
    old_sec = os.environ.get("SESSION_COOKIE_SECURE")

    try:
        os.environ["APP_ENV"] = "production"
        os.environ["SESSION_COOKIE_SECURE"] = "false"

        with pytest.raises(ValueError) as excinfo:
            importlib.reload(config)
        assert "SESSION_COOKIE_SECURE=False est strictement interdit" in str(excinfo.value)
    finally:
        if old_env is not None:
            os.environ["APP_ENV"] = old_env
        else:
            os.environ.pop("APP_ENV", None)

        if old_sec is not None:
            os.environ["SESSION_COOKIE_SECURE"] = old_sec
        else:
            os.environ.pop("SESSION_COOKIE_SECURE", None)

        importlib.reload(config)


def test_p123_02_cookie_httponly_mandatory():
    """P123-02: Vérifie que SESSION_COOKIE_HTTPONLY=False en production provoque un refus explicite."""
    import importlib
    old_env = os.environ.get("APP_ENV")
    old_sec = os.environ.get("SESSION_COOKIE_SECURE")
    old_http = os.environ.get("SESSION_COOKIE_HTTPONLY")

    try:
        os.environ["APP_ENV"] = "production"
        os.environ["SESSION_COOKIE_SECURE"] = "true"
        os.environ["SESSION_COOKIE_HTTPONLY"] = "false"

        with pytest.raises(ValueError) as excinfo:
            importlib.reload(config)
        assert "SESSION_COOKIE_HTTPONLY=False est strictement interdit" in str(excinfo.value)
    finally:
        if old_env is not None:
            os.environ["APP_ENV"] = old_env
        else:
            os.environ.pop("APP_ENV", None)

        if old_sec is not None:
            os.environ["SESSION_COOKIE_SECURE"] = old_sec
        else:
            os.environ.pop("SESSION_COOKIE_SECURE", None)

        if old_http is not None:
            os.environ["SESSION_COOKIE_HTTPONLY"] = old_http
        else:
            os.environ.pop("SESSION_COOKIE_HTTPONLY", None)

        importlib.reload(config)


def test_p123_03_session_revocation_rejection():
    """P123-03: Vérifie qu'un cookie capturé d'une session révoquée est rejeté (401) sur route sensible."""
    app, coordinator = create_app()
    app.config["TESTING"] = True
    config.AUTH_ENABLED = True

    with app.test_client() as client:
        with get_db_session() as db:
            from werkzeug.security import generate_password_hash
            u = db.query(User).filter(User.username == "u_revoked_test").first()
            if not u:
                u = User(id="u_rev_01", username="u_revoked_test", password_hash=generate_password_hash("Pass#Revoke123!"), role="ADMIN", is_active=True)
                db.add(u)

        login_res = client.post('/api/auth/login', json={"username": "u_revoked_test", "password": "Pass#Revoke123!"})
        assert login_res.status_code == 200

        set_cookie = login_res.headers.get("Set-Cookie", "")
        session_val = [p.split("session=", 1)[1].strip() for p in set_cookie.split(";") if p.strip().startswith("session=")][0]

        # Déconnexion révoquant la session côté serveur
        logout_res = client.post('/api/auth/logout')
        assert logout_res.status_code == 200

    # L'attaquant réinjecte l'ancien cookie capturé dans un nouveau client
    with app.test_client() as attacker:
        attacker.set_cookie("session", session_val)
        stolen_req = attacker.get('/api/users')
        assert stolen_req.status_code == 401
        assert "Session révoquée ou invalide" in stolen_req.get_json()["message"]


def test_p123_04_deactivated_user_immediate_block():
    """P123-04: Vérifie qu'un utilisateur désactivé en base voit sa session rejetée avec HTTP 401."""
    app, coordinator = create_app()
    app.config["TESTING"] = True
    config.AUTH_ENABLED = True

    with app.test_client() as client:
        with get_db_session() as db:
            from werkzeug.security import generate_password_hash
            u = db.query(User).filter(User.username == "u_deact_test").first()
            if not u:
                u = User(id="u_deact_01", username="u_deact_test", password_hash=generate_password_hash("Deact#2026Pass!"), role="OPERATOR", is_active=True)
                db.add(u)
            else:
                u.is_active = True

        login_res = client.post('/api/auth/login', json={"username": "u_deact_test", "password": "Deact#2026Pass!"})
        assert login_res.status_code == 200

        # Désactivation immédiate du compte
        with get_db_session() as db:
            u = db.query(User).filter(User.username == "u_deact_test").first()
            u.is_active = False

        res = client.get('/api/auth/me')
        assert res.status_code == 401


# =============================================================================
# LOT B : CSRF DEFENSE EN PROFONDEUR (P123-05 À P123-07)
# =============================================================================

def test_p123_05_csrf_mutation_without_token_rejected():
    """P123-05: Vérifie qu'une mutation sensible sans jeton CSRF est rejetée avec HTTP 403."""
    app, coordinator = create_app()
    app.config["TESTING"] = True
    app.config["CSRF_REQUIRED"] = True

    with app.test_client() as client:
        # Initialiser une session avec cookie
        with client.session_transaction() as sess:
            sess["user_id"] = "user_admin_01"
            sess["role"] = "ADMIN"
            sess["csrf_token"] = "valid_session_csrf_token_secret_hex"

        # Mutation POST sans en-tête CSRF
        resp = client.post('/api/alarm/arm')
        assert resp.status_code == 403
        assert b"CSRF" in resp.data


def test_p123_06_csrf_foreign_token_rejected():
    """P123-06: Vérifie qu'un jeton CSRF appartenant à une autre session est rejeté avec HTTP 403."""
    app, coordinator = create_app()
    app.config["TESTING"] = True
    app.config["CSRF_REQUIRED"] = True

    with app.test_client() as client:
        with client.session_transaction() as sess:
            sess["user_id"] = "user_admin_01"
            sess["role"] = "ADMIN"
            sess["csrf_token"] = "legitimate_session_token_aaa"

        # Attaquant tente de passer le token d'une autre session 'attacker_foreign_token_bbb'
        resp = client.post(
            '/api/alarm/arm',
            headers={"X-CSRF-Token": "attacker_foreign_token_bbb"}
        )
        assert resp.status_code == 403
        assert b"CSRF" in resp.data


def test_p123_07_csrf_hostile_origin_and_cross_site_rejected():
    """P123-07: Vérifie que les origines hostiles et en-têtes cross-site sont bloqués avec HTTP 403."""
    app, coordinator = create_app()
    app.config["TESTING"] = True

    with app.test_client() as client:
        # Origine hostile
        r1 = client.post(
            '/api/auth/bootstrap',
            headers={"Origin": "https://malicious-attacker.evil"},
            json={"username": "hacker", "password": "BadPassword123!"}
        )
        assert r1.status_code == 403

        # Sec-Fetch-Site cross-site
        r2 = client.post(
            '/api/auth/bootstrap',
            headers={"Sec-Fetch-Site": "cross-site"},
            json={"username": "hacker", "password": "BadPassword123!"}
        )
        assert r2.status_code == 403


# =============================================================================
# LOT C : TWO-MAN RULE & BOOTSTRAP (P123-08 À P123-11)
# =============================================================================

def test_p123_08_two_man_self_approval_disallowed():
    """P123-08: Vérifie que le demandeur ne peut pas approuver sa propre demande."""
    shield = PrivacyShield(master_key=b"0" * 32, key_id="k1")
    req_id = shield.create_decryption_request("res_ev_01", requester="operator_alice", reason="Audit")

    ok, msg = shield.approve_decryption_request(req_id, approver="operator_alice", role="ADMIN", disallow_self_approval=True)
    assert ok is False
    assert "ne peut pas approuver sa propre demande" in msg


def test_p123_09_two_man_distinct_approvers_required():
    """P123-09: Vérifie qu'un approbateur ne peut pas valider deux fois la même demande."""
    shield = PrivacyShield(master_key=b"0" * 32, key_id="k1")
    req_id = shield.create_decryption_request("res_ev_01", requester="operator_alice", reason="Audit")

    ok1, msg1 = shield.approve_decryption_request(req_id, approver="admin_bob", role="ADMIN")
    assert ok1 is True

    ok2, msg2 = shield.approve_decryption_request(req_id, approver="admin_bob", role="ADMIN")
    assert ok2 is False
    assert "déjà validé" in msg2


def test_p123_10_two_man_atomic_multiprocess_single_consumption():
    """P123-10: Vérifie l'atomicité multi-processus : sur 8 processus, exactement 1 réussit."""
    orig_db = config.DB_PATH
    with tempfile.TemporaryDirectory() as tmp_dir:
        db_path = os.path.join(tmp_dir, "mp_tm123.db")
        key_file = os.path.join(tmp_dir, "master.key")
        try:
            _rebind_test_db(db_path)
            init_db()

            gen_ok, gen_msg, gen_key = PrivacyShield.generate_and_save_master_key(key_file)
            shield = PrivacyShield(master_key=gen_key, key_file_path=key_file, key_id="k1")

            raw_file = os.path.join(tmp_dir, "sample.raw")
            with open(raw_file, "wb") as f:
                f.write(b"TOP_SECRET_FORENSIC_EVIDENCE_PRO12_3")
            ok_enc, enc_path = shield.encrypt_evidence_file(raw_file, resource_id="res_tm123")
            assert ok_enc is True

            req_id = shield.create_decryption_request("res_tm123", "requester_agent", "Mandat")
            shield.approve_decryption_request(req_id, approver="judge_1", role="ADMIN")
            shield.approve_decryption_request(req_id, approver="auditor_2", role="AUDITOR")

            import database
            database.SessionLocal.remove()
            database.engine.dispose()

            queue = mp.Queue()
            processes = [
                mp.Process(target=_worker_two_man_process, args=(db_path, key_file, req_id, enc_path, tmp_dir, queue))
                for _ in range(8)
            ]
            for p in processes: p.start()
            for p in processes: p.join(timeout=30)

            results = []
            while not queue.empty():
                results.append(queue.get())

            assert len(results) == 8
            successes = [r for r in results if r[1] is True]
            failures = [r for r in results if r[1] is False]

            assert len(successes) == 1, f"Exactement 1 succès requis, obtenu : {len(successes)}"
            assert len(failures) == 7
        finally:
            import database
            database.SessionLocal.remove()
            database.engine.dispose()
            _rebind_test_db(orig_db)


def test_p123_11_bootstrap_atomic_multiprocess_single_admin():
    """P123-11: Vérifie l'atomicité multi-processus : sur 8 processus de bootstrap, un seul est créé."""
    orig_db = config.DB_PATH
    with tempfile.TemporaryDirectory() as tmp_dir:
        db_path = os.path.join(tmp_dir, "mp_boot123.db")
        token_file = os.path.join(tmp_dir, "bootstrap.token")
        try:
            _rebind_test_db(db_path)
            init_db()

            setup_token = "valid_setup_token_pro12_3_hex"
            with open(token_file, "w") as f:
                json.dump({"token": setup_token, "created_at": time.time()}, f)

            import database
            database.SessionLocal.remove()
            database.engine.dispose()

            queue = mp.Queue()
            processes = [
                mp.Process(target=_worker_bootstrap_process, args=(db_path, f"adm_{i}", "Password#Admin2026!", f"192.168.1.{i+10}", token_file, setup_token, queue))
                for i in range(8)
            ]
            for p in processes: p.start()
            for p in processes: p.join(timeout=30)

            results = []
            while not queue.empty():
                results.append(queue.get())

            assert len(results) == 8
            successes = [r for r in results if r[2] is True]
            failures = [r for r in results if r[2] is False]

            assert len(successes) == 1, f"Exactement 1 admin créé attendu, obtenu : {len(successes)}"
            assert len(failures) == 7
        finally:
            import database
            database.SessionLocal.remove()
            database.engine.dispose()
            _rebind_test_db(orig_db)


# =============================================================================
# LOT D : RATE LIMITING & P2P SYNC (P123-12 À P123-17)
# =============================================================================

def test_p123_12_rate_limiting_shared_in_database():
    """P123-12: Vérifie que les tentatives échouées sont partagées en base SQLite."""
    auth_mgr = AuthManager()
    key = f"ip:10.0.0.99"
    for _ in range(5):
        auth_mgr.record_failed_attempt(key)

    cnt = auth_mgr.get_recent_failed_attempts_count(key, window_seconds=60)
    assert cnt >= 5


def test_p123_13_rate_limiting_persistence_after_restart():
    """P123-13: Vérifie que le compteur de rate limiting survit à une nouvelle instance d'AuthManager."""
    mgr1 = AuthManager()
    key = f"user:attacker_target_{uuid.uuid4().hex[:6]}"
    for _ in range(3):
        mgr1.record_failed_attempt(key)

    # Simulation d'un redémarrage / nouveau worker
    mgr2 = AuthManager()
    assert mgr2.get_recent_failed_attempts_count(key, window_seconds=60) == 3


def test_p123_14_p2p_missing_signature_rejected_in_production():
    """P123-14: Vérifie qu'un événement P2P sans signature est rejeté en mode production."""
    secret = "a_super_secret_p2p_cluster_entropy_key_32_bytes_ok!"
    mgr = P2PSyncManager(cluster_secret=secret, persist_events=False)
    mgr.register_device("dev_p2p_01", "token_dev_secret")

    batch = [{
        "event_id": "ev_unsigned_01",
        "device_id": "dev_p2p_01",
        "sequence_num": 1,
        "event_type": "ALERT",
        "timestamp": time.time(),
        "signature": None  # Signature absente
    }]

    ok, count, ids, msg = mgr.receive_sync_batch("dev_p2p_01", "token_dev_secret", batch, require_event_signatures=True)
    assert count == 0
    assert "ev_unsigned_01" not in ids


def test_p123_15_p2p_invalid_signature_rejected():
    """P123-15: Vérifie qu'un événement P2P avec signature altérée est rejeté."""
    secret = "a_super_secret_p2p_cluster_entropy_key_32_bytes_ok!"
    mgr = P2PSyncManager(cluster_secret=secret, persist_events=False)
    mgr.register_device("dev_p2p_01", "token_dev_secret")

    batch = [{
        "event_id": "ev_forged_01",
        "device_id": "dev_p2p_01",
        "sequence_num": 1,
        "event_type": "ALERT",
        "timestamp": time.time(),
        "signature": "bad_hex_signature_abcdef1234567890"
    }]

    ok, count, ids, msg = mgr.receive_sync_batch("dev_p2p_01", "token_dev_secret", batch, require_event_signatures=True)
    assert count == 0


def test_p123_16_p2p_anti_replay_across_restart():
    """P123-16: Vérifie que les événements déjà intégrés ne peuvent pas être rejoués après un redémarrage."""
    secret = "a_super_secret_p2p_cluster_entropy_key_32_bytes_ok!"
    device_id = "dev_p2p_persist"
    token = "token_dev_persist_secret"
    ev_id = f"ev_persist_{uuid.uuid4().hex[:8]}"
    now = time.time()
    msg = f"{ev_id}:{device_id}:1:INTRUSION:{now}"
    sig = hmac.new(secret.encode("utf-8"), msg.encode("utf-8"), hashlib.sha256).hexdigest()

    batch = [{
        "event_id": ev_id,
        "device_id": device_id,
        "sequence_num": 1,
        "event_type": "INTRUSION",
        "timestamp": now,
        "signature": sig
    }]

    # 1. Première intégration
    mgr1 = P2PSyncManager(cluster_secret=secret, persist_events=True)
    mgr1.register_device(device_id, token)
    ok1, count1, ids1, _ = mgr1.receive_sync_batch(device_id, token, batch, require_event_signatures=True)
    assert count1 == 1

    # 2. Nouvelle instance (redémarrage) tentant de réintégrer le même événement
    mgr2 = P2PSyncManager(cluster_secret=secret, persist_events=True)
    mgr2.register_device(device_id, token)
    ok2, count2, ids2, _ = mgr2.receive_sync_batch(device_id, token, batch, require_event_signatures=True)
    assert count2 == 0  # Rejeté comme rejeu, aucun nouvel événement accepté


def test_p123_17_p2p_concurrent_replay_8_processes():
    """P123-17: Vérifie que 8 processus envoyant simultanément le même événement P2P n'acceptent qu'une seule intégration."""
    orig_db = config.DB_PATH
    with tempfile.TemporaryDirectory() as tmp_dir:
        db_path = os.path.join(tmp_dir, "mp_p2p123.db")
        try:
            _rebind_test_db(db_path)
            init_db()

            secret = "a_super_secret_p2p_cluster_entropy_key_32_bytes_ok!"
            device_id = "dev_p2p_mp"
            token = "token_mp_secret_123"
            ev_id = f"ev_mp_{uuid.uuid4().hex[:8]}"
            now = time.time()
            sig = hmac.new(secret.encode("utf-8"), f"{ev_id}:{device_id}:1:MOTION:{now}".encode("utf-8"), hashlib.sha256).hexdigest()
            batch = [{
                "event_id": ev_id,
                "device_id": device_id,
                "sequence_num": 1,
                "event_type": "MOTION",
                "timestamp": now,
                "signature": sig
            }]

            import database
            database.SessionLocal.remove()
            database.engine.dispose()

            queue = mp.Queue()
            processes = [
                mp.Process(target=_worker_p2p_sync_process, args=(db_path, secret, device_id, token, batch, queue))
                for _ in range(8)
            ]
            for p in processes: p.start()
            for p in processes: p.join(timeout=30)

            results = []
            while not queue.empty():
                results.append(queue.get())

            assert len(results) == 8
            total_accepted = sum(r[2] for r in results)
            assert total_accepted == 1, f"Total accepté doit être exactement 1, obtenu : {total_accepted}"
        finally:
            import database
            database.SessionLocal.remove()
            database.engine.dispose()
            _rebind_test_db(orig_db)


# =============================================================================
# LOT E : AES-256-GCM, NTFS & INTÉGRITÉ FORENSIQUE (P123-18 À P123-27)
# =============================================================================

def test_p123_18_aes_corrupted_key_fail_closed():
    """P123-18: Vérifie qu'une clé de taille invalide ou corrompue conduit à PRIVACY_KEY_UNAVAILABLE."""
    with tempfile.NamedTemporaryFile(delete=False) as f:
        f.write(b"SHORT_CORRUPT_KEY_16_BYTES")
        f_path = f.name

    try:
        shield = PrivacyShield(key_file_path=f_path)
        assert shield.key_status == "PRIVACY_KEY_UNAVAILABLE"
        ok, msg = shield.encrypt_evidence_file(f_path)
        assert ok is False
        assert "PRIVACY_KEY_UNAVAILABLE" in msg
    finally:
        if os.path.exists(f_path):
            os.remove(f_path)


def test_p123_19_aes_aad_substitution_rejected():
    """P123-19: Vérifie que la substitution d'AAD (resource_id altéré) fait échouer le déchiffrement."""
    key = AESGCM.generate_key(bit_length=256)
    with tempfile.TemporaryDirectory() as tmp_dir:
        key_file = os.path.join(tmp_dir, "m.key")
        with open(key_file, "wb") as f:
            f.write(key)

        shield = PrivacyShield(master_key=key, key_file_path=key_file, key_id="k1")
        evidence = os.path.join(tmp_dir, "ev.txt")
        with open(evidence, "wb") as f:
            f.write(b"ORIGINAL_CONFIDENTIAL_CONTENT")

        ok_enc, enc_path = shield.encrypt_evidence_file(evidence, resource_id="res_alpha")
        assert ok_enc is True

        # Altération de l'enveloppe : substitution du resource_id res_alpha par res_omega
        with open(enc_path, "rb") as f:
            enc_data = f.read()

        tampered_data = enc_data.replace(b"res_alpha", b"res_omega")
        tampered_path = os.path.join(tmp_dir, "tampered.enc")
        with open(tampered_path, "wb") as f:
            f.write(tampered_data)

        req_id = shield.create_decryption_request("res_alpha", "admin", "Audit")
        shield.approve_decryption_request(req_id, "admin1", "ADMIN")
        shield.approve_decryption_request(req_id, "admin2", "AUDITOR")

        out_path = os.path.join(tmp_dir, "out.txt")
        ok_dec, msg = shield.execute_authorized_decryption(req_id, tampered_path, out_path)
        assert ok_dec is False
        assert "Erreur cryptographique" in msg or "InvalidTag" in msg


def test_p123_20_aes_ciphertext_alteration_rejected():
    """P123-20: Vérifie que l'altération d'un seul octet du ciphertext provoque le rejet GCM."""
    key = AESGCM.generate_key(bit_length=256)
    with tempfile.TemporaryDirectory() as tmp_dir:
        key_file = os.path.join(tmp_dir, "m.key")
        with open(key_file, "wb") as f:
            f.write(key)

        shield = PrivacyShield(master_key=key, key_file_path=key_file, key_id="k1")
        evidence = os.path.join(tmp_dir, "ev.txt")
        with open(evidence, "wb") as f:
            f.write(b"INTEGRITY_CHECK_FORENSIC_DATA")

        ok_enc, enc_path = shield.encrypt_evidence_file(evidence, resource_id="res_beta")
        with open(enc_path, "rb") as f:
            enc_bytes = bytearray(f.read())

        # Altération du dernier octet (tag GCM)
        enc_bytes[-1] ^= 0xFF
        corrupted_path = os.path.join(tmp_dir, "corrupted.enc")
        with open(corrupted_path, "wb") as f:
            f.write(enc_bytes)

        req_id = shield.create_decryption_request("res_beta", "admin", "Audit")
        shield.approve_decryption_request(req_id, "admin1", "ADMIN")
        shield.approve_decryption_request(req_id, "admin2", "AUDITOR")

        out_path = os.path.join(tmp_dir, "out.txt")
        ok_dec, msg = shield.execute_authorized_decryption(req_id, corrupted_path, out_path)
        assert ok_dec is False


def test_p123_21_aes_no_silent_key_regeneration():
    """P123-21: Vérifie qu'une clé existante ne peut jamais être écrasée silencieusement sans force=True."""
    with tempfile.NamedTemporaryFile(delete=False) as f:
        f.write(b"K" * 32)
        key_path = f.name

    try:
        ok, msg, key = PrivacyShield.generate_and_save_master_key(key_path, force=False)
        assert ok is False
        assert "existe déjà" in msg
    finally:
        if os.path.exists(key_path):
            os.remove(key_path)


def test_p123_22_ntfs_key_file_acl_controlled():
    """P123-22: Vérifie que le fichier de clé maître possède des permissions NTFS restreintes."""
    if os.name != "nt":
        pytest.skip("Test spécifique à l'environnement Windows NTFS.")

    key_path = getattr(config, "PRIVACY_KEY_FILE", os.path.join("storage", "keys", "privacy_master.key"))
    if not os.path.exists(key_path):
        pytest.skip("Fichier de clé non présent sur ce chemin.")

    res = subprocess.run(["icacls", key_path], capture_output=True, text=True, encoding="cp850", errors="ignore")
    assert res.returncode == 0
    output = res.stdout
    # Vérification que l'héritage est coupé (absence de (I)) et que l'utilisateur a (R,W)
    assert "(R,W)" in output or "(F)" in output
    assert "(I)" not in output, "L'héritage NTFS doit être désactivé sur le fichier de clé maître."


def test_p123_23_ntfs_parent_directory_controlled():
    """P123-23: Vérifie que le répertoire storage/keys et privacy_master.key possèdent des ACLs strictes sans groupes non autorisés."""
    if os.name != "nt":
        pytest.skip("Test spécifique à l'environnement Windows NTFS.")

    keys_dir = getattr(config, "KEYS_DIR", os.path.join("storage", "keys"))
    key_file = getattr(config, "PRIVACY_KEY_FILE", os.path.join(keys_dir, "privacy_master.key"))

    # 1. Vérification sur le répertoire storage/keys
    res_dir = subprocess.run(["icacls", keys_dir], capture_output=True, text=True, encoding="cp850", errors="ignore")
    assert res_dir.returncode == 0
    dir_lines = [line.strip() for line in res_dir.stdout.splitlines() if ":" in line and not line.strip().startswith("1 ") and not line.strip().startswith("0 ")]
    for line in dir_lines:
        line_lower = line.lower()
        assert "everyone:" not in line_lower
        assert "tout le monde:" not in line_lower

    # 2. Vérification sur le fichier clé maître privacy_master.key
    if os.path.exists(key_file):
        res_key = subprocess.run(["icacls", key_file], capture_output=True, text=True, encoding="cp850", errors="ignore")
        assert res_key.returncode == 0
        raw_out = res_key.stdout

        # L'héritage NTFS doit être explicitement désactivé sur le fichier
        assert "(I)" not in raw_out, "L'héritage NTFS doit être explicitement désactivé sur privacy_master.key."

        # Extraire les ACEs
        key_lines = [line.strip() for line in raw_out.splitlines() if ":" in line and ("(r,w)" in line.lower() or "(f)" in line.lower() or "(r)" in line.lower())]
        assert len(key_lines) >= 1
        for line in key_lines:
            identity = line.split(":")[-2].strip().split()[-1].lower()
            assert identity not in ["everyone", "tout le monde", "users", "utilisateurs", "builtin\\users", "builtin\\utilisateurs"]
            assert "(r,w)" in line.lower() or "(f)" in line.lower()


def test_p123_24_forensic_local_chained_hmac_identifier():
    """P123-24: Vérifie que le mode local est identifié comme LOCAL_CHAINED_HMAC sans faux qualificatif."""
    mgr = EvidenceIntegrityManager(secret_key=b"test_secret_key_32_bytes_ok_123")
    with tempfile.NamedTemporaryFile(delete=False) as f:
        f.write(b"TEST_PROOF_CONTENT")
        proof_path = f.name

    try:
        manifest = mgr.generate_manifest("ev_test_mode", proof_path, watermark=False)
        assert manifest.tsa_source == "LOCAL_CHAINED_HMAC"
        # Interdiction absolue des qualificatifs trompeurs
        assert manifest.tsa_source != "RFC3161_EXTERNAL_TSA"
        assert "CERTIF" not in manifest.tsa_source
    finally:
        if os.path.exists(proof_path):
            os.remove(proof_path)


def test_p123_25_rfc3161_external_tsa_behavior():
    """P123-25: Vérifie qu'en l'absence de TSA externe configurée, aucun faux statut RFC3161 n'est émis."""
    mgr = EvidenceIntegrityManager()
    mgr.tsa_server_url = ""  # Aucune TSA externe
    token, status = mgr._request_timestamp_token("a" * 64)
    assert status == "LOCAL_CHAINED_HMAC"
    assert status != "RFC3161_EXTERNAL_TSA"


def test_p123_26_pro12_2_baseline_maintained():
    """P123-26: Vérifie les modèles de données, contraintes d'unicité, cascades et rollbacks transactionnels."""
    from monitoring.models import Base, User, UserSession, SystemBootstrap, P2PReceivedEvent, Notification
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    from sqlalchemy.exc import IntegrityError
    import uuid

    # 1. Vérification des tables de métadonnées
    assert SystemBootstrap.__tablename__ == "system_bootstrap"
    assert UserSession.__tablename__ == "user_sessions"
    assert P2PReceivedEvent.__tablename__ == "p2p_received_events"

    # 2. Création réelle des tables en mémoire
    mem_engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(mem_engine)
    Session = sessionmaker(bind=mem_engine)
    db = Session()

    try:
        # 3. Test de contrainte d'unicité sur User.username
        u1 = User(id=f"u_{uuid.uuid4().hex[:8]}", username="alice_ops", password_hash="hash123", role="OPERATOR", is_active=True, created_at=time.time())
        db.add(u1)
        db.commit()

        u_dup = User(id=f"u_{uuid.uuid4().hex[:8]}", username="alice_ops", password_hash="hash456", role="ADMIN", is_active=True, created_at=time.time())
        db.add(u_dup)
        with pytest.raises(IntegrityError):
            db.commit()
        db.rollback()

        # 4. Test d'intégrité relationnelle et persistance de session
        sess = UserSession(session_token="token_alice_123", user_id=u1.id, created_at=time.time(), last_activity=time.time(), revoked=False)
        notif = Notification(id=f"notif_{uuid.uuid4().hex[:6]}", user_id=u1.id, title="Test", message="Alerte", level="INFO", datetime="2026-11-21 16:00:00", timestamp=time.time())
        db.add(sess)
        db.add(notif)
        db.commit()

        # Vérifier présence en base
        loaded_sess = db.query(UserSession).filter(UserSession.session_token == "token_alice_123").first()
        assert loaded_sess is not None
        assert loaded_sess.user_id == u1.id

        loaded_notif = db.query(Notification).filter(Notification.id == notif.id).first()
        assert loaded_notif is not None
        assert loaded_notif.user_id == u1.id

        # 5. Test d'atomicité et contrainte singleton sur SystemBootstrap (clé primaire id=1)
        b1 = SystemBootstrap(id=1, bootstrapped_at=time.time(), bootstrapped_by="admin", admin_user_id=u1.id)
        db.add(b1)
        db.commit()

        b2 = SystemBootstrap(id=1, bootstrapped_at=time.time(), bootstrapped_by="attacker", admin_user_id="fake_id")
        db.add(b2)
        with pytest.raises(IntegrityError):
            db.commit()
        db.rollback()
    finally:
        db.close()


def test_p123_27_smoke_test_functional_chain_integrity():
    """P123-27: Vérifie la validation dynamique de configuration de sécurité et le rejet des valeurs non sécurisées."""
    # 1. Validation de base du runtime actuel
    cfg = config.validate_security_configuration()
    assert cfg["session_cookie_httponly"] is True
    assert cfg["evidence_hmac_configured"] is True
    assert cfg["privacy_master_key_configured"] is True
    assert cfg["p2p_secret_configured"] is True

    # 2. Test du rejet strict anti-SSRF par is_allowed_ip
    assert config.is_allowed_ip("192.168.1.50") is True
    assert config.is_allowed_ip("10.0.0.2") is True
    # Rejet des métadonnées cloud AWS/GCP/Azure link-local (169.254.169.254)
    assert config.is_allowed_ip("169.254.169.254") is False
    # Rejet des adresses publiques arbitraires (ex: Google DNS 8.8.8.8)
    assert config.is_allowed_ip("8.8.8.8") is False
    # Rejet des URLs malicieuses avec credentials ou protocoles
    assert config.is_allowed_ip("admin:pass@192.168.1.1") is False
    assert config.is_allowed_ip("http://192.168.1.1") is False

    # 3. Test de validation en environnement simulé de production
    import unittest.mock as mock
    with mock.patch("config.IS_PRODUCTION", True), \
         mock.patch("config.SESSION_COOKIE_SECURE", False):
        # En production, cookies non sécurisés -> ValueError en mode strict
        with pytest.raises(ValueError, match="non sécurisée"):
            config.validate_security_configuration(strict_production=True)

    with mock.patch("config.IS_PRODUCTION", True), \
         mock.patch("config.SESSION_COOKIE_SECURE", True), \
         mock.patch("config.SESSION_COOKIE_HTTPONLY", True), \
         mock.patch("config.SECRET_KEY", "smart-security-monitor-secret-dev-2026"):
        # En production, clé secrète de développement par défaut -> ValueError en mode strict
        with pytest.raises(ValueError, match="SECRET_KEY"):
            config.validate_security_configuration(strict_production=True)
