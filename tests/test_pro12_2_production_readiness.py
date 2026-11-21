"""
PRO-12.2 : PRODUCTION READINESS & MULTI-PROCESS ADVERSARIAL VERIFICATION SUITE
Vérifications approfondies en conditions réelles de production :
- Concurrence multi-processus réelle (multiprocessing.Process, 8 workers OS distincts)
- Invalidation des sessions Flask côté serveur (anti session-reuse après déconnexion ou changement de mot de passe)
- Protection anti-rejeu P2P persistante inter-redémarrages serveur (SQLite)
- Détection des falsifications cryptographiques AES-256-GCM et gestion fail-closed des clés corrompues
- Harmonisation documentaire et terminologique RFC 3161 (LOCAL_CHAINED_HMAC)
"""

import os
import sys
import time
import json
import shutil
import tempfile
import multiprocessing as mp
import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

import config
from app import create_app
from database import init_db, get_db_session
from monitoring.models import User, UserSession, SystemBootstrap, P2PReceivedEvent, DecryptionRequestModel
from monitoring.privacy_shield import PrivacyShield, DecryptionRequestStatus
from monitoring.auth_manager import AuthManager
from monitoring.p2p_sync import P2PSyncManager
from monitoring.evidence_integrity import EvidenceIntegrityManager


# =============================================================================
# FONCTIONS DE PROCESSUS MULTIPROCESSING DE HAUT NIVEAU (Compatibles Windows spawn)
# =============================================================================

def _rebind_test_db(db_path: str):
    """Reconfigure l'instance SQLite du processus vers une base temporaire dédiée."""
    import config
    import database
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker, scoped_session
    config.DB_PATH = db_path
    database.engine = create_engine(
        f"sqlite:///{db_path}",
        connect_args={"check_same_thread": False, "timeout": 15},
        echo=False
    )
    database.SessionLocal = scoped_session(sessionmaker(autocommit=False, autoflush=False, bind=database.engine))


def _worker_two_man_process(db_path: str, key_file: str, req_id: str, enc_file: str, out_dir: str, queue: mp.Queue):
    """Travailleur exécuté dans un processus OS distinct tentant de consommer l'autorisation."""
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
    """Travailleur exécuté dans un processus OS distinct tentant de réaliser le bootstrap administrateur."""
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


# =============================================================================
# 1.0 SESSIONS FLASK : ADVERSARIAL REUSE & SERVER-SIDE REVOCATION
# =============================================================================

def test_adversarial_session_invalidation_after_logout():
    """Vérifie qu'un cookie de session capturé avant déconnexion est définitivement refusé après logout."""
    app, coordinator = create_app()
    app.config["TESTING"] = True
    config.AUTH_ENABLED = True

    with app.test_client() as client:
        # Création d'un compte utilisateur dédié
        with get_db_session() as db:
            user = db.query(User).filter(User.username == "test_session_user").first()
            if not user:
                from werkzeug.security import generate_password_hash
                user = User(
                    id="user_sess_01",
                    username="test_session_user",
                    password_hash=generate_password_hash("SessionPass123!"),
                    role="OPERATOR",
                    is_active=True
                )
                db.add(user)

        # 1. Connexion légitime
        login_resp = client.post('/api/auth/login', json={
            "username": "test_session_user",
            "password": "SessionPass123!"
        })
        assert login_resp.status_code == 200

        # 2. Capture du cookie de session légitime depuis l'en-tête Set-Cookie
        set_cookie = login_resp.headers.get("Set-Cookie", "")
        session_val = None
        for part in set_cookie.split(";"):
            part = part.strip()
            if part.startswith("session="):
                session_val = part.split("session=", 1)[1]
                break
        assert session_val is not None

        # Accès autorisé avec la session courante
        me_resp = client.get('/api/auth/me', headers={"Cookie": f"session={session_val}"})
        assert me_resp.status_code == 200

        # 3. Déconnexion explicite
        logout_resp = client.post('/api/auth/logout')
        assert logout_resp.status_code == 200

        # 4. Scénario adversarial : l'attaquant réinjecte l'ancien cookie capturé
        replay_resp = client.get('/api/auth/me', headers={"Cookie": f"session={session_val}"})
        assert replay_resp.status_code == 401
        data = replay_resp.get_json()
        assert data.get("authenticated") is False


def test_adversarial_session_invalidation_after_password_change():
    """Vérifie que la modification du mot de passe révoque l'ancien cookie de session."""
    app, coordinator = create_app()
    app.config["TESTING"] = True
    config.AUTH_ENABLED = True

    with app.test_client() as client:
        with get_db_session() as db:
            from werkzeug.security import generate_password_hash
            user = db.query(User).filter(User.username == "test_pwd_change_user").first()
            if not user:
                user = User(
                    id="user_pwd_01",
                    username="test_pwd_change_user",
                    password_hash=generate_password_hash("OldPassword123!"),
                    role="OPERATOR",
                    is_active=True
                )
                db.add(user)
            else:
                user.password_hash = generate_password_hash("OldPassword123!")
                user.is_active = True

        # 1. Connexion
        login_resp = client.post('/api/auth/login', json={
            "username": "test_pwd_change_user",
            "password": "OldPassword123!"
        })
        assert login_resp.status_code == 200

        # 2. Capture du premier cookie
        set_cookie = login_resp.headers.get("Set-Cookie", "")
        old_session_val = None
        for part in set_cookie.split(";"):
            part = part.strip()
            if part.startswith("session="):
                old_session_val = part.split("session=", 1)[1]
                break
        assert old_session_val is not None

        # 3. Changement de mot de passe
        change_resp = client.post('/api/auth/change_password', json={
            "current_password": "OldPassword123!",
            "new_password": "NewSecurePass2026!",
            "confirm_password": "NewSecurePass2026!"
        })
        assert change_resp.status_code == 200

        # 4. Attaque par réutilisation de l'ancien cookie capturé (depuis un client tiers / session séparée)
        with app.test_client() as attacker_client:
            replay_resp = attacker_client.get('/api/auth/me', headers={"Cookie": f"session={old_session_val}"})
            assert replay_resp.status_code == 401


def test_deactivated_user_immediate_session_rejection():
    """Vérifie qu'un compte utilisateur désactivé voit sa session immédiatement rejetée."""
    app, coordinator = create_app()
    app.config["TESTING"] = True
    config.AUTH_ENABLED = True

    with app.test_client() as client:
        with get_db_session() as db:
            user = db.query(User).filter(User.username == "test_deact_user").first()
            if not user:
                from werkzeug.security import generate_password_hash
                user = User(
                    id="user_deact_01",
                    username="test_deact_user",
                    password_hash=generate_password_hash("DeactPass123!"),
                    role="OPERATOR",
                    is_active=True
                )
                db.add(user)
            else:
                user.is_active = True

        login_resp = client.post('/api/auth/login', json={
            "username": "test_deact_user",
            "password": "DeactPass123!"
        })
        assert login_resp.status_code == 200
        set_cookie = login_resp.headers.get("Set-Cookie", "")
        session_val = None
        for part in set_cookie.split(";"):
            part = part.strip()
            if part.startswith("session="):
                session_val = part.split("session=", 1)[1]
                break

        # Vérification session active
        assert client.get('/api/auth/me', headers={"Cookie": f"session={session_val}"}).status_code == 200

        # Désactivation du compte utilisateur en base
        with get_db_session() as db:
            target = db.query(User).filter(User.username == "test_deact_user").first()
            target.is_active = False

        # Requête ultérieure avec la même session -> Rejet 401
        resp = client.get('/api/auth/me', headers={"Cookie": f"session={session_val}"})
        assert resp.status_code == 401


def test_csrf_and_security_headers_protection():
    """Vérifie le rejet des requêtes cross-site et la présence des en-têtes HTTP de sécurité."""
    app, coordinator = create_app()
    app.config["TESTING"] = True

    with app.test_client() as client:
        # 1. En-têtes de sécurité
        resp = client.get('/api/auth/bootstrap/status')
        assert resp.headers.get("X-Content-Type-Options") == "nosniff"
        assert resp.headers.get("X-Frame-Options") == "SAMEORIGIN"
        assert "default-src 'self'" in resp.headers.get("Content-Security-Policy", "")

        # 2. Protection Sec-Fetch-Site (cross-site interdit sur POST)
        blocked_resp = client.post(
            '/api/auth/bootstrap',
            headers={"Sec-Fetch-Site": "cross-site"},
            json={"username": "attacker", "password": "BadPassword123!"}
        )
        assert blocked_resp.status_code == 403

        # 3. Protection Origin non autorisée
        untrusted_resp = client.post(
            '/api/auth/bootstrap',
            headers={"Origin": "https://evil-attacker-website.com"},
            json={"username": "attacker", "password": "BadPassword123!"}
        )
        assert untrusted_resp.status_code == 403


# =============================================================================
# 2.0 MULTI-PROCESSUS : TWO-MAN RULE STRICT CONCURRENCY (8 PROCESSUS OS)
# =============================================================================

def test_multiprocess_two_man_rule_atomic_concurrency_8_workers():
    """Vérifie l'exclusion mutuelle stricte de la Two-Man Rule entre 8 processus OS distincts."""
    orig_db_path = config.DB_PATH
    with tempfile.TemporaryDirectory() as tmp_dir:
        db_path = os.path.join(tmp_dir, "mp_twoman.db")
        key_file = os.path.join(tmp_dir, "master.key")
        try:
            _rebind_test_db(db_path)
            init_db()

            # 1. Initialisation de la clé et du Privacy Shield
            gen_ok, gen_msg, gen_key = PrivacyShield.generate_and_save_master_key(key_file)
            assert gen_ok is True, gen_msg
            shield = PrivacyShield(master_key=gen_key, key_file_path=key_file, key_id="k1")

            # 2. Chiffrement d'une preuve originale
            sample_evidence = os.path.join(tmp_dir, "evidence_original.raw")
            secret_content = b"CRITICAL_FORENSIC_EVIDENCE_FOR_JUDICIAL_PROCEEDING_2026"
            with open(sample_evidence, "wb") as f:
                f.write(secret_content)

            ok_enc, enc_path = shield.encrypt_evidence_file(sample_evidence, resource_id="res_evidence_88")
            assert ok_enc is True

            # 3. Création et double approbation complète
            req_id = shield.create_decryption_request("res_evidence_88", "police_officer", "Réquisition Judiciaire")
            shield.approve_decryption_request(req_id, approver="magistrate_bob", role="ADMIN")
            shield.approve_decryption_request(req_id, approver="auditor_claire", role="AUDITOR")

            # 4. Lancement de 8 processus OS distincts concourant simultanément
            import database
            database.SessionLocal.remove()
            database.engine.dispose()

            queue = mp.Queue()
            processes = []
            for i in range(8):
                p = mp.Process(
                    target=_worker_two_man_process,
                    args=(db_path, key_file, req_id, enc_path, tmp_dir, queue)
                )
                processes.append(p)

            for p in processes:
                p.start()
            for p in processes:
                p.join(timeout=30)

            # 5. Collecte et analyse des résultats
            results = []
            while not queue.empty():
                results.append(queue.get())

            assert len(results) == 8, f"8 résultats attendus, obtenus : {len(results)}"
            successes = [r for r in results if r[1] is True]
            failures = [r for r in results if r[1] is False]

            # Règle d'or : Exactement 1 succès et 7 échecs
            assert len(successes) == 1, f"Exactement 1 processus doit réussir, obtenu : {len(successes)}"
            assert len(failures) == 7, f"Exactement 7 processus doivent échouer, obtenu : {len(failures)}"

            for f in failures:
                assert "CONSUMED" in f[2] or "incomplète" in f[2]
        finally:
            import database
            database.SessionLocal.remove()
            database.engine.dispose()
            _rebind_test_db(orig_db_path)


# =============================================================================
# 3.0 MULTI-PROCESSUS : BOOTSTRAP ADMINISTRATEUR ATOMIQUE (8 PROCESSUS OS)
# =============================================================================

def test_multiprocess_admin_bootstrap_atomic_concurrency_8_workers():
    """Vérifie qu'exactement un seul administrateur peut être créé lors d'une course entre 8 processus OS."""
    orig_db_path = config.DB_PATH
    with tempfile.TemporaryDirectory() as tmp_dir:
        db_path = os.path.join(tmp_dir, "mp_boot.db")
        token_file = os.path.join(tmp_dir, "bootstrap.token")
        try:
            _rebind_test_db(db_path)
            init_db()

            # Jeton de bootstrap valide partagé
            setup_token = "valid_secure_bootstrap_token_hex_999888777"
            with open(token_file, "w") as f:
                json.dump({"token": setup_token, "created_at": time.time()}, f)

            # 8 processus tentent un bootstrap simultané avec des identifiants différents
            import database
            database.SessionLocal.remove()
            database.engine.dispose()

            queue = mp.Queue()
            processes = []
            for i in range(8):
                uname = f"candidate_admin_{i}"
                p = mp.Process(
                    target=_worker_bootstrap_process,
                    args=(db_path, uname, "Master#AdminPass2026!", f"127.0.0.{i+1}", token_file, setup_token, queue)
                )
                processes.append(p)

            for p in processes:
                p.start()
            for p in processes:
                p.join(timeout=30)

            results = []
            while not queue.empty():
                results.append(queue.get())

            assert len(results) == 8
            successes = [r for r in results if r[2] is True]
            failures = [r for r in results if r[2] is False]

            assert len(successes) == 1, f"Exactement 1 bootstrap doit réussir, obtenu : {len(successes)}"
            assert len(failures) == 7, f"Exactement 7 tentatives doivent échouer, obtenu : {len(failures)}"

            for fail in failures:
                assert "déjà" in fail[3].lower() or "refusée" in fail[3].lower()

            # Vérification d'intégrité en base
            with get_db_session() as db:
                admins = db.query(User).filter(User.role == "ADMIN").all()
                sentinels = db.query(SystemBootstrap).all()
                assert len(admins) == 1, f"Exactement 1 admin en base attendu, trouvé : {len(admins)}"
                assert len(sentinels) == 1, f"Exactement 1 sentinelle attendue, trouvée : {len(sentinels)}"
        finally:
            import database
            database.SessionLocal.remove()
            database.engine.dispose()
            _rebind_test_db(orig_db_path)


# =============================================================================
# 4.0 P2P SYNC : ANTI-REJEU PERSISTANT INTER-REDÉMARRAGE & SIGNATURES
# =============================================================================

def test_persistent_p2p_anti_replay_across_restart():
    """Vérifie que les événements synchronisés ne peuvent pas être rejoués après un redémarrage serveur."""
    init_db()
    secret = "cluster_p2p_shared_secret_min_32_chars_ok!"
    device_id = "camera_gate_01"
    device_token = "cam_gate_token_123"

    # Instance 1 : réception d'un premier événement avec persistance activée
    p2p_1 = P2PSyncManager(cluster_secret=secret, event_ttl_seconds=3600, persist_events=True)
    p2p_1.register_device(device_id, device_token)

    now = time.time()
    ev_id = f"p2p_{device_id}_seq1_{int(now)}"
    msg = f"{ev_id}:{device_id}:1:INTRUSION_DETECTED:{now}"
    import hmac
    import hashlib
    sig = hmac.new(secret.encode("utf-8"), msg.encode("utf-8"), hashlib.sha256).hexdigest()

    batch = [{
        "event_id": ev_id,
        "sequence_num": 1,
        "event_type": "INTRUSION_DETECTED",
        "timestamp": now,
        "signature": sig,
        "payload": {"zone": "gate"}
    }]

    ok1, count1, ids1, _ = p2p_1.receive_sync_batch(device_id, device_token, batch, require_event_signatures=True)
    assert ok1 is True
    assert count1 == 1
    assert ev_id in ids1

    # Simulation d'un redémarrage complet du serveur :
    # Instance 2 instanciée sans aucun état mémoire résiduel
    p2p_2 = P2PSyncManager(cluster_secret=secret, event_ttl_seconds=3600, persist_events=True)
    p2p_2.register_device(device_id, device_token)
    assert ev_id not in p2p_2._received_event_ids

    # Tentative de rejeu du même lot sur la nouvelle instance
    ok2, count2, ids2, _ = p2p_2.receive_sync_batch(device_id, device_token, batch, require_event_signatures=True)
    assert ok2 is True
    # count2 doit valoir 0 : l'événement a été détecté comme déjà consommé grâce à la table persistante
    assert count2 == 0

    # Un nouvel événement avec un nouvel ID et séquence doit être accepté
    ev_id_2 = f"p2p_{device_id}_seq2_{int(now+1)}"
    msg2 = f"{ev_id_2}:{device_id}:2:DOOR_CLOSED:{now+1}"
    sig2 = hmac.new(secret.encode("utf-8"), msg2.encode("utf-8"), hashlib.sha256).hexdigest()
    batch_new = [{
        "event_id": ev_id_2,
        "sequence_num": 2,
        "event_type": "DOOR_CLOSED",
        "timestamp": now + 1,
        "signature": sig2,
        "payload": {"status": "closed"}
    }]
    ok3, count3, ids3, _ = p2p_2.receive_sync_batch(device_id, device_token, batch_new, require_event_signatures=True)
    assert ok3 is True
    assert count3 == 1


def test_production_p2p_mandatory_signatures():
    """Vérifie qu'en production, les lots P2P sans signature sont systématiquement rejetés."""
    secret = "cluster_p2p_shared_secret_min_32_chars_ok!"
    device_id = "sensor_radar_02"
    device_token = "radar_token_456"

    old_prod = getattr(config, "IS_PRODUCTION", False)
    config.IS_PRODUCTION = True
    try:
        p2p = P2PSyncManager(cluster_secret=secret)
        p2p.register_device(device_id, device_token)

        now = time.time()
        unsigned_batch = [{
            "event_id": f"p2p_{device_id}_unsigned_{int(now)}",
            "sequence_num": 1,
            "event_type": "RADAR_TRIP",
            "timestamp": now,
            "payload": {"dist": 2.5}
        }]

        # Rejet sans signature
        ok, count, _, _ = p2p.receive_sync_batch(device_id, device_token, unsigned_batch)
        assert ok is True
        assert count == 0
    finally:
        config.IS_PRODUCTION = old_prod


# =============================================================================
# 5.0 CRYPTOGRAPHIE : FAIL-CLOSED SUR CLÉ CORROMPUE & INTÉGRITÉ RFC 3161
# =============================================================================

def test_aes256_gcm_corrupt_key_fail_closed_and_tamper_detection():
    """Vérifie le mode fail-closed face à une clé corrompue et la détection d'altération AAD/Ciphertext."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        # 1. Clé corrompue (taille invalide 16 octets au lieu de 32)
        corrupt_key_path = os.path.join(tmp_dir, "corrupt.key")
        with open(corrupt_key_path, "wb") as f:
            f.write(b"SHORT_KEY_16_BYTES_ONLY")

        shield_corrupt = PrivacyShield(key_file_path=corrupt_key_path)
        assert shield_corrupt.key_status == "PRIVACY_KEY_UNAVAILABLE"

        dummy_file = os.path.join(tmp_dir, "dummy.txt")
        with open(dummy_file, "wb") as f:
            f.write(b"SAMPLE")

        ok_enc, msg = shield_corrupt.encrypt_evidence_file(dummy_file)
        assert ok_enc is False
        assert "PRIVACY_KEY_UNAVAILABLE" in msg

        # 2. Clé valide
        valid_key = AESGCM.generate_key(bit_length=256)
        shield_valid = PrivacyShield(master_key=valid_key, key_id="prod_k1")

        ok_enc, enc_path = shield_valid.encrypt_evidence_file(dummy_file, resource_id="res_doc_10")
        assert ok_enc is True

        # Altération d'un octet de ciphertext
        with open(enc_path, "rb") as f:
            data = bytearray(f.read())
        data[-1] ^= 0xFF  # Flip le dernier octet (tag GCM altéré)
        tampered_path = os.path.join(tmp_dir, "tampered.enc")
        with open(tampered_path, "wb") as f:
            f.write(data)

        req_id = shield_valid.create_decryption_request("res_doc_10", "officer", "Procédure")
        shield_valid.approve_decryption_request(req_id, "admin1", "ADMIN")
        shield_valid.approve_decryption_request(req_id, "admin2", "AUDITOR")

        out_tampered = os.path.join(tmp_dir, "restored.txt")
        ok_dec, msg_dec = shield_valid.execute_authorized_decryption(req_id, tampered_path, out_tampered)
        assert ok_dec is False
        assert "Erreur cryptographique" in msg_dec


def test_local_chained_hmac_tsa_source_consistency():
    """Vérifie l'harmonisation terminologique RFC 3161 : LOCAL_CHAINED_HMAC est certifié."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        integrity_mgr = EvidenceIntegrityManager(
            secret_key="SECURE_HMAC_SECRET_KEY_FOR_INTEGRITY_LOG_CHAIN_2026",
            tsa_server_url=""  # Force le fallback local certifié
        )

        test_file = os.path.join(tmp_dir, "evidence_hash.bin")
        with open(test_file, "wb") as f:
            f.write(b"SAMPLE_EVIDENCE_PAYLOAD_FOR_HASH_VERIFICATION")

        manifest = integrity_mgr.generate_manifest("proof_1", test_file, watermark=False)
        assert manifest.hmac_signature is not None
        # Vérification stricte : la source n'est PAS une autorité de certificat publique mais un HMAC chaîné local
        assert manifest.tsa_source == "LOCAL_CHAINED_HMAC"
        assert manifest.tsa_source != "LOCAL_CERTIFICATE_AUTHORITY"
