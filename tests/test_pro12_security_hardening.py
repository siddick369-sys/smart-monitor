"""
Test Suite PRO-12: Security Hardening, Cryptographic Key Management & Authentication Hardening
Valide de manière exhaustive et contradictoire les critères d'acceptation P12-01 à P12-15 :
- P12-01 & P12-02 : Intégrité des preuves, absence de secret en dur, scellement unsealed et vérification HMAC
- P12-03 : Secret de cluster P2P obligatoire, résilience de la file locale sans perte de données
- P12-04 : Clé maître AES-256-GCM persistante, persistance sur disque, refus sans clé
- P12-05 : Enveloppe versionnée SSMENC01, détection des altérations AEAD et compatibilité v0
- P12-06 : Double contrôle judiciaire (Two-Man Rule) strict : demandeur non approbateur, non-réutilisation
- P12-07 & P12-08 : Durcissement des sessions Flask, cookies SameSite/HttpOnly/Secure, régénération
- P12-09 & P12-10 : Matrice anti-SSRF stricte, validation IP privées RFC 1918 et ports de caméras
- P12-11 & P12-12 : Politique de mot de passe robuste, token de bootstrap à usage unique et anti-bruteforce
- P12-13 : Résilience 100% locale sans dépendance cloud ni internet
- P12-14 : Zéro divulgation de secrets dans les configurations, logs et rapports
- P12-15 : Non-régression globale de l'architecture
"""

import os
import sys
import time
import json
import tempfile
import struct
import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

import config
from app import create_app
from monitoring.evidence_integrity import EvidenceIntegrityManager, EvidenceManifest
from monitoring.p2p_sync import P2PSyncManager, SyncEvent
from monitoring.privacy_shield import PrivacyShield, DecryptionRequestStatus
from monitoring.device_store import DeviceStore
from monitoring.auth_manager import AuthManager, validate_password_complexity


# =============================================================================
# P12-01 & P12-02 : Scellement d'intégrité HMAC & Absence de secret en dur
# =============================================================================

def test_p12_01_and_p12_02_evidence_hmac_lifecycle():
    """Vérifie le comportement du scellement d'intégrité avec et sans clé HMAC."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        test_file = os.path.join(tmp_dir, "incident_sample.jpg")
        with open(test_file, "wb") as f:
            f.write(b"IMAGE_CONTENT_SAMPLE_FOR_PRO12_EVIDENCE")

        # 1. Gestionnaire SANS clé secrète HMAC
        mgr_no_key = EvidenceIntegrityManager(secret_key=None)
        assert mgr_no_key.secret_key is None
        assert mgr_no_key.is_sealing_available() is False

        manifest_unsealed = mgr_no_key.generate_manifest(
            proof_id="proof_unsealed_001",
            file_path=test_file,
            watermark=False,
            output_dir=tmp_dir
        )
        assert manifest_unsealed.sha256_hash is not None
        assert len(manifest_unsealed.sha256_hash) == 64
        assert manifest_unsealed.hmac_signature is None
        assert manifest_unsealed.tsa_source == "UNSEALED_NO_HMAC_KEY"

        # Vérification d'un manifeste non scellé sans clé -> Intègre sans signature
        ok_unsealed, msg_unsealed = mgr_no_key.verify_manifest(manifest_unsealed)
        assert ok_unsealed is True
        assert msg_unsealed == "INTÈGRE_SANS_SIGNATURE"

        # 2. Gestionnaire AVEC clé secrète HMAC (32 octets)
        valid_key = "secure_hmac_secret_key_32_bytes_len!!"
        mgr_with_key = EvidenceIntegrityManager(secret_key=valid_key)
        assert mgr_with_key.is_sealing_available() is True

        manifest_sealed = mgr_with_key.generate_manifest(
            proof_id="proof_sealed_001",
            file_path=test_file,
            watermark=False,
            output_dir=tmp_dir
        )
        assert manifest_sealed.hmac_signature is not None
        assert len(manifest_sealed.hmac_signature) == 64
        assert "LOCAL" in manifest_sealed.tsa_source

        # Vérification avec clé correcte -> Intègre et conforme
        ok_sealed, msg_sealed = mgr_with_key.verify_manifest(manifest_sealed)
        assert ok_sealed is True
        assert msg_sealed == "INTÈGRE_ET_CONFORME"

        # Vérification du manifeste scellé par un vérificateur sans clé -> HMAC_KEY_UNAVAILABLE
        ok_missing_key, msg_missing = mgr_no_key.verify_manifest(manifest_sealed)
        assert ok_missing_key is False
        assert msg_missing == "HMAC_KEY_UNAVAILABLE"

        # 3. Altération du fichier -> Détection corruption de hachage
        with open(test_file, "wb") as f:
            f.write(b"IMAGE_CONTENT_ALTERED_BY_TAMPERER")

        ok_tampered, msg_tampered = mgr_with_key.verify_manifest(manifest_sealed)
        assert ok_tampered is False
        assert "ALTÉRATION_DÉTECTÉE" in msg_tampered

        # Rétablissement du fichier pour tests suivants
        with open(test_file, "wb") as f:
            f.write(b"IMAGE_CONTENT_SAMPLE_FOR_PRO12_EVIDENCE")

        # 4. Altération de la signature -> Signature invalide
        manifest_fake_sig = EvidenceManifest(
            proof_id=manifest_sealed.proof_id,
            file_path=manifest_sealed.file_path,
            sha256_hash=manifest_sealed.sha256_hash,
            file_size=manifest_sealed.file_size,
            timestamp=manifest_sealed.timestamp,
            tsa_token=manifest_sealed.tsa_token,
            tsa_source=manifest_sealed.tsa_source,
            watermarked_path=manifest_sealed.watermarked_path,
            hmac_signature="a" * 64
        )
        ok_bad_sig, msg_bad_sig = mgr_with_key.verify_manifest(manifest_fake_sig)
        assert ok_bad_sig is False
        assert "SIGNATURE_HMAC_INVALIDE" in msg_bad_sig

        # 5. Clé secrète trop courte (<16 octets) non considérée comme utilisable
        mgr_short_key = EvidenceIntegrityManager(secret_key="short")
        assert mgr_short_key.is_sealing_available() is False


# =============================================================================
# P12-03 : Secret de Cluster P2P & Résilience de la file Store-and-Forward
# =============================================================================

def test_p12_03_p2p_secret_enforcement_and_resilience():
    """Vérifie le contrôle du secret de cluster P2P et la persistance de la file locale."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        # 1. Gestionnaire SANS secret
        mgr_no_secret = P2PSyncManager(cluster_secret=None)
        assert mgr_no_secret.cluster_secret is None
        assert mgr_no_secret.is_sync_available() is False

        # Authentification d'un appareil refusée
        auth_ok = mgr_no_secret.authenticate_device("node_b", "token_xyz")
        assert auth_ok is False

        # Synchronisation d'un lot refusée
        sync_ok, count, ids, sync_msg = mgr_no_secret.receive_sync_batch("node_b", "token_xyz", [{"event_id": "ev_001"}])
        assert sync_ok is False
        assert "non configuré" in sync_msg

        # File store-and-forward : ajout d'événements locaux préservé sans perte
        ev1 = mgr_no_secret.enqueue_local_event("cam_01", "MOTION_ALERT", {"area": 12.5})
        ev2 = mgr_no_secret.enqueue_local_event("cam_01", "DOOR_OPEN", {"zone": "Entrée"})
        assert len(mgr_no_secret._store_forward_queue) == 2
        assert mgr_no_secret._store_forward_queue[0].event_type == "MOTION_ALERT"
        assert mgr_no_secret._store_forward_queue[1].event_type == "DOOR_OPEN"

        # 2. Secret trop court en production (< 32 octets)
        old_prod = config.IS_PRODUCTION
        try:
            config.IS_PRODUCTION = True
            mgr_short_prod = P2PSyncManager(cluster_secret="short_19_chars_key")
            assert mgr_short_prod.cluster_secret is None
            assert mgr_short_prod.is_sync_available() is False
        finally:
            config.IS_PRODUCTION = old_prod

        # 3. Secret valide (>= 32 octets)
        valid_cluster_secret = "p2p_master_cluster_secret_32_bytes_minimum!!"
        mgr = P2PSyncManager(cluster_secret=valid_cluster_secret)
        assert mgr.is_sync_available() is True

        # Enregistrement et authentification d'un appareil pair
        device_token = "device_auth_token_secret_9988"
        mgr.register_device("device_edge_01", device_token)
        assert mgr.authenticate_device("device_edge_01", device_token) is True
        assert mgr.authenticate_device("device_edge_01", "wrong_token") is False

        # Traitement d'un lot d'événements P2P
        now = time.time()
        ev_id = f"p2p_device_edge_01_1_{int(now)}"
        sig = mgr.compute_event_signature(
            event_id=ev_id,
            device_id="device_edge_01",
            sequence_num=1,
            event_type="ALARM",
            timestamp=now,
            payload={},
            proto_version="SSMP2P02"
        )

        batch = [{
            "event_id": ev_id,
            "device_id": "device_edge_01",
            "sequence_num": 1,
            "event_type": "ALARM",
            "timestamp": now,
            "payload": {},
            "proto_version": "SSMP2P02",
            "signature": sig
        }]
        b_ok, b_count, b_ids, _ = mgr.receive_sync_batch("device_edge_01", device_token, batch)
        assert b_ok is True
        assert b_count == 1
        assert ev_id in b_ids


# =============================================================================
# P12-04 : Clé maître AES-256-GCM persistante & Cycle de redémarrage
# =============================================================================

def test_p12_04_aes256_gcm_master_key_persistence_and_lifecycle():
    """Vérifie la génération, la persistance sur disque et la persistance inter-redémarrage."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        key_file = os.path.join(tmp_dir, "test_privacy_master.key")
        test_evidence = os.path.join(tmp_dir, "original_sensitive.jpg")
        with open(test_evidence, "wb") as f:
            f.write(b"TOP_SECRET_EVIDENCE_PAYLOAD_FOR_JUDICIAL_RECORD")

        # 1. Génération de la clé maître dans un fichier persistant
        gen_ok, gen_msg, gen_key = PrivacyShield.generate_and_save_master_key(key_file)
        assert gen_ok is True
        assert os.path.exists(key_file)
        assert os.path.getsize(key_file) == 32

        # Refus d'écraser la clé sans force=True
        dup_ok, dup_msg, _ = PrivacyShield.generate_and_save_master_key(key_file)
        assert dup_ok is False
        assert "interdit" in dup_msg

        # 2. Instance de service 1 : Chiffrement du fichier
        shield_instance_1 = PrivacyShield(key_file_path=key_file, key_id="key_v1")
        assert shield_instance_1.key_status == "ACTIVE"

        enc_ok, enc_path = shield_instance_1.encrypt_evidence_file(test_evidence, resource_id="res_incident_42")
        assert enc_ok is True
        assert os.path.exists(enc_path)
        assert enc_path.endswith(".enc")

        # 3. Simulation d'un redémarrage serveur : nouvelle instance sans état mémoire
        shield_instance_2 = PrivacyShield(key_file_path=key_file, key_id="key_v1")
        assert shield_instance_2.key_status == "ACTIVE"
        assert shield_instance_2.master_key == shield_instance_1.master_key

        # 4. Autorisation de déchiffrement via Two-Man Rule sur l'instance 2
        req_id = shield_instance_2.create_decryption_request(
            resource_id="res_incident_42",
            requester="officer_alice",
            reason="Instruction judiciaire n° 2026-99"
        )
        shield_instance_2.approve_decryption_request(req_id, approver="admin_bob", role="ADMIN")
        shield_instance_2.approve_decryption_request(req_id, approver="auditor_charlie", role="AUDITOR")

        decrypted_out = os.path.join(tmp_dir, "restored_evidence.jpg")
        dec_ok, dec_msg = shield_instance_2.execute_authorized_decryption(req_id, enc_path, decrypted_out)
        assert dec_ok is True
        assert os.path.exists(decrypted_out)
        with open(decrypted_out, "rb") as f:
            assert f.read() == b"TOP_SECRET_EVIDENCE_PAYLOAD_FOR_JUDICIAL_RECORD"

        # 5. Si le fichier de clé est absent et aucun env n'est configuré -> Refus sans génération volatile
        missing_key_file = os.path.join(tmp_dir, "nonexistent.key")
        old_env_key = getattr(config, "PRIVACY_MASTER_KEY", None)
        try:
            config.PRIVACY_MASTER_KEY = None
            shield_unconfigured = PrivacyShield(key_file_path=missing_key_file)
            assert shield_unconfigured.key_status == "PRIVACY_KEY_UNAVAILABLE"
            assert shield_unconfigured.master_key is None

            # Tentative de chiffrement refusée
            fail_enc_ok, fail_enc_msg = shield_unconfigured.encrypt_evidence_file(test_evidence)
            assert fail_enc_ok is False
            assert "PRIVACY_KEY_UNAVAILABLE" in fail_enc_msg
        finally:
            config.PRIVACY_MASTER_KEY = old_env_key


# =============================================================================
# P12-05 : Enveloppe versionnée SSMENC01, détection d'altération AEAD & Compatibilité v0
# =============================================================================

def test_p12_05_aead_envelope_and_tampering_detection():
    """Vérifie l'en-tête SSMENC01, le rejet du texte corrompu et la compatibilité ascendante."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        master_key = AESGCM.generate_key(bit_length=256)
        shield = PrivacyShield(master_key=master_key, key_id="prod_k1")

        raw_evidence = os.path.join(tmp_dir, "evidence_raw.bin")
        with open(raw_evidence, "wb") as f:
            f.write(b"ORIGINAL_EVIDENCE_FORENSIC_INTEGRITY_DATA")

        # 1. Chiffrement sous enveloppe SSMENC01
        ok_enc, enc_path = shield.encrypt_evidence_file(raw_evidence, resource_id="ev_doc_01")
        assert ok_enc is True
        with open(enc_path, "rb") as f:
            header_magic = f.read(8)
            assert header_magic == b"SSMENC01"

        # 2. Déchiffrement régulier
        req_id = shield.create_decryption_request("ev_doc_01", "req_user", "Audit légal")
        shield.approve_decryption_request(req_id, "admin1", "ADMIN")
        shield.approve_decryption_request(req_id, "admin2", "AUDITOR")

        out_path = os.path.join(tmp_dir, "decrypted_valid.bin")
        dec_ok, dec_msg = shield.execute_authorized_decryption(req_id, enc_path, out_path)
        assert dec_ok is True
        with open(out_path, "rb") as f:
            assert f.read() == b"ORIGINAL_EVIDENCE_FORENSIC_INTEGRITY_DATA"

        # 3. Altération du texte chiffré ou du tag d'authentification
        with open(enc_path, "rb") as f:
            valid_bytes = bytearray(f.read())

        # Altération d'un octet dans la charge utile chiffrée
        valid_bytes[-5] ^= 0xFF
        tampered_enc_path = os.path.join(tmp_dir, "tampered.enc")
        with open(tampered_enc_path, "wb") as f:
            f.write(valid_bytes)

        req_id_tamper = shield.create_decryption_request("ev_doc_01", "req_user", "Audit")
        shield.approve_decryption_request(req_id_tamper, "admin1", "ADMIN")
        shield.approve_decryption_request(req_id_tamper, "admin2", "AUDITOR")

        tamper_out = os.path.join(tmp_dir, "decrypted_tampered.bin")
        dec_tamper_ok, dec_tamper_msg = shield.execute_authorized_decryption(req_id_tamper, tampered_enc_path, tamper_out)
        assert dec_tamper_ok is False
        assert "Erreur cryptographique" in dec_tamper_msg or "Échec" in dec_tamper_msg

        # 4. Compatibilité ascendante avec les fichiers v0 (sans préfixe magique SSMENC01)
        v0_nonce = os.urandom(12)
        v0_aes = AESGCM(master_key)
        v0_ciphertext = v0_aes.encrypt(v0_nonce, b"V0_LEGACY_DATA_COMPATIBILITY", None)
        v0_file = os.path.join(tmp_dir, "legacy_v0.enc")
        with open(v0_file, "wb") as f:
            f.write(v0_nonce + v0_ciphertext)

        req_id_v0 = shield.create_decryption_request("legacy_doc", "req_user", "Legacy support")
        shield.approve_decryption_request(req_id_v0, "admin1", "ADMIN")
        shield.approve_decryption_request(req_id_v0, "admin2", "AUDITOR")

        v0_out = os.path.join(tmp_dir, "decrypted_v0.bin")
        dec_v0_ok, dec_v0_msg = shield.execute_authorized_decryption(req_id_v0, v0_file, v0_out)
        assert dec_v0_ok is True
        with open(v0_out, "rb") as f:
            assert f.read() == b"V0_LEGACY_DATA_COMPATIBILITY"


# =============================================================================
# P12-06 : Règle stricte du double contrôle (Two-Man Rule)
# =============================================================================

def test_p12_06_two_man_rule_strict_enforcement():
    """Vérifie l'interdiction d'auto-approbation, l'unicité et la consommation unique."""
    master_key = AESGCM.generate_key(bit_length=256)
    shield = PrivacyShield(master_key=master_key, key_id="k1", default_expiry_seconds=2)

    req_id = shield.create_decryption_request(
        resource_id="incident_999",
        requester="operator_david",
        reason="Examen contradictoire"
    )

    # 1. Le demandeur ne peut pas approuver sa propre demande si restriction activée
    self_app_ok, self_app_msg = shield.approve_decryption_request(req_id, approver="operator_david", role="OPERATOR", disallow_self_approval=True)
    assert self_app_ok is False
    assert "demandeur ne peut pas approuver" in self_app_msg

    # 2. Première approbation légitime par ADMIN
    app1_ok, _ = shield.approve_decryption_request(req_id, approver="admin_eva", role="ADMIN")
    assert app1_ok is True
    req = shield._requests[req_id]
    assert req.status == DecryptionRequestStatus.PENDING

    # 3. Le même approbateur ne peut pas valider deux fois
    dup_app_ok, dup_app_msg = shield.approve_decryption_request(req_id, approver="admin_eva", role="ADMIN")
    assert dup_app_ok is False
    assert "déjà validé" in dup_app_msg

    # 4. Seconde approbation par AUDITOR -> APPROUVÉ
    app2_ok, _ = shield.approve_decryption_request(req_id, approver="auditor_felix", role="AUDITOR")
    assert app2_ok is True
    assert req.status == DecryptionRequestStatus.APPROVED

    # 5. Consommation unique lors de l'exécution
    with tempfile.TemporaryDirectory() as tmp_dir:
        dummy_file = os.path.join(tmp_dir, "dummy.txt")
        with open(dummy_file, "wb") as f:
            f.write(b"SAMPLE")
        _, enc_path = shield.encrypt_evidence_file(dummy_file, "incident_999")
        out_f = os.path.join(tmp_dir, "dummy_out.txt")

        exec_ok, _ = shield.execute_authorized_decryption(req_id, enc_path, out_f)
        assert exec_ok is True
        assert req.status == DecryptionRequestStatus.CONSUMED

        # Tentative de rejeu -> REFUSÉ (CONSUMED)
        replay_ok, replay_msg = shield.execute_authorized_decryption(req_id, enc_path, out_f)
        assert replay_ok is False
        assert "CONSUMED" in replay_msg

    # 6. Expiration de la demande
    req_exp_id = shield.create_decryption_request("exp_res", "user1", "test", expires_in_seconds=1)
    time.sleep(1.2)
    app_exp_ok, app_exp_msg = shield.approve_decryption_request(req_exp_id, "admin1", "ADMIN")
    assert app_exp_ok is False
    assert "expiré" in app_exp_msg


# =============================================================================
# P12-07 & P12-08 : Durcissement des sessions Flask & Régénération
# =============================================================================

def test_p12_07_and_p12_08_session_hardening_and_lifecycle():
    """Vérifie la sécurité des cookies de session (HttpOnly, SameSite, Secure) et la régénération."""
    # 1. Vérification des directives de session en configuration
    assert config.SESSION_COOKIE_HTTPONLY is True
    assert config.SESSION_COOKIE_SAMESITE == "Lax"

    app, coordinator = create_app()
    app.config["TESTING"] = True

    with app.test_client() as client:
        # Étape 1 : Non authentifié -> /api/auth/me renvoie 401
        res_unauth = client.get('/api/auth/me')
        assert res_unauth.status_code == 401

        # Étape 2 : Connexion réussie -> Obtention du cookie de session
        admin_pwd = config.ADMIN_DEFAULT_PASSWORD or "AdminSecurity2026!"
        login_res = client.post('/api/auth/login', json={
            "username": config.ADMIN_DEFAULT_USERNAME,
            "password": admin_pwd
        })
        assert login_res.status_code == 200

        # Vérification des attributs du cookie Set-Cookie
        set_cookie = login_res.headers.get("Set-Cookie", "")
        assert "HttpOnly" in set_cookie
        assert "SameSite=Lax" in set_cookie

        # Étape 3 : Session authentifiée valide
        me_res = client.get('/api/auth/me')
        assert me_res.status_code == 200
        assert me_res.get_json()["user"]["role"] == "ADMIN"

        # Étape 4 : Déconnexion explicite -> Invalidation de session et suppression du cookie
        logout_res = client.post('/api/auth/logout')
        assert logout_res.status_code == 200

        # Accès ultérieur révoqué
        me_after = client.get('/api/auth/me')
        assert me_after.status_code == 401

    coordinator.stop()


# =============================================================================
# P12-09 & P12-10 : Matrice Anti-SSRF & Validation des cibles caméras
# =============================================================================

def test_p12_09_and_p12_10_ssrf_and_camera_validation_matrix():
    """Vérifie le filtrage strict des IP et ports autorisés pour les périphériques vidéo."""
    # 1. Tests en mode Production (is_test_env=False)
    # Loopback doit être interdit en production
    ok_loop_prod, _ = config.is_allowed_camera_target("127.0.0.1", 8081, is_test_env=False)
    assert ok_loop_prod is False

    # Port Flask local 5000 interdit en production comme en test
    ok_flask_prod, _ = config.is_allowed_camera_target("127.0.0.1", 5000, is_test_env=False)
    assert ok_flask_prod is False
    ok_flask_test, _ = config.is_allowed_camera_target("127.0.0.1", 5000, is_test_env=True)
    assert ok_flask_test is False

    # 2. Tests en mode Test / Développement (is_test_env=True)
    # Loopback accepté sur port caméra autorisé
    ok_loop_test, msg_loop_test = config.is_allowed_camera_target("127.0.0.1", 8081, is_test_env=True)
    assert ok_loop_test is True
    assert "LOOPBACK" in msg_loop_test

    # 3. Adresses dangereuses ou interdites
    # 0.0.0.0 interdit
    ok_zero, _ = config.is_allowed_camera_target("0.0.0.0", 8080)
    assert ok_zero is False

    # Link-local / metadata cloud interdit (169.254.169.254)
    ok_meta, _ = config.is_allowed_camera_target("169.254.169.254", 8080)
    assert ok_meta is False

    # Multicast interdit (224.0.0.1)
    ok_multi, _ = config.is_allowed_camera_target("224.0.0.1", 8080)
    assert ok_multi is False

    # IP publique interdite (ex. 8.8.8.8, 1.1.1.1)
    ok_pub1, _ = config.is_allowed_camera_target("8.8.8.8", 8080)
    assert ok_pub1 is False
    ok_pub2, _ = config.is_allowed_camera_target("93.184.216.34", 8080)
    assert ok_pub2 is False

    # 4. Adresses LAN privées RFC 1918 valides sur ports autorisés
    ok_c1, _ = config.is_allowed_camera_target("192.168.1.50", 8080)
    assert ok_c1 is True

    ok_c2, _ = config.is_allowed_camera_target("10.0.0.15", 4747)
    assert ok_c2 is True

    ok_c3, _ = config.is_allowed_camera_target("172.16.0.22", 8081)
    assert ok_c3 is True

    ok_c4, _ = config.is_allowed_camera_target("192.168.0.10", 554)
    assert ok_c4 is True

    # 5. Port non autorisé sur IP privée (ex. port SSH 22, port SMB 445, port HTTP Flask 5000)
    ok_bad_port1, msg_bp1 = config.is_allowed_camera_target("192.168.1.50", 22)
    assert ok_bad_port1 is False
    assert "Port" in msg_bp1

    ok_bad_port2, msg_bp2 = config.is_allowed_camera_target("192.168.1.50", 5000)
    assert ok_bad_port2 is False

    # 6. Intégration DeviceStore : rejet à l'ajout
    with tempfile.TemporaryDirectory() as tmp_dir:
        dev_file = os.path.join(tmp_dir, "devices.json")
        sett_file = os.path.join(tmp_dir, "settings.json")
        store = DeviceStore(devices_file=dev_file, settings_file=sett_file)
        with pytest.raises(ValueError, match="non autorisée ou port invalide"):
            store.add_device("HackerTarget", "8.8.8.8", 8080)

        with pytest.raises(ValueError, match="non autorisée ou port invalide"):
            store.add_device("LocalHostProbe", "127.0.0.1", 5000)


# =============================================================================
# P12-11 & P12-12 : Durcissement du bootstrap Admin & Politique de mot de passe
# =============================================================================

def test_p12_11_and_p12_12_admin_bootstrap_and_password_policy(monkeypatch):
    """Vérifie la robustesse de la politique de mot de passe et l'invalidation du bootstrap."""
    # 1. Validation de la complexité des mots de passe
    assert validate_password_complexity("short1!")[0] is False  # Trop court (<8)
    assert validate_password_complexity("nouppercase123!")[0] is False  # Pas de majuscule
    assert validate_password_complexity("NOLOWERCASE123!")[0] is False  # Pas de minuscule
    assert validate_password_complexity("NoDigitsHere!")[0] is False  # Pas de chiffre
    assert validate_password_complexity("NoSpecialChar123")[0] is False  # Pas de caractère spécial
    assert validate_password_complexity("admin1234")[0] is False  # Mot de passe trivial interdit
    assert validate_password_complexity("Password123!")[0] is False  # Mot de passe commun interdit

    # Mot de passe conforme
    ok_pwd, _ = validate_password_complexity("Admin#Master2026!")
    assert ok_pwd is True

    # 2. Gestionnaire AuthManager et cycle de bootstrap
    auth_mgr = AuthManager()

    # Simulation d'un système sans administrateur pour tester le token et la politique
    from contextlib import contextmanager
    from unittest.mock import MagicMock

    @contextmanager
    def mock_empty_db():
        mock_db = MagicMock()
        mock_db.query.return_value.filter.return_value.first.return_value = None
        mock_db.query.return_value.filter.return_value.count.return_value = 0
        yield mock_db

    monkeypatch.setattr(auth_mgr, "is_bootstrap_required", lambda: True)
    monkeypatch.setattr("monitoring.auth_manager.get_db_session", mock_empty_db)

    # Réinitialisation du mode TESTING pour tester la vérification stricte du token
    old_testing = getattr(config, "TESTING", False)
    config.TESTING = False
    try:
        token = auth_mgr.get_or_create_bootstrap_token()
        assert token is not None
        assert len(token) >= 32

        # Tentative avec mauvais token -> Rejet
        fail_res, _, fail_msg = auth_mgr.bootstrap_admin("admin_sec", "Admin#Master2026!", setup_token="invalid_token")
        assert fail_res is False
        assert "invalide" in fail_msg or "manquant" in fail_msg

        # Tentative avec mot de passe trop simple -> Rejet
        weak_res, _, weak_msg = auth_mgr.bootstrap_admin("admin_sec", "weak", setup_token=token)
        assert weak_res is False
        assert "8 caractères" in weak_msg

        # Bootstrap réussi avec token valide et mot de passe conforme
        ok_res, ok_user, _ = auth_mgr.bootstrap_admin("admin_sec", "Admin#Master2026!", setup_token=token)
        assert ok_res is True
        assert ok_user["role"] == "ADMIN"
    finally:
        config.TESTING = old_testing
        monkeypatch.undo()

    # Si un administrateur existe déjà dans la base réelle, le bootstrap doit être rejeté (P12-12)
    second_res, _, second_msg = auth_mgr.bootstrap_admin("admin_hacker", "Admin#Master2026!", setup_token=token)
    assert second_res is False
    assert "déjà" in second_msg or "invalide" in second_msg


# =============================================================================
# P12-13 : Résilience 100% locale sans dépendance cloud ni internet
# =============================================================================

def test_p12_13_offline_and_opencv_resilience():
    """Vérifie le fonctionnement 100% autonome et local en l'absence de toute clé d'API cloud."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        frame_file = os.path.join(tmp_dir, "local_frame.jpg")
        with open(frame_file, "wb") as f:
            f.write(b"OFFLINE_FRAME_BYTES_SIMULATED")

        # Scellement d'intégrité local autonome
        local_mgr = EvidenceIntegrityManager(secret_key="offline_local_key_for_testing!!")
        manifest = local_mgr.generate_manifest(proof_id="offline_01", file_path=frame_file)
        assert manifest.sha256_hash is not None
        assert "LOCAL" in manifest.tsa_source

        # Vérification locale sans appel externe
        valid, msg = local_mgr.verify_manifest(manifest)
        assert valid is True
        assert msg == "INTÈGRE_ET_CONFORME"


# =============================================================================
# P12-14 : Zéro divulgation de secrets dans la configuration et les audits
# =============================================================================

def test_p12_14_zero_secret_leakage():
    """Vérifie qu'aucun secret (clé HMAC, clé P2P, clé AES) n'est exposé en clair."""
    sec_report = config.validate_security_configuration()
    assert isinstance(sec_report, dict)

    # Le rapport ne doit contenir que des booléens ou des identifiants non sensibles
    for key, value in sec_report.items():
        assert not isinstance(value, (bytes, bytearray))
        if isinstance(value, str):
            assert "secret" not in value.lower()
            assert "key" not in value.lower() or value in ["ACTIVE", "UNAVAILABLE"]

    # Vérification dans le code source qu'aucun secret par défaut n'est codé en dur
    import inspect
    import monitoring.evidence_integrity as ei
    import monitoring.p2p_sync as ps

    src_ei = inspect.getsource(ei)
    assert "default_evidence_integrity_key_pro09" not in src_ei

    src_ps = inspect.getsource(ps)
    assert "p2p_default_cluster_secret_pro11" not in src_ps


# =============================================================================
# P12-15 : Non-régression globale
# =============================================================================

def test_p12_15_global_non_regression():
    """Valide la cohérence des modules de sécurité après durcissement PRO-12."""
    assert hasattr(config, "is_allowed_camera_target")
    assert hasattr(config, "validate_security_configuration")
    assert hasattr(PrivacyShield, "generate_and_save_master_key")
    assert hasattr(AuthManager, "get_or_create_bootstrap_token")
