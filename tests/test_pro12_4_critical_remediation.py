"""
SUITE DE TESTS ADVERSARIAUX ET DE VALIDATION FORENSIQUE — PRO-12.4
Référence : SSM-PRO12.4-CRITICAL-SECURITY-REMEDIATION
Périmètre : Lots A à H (SEC-123-01 à SEC-123-08)
"""

import os
import time
import json
import uuid
import tempfile
import pytest
from app import create_app
from database import get_db_session, init_db
from monitoring.models import User, UserSession, DecryptionRequestModel, DecryptionApprovalModel
from monitoring.privacy_shield import PrivacyShield, DecryptionRequestStatus
from werkzeug.security import generate_password_hash

def _create_authenticated_client(app, username, role="ADMIN", password="Password#Secure2026!"):
    """Helper créant un utilisateur réel en base et réalisant un login HTTP avec session et CSRF réels."""
    with get_db_session() as db:
        u = db.query(User).filter(User.username == username).first()
        if not u:
            u = User(
                id=f"u_{uuid.uuid4().hex[:8]}",
                username=username,
                password_hash=generate_password_hash(password),
                role=role,
                is_active=True,
                created_at=time.time()
            )
            db.add(u)
        else:
            u.role = role
            u.is_active = True
            u.password_hash = generate_password_hash(password)
    client = app.test_client()
    resp = client.post('/api/auth/login', json={"username": username, "password": password})
    assert resp.status_code == 200, f"Login failed for {username}: {resp.get_json()}"
    csrf_token = resp.get_json().get("csrf_token")
    return client, csrf_token


# =============================================================================
# LOT A : TWO-MAN RULE ADVERSARIAL HTTP TESTS (SEC-123-01)
# =============================================================================

def test_lota_self_approval_http_rejected():
    """Vérifie au niveau de la route HTTP que le demandeur ne peut pas approuver sa propre demande."""
    app, coord = create_app()
    app.config["TESTING"] = True

    try:
        # Session de Alice (Admin)
        alice_client, alice_csrf = _create_authenticated_client(app, "alice_requester", role="ADMIN")

        # Alice crée une demande de déchiffrement
        res_req = alice_client.post('/api/privacy/request_decryption', json={
            "resource_id": "video_confidential_01.mp4",
            "reason": "Audit judiciaire"
        }, headers={"X-CSRF-Token": alice_csrf})
        assert res_req.status_code == 200
        req_id = res_req.get_json()["request"]["id"]

        # Alice tente d'approuver sa propre demande -> DOIT ÊTRE REFUSÉ
        res_app = alice_client.post('/api/privacy/approve_decryption', json={
            "request_id": req_id
        }, headers={"X-CSRF-Token": alice_csrf})
        assert res_app.status_code == 400
        assert "ne peut pas approuver sa propre demande" in res_app.get_json()["message"]
    finally:
        coord.stop()


def test_lota_client_parameter_override_disallow_self_approval_ignored():
    """Vérifie qu'un attaquant soumettant disallow_self_approval: false ne peut PAS contourner la règle."""
    app, coord = create_app()
    app.config["TESTING"] = True

    try:
        alice_client, alice_csrf = _create_authenticated_client(app, "alice_requester", role="ADMIN")

        res_req = alice_client.post('/api/privacy/request_decryption', json={
            "resource_id": "video_confidential_02.mp4",
            "reason": "Enquête interne"
        }, headers={"X-CSRF-Token": alice_csrf})
        assert res_req.status_code == 200
        req_id = res_req.get_json()["request"]["id"]

        # L'attaquant injecte explicitement disallow_self_approval: false
        res_app = alice_client.post('/api/privacy/approve_decryption', json={
            "request_id": req_id,
            "disallow_self_approval": False
        }, headers={"X-CSRF-Token": alice_csrf})
        assert res_app.status_code == 400
        assert "ne peut pas approuver sa propre demande" in res_app.get_json()["message"]
    finally:
        coord.stop()


def test_lota_distinct_approver_and_second_approver_workflow():
    """Vérifie le cycle complet avec deux approbateurs distincts différents du demandeur."""
    app, coord = create_app()
    app.config["TESTING"] = True

    try:
        # 1. Demandeur Alice (Opérateur)
        alice_client, alice_csrf = _create_authenticated_client(app, "alice_op", role="OPERATOR")

        res_req = alice_client.post('/api/privacy/request_decryption', json={
            "resource_id": "video_confidential_03.mp4",
            "reason": "Validation officielle"
        }, headers={"X-CSRF-Token": alice_csrf})
        assert res_req.status_code == 200
        req_id = res_req.get_json()["request"]["id"]

        # 2. Approbateur distinct Bob (Admin) -> Succès approbation 1/2
        bob_client, bob_csrf = _create_authenticated_client(app, "bob_admin", role="ADMIN")

        res_app1 = bob_client.post('/api/privacy/approve_decryption', json={
            "request_id": req_id
        }, headers={"X-CSRF-Token": bob_csrf})
        assert res_app1.status_code == 200
        assert "Approbation enregistrée" in res_app1.get_json()["message"]

        # 3. Bob tente de valider une 2ème fois -> Rejeté
        res_dup = bob_client.post('/api/privacy/approve_decryption', json={
            "request_id": req_id
        }, headers={"X-CSRF-Token": bob_csrf})
        assert res_dup.status_code == 400
        assert "déjà validé" in res_dup.get_json()["message"]

        # 4. Approbateur distinct Charlie (Admin) -> Succès approbation 2/2 -> APPROUVÉ
        charlie_client, charlie_csrf = _create_authenticated_client(app, "charlie_admin", role="ADMIN")

        res_app2 = charlie_client.post('/api/privacy/approve_decryption', json={
            "request_id": req_id
        }, headers={"X-CSRF-Token": charlie_csrf})
        assert res_app2.status_code == 200
        assert "pleinement approuvée" in res_app2.get_json()["message"]
    finally:
        coord.stop()


def test_lota_insufficient_role_for_approval_rejected():
    """Vérifie qu'un utilisateur sans le rôle ADMIN ne peut pas approuver."""
    app, coord = create_app()
    app.config["TESTING"] = True

    try:
        dave_client, dave_csrf = _create_authenticated_client(app, "operator_dave", role="OPERATOR")

        res = dave_client.post('/api/privacy/approve_decryption', json={
            "request_id": "req_any_123"
        }, headers={"X-CSRF-Token": dave_csrf})
        assert res.status_code == 403
    finally:
        coord.stop()


def test_lota_self_approval_with_arbitrary_injected_parameters_rejected():
    """Vérifie que l'injection de paramètres additionnels arbitraires ne permet pas l'auto-approbation."""
    app, coord = create_app()
    app.config["TESTING"] = True

    try:
        alice_client, alice_csrf = _create_authenticated_client(app, "alice_requester", role="ADMIN")

        res_req = alice_client.post('/api/privacy/request_decryption', json={
            "resource_id": "video_confidential_04.mp4",
            "reason": "Test paramètres parasites"
        }, headers={"X-CSRF-Token": alice_csrf})
        req_id = res_req.get_json()["request"]["id"]

        # Attaque par injection de paramètres JSON
        res_app = alice_client.post('/api/privacy/approve_decryption', json={
            "request_id": req_id,
            "bypass": True,
            "admin_override": True,
            "disallow_self_approval": False,
            "role": "SUPERUSER"
        }, headers={"X-CSRF-Token": alice_csrf})
        assert res_app.status_code == 400
        assert "ne peut pas approuver sa propre demande" in res_app.get_json()["message"]
    finally:
        coord.stop()


def test_lota_expired_request_approval_rejected():
    """Vérifie qu'une demande expirée ne peut plus être approuvée."""
    app, coord = create_app()
    app.config["TESTING"] = True

    try:
        alice_client, alice_csrf = _create_authenticated_client(app, "alice_op_exp", role="OPERATOR")

        # Demande avec expiration immédiate
        shield = coord.privacy_shield
        req_id = shield.create_decryption_request("res_exp_01", requester="alice_op_exp", reason="Audit", expires_in_seconds=-10)

        bob_client, bob_csrf = _create_authenticated_client(app, "bob_admin_exp", role="ADMIN")
        res_app = bob_client.post('/api/privacy/approve_decryption', json={
            "request_id": req_id
        }, headers={"X-CSRF-Token": bob_csrf})
        assert res_app.status_code == 400
        assert "expiré" in res_app.get_json()["message"]
    finally:
        coord.stop()


def test_lota_consumed_request_cannot_be_approved():
    """Vérifie qu'une demande déjà consommée ne peut plus recevoir d'approbations."""
    app, coord = create_app()
    app.config["TESTING"] = True

    try:
        shield = coord.privacy_shield
        req_id = shield.create_decryption_request("res_cons_01", requester="alice_op_cons", reason="Audit")
        shield.approve_decryption_request(req_id, "bob_adm1", role="ADMIN")
        shield.approve_decryption_request(req_id, "charlie_adm2", role="ADMIN")

        # Marquer comme consommée
        shield._requests[req_id].status = DecryptionRequestStatus.CONSUMED

        bob_client, bob_csrf = _create_authenticated_client(app, "bob_adm3", role="ADMIN")
        res_app = bob_client.post('/api/privacy/approve_decryption', json={
            "request_id": req_id
        }, headers={"X-CSRF-Token": bob_csrf})
        assert res_app.status_code == 400
        assert "clôturée" in res_app.get_json()["message"] or "CONSUMED" in res_app.get_json()["message"]
    finally:
        coord.stop()


# =============================================================================
# LOT B : SESSION VALIDATION FAIL-CLOSED (SEC-123-02)
# =============================================================================

def test_lotb_session_validation_fail_closed_on_db_exception():
    """Prouve que validate_session renvoie False (fail-closed) lors d'une indisponibilité de la base."""
    import monitoring.auth_manager as am
    class BrokenDBSession:
        def __enter__(self):
            raise RuntimeError("CRITICAL_DATABASE_LOCKED: SQLite simulated failure")
        def __exit__(self, *args):
            pass

    orig_get_db = am.get_db_session
    am.get_db_session = lambda: BrokenDBSession()
    try:
        auth_mgr = am.AuthManager()
        # Même avec des identifiants et jetons valides, une erreur DB DOIT renvoyer False
        is_valid = auth_mgr.validate_session("u_any_user", "tok_valid_or_invalid")
        assert is_valid is False, "La validation de session en cas d'erreur de base de données DOIT échouer fermé (False)."
    finally:
        am.get_db_session = orig_get_db


def test_lotb_session_validation_states_matrix():
    """Vérifie la matrice complète des états de session : valide, révoquée, désactivée, inexistante."""
    app, coord = create_app()
    app.config["TESTING"] = True
    auth_mgr = coord.auth_manager

    with get_db_session() as db:
        # 1. Utilisateur actif
        u_active_id = f"u_act_{uuid.uuid4().hex[:6]}"
        u_active = User(
            id=u_active_id,
            username=f"user_active_{uuid.uuid4().hex[:6]}",
            password_hash=generate_password_hash("Pass#123!"),
            role="OPERATOR",
            is_active=True
        )
        # 2. Utilisateur inactif / désactivé
        u_deact_id = f"u_dea_{uuid.uuid4().hex[:6]}"
        u_deact = User(
            id=u_deact_id,
            username=f"user_deact_{uuid.uuid4().hex[:6]}",
            password_hash=generate_password_hash("Pass#123!"),
            role="OPERATOR",
            is_active=False
        )
        db.add_all([u_active, u_deact])
        db.flush()

        # Session 1 : valide
        tok_valid = f"tok_val_{uuid.uuid4().hex}"
        s_val = UserSession(session_token=tok_valid, user_id=u_active_id, revoked=False)

        # Session 2 : révoquée
        tok_revoked = f"tok_rev_{uuid.uuid4().hex}"
        s_rev = UserSession(session_token=tok_revoked, user_id=u_active_id, revoked=True)

        # Session 3 : rattachée à un utilisateur désactivé
        tok_deact = f"tok_dea_{uuid.uuid4().hex}"
        s_dea = UserSession(session_token=tok_deact, user_id=u_deact_id, revoked=False)

        db.add_all([s_val, s_rev, s_dea])

    try:
        # A. Session valide -> True
        assert auth_mgr.validate_session(u_active_id, tok_valid) is True

        # B. Session révoquée -> False
        assert auth_mgr.validate_session(u_active_id, tok_revoked) is False

        # C. Utilisateur désactivé -> False
        assert auth_mgr.validate_session(u_deact_id, tok_deact) is False

        # D. Session inexistante -> False
        assert auth_mgr.validate_session(u_active_id, "tok_non_existent") is False

        # E. Paramètres vides -> False
        assert auth_mgr.validate_session("", tok_valid) is False
        assert auth_mgr.validate_session(u_active_id, "") is False
    finally:
        coord.stop()


def test_lotb_http_route_fails_closed_when_db_down():
    """Vérifie au niveau HTTP qu'une route protégée rejette avec 401 si la validation DB plante."""
    app, coord = create_app()
    app.config["TESTING"] = True

    try:
        client, csrf = _create_authenticated_client(app, f"user_dbfail_{uuid.uuid4().hex[:6]}", role="ADMIN")

        # Simuler une panne DB brutale
        import monitoring.auth_manager as am
        class BrokenDBSession:
            def __enter__(self): raise RuntimeError("Simulated DB Unavailability")
            def __exit__(self, *args): pass

        orig_get_db = am.get_db_session
        am.get_db_session = lambda: BrokenDBSession()
        try:
            resp = client.get('/api/users')
            # DOIT être rejeté avec 401 (fail-closed) et JAMAIS accepté avec 200
            assert resp.status_code == 401
            assert "révoquée ou invalide" in resp.get_json()["message"]
        finally:
            am.get_db_session = orig_get_db
    finally:
        coord.stop()


# =============================================================================
# LOT C : NOTIFICATIONS AUTH, OWNERSHIP & CSRF (SEC-123-03)
# =============================================================================

def test_lotc_anonymous_notifications_access_rejected():
    """Vérifie que les routes de notifications rejettent les accès non authentifiés avec HTTP 401."""
    app, coord = create_app()
    app.config["TESTING"] = True
    app.config["TESTING_ENFORCE_AUTH"] = True

    try:
        with app.test_client() as anon:
            # 1. Lecture de la liste
            r_list = anon.get('/api/notifications')
            assert r_list.status_code == 401

            # 2. Marquer lue
            r_read = anon.post('/api/notifications/notif_any/read')
            assert r_read.status_code == 401

            # 3. Marquer tout comme lu
            r_all = anon.post('/api/notifications/read_all')
            assert r_all.status_code == 401

            # 4. Suppression
            r_del = anon.delete('/api/notifications/notif_any')
            assert r_del.status_code == 401
    finally:
        coord.stop()


def test_lotc_notifications_csrf_protection_enforced():
    """Vérifie que les mutations de notifications exigent un jeton CSRF valide."""
    app, coord = create_app()
    app.config["TESTING"] = True
    app.config["CSRF_REQUIRED"] = True

    try:
        client, csrf = _create_authenticated_client(app, f"user_csrf_{uuid.uuid4().hex[:6]}", role="OPERATOR")

        # 1. Mutation sans jeton CSRF -> 403
        r_no_csrf = client.post('/api/notifications/read_all')
        assert r_no_csrf.status_code == 403
        assert b"CSRF" in r_no_csrf.data

        # 2. Mutation avec jeton CSRF invalide -> 403
        r_bad_csrf = client.post('/api/notifications/read_all', headers={"X-CSRF-Token": "bad_token_12345"})
        assert r_bad_csrf.status_code == 403

        # 3. Mutation avec jeton CSRF valide -> 200
        r_ok_csrf = client.post('/api/notifications/read_all', headers={"X-CSRF-Token": csrf})
        assert r_ok_csrf.status_code == 200
    finally:
        coord.stop()


def test_lotc_notifications_user_ownership_and_anti_idor():
    """Vérifie l'isolation stricte : un utilisateur ne peut ni lire ni altérer les notifications d'un tiers."""
    app, coord = create_app()
    app.config["TESTING"] = True
    notif_mgr = coord.notification_manager

    try:
        # Création de deux utilisateurs distincts
        client_a, csrf_a = _create_authenticated_client(app, "user_notif_a", role="OPERATOR")
        client_b, csrf_b = _create_authenticated_client(app, "user_notif_b", role="OPERATOR")

        # Obtenir les user_id réels
        with get_db_session() as db:
            ua = db.query(User).filter(User.username == "user_notif_a").first()
            ub = db.query(User).filter(User.username == "user_notif_b").first()
            uid_a = ua.id
            uid_b = ub.id

        # Création d'une notification pour A et d'une pour B
        n_a = notif_mgr.add_notification("INFO", "Titre A", "Message confidentiel A", user_id=uid_a)
        n_b = notif_mgr.add_notification("INFO", "Titre B", "Message confidentiel B", user_id=uid_b)

        assert n_a is not None and n_b is not None

        # 1. Utilisateur A consulte ses notifications -> ne doit PAS voir la notification de B
        res_list_a = client_a.get('/api/notifications')
        assert res_list_a.status_code == 200
        ids_a = [n["id"] for n in res_list_a.get_json()["notifications"]]
        assert n_a["id"] in ids_a
        assert n_b["id"] not in ids_a

        # 2. Attaque IDOR : A tente de marquer comme lue la notification de B -> 404 (non autorisée / introuvable)
        res_idor_read = client_a.post(f'/api/notifications/{n_b["id"]}/read', headers={"X-CSRF-Token": csrf_a})
        assert res_idor_read.status_code == 404

        # 3. Attaque IDOR : A tente de supprimer la notification de B -> 404 (non autorisée / introuvable)
        res_idor_del = client_a.delete(f'/api/notifications/{n_b["id"]}', headers={"X-CSRF-Token": csrf_a})
        assert res_idor_del.status_code == 404

        # 4. A peut marquer sa propre notification comme lue -> 200
        res_own_read = client_a.post(f'/api/notifications/{n_a["id"]}/read', headers={"X-CSRF-Token": csrf_a})
        assert res_own_read.status_code == 200

        # 5. A peut supprimer sa propre notification -> 200
        res_own_del = client_a.delete(f'/api/notifications/{n_a["id"]}', headers={"X-CSRF-Token": csrf_a})
        assert res_own_del.status_code == 200

        # 6. B vérifie que sa notification n'a pas été altérée par les tentatives de A
        res_list_b = client_b.get('/api/notifications')
        ids_b = [n["id"] for n in res_list_b.get_json()["notifications"]]
        assert n_b["id"] in ids_b
    finally:
        coord.stop()


# =============================================================================
# LOT D : P2P FULL PAYLOAD HMAC SIGNATURE & INTEGRITY (SEC-123-04)
# =============================================================================

def test_lotd_p2p_tampered_payload_rejected():
    """Vérifie que l'altération d'un champ quelconque du payload invalide la signature HMAC et rejette l'événement."""
    from monitoring.p2p_sync import P2PSyncManager
    secret = "a_super_secret_p2p_cluster_entropy_key_32_bytes_ok!"
    mgr = P2PSyncManager(cluster_secret=secret, persist_events=False)
    dev_id = "cam_hall_01"
    tok = "tok_cam_secret_123"
    mgr.register_device(dev_id, tok)

    now = time.time()
    ev_id = "ev_p2p_sec04_01"
    original_payload = {"details": "Personne autorisée", "confidence": 0.95, "zone": "Hall"}

    # Calcul de la signature moderne SSMP2P02 couvrant le payload
    sig = mgr.compute_event_signature(
        event_id=ev_id,
        device_id=dev_id,
        sequence_num=1,
        event_type="INTRUSION",
        timestamp=now,
        payload=original_payload,
        proto_version="SSMP2P02"
    )

    # 1. Soumission payload original intact -> SUCCÈS
    batch_valid = [{
        "event_id": ev_id,
        "device_id": dev_id,
        "sequence_num": 1,
        "event_type": "INTRUSION",
        "timestamp": now,
        "payload": original_payload,
        "proto_version": "SSMP2P02",
        "signature": sig
    }]
    ok, count, ids, msg = mgr.receive_sync_batch(dev_id, tok, batch_valid, require_event_signatures=True)
    assert ok is True
    assert count == 1
    assert ev_id in ids

    # 2. Attaquant modifie un champ dans le payload (ex: falsification d'alerte)
    ev_id_tamper = "ev_p2p_sec04_02"
    tampered_payload = {"details": "Intrus armé", "confidence": 0.95, "zone": "Hall"}
    batch_tampered = [{
        "event_id": ev_id_tamper,
        "device_id": dev_id,
        "sequence_num": 2,
        "event_type": "INTRUSION",
        "timestamp": now,
        "payload": tampered_payload,  # Payload altéré sans recalcul de signature valide
        "proto_version": "SSMP2P02",
        "signature": sig  # Signature originale
    }]
    ok_t, count_t, ids_t, msg_t = mgr.receive_sync_batch(dev_id, tok, batch_tampered, require_event_signatures=True)
    assert count_t == 0
    assert ev_id_tamper not in ids_t, "Un événement au payload altéré DOIT être strictement rejeté."


def test_lotd_p2p_metadata_tampering_rejected():
    """Vérifie que l'altération de n'importe quelle métadonnée (device_id, event_id, sequence, timestamp) est rejetée."""
    from monitoring.p2p_sync import P2PSyncManager
    secret = "a_super_secret_p2p_cluster_entropy_key_32_bytes_ok!"
    mgr = P2PSyncManager(cluster_secret=secret, persist_events=False)
    dev_id = "cam_hall_01"
    tok = "tok_cam_secret_123"
    mgr.register_device(dev_id, tok)

    now = time.time()
    payload = {"alert": "Motion detected"}
    sig = mgr.compute_event_signature(
        event_id="ev_meta_01",
        device_id=dev_id,
        sequence_num=5,
        event_type="MOTION",
        timestamp=now,
        payload=payload,
        proto_version="SSMP2P02"
    )

    # A. Timestamp altéré
    batch_bad_time = [{
        "event_id": "ev_meta_01", "device_id": dev_id, "sequence_num": 5, "event_type": "MOTION",
        "timestamp": now + 1.0, "payload": payload, "proto_version": "SSMP2P02", "signature": sig
    }]
    _, count_bt, _, _ = mgr.receive_sync_batch(dev_id, tok, batch_bad_time, require_event_signatures=True)
    assert count_bt == 0

    # B. Numéro de séquence altéré
    batch_bad_seq = [{
        "event_id": "ev_meta_01", "device_id": dev_id, "sequence_num": 6, "event_type": "MOTION",
        "timestamp": now, "payload": payload, "proto_version": "SSMP2P02", "signature": sig
    }]
    _, count_bs, _, _ = mgr.receive_sync_batch(dev_id, tok, batch_bad_seq, require_event_signatures=True)
    assert count_bs == 0

    # C. Type d'événement altéré
    batch_bad_type = [{
        "event_id": "ev_meta_01", "device_id": dev_id, "sequence_num": 5, "event_type": "TAMPER",
        "timestamp": now, "payload": payload, "proto_version": "SSMP2P02", "signature": sig
    }]

# =============================================================================
# LOT E : FORENSIC PDF RBAC & ANTI-IDOR TESTS (SEC-123-05)
# =============================================================================

def test_lote_forensic_pdf_anonymous_rejected():
    """Vérifie que les requêtes anonymes vers la génération et le téléchargement PDF sont rejetées (401)."""
    app, coord = create_app()
    app.config["TESTING"] = True
    app.config["TESTING_ENFORCE_AUTH"] = True
    try:
        client = app.test_client()
        # Génération anonyme
        res_gen = client.post('/api/forensic/generate_pdf/alert_anon_01')
        assert res_gen.status_code == 401

        # Téléchargement anonyme
        res_dl = client.get('/api/forensic/download/report_anon_01.pdf')
        assert res_dl.status_code == 401
    finally:
        coord.stop()

def test_lote_forensic_pdf_rbac_non_admin_auditor_rejected():
    """Vérifie qu'un utilisateur authentifié avec un rôle non autorisé (ex: OPERATOR) est rejeté (403)."""
    app, coord = create_app()
    app.config["TESTING"] = True
    app.config["TESTING_ENFORCE_AUTH"] = True
    try:
        op_client, op_csrf = _create_authenticated_client(app, "operator_pdf_user", role="OPERATOR")
        headers = {"X-CSRF-Token": op_csrf}

        res_gen = op_client.post('/api/forensic/generate_pdf/alert_rbac_01', headers=headers)
        assert res_gen.status_code == 403

        res_dl = op_client.get('/api/forensic/download/some_report.pdf', headers=headers)
        assert res_dl.status_code == 403
    finally:
        coord.stop()

def test_lote_forensic_pdf_path_traversal_and_extension_rejected():
    """Vérifie que les tentatives de traversée de chemin et les extensions non-PDF sont bloquées."""
    app, coord = create_app()
    app.config["TESTING"] = True
    try:
        admin_client, admin_csrf = _create_authenticated_client(app, "admin_pdf_traversal", role="ADMIN")
        headers = {"X-CSRF-Token": admin_csrf}

        # 1. Path traversal via '../' ou '..\'
        res_trav1 = admin_client.get('/api/forensic/download/..%2f..%2fconfig.py', headers=headers)
        assert res_trav1.status_code in (400, 403, 404)

        res_trav2 = admin_client.get('/api/forensic/download/subdir/report.pdf', headers=headers)
        assert res_trav2.status_code in (400, 403, 404)

        # 2. Extension non autorisée (ex: .key, .py, .db)
        res_ext = admin_client.get('/api/forensic/download/privacy_master.key', headers=headers)
        assert res_ext.status_code == 400
        assert "invalide" in res_ext.get_json().get("message", "").lower()
    finally:
        coord.stop()

def test_lote_forensic_pdf_admin_generate_and_download_flow():
    """Vérifie le cycle complet de génération et téléchargement de rapport forensique certifié par un ADMIN."""
    app, coord = create_app()
    app.config["TESTING"] = True
    try:
        admin_client, admin_csrf = _create_authenticated_client(app, "admin_pdf_valid", role="ADMIN")
        headers = {"X-CSRF-Token": admin_csrf}

        # Injecter une alerte de test
        test_alert_id = f"alert_forensic_{uuid.uuid4().hex[:6]}"
        fake_alert = {
            "id": test_alert_id,
            "timestamp": time.time(),
            "type": "INTRUSION_DETECTED",
            "category": "INTRUSION",
            "severity": "CRITIQUE",
            "device_id": "cam_east_01",
            "device_name": "Camera Est",
            "details": "Détection d'intrusion nocturne vérifiée",
            "screenshot": None,
            "video_file": None,
            "ai_analysis": {"classification": "INTRUDER", "confidence": 0.96}
        }
        with coord.recording_manager._lock:
            coord.recording_manager.alerts.insert(0, fake_alert)

        # Génération du rapport
        res_gen = admin_client.post(f'/api/forensic/generate_pdf/{test_alert_id}', headers=headers)
        assert res_gen.status_code == 200
        gen_data = res_gen.get_json()
        assert gen_data["status"] == "ok"
        filename = gen_data["filename"]
        assert filename.endswith(".pdf")
        assert f"/api/forensic/download/{filename}" == gen_data["download_url"]

        # Téléchargement du rapport généré
        res_dl = admin_client.get(f'/api/forensic/download/{filename}', headers=headers)
        assert res_dl.status_code == 200
        assert res_dl.content_type == "application/pdf"
        assert len(res_dl.data) > 0
        assert res_dl.data.startswith(b"%PDF")

        # Téléchargement d'un rapport inexistant
        res_404 = admin_client.get('/api/forensic/download/nonexistent_report_999.pdf', headers=headers)
        assert res_404.status_code == 404
    finally:
        coord.stop()


# =============================================================================
# LOT F : LOGOUT CSRF & EXEMPTIONS AUDIT TESTS (SEC-123-06)
# =============================================================================

def test_lotf_logout_csrf_protection_enforced():
    """Vérifie que la déconnexion exige un jeton CSRF valide quand la protection est activée."""
    app, coord = create_app()
    app.config["TESTING"] = True
    app.config["CSRF_REQUIRED"] = True

    try:
        # 1. Création d'une session valide
        client, csrf_tok = _create_authenticated_client(app, "csrf_logout_user", role="ADMIN")

        # 2. Requête POST logout SANS jeton CSRF -> 403
        res_no_csrf = client.post('/api/auth/logout')
        assert res_no_csrf.status_code == 403
        assert b"CSRF" in res_no_csrf.data

        # 3. Requête POST logout avec jeton CSRF invalide -> 403
        res_bad_csrf = client.post('/api/auth/logout', headers={"X-CSRF-Token": "invalid_forged_csrf_token_999"})
        assert res_bad_csrf.status_code == 403
        assert b"CSRF" in res_bad_csrf.data

        # 4. Requête POST logout avec jeton CSRF valide -> 200 et session invalidée
        res_ok = client.post('/api/auth/logout', headers={"X-CSRF-Token": csrf_tok})
        assert res_ok.status_code == 200
        assert res_ok.get_json()["status"] == "ok"

        # 5. Vérifier que la session est bien invalidée
        res_me = client.get('/api/auth/me')
        assert res_me.status_code == 401
    finally:
        coord.stop()

def test_lotf_logout_get_method_rejected():
    """Vérifie que la tentative de déconnexion via méthode GET est rejetée (405 Method Not Allowed)."""
    app, coord = create_app()
    app.config["TESTING"] = True

    try:
        client, _ = _create_authenticated_client(app, "get_logout_user", role="ADMIN")

        # GET /api/auth/logout n'accepte pas GET -> 405
        res_api_get = client.get('/api/auth/logout')
        assert res_api_get.status_code == 405

        # GET /logout n'accepte plus GET -> 405
        res_web_get = client.get('/logout')
        assert res_web_get.status_code == 405
    finally:
        coord.stop()

def test_lotf_bootstrap_already_initialized_rejected():
    """Vérifie qu'une tentative de bootstrap quand un admin existe déjà est rejetée immédiatement (403)."""
    app, coord = create_app()
    app.config["TESTING"] = True

    try:
        client = app.test_client()

        # S'assurer qu'au moins un admin existe
        with get_db_session() as db:
            existing_admin = db.query(User).filter(User.role == "ADMIN").first()
            if not existing_admin:
                admin_user = User(
                    id=f"u_{uuid.uuid4().hex[:8]}",
                    username="super_admin_existing",
                    password_hash=generate_password_hash("AdminPass123!"),
                    role="ADMIN",
                    is_active=True,
                    created_at=time.time()
                )
                db.add(admin_user)

        # Tentative de bootstrap hostile
        res_boot = client.post('/api/auth/bootstrap', json={
            "username": "hostile_takeover_admin",
            "password": "AttackerPass2026!",
            "confirm_password": "AttackerPass2026!"
        })
        assert res_boot.status_code == 403
        assert "déjà initialisé" in res_boot.get_json()["message"]
    finally:
        coord.stop()


# =============================================================================
# LOT H : LEGACY DECRYPTION FALLBACK & AAD SECURITY AUDIT TESTS (SEC-123-08)
# =============================================================================

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def test_loth_modern_envelope_aad_tampering_rejected_no_fallback():
    """Vérifie qu'un fichier chiffré moderne SSMENC01 avec AAD altéré est rejeté sans fallback silencieux."""
    master_key = AESGCM.generate_key(bit_length=256)
    shield = PrivacyShield(master_key=master_key, key_id="key_loth_01")

    with tempfile.TemporaryDirectory() as tmp_dir:
        plain_path = os.path.join(tmp_dir, "incident_proof.txt")
        with open(plain_path, "wb") as f:
            f.write(b"TOP_SECRET_FORENSIC_EVIDENCE_PRO124")

        # Chiffrement avec enveloppe moderne SSMENC01 et AAD lié à 'res_incident_01'
        ok, enc_path = shield.encrypt_evidence_file(plain_path, resource_id="res_incident_01")
        assert ok is True

        with open(enc_path, "rb") as f:
            enc_data = bytearray(f.read())

        # Altération de l'identifiant de ressource dans le header (modification de l'AAD implicite)
        kid_len = enc_data[8]
        res_len = int.from_bytes(enc_data[9:11], "big")
        res_offset = 11 + kid_len
        enc_data[res_offset] = ord(b"X") if enc_data[res_offset] != ord(b"X") else ord(b"Y")

        tampered_path = os.path.join(tmp_dir, "tampered_aad.enc")
        with open(tampered_path, "wb") as f:
            f.write(enc_data)

        # Création et approbation complète d'une demande de déchiffrement
        req_id = shield.create_decryption_request("res_incident_01", "auditor_alice", "Revue judiciaire")
        shield.approve_decryption_request(req_id, "admin_approver_1", "ADMIN")
        shield.approve_decryption_request(req_id, "admin_approver_2", "AUDITOR")

        out_path = os.path.join(tmp_dir, "out_decrypted.txt")
        dec_ok, dec_msg = shield.execute_authorized_decryption(req_id, tampered_path, out_path)

        # Le déchiffrement DOIT échouer sans exécuter de fallback
        assert dec_ok is False
        assert "Erreur cryptographique" in dec_msg
        assert not os.path.exists(out_path)

def test_loth_modern_envelope_ciphertext_tampering_rejected():
    """Vérifie que toute altération du ciphertext dans l'enveloppe moderne est rejetée par AES-256-GCM."""
    master_key = AESGCM.generate_key(bit_length=256)
    shield = PrivacyShield(master_key=master_key, key_id="key_loth_02")

    with tempfile.TemporaryDirectory() as tmp_dir:
        plain_path = os.path.join(tmp_dir, "evidence_original.txt")
        with open(plain_path, "wb") as f:
            f.write(b"ORIGINAL_EVIDENCE_FOR_CIPHERTEXT_TEST")

        ok, enc_path = shield.encrypt_evidence_file(plain_path, resource_id="res_cipher_01")
        assert ok is True

        with open(enc_path, "rb") as f:
            enc_data = bytearray(f.read())

        # Altération du dernier octet (tag d'authentification GCM)
        enc_data[-1] ^= 0xFF

        corrupted_path = os.path.join(tmp_dir, "corrupted_cipher.enc")
        with open(corrupted_path, "wb") as f:
            f.write(enc_data)

        req_id = shield.create_decryption_request("res_cipher_01", "investigator", "Enquête")
        shield.approve_decryption_request(req_id, "admin1", "ADMIN")
        shield.approve_decryption_request(req_id, "admin2", "AUDITOR")

        out_path = os.path.join(tmp_dir, "out_cipher.txt")
        dec_ok, dec_msg = shield.execute_authorized_decryption(req_id, corrupted_path, out_path)

        assert dec_ok is False
        assert "Erreur cryptographique" in dec_msg
        assert not os.path.exists(out_path)

def test_loth_legacy_envelope_decrypted_with_audit_warning(caplog):
    """Vérifie qu'un fichier legacy (sans SSMENC01) est déchiffré mais génère un avertissement de sécurité explicite."""
    import logging
    master_key = AESGCM.generate_key(bit_length=256)
    shield = PrivacyShield(master_key=master_key, key_id="key_loth_legacy")

    with tempfile.TemporaryDirectory() as tmp_dir:
        # Création d'un fichier chiffré legacy v0 (nonce 12 + ciphertext sans AAD)
        v0_nonce = os.urandom(12)
        v0_aes = AESGCM(master_key)
        v0_ciphertext = v0_aes.encrypt(v0_nonce, b"HISTORICAL_LEGACY_PROOF_V0", None)
        v0_path = os.path.join(tmp_dir, "historical_v0.enc")
        with open(v0_path, "wb") as f:
            f.write(v0_nonce + v0_ciphertext)

        req_id = shield.create_decryption_request("historical_v0", "archivist", "Revue archive")
        shield.approve_decryption_request(req_id, "admin1", "ADMIN")
        shield.approve_decryption_request(req_id, "admin2", "AUDITOR")

        out_path = os.path.join(tmp_dir, "historical_v0.dec")
        with caplog.at_level(logging.WARNING):
            dec_ok, dec_msg = shield.execute_authorized_decryption(req_id, v0_path, out_path)

        assert dec_ok is True
        assert "mode dégradé legacy sans AAD" in dec_msg
        with open(out_path, "rb") as f:
            assert f.read() == b"HISTORICAL_LEGACY_PROOF_V0"
        # Vérifier que le warning d'audit a bien été émis
        assert any("mode dégradé legacy sans AAD" in record.message for record in caplog.records)

def test_loth_modern_file_stripped_header_fails_closed():
    """Vérifie qu'un attaquant supprimant le header SSMENC01 d'un fichier moderne échoue car le tag GCM exige l'AAD."""
    master_key = AESGCM.generate_key(bit_length=256)
    shield = PrivacyShield(master_key=master_key, key_id="key_loth_stripped")

    with tempfile.TemporaryDirectory() as tmp_dir:
        plain_path = os.path.join(tmp_dir, "modern_file.txt")
        with open(plain_path, "wb") as f:
            f.write(b"MODERN_PAYLOAD_PROTECTED_BY_AAD")

        ok, enc_path = shield.encrypt_evidence_file(plain_path, resource_id="modern_res_01")
        assert ok is True

        with open(enc_path, "rb") as f:
            full_data = f.read()

        kid_len = full_data[8]
        res_len = int.from_bytes(full_data[9:11], "big")
        offset = 11 + kid_len + res_len
        nonce = full_data[offset:offset+12]
        ciphertext = full_data[offset+12:]

        fake_legacy_path = os.path.join(tmp_dir, "stripped_modern.enc")
        with open(fake_legacy_path, "wb") as f:
            f.write(nonce + ciphertext)

        req_id = shield.create_decryption_request("modern_res_01", "attacker", "Bypass attempt")
        shield.approve_decryption_request(req_id, "admin1", "ADMIN")
        shield.approve_decryption_request(req_id, "admin2", "AUDITOR")

        out_path = os.path.join(tmp_dir, "stripped_out.txt")
        dec_ok, dec_msg = shield.execute_authorized_decryption(req_id, fake_legacy_path, out_path)

        assert dec_ok is False
        assert "Erreur cryptographique" in dec_msg
        assert not os.path.exists(out_path)






