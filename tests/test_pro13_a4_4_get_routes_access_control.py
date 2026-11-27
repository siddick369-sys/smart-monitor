"""
Tests de contrôle d'accès sur les routes GET sensibles (PRO-13-A.4.4 Lot E).
Couvre : /api/timeline, /api/reports/*/pdf, /storage/screenshots/*, /storage/recordings/*,
/video_feed/*, /api/devices, /api/status, /api/statistics, /api/storage/stats.
"""

import os
import time
import uuid
import pytest
from werkzeug.security import generate_password_hash

import config
from app import create_app
from database import get_db_session
from monitoring.models import User, UserSession


@pytest.fixture(scope="module")
def strict_app():
    app, coordinator = create_app()
    app.config["TESTING"] = True
    app.config["TESTING_ENFORCE_AUTH"] = True
    app.config["WTF_CSRF_ENABLED"] = False
    return app, coordinator


def _make_session(role: str):
    uniq = uuid.uuid4().hex[:6]
    uid = f"u_{role}_{uniq}"
    tok = f"t_{uuid.uuid4().hex}"
    with get_db_session() as db:
        db.add(User(
            id=uid, username=f"{role.lower()}_{uniq}",
            password_hash=generate_password_hash("StrongPass123!"),
            role=role, is_active=True, created_at=time.time()
        ))
        db.flush()
        db.add(UserSession(session_token=tok, user_id=uid, created_at=time.time(), last_activity=time.time(), revoked=False))
    return uid, tok


_PROTECTED_GET_ROUTES = [
    "/api/timeline",
    "/api/reports/summary/pdf",
    "/api/reports/incident/nonexistent/pdf",
    "/storage/screenshots/missing.jpg",
    "/storage/recordings/missing.mp4",
    "/video_feed/dev_missing",
    "/api/devices",
    "/api/status",
    "/api/statistics",
    "/api/storage/stats",
    "/api/diagnostics",
    "/api/telegram/status",
    "/api/qwen_vision/status",
    "/api/database/status",
]


def test_a44_get_01_anonymous_rejected_on_all_sensitive_get_routes(strict_app):
    """Tous les endpoints GET sensibles rejettent les requêtes anonymes."""
    app, _ = strict_app
    with app.test_client() as client:
        for route in _PROTECTED_GET_ROUTES:
            res = client.get(route)
            if route.startswith("/api/"):
                assert res.status_code == 401, f"Route {route} devrait renvoyer 401, obtenu {res.status_code}"
            else:
                # Les routes non-/api/ redirigent vers /login (302)
                assert res.status_code in (302, 401), f"Route {route} devrait bloquer l'anonyme, obtenu {res.status_code}"


def test_a44_get_02_unauthorized_role_rejected_403(strict_app):
    """Un utilisateur authentifié avec rôle non autorisé (GUEST) reçoit HTTP 403."""
    app, _ = strict_app
    uid, tok = _make_session("GUEST")
    with app.test_client() as client:
        with client.session_transaction() as sess:
            sess["user_id"] = uid
            sess["role"] = "GUEST"
            sess["session_token"] = tok

        for route in _PROTECTED_GET_ROUTES:
            res = client.get(route)
            assert res.status_code == 403, f"Route {route} devrait renvoyer 403 pour GUEST, obtenu {res.status_code}"


def test_a44_get_03_authorized_roles_allowed(strict_app):
    """ADMIN, OPERATOR et AUDITOR accèdent aux routes GET autorisées."""
    app, _ = strict_app
    for role in ("ADMIN", "OPERATOR", "AUDITOR"):
        uid, tok = _make_session(role)
        with app.test_client() as client:
            with client.session_transaction() as sess:
                sess["user_id"] = uid
                sess["role"] = role
                sess["session_token"] = tok

            assert client.get("/api/timeline").status_code == 200
            assert client.get("/api/devices").status_code == 200
            assert client.get("/api/status").status_code == 200
            assert client.get("/api/statistics").status_code == 200
            assert client.get("/api/storage/stats").status_code == 200
            assert client.get("/api/reports/summary/pdf").status_code == 200


def test_a44_get_04_traversal_and_malformed_ids_blocked(strict_app):
    """Vérifie le blocage des traversées de répertoire et identifiants malformés."""
    app, _ = strict_app
    uid, tok = _make_session("ADMIN")
    with app.test_client() as client:
        with client.session_transaction() as sess:
            sess["user_id"] = uid
            sess["role"] = "ADMIN"
            sess["session_token"] = tok

        assert client.get("/storage/screenshots/..%2Fsecret.txt").status_code == 400
        assert client.get("/storage/recordings/sub%2Ffile.mp4").status_code == 400
        assert client.get("/video_feed/bad;id").status_code == 400
        assert client.get("/video_feed/nonexistent_cam").status_code == 404
        assert client.get("/api/reports/incident/bad;id/pdf").status_code == 400
        assert client.get("/api/timeline?limit=invalid").status_code == 400
