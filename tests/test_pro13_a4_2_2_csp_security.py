"""
SSM PRO-13-A.4.2.2 — Test Suite: Content Security Policy (CSP) & HTTP Security Headers
Vérifie la présence et la rigueur des en-têtes HTTP de sécurité sur les routes HTML et API :
- Content-Security-Policy (directives obligatoires : default-src, script-src, style-src, font-src, object-src, base-uri, form-action, frame-ancestors)
- X-Content-Type-Options: nosniff
- X-Frame-Options: SAMEORIGIN
- Referrer-Policy: strict-origin-when-cross-origin
"""

import pytest
from app import create_app


@pytest.fixture(scope="module")
def client():
    app, _ = create_app()
    app.config["TESTING"] = True
    app.config["WTF_CSRF_ENABLED"] = False
    with app.test_client() as c:
        yield c


def test_csp_header_present_on_login(client):
    """Vérifie que la page /login renvoie tous les en-têtes de sécurité requis."""
    res = client.get('/login')
    assert res.status_code == 200

    headers = res.headers
    assert "Content-Security-Policy" in headers
    assert headers.get("X-Content-Type-Options") == "nosniff"
    assert headers.get("X-Frame-Options") == "SAMEORIGIN"
    assert headers.get("Referrer-Policy") == "strict-origin-when-cross-origin"

    csp = headers.get("Content-Security-Policy")
    # Vérification des directives obligatoires
    assert "default-src 'self'" in csp
    assert "script-src 'self'" in csp
    assert "https://cdn.tailwindcss.com" in csp
    assert "style-src 'self'" in csp
    assert "https://cdnjs.cloudflare.com" in csp
    assert "font-src 'self' https://cdnjs.cloudflare.com" in csp
    assert "img-src 'self' data: blob:" in csp
    assert "media-src 'self' data: blob:" in csp
    assert "connect-src 'self'" in csp
    assert "object-src 'none'" in csp
    assert "base-uri 'self'" in csp
    assert "form-action 'self'" in csp
    assert "frame-ancestors 'self'" in csp


def test_csp_header_present_on_dashboard(client):
    """Vérifie que le dashboard / renvoie la même politique stricte."""
    res = client.get('/')
    # Peut être 200 ou 302 vers login selon session, mais l'en-tête de sécurité doit être présent
    assert "Content-Security-Policy" in res.headers
    csp = res.headers.get("Content-Security-Policy")
    assert "object-src 'none'" in csp
    assert "base-uri 'self'" in csp
    assert "form-action 'self'" in csp
    assert "frame-ancestors 'self'" in csp


def test_csp_header_present_on_api(client):
    """Vérifie que les endpoints API bénéficient également de la CSP et des en-têtes de durcissement."""
    res = client.get('/api/storage/stats')
    assert "Content-Security-Policy" in res.headers
    assert res.headers.get("X-Content-Type-Options") == "nosniff"
    assert res.headers.get("X-Frame-Options") == "SAMEORIGIN"


def test_csp_no_dangerous_wildcards(client):
    """Vérifie l'absence de wildcards dangereux (*) dans les directives de scripts et objets."""
    res = client.get('/login')
    csp = res.headers.get("Content-Security-Policy")

    # Aucun wildcard global autorisé pour script-src ou object-src
    directives = dict(part.strip().split(" ", 1) for part in csp.split(";") if part.strip())
    assert "*" not in directives.get("script-src", "")
    assert "*" not in directives.get("object-src", "")
    assert "*" not in directives.get("default-src", "")
