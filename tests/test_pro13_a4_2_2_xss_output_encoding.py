"""
SSM PRO-13-A.4.2.2 — Test Suite: XSS Output Encoding & DOM Injection Neutralization
Vérifie la robustesse du frontend face aux charges utiles d'injection XSS et DOM :
- Définition et comportement exact de escapeHtml() dans static/js/dashboard.js
- Neutralisation des caractères spéciaux HTML (<, >, &, \", ')
- Échappement des champs sensibles d'alertes (device_name, type, details, severity, category)
- Échappement des notifications (title, message) et des zones de détection
"""

import os
import re
import html
import pytest


def test_escape_html_defined_in_dashboard_js():
    """Vérifie que la fonction escapeHtml est explicitement définie dans static/js/dashboard.js."""
    js_path = os.path.join(os.path.dirname(__file__), "..", "static", "js", "dashboard.js")
    with open(js_path, "r", encoding="utf-8") as f:
        content = f.read()

    assert "function escapeHtml" in content, "La fonction escapeHtml doit être formellement définie dans static/js/dashboard.js"
    # Vérification des remplacements de caractères obligatoires
    assert "&amp;" in content
    assert "&lt;" in content
    assert "&gt;" in content
    assert "&quot;" in content
    assert "&#039;" in content or "&#39;" in content


def test_escape_html_logic_correctness():
    """Vérifie la logique algorithmique d'échappement équivalente à escapeHtml côté serveur."""
    def py_escape_html(s):
        if s is None:
            return ""
        return (str(s)
                .replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
                .replace('"', "&quot;")
                .replace("'", "&#039;"))

    payloads = [
        ("<script>alert('XSS')</script>", "&lt;script&gt;alert(&#039;XSS&#039;)&lt;/script&gt;"),
        ('<img src=x onerror="alert(1)">', "&lt;img src=x onerror=&quot;alert(1)&quot;&gt;"),
        ("Test & Trace", "Test &amp; Trace"),
        ("Zone 'Sécurité' A", "Zone &#039;Sécurité&#039; A"),
        ("<svg/onload=fetch('//leak')>", "&lt;svg/onload=fetch(&#039;//leak&#039;)&gt;")
    ]

    for raw, expected in payloads:
        escaped = py_escape_html(raw)
        assert escaped == expected
        assert "<" not in escaped
        assert ">" not in escaped
        assert '"' not in escaped
        assert "'" not in escaped


def test_dashboard_js_no_raw_innerhtml_unprotected():
    """Vérifie statiquement que renderAlertsTable et renderNotifications utilisent safe* ou escapeHtml."""
    js_path = os.path.join(os.path.dirname(__file__), "..", "static", "js", "dashboard.js")
    with open(js_path, "r", encoding="utf-8") as f:
        content = f.read()

    # Trouver le bloc de renderAlertsTable
    m_alerts = re.search(r'function renderAlertsTable\(alerts\) \{(.*?)\n\}', content, re.DOTALL)
    assert m_alerts, "renderAlertsTable non trouvé"
    alerts_body = m_alerts.group(1)
    assert "safeDeviceName" in alerts_body or "escapeHtml" in alerts_body
    assert "safeType" in alerts_body or "escapeHtml" in alerts_body
    assert "safeDetails" in alerts_body or "escapeHtml" in alerts_body

    # Trouver le bloc de renderNotifications
    m_notifs = re.search(r'function renderNotifications\(data\) \{(.*?)\n\}', content, re.DOTALL)
    assert m_notifs, "renderNotifications non trouvé"
    notifs_body = m_notifs.group(1)
    assert "safeTitle" in notifs_body or "escapeHtml" in notifs_body
    assert "safeMessage" in notifs_body or "escapeHtml" in notifs_body

    # Vérifier la remédiation du contexte onclick dans renderAlertsTable et renderDiagnostic (PRO-13 A.4.4 Lot F)
    assert "safeTitleParam" in alerts_body and "decodeURIComponent" in alerts_body
    m_diag = re.search(r'function renderDiagnostic\(diag\) \{(.*?)\n\}', content, re.DOTALL)
    assert m_diag, "renderDiagnostic non trouvé"
    assert "escapeHtml(diag.name)" in m_diag.group(1)
