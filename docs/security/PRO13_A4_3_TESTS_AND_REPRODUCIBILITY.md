# PRO13-A.4.3 — TESTS & REPRODUCIBILITY REPORT

**Mission ID :** `SSM-PRO13-A4-3-EGRESS-HARDENING-AND-CRYPTOGRAPHIC-CONTINUITY-01`  
**Date / Horodatage :** 2026-11-27T07:11:00+01:00  
**Dépôt :** `C:\Users\USER\Documents\alarme-sys` | **Branche :** `main` | **HEAD :** `b339a9c82d5b410e78d1ea6d43cae556049ba2c0`  

---

## 1. ENVIRONNEMENT VÉRIFIÉ

- **Python :** 3.11.8 (64-bit)
- **Pytest :** 9.1.1
- **Compilation statique :** `python -m compileall -q app.py routes monitoring` -> **Code de sortie `0`** (aucune erreur de syntaxe).

---

## 2. ANALYSE DE SÉCURITÉ DES TESTS ET EFFETS DE BORD PERSISTANTS

Conformément à la Section 9.3 du mandat PRO-13-A.4.3 (*« Si les tests ont des effets de bord persistants, ne pas lancer la suite complète et documenter le blocage »*) :
- L'audit forensique de la Phase 4 a démontré que les suites existantes (`tests/test_integrity.py`, `tests/test_pro13_a4_2_2_alerts_endpoint_security.py`, `create_app()`) **écrivent directement dans la base persistante `storage/security_monitor.db`** (faisant croître `integrity_log` de 1 018 à 1 031 lignes lors de la reproduction précédente).
- En mode strictement lecture seule visant à préserver l'intégrité exacte de `storage/security_monitor.db`, la suite complète n'a pas été relancée durant A.4.3.
- **Référence de la dernière exécution sur code strictement identique (PRO-13-A.4.2.3, aucun fichier code/test modifié depuis) :**
  - Commande : `python -m pytest tests/ -q`
  - Résultat : `347 passed, 0 failed, 0 skipped, 1 warning in 129.32s` (code `0`).

---

## 3. ÉVALUATION QUALITATIVE DES SUITES CRITIQUES

- **Tests Egress (`test_pro13_a4_2_egress_enforcement.py`) :** Valident fidèlement `EgressPolicy`, le blocage IPv4/IPv6/cloud metadata et le comportement fail-closed avec `MockEgressProvider`, mais **ne prouvent pas** le comportement réel du pare-feu Windows (mocks).
- **Tests HMAC (`test_integrity.py`) :** Valident `IntegrityManager`, mais polluent la base partagée avec des clés de test (`"test-secret-hmac-key"`, `"chain-test-key"`, `None`).
- **Tests Alertes/CSP/XSS (`test_pro13_a4_2_2_*.py`) :** Valident les codes HTTP 401/403/200, la neutralisation CSV et les en-têtes CSP.

---

## 4. STATUT

```text
REGRESSION_GATE = PASS_WITH_LIMITATIONS  (Code inchangé depuis 347/347 en A.4.2.3 ; ré-exécution bloquée en A.4.3 pour préserver storage/security_monitor.db des effets de bord persistants)
```
