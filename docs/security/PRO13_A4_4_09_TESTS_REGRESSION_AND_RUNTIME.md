# PRO13-A.4.4 — TESTS, REGRESSION & RUNTIME REPORT

**Mission ID :** `SSM-PRO13-A4-4-CONTROLLED-REMEDIATION-AND-SECURITY-CLOSURE-01`  
**Date / Horodatage :** 2026-11-27T08:26:00+01:00  
**Dépôt :** `C:\Users\USER\Documents\alarme-sys` | **Branche :** `main` | **HEAD :** `b339a9c82d5b410e78d1ea6d43cae556049ba2c0`  

---

## 1. EXÉCUTIONS RÉELLES EN ENVIRONNEMENT ISOLÉ

1. **Suite complète isolée (`python -m pytest tests/ -q`) :**
   - **Résultat :** **`371 passed, 0 failed, 0 skipped, 1 warning`** en `174.58s` (`code 0`).
   - **Avertissement :** `SAWarning: New instance <SystemBootstrap>` dans `test_p123_26_pro12_2_baseline_maintained` (préexistant).
   - **Note de transparence sur la 1ère exécution complète :** Une première exécution isolée avait révélé 5 échecs sur des tests historiques (`test_auth_rbac.py`, `test_pro12_1_adversarial.py`, `test_pro12_security_hardening.py`) qui supposaient un compte `admin` pré-amorcé ; l'ajout d'un amorçage de test isolé dans `tests/conftest.py` (uniquement sur la base temporaire) a permis d'atteindre 371/371 sans toucher à `storage/security_monitor.db`.
2. **Compilation statique (`python -m compileall -q app.py routes monitoring`) :** Code de sortie `0`.
3. **Vérification post-tests de `storage/security_monitor.db` :**
   - Empreinte SHA-256 : `a06e40bdd9c2369477a66c84cc3d351a220d0ef46974a7c899e4cfcc31349e02` (**inchangée**).
   - `integrity_log` : `1 031` entrées (**inchangées**).

---

## 2. NOUVELLES SUITES AJOUTÉES EN A.4.4

- `tests/test_pro13_a4_4_sqlite_isolation.py` : 8 tests (garde anti-production, chemins relatifs/Windows/URI, isolation consécutive).
- `tests/test_pro13_a4_4_hmac_continuity.py` : 5 tests (v2 `key_id`/`algorithm`, héritage `LEGACY_UNVERIFIABLE`, `HMAC_MISSING`, `HMAC_INVALID`, `KEY_UNAVAILABLE`, manifeste en lecture seule).
- `tests/test_pro13_a4_4_egress_scripts.py` : 7 tests (soustraction CIDR IPv4/IPv6, IPv4-mapped IPv6, purge proxy FFmpeg, diagnostic `check` non destructif, idempotence/IPv6 Docker).
- `tests/test_pro13_a4_4_get_routes_access_control.py` : 4 tests (401/302 anonyme, 403 `GUEST`, 200 `ADMIN`/`OPERATOR`/`AUDITOR`, blocage traversée/`..`/IDs malformés).

---

## 3. STATUT

```text
REGRESSION_GATE = PASS
```
