# PRO13-A.4.4 — SQLITE TEST ISOLATION REPORT

**Mission ID :** `SSM-PRO13-A4-4-CONTROLLED-REMEDIATION-AND-SECURITY-CLOSURE-01`  
**Date / Horodatage :** 2026-11-27T07:28:00+01:00  
**Dépôt :** `C:\Users\USER\Documents\alarme-sys` | **Branche :** `main` | **HEAD :** `b339a9c82d5b410e78d1ea6d43cae556049ba2c0`  

---

## 1. REMÉDIATION APPLIQUÉE (LOT A)

1. **`config.py` :** `DB_PATH = os.environ.get("SSM_DB_PATH") or os.path.join(STORAGE_DIR, "security_monitor.db")`.
2. **`database.py` :**
   - Ajout de `is_protected_production_db_path(candidate_path)` normalisant les séparateurs Windows/Linux, résolvant les `..`, liens symboliques et préfixes `sqlite:///` avant comparaison insensible à la casse.
   - Ajout de `rebind_database(db_path, initialize=True)` gérant proprement `SessionLocal.remove()`, `engine.dispose()` et la reconfiguration du moteur.
3. **`tests/conftest.py` (nouveau) :**
   - Crée un répertoire temporaire isolé `_SESSION_TEST_DB_DIR` (`ssm_pytest_isolated_*`) et définit `SSM_DB_PATH` **avant tout import applicatif**.
   - `pytest_configure` exécute `assert_not_production_db(...)` sur `config.DB_PATH` et `database.engine.url.database` (échec immédiat `RuntimeError: BLOCKED_PRODUCTION_DB_WRITE` en cas de cible persistante).
   - Fixture `isolated_test_db` fournissant une base SQLite propre par test via `tmp_path`.
   - `pytest_unconfigure` libère les connexions et supprime le répertoire temporaire de session.

---

## 2. PREUVE DE NON-POLLUTION DE LA BASE HISTORIQUE

- Suite exécutée : `tests/test_pro13_a4_4_sqlite_isolation.py` + `tests/test_integrity.py`.
- Empreinte SHA-256 de `storage/security_monitor.db` avant et après : **`a06e40bdd9c2369477a66c84cc3d351a220d0ef46974a7c899e4cfcc31349e02`** (identique au bit près).

---

## 3. STATUT

```text
SQLITE_ISOLATION_GATE = PASS
```
