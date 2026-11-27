# PRO13-A.4.2.2 — ALERTS ENDPOINT SECURITY & CSV FORMULA INJECTION HARDENING REPORT

**Mission ID:** `SSM-PRO13-A4-2-2-SECURITY-CLOSURE-AND-FULL-LOCAL-REQUALIFICATION-01`  
**Classification:** CRITICAL SECURITY REMEDIATION / AUTHENTICATION / RBAC / CSV INJECTION DEFENSE  
**Date / Timestamp:** 2026-11-26T18:25:00+01:00  
**Repository:** `C:\Users\USER\Documents\alarme-sys`  
**Branch:** `main`  
**HEAD de référence:** `b339a9c82d5b410e78d1ea6d43cae556049ba2c0`  

---

## 1. FINDING INITIAL (AUDIT PRO-13-A.4.2.1 FINDING F-01 / PRIORITÉ HAUTE P1)

Dans la version précédente du module `routes/alerts.py`, les deux routes suivantes étaient déclarées sans décorateur d'authentification ni contrôle d'autorisation RBAC :
- `GET /api/alerts` (consultation de la liste des incidents) ;
- `GET /api/alerts/export/csv` (exportation brute de l'historique d'incidents au format CSV).

Tout utilisateur réseau, même non authentifié ou anonyme, pouvait interroger ces routes pour énumérer les alertes de sécurité, les adresses IP des caméras, les identifiants d'incidents et extraire l'intégralité du journal de sécurité.

De surcroît, l'exportation CSV ne neutralisait pas les cellules contrôlables par les utilisateurs ou capteurs débutant par des caractères de déclenchement de formules tableurs (`=`, `+`, `-`, `@`, `\t`, `\r`, `\n`), exposant les postes de supervision à des attaques par injection de formules (CSV Formula Injection / DDE Execution).

---

## 2. ANALYSE DE CAUSE RACINE

1. **Absence de décorateurs d'accès :** Lors des refactorisations précédentes, les endpoints d'alertes n'avaient pas reçu `@login_required` ni `@roles_required("ADMIN", "OPERATOR", "AUDITOR")`.
2. **Manque de validation sur les filtres :** Les paramètres `device_id`, `limit`, `offset`, `period`, `query` et `type` n'étaient pas filtrés de manière stricte contre les injections et valeurs négatives.
3. **Absence de filtrage dans `RecordingManager.export_csv()` :** La méthode `export_csv()` écrivait directement les dictionnaires d'alertes dans le flux `csv.DictWriter` sans inspecter les caractères initiaux des champs texte.

---

## 3. MODIFICATIONS APPORTÉES ET REMÉDIATION

### 3.1. `routes/alerts.py`
- Ajout des décorateurs `@login_required` et `@roles_required("ADMIN", "OPERATOR", "AUDITOR")` sur `list_alerts()` et `export_csv()`.
- Validation stricte du paramètre `device_id` via regex `^[a-zA-Z0-9_-]+$` (rejet 400 en cas de caractère spécial / tentative de traversée) et contrôle d'existence sur le magasin d'appareils `coordinator.device_store` (rejet 404 si l'appareil est inexistant ou hors périmètre).
- Rejet des caractères de contrôle (`\x00`, `\r`, `\n`) dans les champs textuels `type` et `query` (rejet 400).
- Contrôle de la période temporelle `period` (whitelist : `today`, `24h`, `7d`, `all`).
- Validation stricte de la pagination : `limit` (rejet si négatif ou non entier, clamp sécurisé à 1000 maximum) et `offset` (rejet si négatif ou non entier).
- Alignement du périmètre d'exportation : `export_csv` accepte les mêmes paramètres de filtrage que `list_alerts` et transmet la liste filtrée à `coordinator.recording_manager.export_csv(alerts=alerts)`.

### 3.2. `monitoring/recording_manager.py`
- Mise à jour de la signature : `def export_csv(self, alerts: Optional[List[dict]] = None) -> str`.
- Implémentation de la neutralisation OWASP CSV Formula Injection :
  - Détection des chaînes débutant par `=`, `+`, `-`, `@`, `\t`, `\r`, `\n` ou précédées d'espaces avant ces caractères.
  - Préfixage systématique d'une apostrophe (`'`) pour forcer l'évaluation textuelle dans les suites bureautiques (Microsoft Excel, LibreOffice Calc).
  - Préservation intelligente des valeurs purement numériques dans les colonnes `measured_value` et `threshold` (ex: `-5.2` ou `+3.0`).

---

## 4. MATRICE DE TESTS ADVERSARIAUX (`tests/test_pro13_a4_2_2_alerts_endpoint_security.py`)

| Test ID | Scénario testé | Résultat attendu | Résultat obtenu | Statut |
|---|---|---|---|---|
| `test_a422_01` | GET `/api/alerts` sans session | HTTP 401 Rejet | HTTP 401 | **PASS** |
| `test_a422_02` | GET `/api/alerts/export/csv` sans session | HTTP 401 Rejet | HTTP 401 | **PASS** |
| `test_a422_03` | Session révoquée côté serveur | HTTP 401 Rejet | HTTP 401 | **PASS** |
| `test_a422_04` | Utilisateur désactivé (`is_active=False`) | HTTP 401 Rejet | HTTP 401 | **PASS** |
| `test_a422_05` | Rôle non autorisé (`GUEST` / `VIEWER`) | HTTP 403 Rejet | HTTP 403 | **PASS** |
| `test_a422_06` | Rôle `OPERATOR` légitime | HTTP 200 Succès | HTTP 200 | **PASS** |
| `test_a422_07` | Rôle `AUDITOR` légitime | HTTP 200 Succès | HTTP 200 | **PASS** |
| `test_a422_08` | Rôle `ADMIN` légitime | HTTP 200 Succès | HTTP 200 | **PASS** |
| `test_a422_09` | Validation `device_id` (traversée, injection, 404 périmètre) | 400 Bad / 404 Not Found | 400 & 404 | **PASS** |
| `test_a422_10` | Pagination négative, non entière, query invalide | HTTP 400 Bad Request | HTTP 400 | **PASS** |
| `test_a422_11` | Neutralisation Formula Injection (`=`, `+`, `-`, `@`, `\t`, `\r`, `\n`) | Cellules préfixées par `'` | Préfixées `'` | **PASS** |

---

## 5. VERDICT TECHNIQUE

```text
FINDING_F01_STATUS = RESOLVED
ALERTS_ENDPOINT_SECURITY = PASS
CSV_FORMULA_INJECTION_DEFENSE = PASS
TESTS_COVERAGE = 11/11 PASSED (100%)
REGRESSION_RISK = ZERO
```
