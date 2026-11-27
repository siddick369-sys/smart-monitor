# PRO13-A.4.2.2 — AUTHENTICATION, RBAC & CSRF INDEPENDENT AUDIT REPORT

**Mission ID:** `SSM-PRO13-A4-2-2-SECURITY-CLOSURE-AND-FULL-LOCAL-REQUALIFICATION-01`  
**Classification:** SECURITY ARCHITECTURE AUDIT / IDENTITY & ACCESS MANAGEMENT / CSRF PROTECTION  
**Date / Timestamp:** 2026-11-26T18:47:00+01:00  
**Repository:** `C:\Users\USER\Documents\alarme-sys`  
**Branch:** `main`  
**HEAD:** `b339a9c82d5b410e78d1ea6d43cae556049ba2c0`  

---

## 1. PÉRIMÈTRE ET ARCHITECTURE D'AUTHENTIFICATION

L'architecture d'authentification et de contrôle d'accès repose sur le module `monitoring/auth_manager.py` et les modèles SQLAlchemy de `monitoring/models.py` :

1. **Gestion des sessions côté serveur :**
   - Chaque connexion génère un jeton cryptographiquement sécurisé (`secrets.token_hex(32)`) enregistré dans la table `user_sessions`.
   - La fonction `validate_session(user_id, session_token)` vérifie en base que la session existe, que le jeton correspond, que `revoked == False` et que l'utilisateur est actif (`User.is_active == True`).
   - Comportement strictement **FAIL-CLOSED** en cas d'erreur ou d'absence de session en base.

2. **Révocation de session :**
   - La déconnexion (`/auth/logout`) révoque la session spécifique.
   - Toute suppression d'utilisateur ou changement de mot de passe révoque l'intégralité des sessions actives de cet utilisateur via `revoke_all_sessions_for_user()`.

3. **Protection anti-bruteforce :**
   - Les tentatives infructueuses sont tracées en mémoire et en base (`failed_auth_attempts`).
   - Verrouillage temporaire après 5 échecs consécutifs sur une fenêtre de 300 secondes.

4. **Politique de mot de passe & 2FA :**
   - Complexité obligatoire (8 caractères minimum, majuscule, minuscule, chiffre, caractère spécial).
   - Authentification à deux facteurs TOTP (RFC 6238) avec codes de secours à usage unique.

---

## 2. MODÈLE RBAC (ROLE-BASED ACCESS CONTROL)

Le système reconnaît trois rôles distincts et immuables :
- `ADMIN` : Administration complète du système, gestion des utilisateurs, suppression des preuves, modification des seuils et configuration réseau.
- `OPERATOR` : Surveillance opérationnelle, acquittement des notifications, pilotage des caméras, consultation des alertes, simulation d'incidents.
- `AUDITOR` : Revue médico-légale et conformité, vérification de la chaîne d'intégrité HMAC, export des données, consultation des alertes et du journal de sécurité.

### Matrice d'autorisation des routes critiques :

| Route | Méthode | Rôles autorisés | Comportement si non authentifié | Comportement si rôle insuffisant |
|---|---|---|---|---|
| `/api/alerts` | GET | ADMIN, OPERATOR, AUDITOR | 401 Unauthorized | 403 Forbidden |
| `/api/alerts/export/csv` | GET | ADMIN, OPERATOR, AUDITOR | 401 Unauthorized | 403 Forbidden |
| `/api/alerts/<id>` | DELETE | ADMIN | 401 Unauthorized | 403 Forbidden |
| `/api/alerts/clear` | POST | ADMIN | 401 Unauthorized | 403 Forbidden |
| `/api/simulate_alert` | POST | ADMIN, OPERATOR | 401 Unauthorized | 403 Forbidden |
| `/api/storage/clean` | POST | ADMIN | 401 Unauthorized | 403 Forbidden |
| `/api/integrity/chain/verify` | GET | ADMIN, AUDITOR | 401 Unauthorized | 403 Forbidden |
| `/api/database/migrate` | POST | ADMIN | 401 Unauthorized | 403 Forbidden |
| `/api/database/export` | GET | ADMIN, AUDITOR | 401 Unauthorized | 403 Forbidden |

---

## 3. PROTECTION CONTRE LES ATTAQUES CSRF

1. **Jeton CSRF synchrone :**
   - Un jeton cryptographique aléatoire de 32 octets est associé à la session utilisateur (`session["csrf_token"]`).
   - L'endpoint `/api/auth/csrf_token` permet au frontend de synchroniser son jeton.
2. **Interception et validation globale (`app.py:enforce_csrf`) :**
   - Toutes les requêtes HTTP mutatives (`POST`, `PUT`, `DELETE`, `PATCH`) sont interceptées.
   - Le jeton transmis via l'en-tête `X-CSRF-Token` est comparé au jeton de session via `hmac.compare_digest` (protection contre les attaques temporelles).
   - Les requêtes sans jeton valide sont rejetées avec HTTP 403.
   - Les endpoints légitimement pré-authentification (`/auth/login`, `/api/auth/csrf_token`) sont exemptés de manière ciblée.

---

## 4. VERDICT

```text
AUTHENTICATION_CONTROLS = PASS
RBAC_POLICY_ENFORCEMENT = PASS
CSRF_DEFENSE = PASS
OVERALL_IAM_GATE = PASS
```
