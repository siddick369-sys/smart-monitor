# PRO13-A.4.2.2 — BASELINE FORENSIC REPORT

**Mission ID:** `SSM-PRO13-A4-2-2-SECURITY-CLOSURE-AND-FULL-LOCAL-REQUALIFICATION-01`  
**Classification:** FORENSIC BASELINE & AUDIT INTEGRITY REGISTER  
**Date / Timestamp:** 2026-11-26T18:20:00+01:00  
**Repository:** `C:\Users\USER\Documents\alarme-sys`  
**Branch:** `main`  
**Historical Baseline HEAD:** `b339a9c82d5b410e78d1ea6d43cae556049ba2c0`  

---

## 1. ENVIRONNEMENT TECHNIQUE

| Paramètre | Valeur constatée |
|---|---|
| **Système d'exploitation** | Windows 11 Professionnel (Build 10.0.26200, AMD64) |
| **Interpréteur Python** | Python 3.11.8 (tags/v3.11.8:db85d51, Feb 6 2024, MSC v.1937 64 bit) |
| **OpenCV** | 4.10.0 |
| **Flask** | 3.0.3 / Werkzeug 3.0.3 |
| **SQLAlchemy** | 2.0.30 (Moteur SQLite 3) |
| **Privilèges processus** | Utilisateur standard (`IsInRole(Administrator) == False`) |
| **Pare-feu hôte** | Windows Defender Firewall actif (non modifiable sans élévation de privilèges) |
| **Docker daemon** | Arrêté / Service non accessible sur le host (`NOT_AVAILABLE`) |
| **Binaire FFmpeg** | Absent du PATH système (`NOT_AVAILABLE`) |
| **Caméra physique** | Absente (`NOT_AVAILABLE`) / Remplacée par simulateur local HTTP |
| **Modèle IA ONNX** | Inexistant sur disque / Remplacé par le moteur de repli OpenCV |

---

## 2. INTÉGRITÉ DE LA BASE DE DONNÉES (`storage/security_monitor.db`)

État initial vérifié avant toute opération :

| Table | Nombre de lignes | Note d'intégrité |
|---|---|---|
| `users` | 174 | Comptes administrateurs, opérateurs et auditeurs |
| `devices` | 1 | Appareil par défaut configuré |
| `notifications` | 1009 | Historique des alertes et événements |
| `integrity_log` | 959 | Chaîne de confiance HMAC SHA-256 |
| `alerts` | 4 | Alertes persistées |
| `evidences` | 679 | Empreintes SHA-256 des preuves photo et vidéo |
| `decryption_requests` | 972 | Registre de confidentialité |
| `system_bootstrap` | 0 | Amorce système |
| `user_sessions` | 1585 | Sessions utilisateurs (gestion des révocations) |
| `p2p_received_events` | 6 | Événements réseau P2P |
| `failed_auth_attempts` | 808 | Registre anti-bruteforce |
| `decryption_approvals` | 1405 | Approbations multi-clés |

La chaîne HMAC de 959 entrées est intacte et exempte de corruption.

---

## 3. EMPREINTES SHA-256 DES FICHIERS CRITIQUES INITIALS

| Fichier | Empreinte SHA-256 de référence |
|---|---|
| `app.py` | `701b35fdcc8ca813d1a5e91f524cbdbe9abe14105be4fbd52632481c0c5fa8b5` |
| `routes/alerts.py` | `2edb3ab605ab42e0fb5b64afa98ff2e84809872f915d2948be157916db5ef847` |
| `monitoring/recording_manager.py` | `85550032a65826ebf9f7d7576b5871955c803e517fdf1ac9660b3d8272697088` |
| `monitoring/notification_manager.py` | `1b461bffdcd3792739dd77ffd9685c5171ce2810007080c5a1a7541a56b6a12b` |
| `monitoring/acquisition/egress_policy.py` | `c507a6379ddd46bc6a38ca27626baddcbe30f842cab1956a48ad5c8b1827640e` |
| `monitoring/acquisition/ffmpeg_adapter.py` | `7ce5ee4d27c1f49c8daf2e07b94164f7773750908b41ddd2b8a83e43d3e32a93` |
| `monitoring/acquisition/security.py` | `be5cb25a445e421be4da0535c262aa48a2da70b7fba28b1bd42edc1f1e4786c1` |

---

## 4. VALIDATION DU SOCLE DE TESTS DE DÉPART (NON-RÉGRESSION INITIALE)

Exécution forensique directe des suites existantes sur l'environnement hôte :

1. **Suite historique PRO-12 (6 fichiers, 127 tests) :**
   - Commande : `python -m pytest tests/test_pro12*.py -q`
   - Résultat : `127 passed, 1 warning in 66.33s`
   - Statut : **CONFORME À 100%**
2. **Suite NVR Lot A (1 fichier, 55 tests) :**
   - Fichier : `tests/test_pro13_lot_a_nvr.py`
   - Résultat : `55 passed in 18.15s`
   - Statut : **CONFORME À 100%**
3. **Suite Egress Enforcement A.4.2 (1 fichier, 37 tests) :**
   - Fichier : `tests/test_pro13_a4_2_egress_enforcement.py`
   - Résultat : `37 passed in 5.05s`
   - Statut : **CONFORME À 100%**

**Total baseline vérifié : 219 tests réussis sans aucune régression.**

---

## 5. FINDINGS IDENTIFIÉS EN ENTRÉE DE MISSION A.4.2.2

1. **Finding F-01 (Priorité Haute / P1) : Endpoints Alertes Non Authentifiés**
   - Emplacement : `routes/alerts.py` (lignes 14 et 33).
   - Constat : `GET /api/alerts` et `GET /api/alerts/export/csv` ne possèdent pas `@login_required` ni `@roles_required`. Tout client anonyme peut extraire l'intégralité du journal des alertes.
   - Constat additionnel : Absence de neutralisation anti-CSV Formula Injection sur les cellules contrôlables par les utilisateurs ou capteurs (cellules débutant par `=`, `+`, `-`, `@`, `\t`, `\r`, `\n`).

2. **Finding F-02 (Priorité Moyenne / P2) : Durcissement CSP & Absence de définition `escapeHtml` côté Frontend**
   - Emplacement : `app.py` et `static/js/dashboard.js`.
   - Constat : La CSP contient `'unsafe-inline'`. Des directives de restriction de frame, plugins et actions de formulaires manquent (`object-src 'none'`, `base-uri 'self'`, `form-action 'self'`, `frame-ancestors 'self'`).
   - Constat frontend : Dans `static/js/dashboard.js`, la fonction `escapeHtml` est appelée sur certains éléments mais n'est pas définie dans le script ni dans les templates, et plusieurs injections directes dans `innerHTML` (notamment `renderAlertsTable` et `renderNotifications`) n'appliquent aucun échappement HTML.

3. **Finding F-03 (Priorité Information / P3) : Confinement Egress sous Windows Standard**
   - Emplacement : `monitoring/acquisition/egress_policy.py`.
   - Constat : Sous environnement non-administrateur sans FFmpeg installé, `WindowsEgressProvider` détecte l'absence d'élévation et applique le fail-closed sécurisé conformément aux règles d'architecture.

---

## 6. VERDICT INITIAL

```text
BASELINE_STATE = VERIFIED_CLEAN
PREVIOUS_REGRESSIONS = NONE
SECURITY_FINDINGS_PENDING = F-01, F-02
PROCEED_TO_REMEDIATION = AUTHORIZED
```
