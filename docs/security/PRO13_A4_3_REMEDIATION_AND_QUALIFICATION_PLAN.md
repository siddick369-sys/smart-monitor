# PRO13-A.4.3 — REMEDIATION & QUALIFICATION PLAN (NON APPLIQUÉ)

**Mission ID :** `SSM-PRO13-A4-3-EGRESS-HARDENING-AND-CRYPTOGRAPHIC-CONTINUITY-01`  
**Date / Horodatage :** 2026-11-27T07:12:00+01:00  
**Dépôt :** `C:\Users\USER\Documents\alarme-sys` | **Branche :** `main` | **HEAD :** `b339a9c82d5b410e78d1ea6d43cae556049ba2c0`  
**Statut :** PLAN PRÉPARATOIRE — AUCUNE ÉTAPE EXÉCUTÉE DURANT CETTE MISSION.

---

## 1. PLAN DE REMÉDIATION EGRESS (WINDOWS & DOCKER)

1. **Modification des scripts (Phase ultérieure autorisée) :**
   - `scripts/setup_ffmpeg_egress_firewall.ps1` : supprimer l'exclusion globale de tout `/8`, `/12`, `/16` lors d'un chevauchement d'une IP caméra unique ; bloquer explicitement les plages publiques et le reste du sous-réseau privé pour `ffmpeg.exe` (ou exiger un hôte dédié avec `-EnforceDefaultBlockProfile`).
   - `scripts/check_ffmpeg_egress_firewall.ps1` : ne retourner `WINDOWS_EGRESS_ENFORCED` que si `DefaultOutboundAction=Block` OU si le jeu de règles Block couvre explicitement IPv4 + IPv6 (y compris plages publiques et sous-réseaux privés hors IP caméras), et échouer si une destination attendue manque.
   - `scripts/setup_docker_egress_host.sh` : ajouter les règles `ip6` dans la branche `nftables` et rendre l'insertion `DOCKER-USER` idempotente (nettoyage préalable des règles `SSM_DOCKER_EGRESS_DROP`).
2. **Autorisation & Application Administrateur :** Validation humaine, puis exécution en session Administrateur (Windows) ou root (Linux).
3. **Contrôle après application & Test de trafic :** Exécuter `check_ffmpeg_egress_firewall.ps1` puis `test_ffmpeg_egress_connectivity.ps1` (vérifier connexion autorisée vs refus port interdit / IP tierce / `::1`).
4. **Rollback :** `scripts/teardown_ffmpeg_egress_firewall.ps1 -Force`.

---

## 2. PLAN DE CONTINUITÉ CRYPTOGRAPHIQUE (HMAC & ISOLATION DB)

1. **Isolation des tests :** Configurer `conftest.py` pour rediriger `config.DB_PATH` vers une base SQLite temporaire (`tmp_path`) afin de stopper toute pollution de `storage/security_monitor.db`.
2. **Préservation & Manifeste :** Figer `storage/security_monitor.db` telle quelle (ou archiver pour la production), générer un manifeste JSON signé (`storage/continuity_manifest.json`) documentant les entrées historiques #1-#1031 sans jamais réécrire leurs signatures.
3. **Schéma v2 (`IntegrityLogEntry`) :** Ajouter `format_version`, `algorithm`, `key_id` ; imposer `check_hmac=True` sans fallback silencieux sur toutes les nouvelles entrées `v2`.

---

## 3. PLAN CSP / XSS & SÉCURITÉ GLOBALE

1. **Correction des sinks résiduels :** Passer `safeType` par `encodeURIComponent` / `data-*` sur `openImageModal` dans `renderAlertsTable` ; remplacer `${err.message}` et `renderDiagnostic` par `textContent`.
2. **Suppression progressive de `'unsafe-inline'` :** Externaliser les `<script>` inline de `login.html` / `dashboard.html`, remplacer les `onclick` par `addEventListener`, servir Tailwind CSS compilé localement, tester en `Content-Security-Policy-Report-Only` puis basculer en CSP stricte (et vérifier en navigateur réel).
3. **Protection des routes `GET` secondaires :** Ajouter `@login_required` et `@roles_required` sur `/api/timeline`, `/api/reports/*/pdf`, `/storage/screenshots/*`, `/storage/recordings/*`, `/api/devices`, `/video_feed/*`, `/api/status`.
