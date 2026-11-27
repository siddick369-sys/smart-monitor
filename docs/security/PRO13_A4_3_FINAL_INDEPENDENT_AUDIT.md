# PRO13-A.4.3 — FINAL INDEPENDENT AUDIT REPORT

**Mission ID :** `SSM-PRO13-A4-3-EGRESS-HARDENING-AND-CRYPTOGRAPHIC-CONTINUITY-01`  
**Date / Horodatage :** 2026-11-27T07:13:00+01:00  
**Dépôt :** `C:\Users\USER\Documents\alarme-sys` | **Branche :** `main` | **HEAD :** `b339a9c82d5b410e78d1ea6d43cae556049ba2c0`  

---

## 1. SYNTHÈSE EXÉCUTIVE DE L'AUDIT

L'audit indépendant en lecture seule **PRO-13-A.4.3** a permis d'établir par preuves directes les causes techniques des deux limitations majeures identifiées en PRO-13-A.4.2.3 ainsi que des écarts résiduels de surface Web/API :

1. **Confinement Egress Windows & Docker :**
   - Sur l'hôte Windows actuel, `DefaultOutboundAction=NotConfigured` (équivalent à `Allow`) et aucune règle `SSM_NVR_FFmpeg_Egress*` n'est active (`WINDOWS_EGRESS_NOT_ENFORCED`).
   - L'audit statique de `scripts/setup_ffmpeg_egress_firewall.ps1` révèle deux défauts de conception majeurs : absence de blocage des IP publiques sans `-EnforceDefaultBlockProfile`, et exclusion de tout le sous-réseau privé `/8`, `/12` ou `/16` lors du chevauchement d'une seule IP caméra.
   - `scripts/check_ffmpeg_egress_firewall.ps1` peut émettre un faux positif `WINDOWS_EGRESS_ENFORCED` sous `DefaultOutboundAction=NotConfigured`.
   - `com.docker.service` est arrêté (`Stopped`), et `scripts/setup_docker_egress_host.sh` omet les règles IPv6 dans sa branche `nftables` ainsi que l'idempotence dans `DOCKER-USER`.

2. **Continuité HMAC (`storage/security_monitor.db` — `integrity_log`) :**
   - La cause racine de l'échec `verify_chain_integrity(check_hmac=True)` à l'entrée #3 est **démontrée à 100 %** : sur 1 031 entrées, le chaînage SHA-256 (`prev_hash` et `entry_hash`) est exact pour toutes les entrées, mais 377 entrées ont `hmac_sig=None` et 176 entrées (dont l'entrée #3 issue de `pytest` — `test_integrity.py`) ont été signées avec des clés de test différentes dans la même base partagée, sans colonne `key_id`.

3. **CSP/XSS & Routes `GET` secondaires :**
   - `'unsafe-inline'` reste requis par Tailwind Play CDN et les handlers/scripts inline.
   - Un contexte mixte HTML -> JS subsiste dans `openImageModal` (`renderAlertsTable`), et plusieurs routes `GET` de lecture (`/api/timeline`, `/api/reports/*/pdf`, `/storage/screenshots/*`, `/video_feed/*`, `/api/devices`, `/api/status`) restent dépourvues de `@login_required`.

---

## 2. PRÉSERVATION DES PREUVES ET RESPECT DES INTERDICTIONS

- Aucune modification de code applicatif, de test, de base de données, de pare-feu ou de configuration Git n'a été effectuée durant cette mission.
- **Lot B demeure strictement bloqué.**
