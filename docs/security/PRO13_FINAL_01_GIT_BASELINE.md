# PRO13_FINAL_01_GIT_BASELINE

**Mission ID:** `SSM-PRO13-FINAL-LIVE-QUALIFICATION-AND-GITHUB-PUSH-01`  
**Date:** 2026-11-27  
**Projet:** Smart Security Monitor (SSM)  
**Branche:** `main`  
**HEAD de référence initial:** `b339a9c82d5b410e78d1ea6d43cae556049ba2c0`  
**Dépôt canonique:** `C:\Users\USER\Documents\alarme-sys`  

---

## 1. État Initial du Dépôt

L'inspection forensique initiale au démarrage de la mission confirme :
- **Branche active :** `main`
- **Dernier commit HEAD :** `b339a9c82d5b410e78d1ea6d43cae556049ba2c0` (`docs(pro13): add Lot A NVR report and git push automation scripts`)
- **Dépôt distant (origin) :** `https://github.com/siddick369-sys/smart-monitor.git`

## 2. Inventaire des Modifications en Espace de Travail

Les fichiers modifiés et non encore indexés proviennent des missions de remédiation contrôlées PRO-13-A.1 à PRO-13-A.4.4 :

### Fichiers Applicatifs Modifiés (16 fichiers) :
- `app.py` : Entêtes de sécurité CSP/HSTS/Frame-Ancestors, redirection login, validation stricte de démarrage.
- `config.py` : Paramètre dynamique `SSM_DB_PATH`, durcissement des variables d'environnement.
- `database.py` : Garde `is_protected_production_db_path()` et reconfiguration dynamique `rebind_database()`.
- `monitoring/acquisition/__init__.py` : Exports du sous-système d'acquisition NVR et egress policy.
- `monitoring/acquisition/discovery.py` : Validation et filtrage sécurisé des périphériques découverts.
- `monitoring/acquisition/ffmpeg_adapter.py` : Confinement d'exécution FFmpeg, suppression des proxies d'environnement, timeouts stricts.
- `monitoring/acquisition/onvif_adapter.py` : Confinement ONNX/RTSP et gestion des timeouts réseau.
- `monitoring/acquisition/security.py` : Validation stricte des flux RTSP/HTTP, filtrage DNS/SSRF et adresses interdites.
- `monitoring/integrity_manager.py` : Support format v2 HMAC-SHA256 avec clé `k_active_v2`, génération de manifeste de continuité en lecture seule.
- `monitoring/models.py` : Champs cryptographiques v2 (`format_version`, `algorithm`, `key_id`).
- `monitoring/notification_manager.py` : Contrôle d'accès et isolation multi-utilisateurs des notifications.
- `monitoring/recording_manager.py` : Nettoyage sécurisé et vérification d'intégrité des enregistrements.
- `routes/alerts.py` : Contrôle d'accès RBAC `@login_required` / `@roles_required`, validation canonique des chemins de preuves, export CSV sécurisé (anti formule CSV injection).
- `routes/dashboard.py` : Contrôle d'accès RBAC et injection des jetons CSRF.
- `routes/devices.py` : Validation des paramètres d'acquisition réseau.
- `static/js/dashboard.js` : Élimination des injections XSS contextuelles, assainissement `openImageModal` via `decodeURIComponent`.
- `tests/test_pro13_lot_a_nvr.py` : Suite complète de qualification NVR Lot A (700+ lignes).
- `tests/test_pro13_a4_4_hmac_continuity.py` : Tests de continuité cryptographique et manifeste.

### Fichiers Nouveaux (Scripts & Tests de Sécurité) :
- `monitoring/acquisition/egress_policy.py` : Calcul précis des CIDR complémentaires de blocage egress.
- `scripts/check_ffmpeg_egress_firewall.ps1` : Audit non-privilégié des règles de pare-feu Windows.
- `scripts/setup_ffmpeg_egress_firewall.ps1` : Script de configuration Egress Windows avec calcul de masques sans chevauchement.
- `scripts/teardown_ffmpeg_egress_firewall.ps1` : Démontage propre des règles pare-feu.
- `scripts/test_ffmpeg_egress_connectivity.ps1` : Test de connectivité egress.
- `scripts/setup_docker_egress_host.sh` : Script iptables/ip6tables durci et idempotent.
- `docker/` : Configuration de confinement Docker multi-stage.
- `tests/conftest.py` : Fixture globale pytest avec isolation stricte SQLite dans répertoire temporaire.
- `tests/test_pro13_a4_2_2_alerts_endpoint_security.py`
- `tests/test_pro13_a4_2_2_csp_security.py`
- `tests/test_pro13_a4_2_2_xss_output_encoding.py`
- `tests/test_pro13_a4_2_egress_enforcement.py`
- `tests/test_pro13_a4_4_egress_scripts.py`
- `tests/test_pro13_a4_4_get_routes_access_control.py`
- `tests/test_pro13_a4_4_sqlite_isolation.py`

---
## 3. Conformité de la Baseline
Aucune divergence non maîtrisée n'est présente sur le dépôt. L'intégralité du code et des tests est cohérente avec les spécifications de la mission.
