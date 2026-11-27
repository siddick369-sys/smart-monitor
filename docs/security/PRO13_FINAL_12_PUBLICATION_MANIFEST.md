# PRO13_FINAL_12_PUBLICATION_MANIFEST

**Mission ID:** `SSM-PRO13-FINAL-LIVE-QUALIFICATION-AND-GITHUB-PUSH-01`  
**Date:** 2026-11-27  

---

## 1. Périmètre Exact de Publication (Fichiers Inclus)

La publication vers le dépôt distant `origin/main` inclut exclusivement les fichiers validés ci-dessous :

### Code Applicatif & Configuration :
- `app.py`
- `config.py`
- `database.py`
- `monitoring/acquisition/__init__.py`
- `monitoring/acquisition/discovery.py`
- `monitoring/acquisition/egress_policy.py`
- `monitoring/acquisition/ffmpeg_adapter.py`
- `monitoring/acquisition/onvif_adapter.py`
- `monitoring/acquisition/security.py`
- `monitoring/integrity_manager.py`
- `monitoring/models.py`
- `monitoring/notification_manager.py`
- `monitoring/recording_manager.py`
- `routes/alerts.py`
- `routes/dashboard.py`
- `routes/devices.py`
- `static/js/dashboard.js`

### Confinement & Scripts de Déploiement :
- `docker/`
- `scripts/check_ffmpeg_egress_firewall.ps1`
- `scripts/setup_docker_egress_host.sh`
- `scripts/setup_ffmpeg_egress_firewall.ps1`
- `scripts/teardown_ffmpeg_egress_firewall.ps1`
- `scripts/test_ffmpeg_egress_connectivity.ps1`

### Suite de Tests Automatisés :
- `tests/conftest.py`
- `tests/test_pro13_lot_a_nvr.py`
- `tests/test_pro13_a4_2_2_alerts_endpoint_security.py`
- `tests/test_pro13_a4_2_2_csp_security.py`
- `tests/test_pro13_a4_2_2_xss_output_encoding.py`
- `tests/test_pro13_a4_2_egress_enforcement.py`
- `tests/test_pro13_a4_4_egress_scripts.py`
- `tests/test_pro13_a4_4_get_routes_access_control.py`
- `tests/test_pro13_a4_4_hmac_continuity.py`
- `tests/test_pro13_a4_4_sqlite_isolation.py`

### Documentation et Rapports d'Audit de Sécurité :
- Tous les rapports d'audit forensique et de qualification dans `docs/security/` (y compris les rapports PRO-13-A.1 à PRO-13-FINAL).

---

## 2. Périmètre des Exclusions Strictes (Non Publiés)

Les fichiers suivants sont strictement exclus de la publication :
- `.env` et `.env.local`
- `storage/*.db*` (y compris `storage/security_monitor.db`, bases temporaires, fichiers WAL et SHM)
- `storage/recordings/*` (hors `.gitkeep`)
- `storage/screenshots/*` (hors `.gitkeep`)
- `storage/logs/*` (hors `.gitkeep`)
- `storage/keys/*` (hors `.gitkeep`)
- `storage/backups/*` (hors `.gitkeep`)
- `.pytest_cache/`
- Dossiers temporaires de tests et fichiers de cache Python (`__pycache__`)
