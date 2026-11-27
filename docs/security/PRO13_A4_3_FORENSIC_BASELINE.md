# PRO13-A.4.3 — FORENSIC BASELINE & REPOSITORY INTEGRITY REPORT

**Mission ID :** `SSM-PRO13-A4-3-EGRESS-HARDENING-AND-CRYPTOGRAPHIC-CONTINUITY-01`  
**Date / Horodatage local :** 2026-11-27T07:04:00+01:00  
**Dépôt :** `C:\Users\USER\Documents\alarme-sys`  
**Branche :** `main`  
**HEAD :** `b339a9c82d5b410e78d1ea6d43cae556049ba2c0`  
**Périmètre :** Établissement de la baseline forensique en lecture seule avant audit Egress, HMAC et CSP/XSS.  
**Méthode :** Inspection directe Git (`git branch`, `git rev-parse`, `git status`, `git log`) et calcul SHA-256 non mutatif.

---

## 1. ÉTAT DU DÉPÔT ET HISTORIQUE GIT

- **Derniers commits :**
  - `b339a9c` — `docs(pro13): add Lot A NVR report and git push automation scripts`
  - `5952bb8` — `feat(security): complete PRO-12.5 P2P downgrade elimination and startup security enforcement`
  - `8eb75c7` — `first commit`
- **Modifications suivies (`unstaged`, 11 fichiers issus des missions Lot A / A.4.2.x) :**
  `app.py`, `monitoring/acquisition/__init__.py`, `monitoring/acquisition/discovery.py`, `monitoring/acquisition/ffmpeg_adapter.py`, `monitoring/acquisition/onvif_adapter.py`, `monitoring/acquisition/security.py`, `monitoring/notification_manager.py`, `monitoring/recording_manager.py`, `routes/alerts.py`, `static/js/dashboard.js`, `tests/test_pro13_lot_a_nvr.py`.
- **Fichiers non suivis (`untracked`) :**
  `docker/`, `monitoring/acquisition/egress_policy.py`, `scripts/*`, `tests/test_pro13_a4_2*.py`, et les rapports historiques dans `docs/security/` (y compris les 16 rapports `PRO13_A4_2_2_*.md` et les 15 rapports `PRO13_A4_2_3_*.md`).
- **Modifications utilisateur imprévues :** Aucune détectée.

---

## 2. EMPREINTES SHA-256 DES FICHIERS CRITIQUES AUDITÉS

| Fichier | Empreinte SHA-256 |
|---|---|
| `app.py` | `17d96f22c3fa3ff418ca103f833801e1e18d71338d2aa18aa7e711eec93ceb65` |
| `routes/alerts.py` | `4990e257d36513b49d109640fd754cb43cca966de317ca3fae762ddccf7db5d0` |
| `monitoring/integrity_manager.py` | `3b00d8d648309f8f7beadb08235e55877826da1f1975d52b32982035002a19eb` |
| `monitoring/models.py` | `4596d83be354d764236c9d69931523ae8c136d61209d384ad1bc8da33a6f4106` |
| `monitoring/acquisition/egress_policy.py` | `c507a6379ddd46bc6a38ca27626baddcbe30f842cab1956a48ad5c8b1827640e` |
| `monitoring/acquisition/ffmpeg_adapter.py` | `7ce5ee4d27c1f49c8daf2e07b94164f7773750908b41ddd2b8a83e43d3e32a93` |
| `monitoring/acquisition/security.py` | `be5cb25a445e421be4da0535c262aa48a2da70b7fba28b1bd42edc1f1e4786c1` |
| `static/js/dashboard.js` | `6688f8c0d8f40c563c2fd268724bdfe6d4c7a107d9c202b9e158f3360bf4cc53` |
| `templates/login.html` | `9d0c65b49622ee8b925ca5cd2b6b6ec663f8864086bd7243cc8547b3363d4f51` |
| `templates/dashboard.html` | `52dde5c1c1fa8a5620a7f9ced8271a91164df2a5b0c1ee1fb31565e2d72a4d73` |
| `scripts/setup_ffmpeg_egress_firewall.ps1` | `9cbd2a719cee7d2c293463666c354912731270c0fbd53f39c3a25ab29bf08620` |
| `scripts/check_ffmpeg_egress_firewall.ps1` | `bc2d068a51999d0401b25d295648675e651a3e59d0c2c30e0c40ff737494b0f3` |
| `scripts/teardown_ffmpeg_egress_firewall.ps1` | `006ca8dcdca9f1790f49d72f6e083c479155a180a91892a5ef680934b94bb0f3` |
| `scripts/test_ffmpeg_egress_connectivity.ps1` | `2268c57d773cd1423b34f5e0203760712e65b9106138ca827d91890741a74d83` |
| `scripts/setup_docker_egress_host.sh` | `00d15df7363e7ba56d4ba32912cfd4a2419280aa3b55e22df71487316a8a5fa8` |

---

## 3. RÉSULTATS, LIMITES ET STATUT

- **Commandes exécutées :** `Get-Location`, `git branch --show-current`, `git rev-parse HEAD`, `git status --short`, `git log -n 3 --oneline`, calcul SHA-256 Python.
- **Limites :** Aucun changement Git ni modification de code autorisé.
- **Constats :** Dépôt conforme à la baseline attendue (`b339a9c82d5b410e78d1ea6d43cae556049ba2c0`), rapports PRO-13-A.4.2.3 tous présents.
- **Statut :** `FORENSIC_GATE = PASS`
- **Recommandations :** Maintenir le gel strict du dépôt durant toute la durée de l'audit PRO-13-A.4.3.
