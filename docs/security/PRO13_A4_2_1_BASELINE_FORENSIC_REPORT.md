# 🛡️ SSM PRO-13-A.4.2.1 — BASELINE FORENSIC REPORT
## RECONSTITUTION INITIALE DU DÉPÔT, MANIFESTE SHA-256 ET AUDIT COMPARATIF DES RAPPORTS A4.2

**Mission ID :** `SSM-PRO13-A4.2.1-INDEPENDENT-AUDIT-AND-LIVE-END-TO-END-QUALIFICATION-01`  
**Projet :** Smart Security Monitor (SSM)  
**Dépôt canonique :** `C:\Users\USER\Documents\alarme-sys`  
**Branche observée :** `main`  
**HEAD de référence vérifié :** `b339a9c82d5b410e78d1ea6d43cae556049ba2c0`  
**Date d'observation :** 2026-11-26T15:53:00+01:00  
**Environnement :** Microsoft Windows 11 AMD64 · Python 3.11.8 · pytest 9.1.1  

---

## 1. ÉTAT INITIAL DU DÉPÔT (GIT BASELINE)

- **Commande :** `git rev-parse HEAD` -> `b339a9c82d5b410e78d1ea6d43cae556049ba2c0`
- **Branche :** `main`
- **Git status :**
  ```text
  M monitoring/acquisition/__init__.py
  M monitoring/acquisition/discovery.py
  M monitoring/acquisition/ffmpeg_adapter.py
  M monitoring/acquisition/onvif_adapter.py
  M monitoring/acquisition/security.py
  M tests/test_pro13_lot_a_nvr.py
  ?? docker/
  ?? docs/security/...
  ?? monitoring/acquisition/egress_policy.py
  ?? scripts/check_ffmpeg_egress_firewall.ps1
  ?? scripts/setup_docker_egress_host.sh
  ?? scripts/setup_ffmpeg_egress_firewall.ps1
  ?? scripts/teardown_ffmpeg_egress_firewall.ps1
  ?? scripts/test_ffmpeg_egress_connectivity.ps1
  ?? tests/test_pro13_a4_2_egress_enforcement.py
  ```
- **Git diff stat :** 6 fichiers suivis modifiés (+1176 / -86 lignes).
- **Git diff check :** Code retour `0` (aucune erreur d'espacement, CRLF/LF normalisés).

---

## 2. MANIFESTE SHA-256 DES COMPOSANTS CRITIQUES

| Composant | Emplacement | SHA-256 |
|---|---|---|
| Egress Policy | `monitoring/acquisition/egress_policy.py` | `c507a6379ddd46bc6a38ca27626baddcbe30f842cab1956a48ad5c8b1827640e` |
| Security | `monitoring/acquisition/security.py` | `be5cb25a445e421be4da0535c262aa48a2da70b7fba28b1bd42edc1f1e4786c1` |
| FFmpeg Adapter | `monitoring/acquisition/ffmpeg_adapter.py` | `7ce5ee4d27c1f49c8daf2e07b94164f7773750908b41ddd2b8a83e43d3e32a93` |
| Acquisition Init | `monitoring/acquisition/__init__.py` | `aeed96b58c858e941d1d933b07750a90c37995cf6cf8b93bbaaa530b125b849a` |
| Discovery | `monitoring/acquisition/discovery.py` | `add5acf0a7b127a4a793488a8fee3347684c904314e717aea563496b290cc06b` |
| ONVIF Adapter | `monitoring/acquisition/onvif_adapter.py` | `ea61696f08f6403579789b942bfe62c706a41695fdfddd8836495a8c3d13624d` |
| Setup Firewall PS1 | `scripts/setup_ffmpeg_egress_firewall.ps1` | `9cbd2a719cee7d2c293463666c354912731270c0fbd53f39c3a25ab29bf08620` |
| Teardown Firewall PS1 | `scripts/teardown_ffmpeg_egress_firewall.ps1` | `006ca8dcdca9f1790f49d72f6e083c479155a180a91892a5ef680934b94bb0f3` |
| Check Firewall PS1 | `scripts/check_ffmpeg_egress_firewall.ps1` | `bc2d068a51999d0401b25d295648675e651a3e59d0c2c30e0c40ff737494b0f3` |
| Test Connectivity PS1 | `scripts/test_ffmpeg_egress_connectivity.ps1` | `2268c57d773cd1423b34f5e0203760712e65b9106138ca827d91890741a74d83` |
| Setup Docker Host SH | `scripts/setup_docker_egress_host.sh` | `00d15df7363e7ba56d4ba32912cfd4a2419280aa3b55e22df71487316a8a5fa8` |
| Docker Compose Egress | `docker/docker-compose.nvr-egress.yml` | `22af489ba6d678a9e99e789f1efb938bc3ea8febae8c5eca11373acc98904337` |
| Dockerfile Worker | `docker/Dockerfile.nvr-worker` | `3cea0e28df4abf6b1e17b4c39e9eb9d55b63049c53a70d171d3362d1af2956ab` |
| Tests Adversariaux A4.2 | `tests/test_pro13_a4_2_egress_enforcement.py` | `d4268fc3e1bc61d2cea3732f577045b300f275357716eee5380dd74824c6eb1a` |
| Tests Lot A NVR | `tests/test_pro13_lot_a_nvr.py` | `0147f12712780c8eaa9ca599a29e123c87c3742b7353c4771fdb2c946cfee96d` |

---

## 3. AUDIT DES DIX RAPPORTS A4.2 EXISTANTS

Les dix rapports obligatoires de la mission précédente `PRO-13-A.4.2` ont été vérifiés sur disque dans `docs/security/` :
1. `PRO13_A4_2_EXECUTIVE_REMEDIATION_REPORT.md` (Présent)
2. `PRO13_A4_2_WINDOWS_FIREWALL_ARCHITECTURE.md` (Présent)
3. `PRO13_A4_2_WINDOWS_EFFECTIVE_POLICY_AUDIT.md` (Présent)
4. `PRO13_A4_2_LINUX_DOCKER_EGRESS_ARCHITECTURE.md` (Présent)
5. `PRO13_A4_2_ENFORCEMENT_PROVIDER_AUDIT.md` (Présent)
6. `PRO13_A4_2_SECONDARY_SOCKET_VALIDATION.md` (Présent)
7. `PRO13_A4_2_ADVERSARIAL_TEST_REGISTER.md` (Présent)
8. `PRO13_A4_2_PRO12_REGRESSION.md` (Présent)
9. `PRO13_A4_2_FINAL_INDEPENDENT_AUDIT.md` (Présent)
10. `PRO13_A4_2_FINAL_GATE_DECISION.md` (Présent)

### Cohérence entre les rapports A4.2 et l'état réel du code
- **Concordance :** Les rapports A4.2 concluent de manière lucide à `A4_2_EGRESS_ENFORCEMENT_NOT_VERIFIED` et `LOT_B_GATE = BLOCKED_PENDING_EXPLICIT_HUMAN_APPROVAL`, reconnaissant formellement l'absence de droits administrateur pour tester le pare-feu réel et l'arrêt du démon Docker.
- **Défaut résiduel identifié lors du Run 1 complet sous A4.2 :** Le rapport `PRO13_A4_2_PRO12_REGRESSION.md` note une collision d'horodatage à la milliseconde dans `NotificationManager` (`notif_1795671658146`), entraînant un échec transitoire dans `test_lotc_notifications_user_ownership_and_anti_idor`. Ce finding fait l'objet d'une remédiation ciblée prioritaire dans la présente mission.
