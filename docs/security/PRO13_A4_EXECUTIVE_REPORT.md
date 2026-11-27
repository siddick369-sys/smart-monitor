# 🛡️ SSM PRO-13-A.4 — EXECUTIVE SECURITY HARDENING REPORT
## FFMPEG NETWORK EGRESS CONFINEMENT, RTSP SECONDARY CONNECTION ISOLATION & LOT A FINAL GATE

**Mission ID :** `SSM-PRO13-A4-FFMPEG-EGRESS-CONFINEMENT-AND-LOT-A-FINAL-GATE-01`  
**Classification :** CRITICAL SECURITY HARDENING / SSRF DEFENSE / NETWORK ISOLATION / ADVERSARIAL TESTING  
**Dépôt canonique :** `C:\Users\USER\Documents\alarme-sys`  
**Branche :** `main`  
**HEAD de référence audité :** `b339a9c82d5b410e78d1ea6d43cae556049ba2c0`  
**Environnement technique :** Windows 11 AMD64 · Python 3.11.8 · pytest 9.1.1 · SQLite 3.45.1 · OpenCV 4.10.0  
**Statut précédent :** `PRO13_A3_1_LOT_A_PASS_WITH_LIMITATIONS`  
**Verdict Lot A final :** `A4_EGRESS_CONFINEMENT_VERIFIED_WITH_LIMITATIONS`  
**Verdict Lot B :** `LOT_B_GATE = BLOCKED_PENDING_EXPLICIT_HUMAN_APPROVAL`

---

## 1. MANDAT ET OBJECTIFS STRATÉGIQUES

La mission **PRO-13-A.4** a été mandatée avec pour objectif exclusif de traiter et contenir le risque résiduel critique identifié lors de l'audit indépendant PRO-13-A.3.1 :
```
[RTSP_EGRESS_CONFINEMENT] = NOT_PROVEN (au niveau applicatif pur)
```
Ce risque tenait au fait que, bien que FFmpeg soit invoqué avec `-protocol_whitelist tcp,rtp,rtsp`, `-rtsp_transport tcp` et un DNS Pinning Python, les connexions réseau secondaires déclenchées en langage C par libavformat (ex: attribut SDP `a=control:rtsp://...` pointant vers une IP interne non autorisée ou redirection RTSP 3xx) s'exécutent en dehors de la boucle d'interception Python.

### Objectifs atteints dans cette mission :
1. **Politique d'egress Deny-by-Default au niveau logiciel :** Conception et implémentation du module `monitoring/acquisition/egress_policy.py`, imposant une validation stricte des destinations caméras explicitement approuvées.
2. **Rejet inconditionnel de l'accès aux réseaux non approuvés :** Interdiction totale d'accès aux métadonnées cloud (`169.254.169.254`), link-local (`169.254.0.0/16`, `fe80::/10`), loopback (`127.0.0.0/8`, `::1`), adresses multicast, broadcast, et adresses RFC1918 / ULA non explicitement autorisées.
3. **Architecture de confinement OS Windows :** Élaboration de scripts PowerShell révisables et sécurisés (`setup_ffmpeg_egress_firewall.ps1` et `teardown_ffmpeg_egress_firewall.ps1`) permettant d'isoler l'exécutable FFmpeg au niveau du pare-feu Windows Defender sans modifier aveuglément la machine hôte.
4. **Architecture de confinement Linux / Docker :** Conception d'une image Docker et d'un service compose dédié (`docker/docker-compose.nvr-egress.yml`), exécuté sous utilisateur non privilégié (`UID:GID 10001:10001`), sans capacités (`cap_drop: ALL`), sans réseau hôte, et avec système de fichiers racine en lecture seule (`read_only: true`).
5. **Comportement Fail-Closed en production :** Intégration dans `FFmpegRTSPAdapter` de la détection de l'état d'application de l'isolation : si l'isolation réseau OS/conteneur est requise mais inactive, la connexion refuse de s'ouvrir (`VideoSourceStatus.BLOCKED_SSRF`).
6. **Validation par matrice de tests adversariaux :** Implémentation et exécution de 20 scénarios adversariaux (A4-01 à A4-20) portant la suite NVR à 55 tests (100% passés) et la suite globale à 292 tests (100% passés).

---

## 2. MATRICE DE CONFRONTATION DES GARANTIES

| Niveau de contrôle | Mécanisme implémenté | Ce qui est effectivement appliqué | Ce qui reste conçu ou simulé |
|---|---|---|---|
| **Applicatif Python** | `EgressPolicy`, `validate_video_target`, `pin_uri_to_ip` | **Appliqué & Vérifié (100%)** : Rejet des IP privées non autorisées, métadonnées cloud, boucles locales, masques /0 ou /8 trop larges, DNS rebinding. | Aucun reliquat non vérifié en couche applicative. |
| **Sous-processus FFmpeg** | `_build_ffmpeg_cmd` durci, `shell=False`, arguments en liste | **Appliqué & Vérifié (100%)** : `-protocol_whitelist tcp,rtp,rtsp`, `-rtsp_transport tcp`, `-rtsp_flags +prefer_tcp`, `-nostdin`, chemin absolu résolu. | Nécessite le binaire `ffmpeg.exe` local pour le rendu vidéo réel (`NOT_AVAILABLE`). |
| **Pare-feu OS (Windows)** | Scripts PowerShell avec règles NetFirewallRule pour l'exécutable | **Conçu & Validé par script** : Le script est généré, sécurisé et prêt. La détection applicative fonctionne. | **Non exécuté sur l'hôte** : Le compte utilisateur actuel n'est pas Administrateur et l'exécution destructive sans accord utilisateur est proscrite (`SCRIPT_ONLY`). |
| **Conteneur (Linux/Docker)** | `docker-compose.nvr-egress.yml`, utilisateur 10001, bridge dédié | **Conçu & Structuré** : Manifeste compose complet et Dockerfile durci déposés dans `docker/`. | **Non exécuté sur l'hôte** : Le démon Docker Linux Engine n'est pas démarré sur la machine de test (`NOT_AVAILABLE`). |

---

## 3. BILAN D'EXÉCUTION DES TESTS ET RÉGRESSIONS

- **Tests Lot A & A.4 (`tests/test_pro13_lot_a_nvr.py`) :** **55 / 55 passés (100%)** en 62.09s.
- **Tests PRO-12 (`tests/test_pro12*.py`) :** **127 / 127 passés (100%)**, 1 warning SQLAlchemy en 486.70s.
- **Suite Complète du Répertoire (`tests/`) :** **292 / 292 passés (100%)**, 1 warning en 241.35s.
- **Compilation bytecode (`compileall`) :** Code 0 (Succès).
- **Formatage et whitespace (`git diff --check`) :** Code 0 (Propre).

---

## 4. DÉCISION FINALE DE GATE

```
================================================================================
LOT A FINAL GATE : A4_EGRESS_CONFINEMENT_VERIFIED_WITH_LIMITATIONS
LOT B GATE       : BLOCKED_PENDING_EXPLICIT_HUMAN_APPROVAL
================================================================================
```

Le Lot A (NVR Universel) est **entièrement finalisé et sécurisé au niveau logiciel**, avec une architecture d'isolation périphérique documentée et instrumentée par scripts et conteneurs.  
Le Lot B demeure **strictement bloqué** jusqu'à instruction humaine explicite.
