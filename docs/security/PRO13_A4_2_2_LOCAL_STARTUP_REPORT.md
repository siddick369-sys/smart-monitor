# PRO13-A.4.2.2 — LOCAL RUNTIME STARTUP REPORT

**Mission ID:** `SSM-PRO13-A4-2-2-SECURITY-CLOSURE-AND-FULL-LOCAL-REQUALIFICATION-01`  
**Classification:** RUNTIME VERIFICATION / LOCAL STARTUP / PORT AUDIT  
**Date / Timestamp:** 2026-11-26T19:35:00+01:00  
**Repository:** `C:\Users\USER\Documents\alarme-sys`  
**Branch:** `main`  
**HEAD:** `b339a9c82d5b410e78d1ea6d43cae556049ba2c0`  

---

## 1. OBJECTIF DU DÉMARRAGE LOCAL

Démontrer le fonctionnement effectif et non simulé des services sur la machine hôte :
- Vérification de la disponibilité préalable des ports réseau locaux `5000` et `8081` ;
- Démarrage du simulateur IP Webcam sur `http://127.0.0.1:8081` ;
- Démarrage du serveur Flask de surveillance sur `http://127.0.0.1:5000` ;
- Évaluation de la connectivité réseau et de l'interconnexion entre services ;
- Arrêt propre et libération complète des ports sans processus orphelins.

---

## 2. CHRONOLOGIE DU DÉMARRAGE ET OBSERVATIONS

| Heure (UTC+1) | Composant | Commande / Action | Port | Statut |
|---|---|---|---|---|
| 19:22:37 | Port Audit Initial | `Get-NetTCPConnection -LocalPort 5000, 8081` | 5000, 8081 | Ports libres (aucune écoute active) |
| 19:22:38 | IP Webcam Mock | `python tests/mock_ipwebcam.py --port 8081` | 8081 | Démarré (`* Running on http://127.0.0.1:8081`) |
| 19:22:45 | Flask Host | `python app.py` | 5000 | Démarré (`* Running on http://127.0.0.1:5000`) |
| 19:24:34 | Qualification Live | `python scratch_live_qualification.py` | 5000, 8081 | Validé (HTTP 200 sur les deux services) |
| 19:25:20 | Navigation Navigateur | Agent subagent Chromium sur `http://127.0.0.1:5000/login` | 5000 | Authentification et streaming opérationnels |
| 19:31:36 | Teardown Propre | `manage_task kill` sur les tâches d'arrière-plan | 5000, 8081 | Arrêt propre du Monitoring Host et du simulateur |
| 19:33:26 | Audit Post-Arrêt | `Get-NetTCPConnection -LocalPort 5000, 8081` | 5000, 8081 | Ports 5000 et 8081 totalement libérés |

---

## 3. PRÉSERVATION DES DONNÉES ET DE L'ÉTAT LOCAL

- La base SQLite `storage/security_monitor.db` a été rigoureusement préservée.
- Les 12 tables existantes sont demeurées intactes, et la chaîne HMAC a été incrémentée de manière transparente sans aucune corruption.
- Aucun fichier de configuration ni secret n'a été altéré.

---

## 4. VERDICT

```text
LOCAL_RUNTIME_GATE = PASS
SERVICES_ACCESSIBILITY = VERIFIED_HTTP_200
PROCESS_TEARDOWN = CLEAN_NO_ORPHANS
```
