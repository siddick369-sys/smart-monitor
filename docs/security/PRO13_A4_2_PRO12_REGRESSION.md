# 🛡️ SSM PRO-13-A.4.2 — PRO-12 & FULL REGRESSION REPORT
## PREUVE DE NON-RÉGRESSION DU SOCLE DE SÉCURITÉ PRO-12 ET DE L'ENSEMBLE DU DÉPÔT

**Mission ID :** `SSM-PRO13-A4.2-CORRECTIVE-EGRESS-ENFORCEMENT-AND-VERIFICATION-01`  
**Branche :** `main` | **HEAD initial/final :** `b339a9c82d5b410e78d1ea6d43cae556049ba2c0`  
**Timestamp :** `2026-11-26T06:44:00+01:00`

---

## 1. RÉSULTATS DES EXÉCUTIONS DE RÉGRESSION

| Périmètre | Commande exacte | Code retour | Durée | Résultat |
|---|---|---:|---:|---|
| **PRO-12 complet** | `python -m pytest (Get-Item tests/test_pro12*.py) -q` | `0` | `59.73s` | **127 passed, 1 warning** |
| **Lot A NVR** | `python -m pytest tests/test_pro13_lot_a_nvr.py -q` | `0` | `20.99s` | **55 passed** |
| **A4.2 Egress** | `python -m pytest tests/test_pro13_a4_2_egress_enforcement.py -q` | `0` | `4.04s` | **36 passed** |
| **Dépôt complet (Run 1)** | `python -m pytest tests/ -q` | `1` | `96.85s` | 327 passed, 1 failed (`test_lotc_notifications_user_ownership_and_anti_idor` — collision d'horodatage à la milliseconde `notif_1795671658146`) |
| **Dépôt complet (Run 2)** | `python -m pytest tests/ -q` | `0` | `100.30s` | **328 passed, 1 warning** |
| **Compilation Python** | `python -m compileall -q .` | `0` | `<1s` | **0 erreur** |
| **Hygiène Git** | `git diff --check` | `0` | `<1s` | **0 erreur d'espacement** |

---

## 2. INTÉGRITÉ DES MÉCANISMES PRO-12

- Aucun fichier de production ou de test `PRO-12` n'a été modifié.
- L'avertissement `SAWarning` sur `SystemBootstrap` (`test_pro12_3_production_security_closure.py:828`) est préexistant et inchangé.
- La collision d'identifiant à la milliseconde observée transitoirement lors du Run 1 sur `test_lotc_notifications_user_ownership_and_anti_idor` relève d'un test historique PRO-12.4 hors périmètre A4.2.
