# PRO13-A.4.2.3 — ALERTS API & RBAC SECURITY AUDIT REPORT

**Mission ID :** `SSM-PRO13-A4-2-3-FINAL-EVIDENCE-RECONCILIATION-AND-INDEPENDENT-CLOSURE-AUDIT-01`  
**Classification :** APPLICATION SECURITY AUDIT / RBAC ENFORCEMENT / INPUT VALIDATION  
**Date / Horodatage :** 2026-11-26T19:58:00+01:00  
**Dépôt :** `C:\Users\USER\Documents\alarme-sys`  
**Branche :** `main`  
**HEAD :** `b339a9c82d5b410e78d1ea6d43cae556049ba2c0`  

---

## 1. REVUE DIRECTE DU CODE SOURCE (`routes/alerts.py`)

L'audit indépendant du fichier [routes/alerts.py](file:///C:/Users/USER/Documents/alarme-sys/routes/alerts.py) confirme :

1. **Décorateurs d'authentification et d'autorisation :**
   - Route `GET /api/alerts` (lignes 14-16) : décorée par `@login_required` et `@roles_required("ADMIN", "OPERATOR", "AUDITOR")`.
   - Route `GET /api/alerts/export/csv` (lignes 76-78) : décorée par `@login_required` et `@roles_required("ADMIN", "OPERATOR", "AUDITOR")`.
   - Aucun contournement par verbe HTTP alternatif (seule la méthode GET est acceptée sur ces routes).
2. **Contrôle d'accès et validation des paramètres :**
   - `device_id` : vérification stricte par regex `^[a-zA-Z0-9_-]+$`. Tout caractère de traversée (`../`, `%2f`, `;`) déclenche un code HTTP 400.
   - Contrôle de périmètre appareil : `coordinator.device_store.get_device(device_id)` est interrogé ; un appareil inexistant retourne HTTP 404.
   - Caractères de contrôle : détection et rejet immédiat (`\x00`, `\r`, `\n`) dans `type` et `query` (HTTP 400).
   - Filtre temporel `period` : restreint à la liste blanche stricte (`today`, `24h`, `7d`, `all`), rejet 400 sinon.
   - Pagination : `limit` et `offset` validés comme entiers positifs avec plafonnement défensif (`clamp`) à 1000 éléments maximum pour prévenir l'épuisement mémoire (DoS).
3. **Parité consultation / exportation :**
   - La fonction `export_csv` applique exactement les mêmes filtres que `list_alerts` et transmet la liste restreinte à `coordinator.recording_manager.export_csv(alerts=alerts)`.

---

## 2. VERDICT DE L'AUDIT API

```text
ALERTS_API_GATE = PASS
AUTHENTICATION_ENFORCEMENT = VERIFIED
RBAC_AUTHORIZATION = VERIFIED
INPUT_VALIDATION = VERIFIED
```
