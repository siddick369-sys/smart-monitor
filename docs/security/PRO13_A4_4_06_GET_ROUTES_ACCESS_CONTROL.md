# PRO13-A.4.4 — GET ROUTES ACCESS CONTROL REPORT

**Mission ID :** `SSM-PRO13-A4-4-CONTROLLED-REMEDIATION-AND-SECURITY-CLOSURE-01`  
**Date / Horodatage :** 2026-11-27T08:14:00+01:00  
**Dépôt :** `C:\Users\USER\Documents\alarme-sys` | **Branche :** `main` | **HEAD :** `b339a9c82d5b410e78d1ea6d43cae556049ba2c0`  

---

## 1. REMÉDIATION APPLIQUÉE (LOT E)

Ajout de `@login_required` et `@roles_required("ADMIN", "OPERATOR", "AUDITOR")` ainsi que la validation stricte des identifiants et chemins sur :
- **`routes/alerts.py` :** `/api/timeline`, `/api/reports/incident/<alert_id>/pdf`, `/api/reports/summary/pdf`, `/storage/screenshots/<filename>`, `/storage/recordings/<filename>`, `/api/storage/stats`, `/api/statistics`, `/api/diagnostics`, `/api/devices/<device_id>/diagnostics`, `/api/integrity/verify/<proof_id>`, `/api/alerts/<alert_id>/integrity`, `/api/telegram/status`, `/api/qwen_vision/status`, `/api/database/status`.
  - `/storage/screenshots/*` et `/storage/recordings/*` rejettent explicitement `..`, `/`, `\`, `\x00` (HTTP 400) et vérifient `os.path.realpath()` contre les liens symboliques.
- **`routes/devices.py` :** `/api/devices`, `/video_feed/<device_id>`, `/api/devices/<device_id>/zones` (avec regex `^[a-zA-Z0-9_-]+$` et contrôle d'existence sur `/video_feed/<device_id>`).
- **`routes/dashboard.py` :** `/api/status` (masquage des messages d'exception internes).

---

## 2. EXCEPTIONS PUBLIQUES LÉGITIMES CONSERVÉES

- `/login`, `/offline`, `/api/auth/bootstrap/status`, `/api/auth/bootstrap`, `/api/auth/login`, `/api/auth/csrf_token`, `/api/auth/me`.

---

## 3. STATUT

```text
GET_ROUTES_SECURITY_GATE = PASS
```
