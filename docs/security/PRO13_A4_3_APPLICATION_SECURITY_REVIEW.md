# PRO13-A.4.3 — GLOBAL APPLICATION SECURITY REVIEW

**Mission ID :** `SSM-PRO13-A4-3-EGRESS-HARDENING-AND-CRYPTOGRAPHIC-CONTINUITY-01`  
**Date / Horodatage :** 2026-11-27T07:10:30+01:00  
**Dépôt :** `C:\Users\USER\Documents\alarme-sys` | **Branche :** `main` | **HEAD :** `b339a9c82d5b410e78d1ea6d43cae556049ba2c0`  
**Périmètre :** Revue statique de toutes les routes Flask (`routes/alerts.py`, `routes/auth.py`, `routes/dashboard.py`, `routes/devices.py`, `routes/master_api.py`, `routes/pro06.py`).

---

## 1. SYNTHÈSE DES CONTRÔLES SUR LES ROUTES MUTATIVES

- **Toutes les routes mutatives (`POST`, `PUT`, `DELETE`)** d'administration, de gestion d'alertes, d'appareils, de zones, de paramètres, d'alarme, de confidentialité et d'intercom sont protégées par `@login_required` + `@roles_required(...)` et par la validation CSRF globale (`app.py:enforce_csrf` via `hmac.compare_digest`).
- Seules les routes de pré-authentification (`/api/auth/login`, `/api/auth/bootstrap`, `/api/auth/logout`, `/logout`) et la synchronisation inter-nœuds `/api/p2p/sync_batch` (protégée par signature P2P HMAC dédiée) font exception.

---

## 2. INVENTAIRE DES ROUTES `GET` DE LECTURE SANS `@login_required`

L'audit systématique des décorateurs `@bp.route` révèle que, bien que `/api/alerts` et `/api/alerts/export/csv` soient désormais protégés, **d'autres routes `GET` en lecture dans `routes/` restent accessibles sans `@login_required`** :

| Fichier | Routes `GET` sans `@login_required` | Nature des données exposées | Sévérité estimée |
|---|---|---|---|
| `routes/alerts.py` | `/api/timeline`, `/api/reports/incident/<alert_id>/pdf`, `/api/reports/summary/pdf`, `/storage/screenshots/<filename>`, `/storage/recordings/<filename>`, `/api/alerts/<alert_id>/integrity`, `/api/integrity/verify/<proof_id>` | Chronologie d'incidents, rapports PDF d'incidents, captures photo/vidéo de preuves | **P2** *(Contournement indirect de la confidentialité des incidents)* |
| `routes/alerts.py` | `/api/storage/stats`, `/api/statistics`, `/api/diagnostics`, `/api/devices/<id>/diagnostics`, `/api/telegram/status`, `/api/qwen_vision/status`, `/api/database/status` | Statistiques, diagnostics réseau/appareil, statuts d'intégration | **P3** |
| `routes/devices.py` | `/api/devices`, `/video_feed/<device_id>`, `/api/devices/<device_id>/zones` | Liste des caméras, flux MJPEG en direct, zones ROI | **P2** *(Exposition du flux vidéo et des caméras sans session)* |
| `routes/dashboard.py` | `/api/status` | État système global, statut alarme et télémétrie | **P2/P3** |

*Note : Aucune modification n'a été apportée durant cet audit strictement en lecture seule.*

---

## 3. STATUT

```text
APPLICATION_SECURITY_GATE = PASS_WITH_LIMITATIONS  (Routes mutatives et /api/alerts sécurisées ; routes GET secondaires sans @login_required recensées)
```
