# 🛡️ SSM PRO-13-A.4.2.1 — DETECTION, ALERT & RECORDING QUALIFICATION
## QUALIFICATION DE LA DÉTECTION VIDÉO/CAPTEURS, DES ALERTES, DES CAPTURES ET DE L'INTÉGRITÉ HMAC

**Mission ID :** `SSM-PRO13-A4.2.1-INDEPENDENT-AUDIT-AND-LIVE-END-TO-END-QUALIFICATION-01`  
**Branche :** `main` | **HEAD :** `b339a9c82d5b410e78d1ea6d43cae556049ba2c0`  
**Timestamp :** `2026-11-26T17:28:00+01:00`  

---

## 1. DÉTECTION VIDÉO ET CAPTEURS EN DIRECT

- **Moteur actif observé :** OpenCV MOG2 / différence inter-frames (`yolov8n.onnx` absent -> `edge_ai.status: MODEL_UNAVAILABLE`, `fallback: True`).
- **Déclenchement réel par injection mouvement (`simulate_trigger?type=motion&val=true`) :**
  - Alerte produite automatiquement par le pipeline : `alert_1795707441451` (`MOUVEMENT_VIDÉO`, sévérité `AVERTISSEMENT`, `2026-11-26 16:37:21`).
  - Détails observés dans `/api/status` : `Mouvement vidéo détecté : 1.53% de l'image (seuil: 1.5%)`.
- **Télémétrie capteurs reçue :** `accel` (`9.81 m/s2`), `sound` (`41.3 dB` au repos), `proximity` (`100.0 cm`), `light` (`150.0 lx`), `battery` (`95.0%`).

---

## 2. SYSTÈME D'ALERTE ET NOTIFICATION MANAGER

- Armement vérifié via `POST /api/alarm/arm` -> `{"is_armed": true, "status": "ok"}`.
- Notification créée avec le nouveau format d'identifiant anti-collision (`notif_1795707281137_12_259859`).
- Aucun actionneur physique (sirène matérielle, relais, stroboscope) n'a été déclenché.

---

## 3. ENREGISTREMENT ET PREUVES FORENSIQUES

- **Capture JPEG générée en direct lors de l'incident :** `storage/screenshots/screenshot_alert_1795707441451.jpg` (`27870` octets).
- **Décodage réel vérifié par OpenCV (`cv2.imread`) :** `Image loaded: True`, dimensions `(480, 640, 3)`.
- **Statistiques stockage (`/api/storage/stats`) :** `77` enregistrements, `16` -> `18` captures après incidents live, `5.44 Mo` utilisés.
- **Chaîne d'intégrité cryptographique HMAC locale (`/api/integrity/chain/verify` sous rôle `AUDITOR`) :**
  - `status: INTEGRITY_VALID`, `valid_chain: True`, `total_entries: 868`, `last_hash: 091fc7f2a42d796f37b3ed00c27fe909a872c9279b7e68f330f0b2aafd4343ab`.
  - *(Rappel : chaîne HMAC locale, ne constitue pas une certification TSA/RFC3161).*
