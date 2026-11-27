# PRO13_FINAL_08_CAMERA_DETECTION_RECORDING

**Mission ID:** `SSM-PRO13-FINAL-LIVE-QUALIFICATION-AND-GITHUB-PUSH-01`  
**Date:** 2026-11-27  

---

## 1. Intégration du Simulateur IP Webcam

Le simulateur de caméra `tests/mock_ipwebcam.py` a été exécuté sur le port 8081 en fournissant :
- Le flux vidéo JPEG/MJPEG continu (`/video`).
- Les clichés instantanés (`/shot.jpg`).
- Le flux télémétrique des capteurs Android (`/sensors.json`) : accéléromètre 3 axes, capteur de proximité optique, niveau sonore en décibels.

## 2. Déclenchement et Chaîne d'Alerte en Direct

- **Action de déclenchement :** Appel de `http://127.0.0.1:8081/simulate_trigger?type=motion&val=true`.
- **Réception par le Monitoring Host :**
  - Détection de mouvement optique immédiate calculée sur les trames vidéo successives.
  - Journalisation de l'événement dans `alerts` avec code événement `MOUVEMENT_VIDÉO` et niveau `AVERTISSEMENT`.
  - Capture photographique instantanée archivée dans `storage/screenshots/`.
  - Génération de l'enregistrement de preuve lié dans `evidences`.
  - Enregistrement du maillon d'intégrité cryptographique dans `integrity_log` au format v2 avec signature HMAC-SHA256 (`k_active_v2`).
- **Comportement UI :**
  - Bannière d'alerte rouge clignotante `ALERTE INTRUSION DÉTECTÉE ! · MOUVEMENT_VIDÉO sur Simulateur Test Smoke`.
  - Incrémentation dynamique des compteurs d'incidents (de 33 à 44 alertes aujourd'hui).
  - Déclenchement de la sirène asynchrone PC.
  - Mise à disposition immédiate des actions : `Voir la capture photo`, `Rapport PDF`, `Certificat d'intégrité SHA-256`, `Acquitter`.

## 3. Gestion des Preuves
- Les empreintes SHA-256 des fichiers de preuves sont calculées à la volée et scellées dans la base d'intégrité.
- La suppression d'une preuve est protégée par un contrôle RBAC strict (réservé aux administrateurs avec validation CSRF).
