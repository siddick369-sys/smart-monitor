# PRO13-A.4.2.3 — CAMERA, DETECTION & AI EVIDENCE AUDIT REPORT

**Mission ID :** `SSM-PRO13-A4-2-3-FINAL-EVIDENCE-RECONCILIATION-AND-INDEPENDENT-CLOSURE-AUDIT-01`  
**Classification :** PIPELINE AUDIT / COMPUTER VISION VS AI DIFFERENTIATION / HARDWARE LIMITATIONS  
**Date / Horodatage :** 2026-11-27T06:47:00+01:00  
**Dépôt :** `C:\Users\USER\Documents\alarme-sys`  
**Branche :** `main`  
**HEAD :** `b339a9c82d5b410e78d1ea6d43cae556049ba2c0`  

---

## 1. AUDIT DU PIPELINE CAMÉRA

1. **Source testée en direct :**
   - Seul le simulateur HTTP/MJPEG local (`tests/mock_ipwebcam.py` sur `127.0.0.1:8081`) a été utilisé lors des essais en direct.
   - Aucune caméra IP RTSP/ONVIF physique n'était connectée sur le réseau local (`NOT_AVAILABLE`).
2. **Binaire FFmpeg :**
   - Vérification système (`where.exe ffmpeg`) : binaire absent du `PATH` système (`NOT_AVAILABLE`).
   - Par conséquent, aucune exécution réelle de sous-processus `ffmpeg.exe` sur un flux RTSP n'a pu être observée ; la validation FFmpeg repose uniquement sur les tests unitaires et adaptateurs (`FFmpegAdapter` fail-closed).

---

## 2. AUDIT DU MOTEUR DE DÉTECTION ET DES MODÈLES IA

1. **Mécanisme réel de détection (`monitoring/detection_engine.py`) :**
   - L'inspection du code source confirme que la détection vidéo repose sur la **différence inter-images OpenCV** (`cv2.cvtColor` en niveaux de gris, lissage `cv2.GaussianBlur(gray, (21, 21), 0)`, différence absolue `cv2.absdiff(prev_gray, gray)`, seuillage `cv2.threshold(delta, 25, 255, cv2.THRESH_BINARY)`, dilatation et calcul d'aire de contours avec filtrage ROI et rejet des flashs globaux > 85 %).
   - Il ne s'agit **ni** d'inférence neuronale, **ni** de YOLOv8, **ni** de recherche sémantique CLIP.
2. **Inventaire des modèles sur disque (`storage/models/`) :**
   - Le répertoire `storage/models/` ne contient que `.gitkeep` (0 octet).
   - Aucun modèle ONNX (`yolov8n.onnx`, `yolov8n-pose.onnx`, `yamnet.onnx`, `clip_visual.onnx`) n'est présent sur la machine hôte.
   - Aucun téléchargement n'a été effectué conformément aux interdictions de mission.

---

## 3. ENREGISTREMENT ET PREUVES

- Les captures JPEG horodatées lors du déclenchement simulé sur `127.0.0.1:8081` ont été observées et enregistrées dans `storage/screenshots/`.
- En l'absence de `ffmpeg.exe`, l'enregistrement vidéo repose sur les mécanismes OpenCV / buffers en mémoire sans encodage FFmpeg externe.

---

## 4. VERDICT CAMÉRA & IA

```text
CAMERA_GATE = PASS_WITH_LIMITATIONS  (Simulateur HTTP/MJPEG validé ; caméra physique et binaire FFmpeg absents)
AI_GATE = PASS_WITH_LIMITATIONS      (Détection OpenCV par différence inter-images vérifiée ; aucun modèle ONNX présent)
```
