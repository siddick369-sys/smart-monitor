# 🛡️ SSM PRO-13-A.4.2.1 — LOCAL STARTUP REPORT
## DÉCOUVERTE DE L'ARCHITECTURE DE DÉMARRAGE, DÉPENDANCES ET EXÉCUTION LOCALE RÉELLE

**Mission ID :** `SSM-PRO13-A4.2.1-INDEPENDENT-AUDIT-AND-LIVE-END-TO-END-QUALIFICATION-01`  
**Branche :** `main` | **HEAD :** `b339a9c82d5b410e78d1ea6d43cae556049ba2c0`  
**Timestamp :** `2026-11-26T17:28:00+01:00`  
**Environnement :** `Windows 11 AMD64 · Python 3.11.8 · SQLite 3 (storage/security_monitor.db)`  

---

## 1. ARCHITECTURE DE DÉMARRAGE DÉCOUVERTE

- **Point d'entrée officiel Flask :** `app.py` (`create_app()`, `coordinator.start()`, `app.run(host=config.HOST, port=config.PORT, debug=config.DEBUG, threaded=True)`).
- **Port configuré :** `127.0.0.1:5000`.
- **Simulateur IP Webcam :** `tests/mock_ipwebcam.py --host 127.0.0.1 --port 8081`.
- **Base de données SQLite :** `storage/security_monitor.db` (12 tables présentes).
- **Appareil configuré :** `dev_2ce36203` (`Simulateur Test Smoke`, `127.0.0.1:8081`, protocole `ANDROID_IPWEBCAM`, `/video` et `/sensors.json`).

---

## 2. SÉQUENCE DE DÉMARRAGE EXÉCUTÉE ET PREUVES

1. **Vérification des ports libres :** `Get-NetTCPConnection -LocalPort 5000, 8081` -> aucun processus en écoute avant démarrage.
2. **Démarrage du simulateur :** `python tests/mock_ipwebcam.py --host 127.0.0.1 --port 8081`
   - `GET http://127.0.0.1:8081/` -> HTTP `200`, JSON `{"service": "Mock IP Webcam Android", ...}`.
   - `GET http://127.0.0.1:8081/shot.jpg` -> HTTP `200`, `19641` octets JPEG.
   - `GET http://127.0.0.1:8081/sensors.json` -> HTTP `200`, clés `['accel', 'battery_level', 'light', 'proximity', 'sound']`.
3. **Démarrage de Flask :** `python app.py`
   - Log observé : `[SystemCoordinator] Monitoring Host démarré avec succès.`
   - `GET http://127.0.0.1:5000/` -> redirection `302` vers `/login` -> HTTP `200` (`14632` octets).
4. **Arrêt propre :** Les deux processus (`mock_ipwebcam.py` et `app.py`) ont été arrêtés proprement en fin de qualification et les ports `5000` et `8081` vérifiés libérés.

---

## 3. LIMITATIONS IDENTIFIÉES

- Binaire `ffmpeg.exe` absent du `PATH` (`NOT_AVAILABLE`).
- Modèle `yolov8n.onnx` absent (`MODEL_UNAVAILABLE`, repli OpenCV actif et documenté).
- Bibliothèque `aiortc` non installée (`FALLBACK_MJPEG` actif).
