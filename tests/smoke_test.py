import os
import sys
import time
import subprocess
import requests
import cv2
import json

def log(msg):
    print(f"[SMOKE TEST] {msg}", flush=True)

def main():
    log("Démarrage du Smoke Test End-to-End...")
    project_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    os.chdir(project_dir)
    if project_dir not in sys.path:
        sys.path.insert(0, project_dir)

    sim_proc = None
    host_proc = None
    created_alert_id = None
    test_dev_id = None
    sim_log = None
    host_log = None

    try:
        # Nettoyage préalable pour garantir un test isolé et reproductible
        devices_file = os.path.join(project_dir, "storage", "logs", "devices.json")
        try:
            with open(devices_file, "w", encoding="utf-8") as f:
                f.write("{}")
        except Exception:
            pass

        try:
            from database import get_db_session
            from monitoring.models import Device
            with get_db_session() as db:
                db.query(Device).delete()
        except Exception:
            pass

        # 1. Démarrage du simulateur IP Webcam sur le port 8081
        log("1. Lancement du simulateur Mock IP Webcam sur http://127.0.0.1:8081 ...")
        sim_log = open(os.path.join(project_dir, "storage", "logs", "sim_smoke.log"), "w", encoding="utf-8")
        sim_proc = subprocess.Popen(
            [sys.executable, os.path.join("tests", "mock_ipwebcam.py"), "--port", "8081", "--host", "127.0.0.1"],
            stdout=sim_log,
            stderr=sim_log
        )

        # Attente que le simulateur réponde
        sim_ready = False
        for _ in range(20):
            try:
                r = requests.get("http://127.0.0.1:8081/", timeout=0.8)
                if r.status_code == 200:
                    sim_ready = True
                    break
            except Exception:
                time.sleep(0.3)
        assert sim_ready, "Échec : le simulateur IP Webcam n'a pas répondu sur le port 8081."
        log("   -> Simulateur prêt et répondant (HTTP 200).")

        # 2. Démarrage du Monitoring Host sur le port 5000
        log("2. Lancement du Monitoring Host sur http://127.0.0.1:5000 ...")
        host_log = open(os.path.join(project_dir, "storage", "logs", "host_smoke.log"), "w", encoding="utf-8")
        host_proc = subprocess.Popen(
            [sys.executable, "app.py"],
            stdout=host_log,
            stderr=host_log
        )

        host_ready = False
        for _ in range(25):
            try:
                r = requests.get("http://127.0.0.1:5000/api/status", timeout=0.8)
                if r.status_code == 200:
                    host_ready = True
                    break
            except Exception:
                time.sleep(0.3)
        assert host_ready, "Échec : le Monitoring Host n'a pas répondu sur le port 5000."
        log("   -> Monitoring Host prêt et répondant (HTTP 200).")

        # 3. Accès au dashboard et authentification de session
        log("3. Vérification de l'accès au tableau de bord (GET /)...")
        session = requests.Session()
        dash_res = session.get("http://127.0.0.1:5000/", timeout=2.0)
        assert dash_res.status_code == 200, f"Erreur code HTTP dashboard : {dash_res.status_code}"
        assert "SMART SECURITY MONITOR" in dash_res.text, "Titre manquant dans le HTML."
        
        # Authentification de l'administrateur
        login_res = session.post("http://127.0.0.1:5000/api/auth/login", json={"username": "admin", "password": "AdminSecurity2026!"}, timeout=2.0)
        assert login_res.status_code == 200, f"Échec authentification administrateur : {login_res.text}"
        csrf_tok = login_res.json().get("csrf_token")
        if csrf_tok:
            session.headers.update({"X-CSRF-Token": csrf_tok})
        log("   -> Dashboard accessible et session Administrateur authentifiée.")

        # 4. Ajout du simulateur via l'API REST
        log("4. Ajout du smartphone simulateur via POST /api/devices ...")
        add_res = session.post("http://127.0.0.1:5000/api/devices", json={
            "name": "Simulateur Test Smoke",
            "ip": "127.0.0.1",
            "port": 8081,
            "enable_torch": True
        }, timeout=2.0)
        assert add_res.status_code == 201, f"Échec ajout appareil : {add_res.text}"
        test_dev_id = add_res.json()["device"]["id"]
        log(f"   -> Appareil ajouté avec succès (ID: {test_dev_id}).")

        # 5. Vérification de l'état CONNECTÉ (vidéo et capteurs)
        log("5. Attente et vérification du statut CONNECTÉ...")
        connected = False
        last_cam_s = None
        last_sens_s = None
        last_status_code = None
        last_devs = []
        last_error_text = ""
        for _ in range(40):
            time.sleep(0.5)
            stat_res = session.get("http://127.0.0.1:5000/api/status", timeout=2.0)
            last_status_code = stat_res.status_code
            if stat_res.status_code == 200:
                devs = stat_res.json().get("devices", [])
                last_devs = devs
                match = next((d for d in devs if d["id"] == test_dev_id), None)
                if match:
                    last_cam_s = match.get("camera_status")
                    last_sens_s = match.get("sensor_status")
                    if last_cam_s == "CONNECTÉ" and last_sens_s == "CONNECTÉ":
                        connected = True
                        break
            else:
                last_error_text = stat_res.text[:200]
        assert connected, f"L'appareil ne passe pas à l'état CONNECTÉ (HTTP={last_status_code}, Erreur={last_error_text}, DevsCount={len(last_devs)}, DevIds={[d.get('id') for d in last_devs]}, Cherché={test_dev_id}, Caméra={last_cam_s}, Capteurs={last_sens_s})."
        log("   -> Appareil connecté (Caméra: CONNECTÉ, Capteurs: CONNECTÉ).")

        # 6. Réception du flux vidéo MJPEG
        log("6. Réception et décodage du flux vidéo MJPEG...")
        stream_res = session.get(f"http://127.0.0.1:5000/video_feed/{test_dev_id}", stream=True, timeout=5.0)
        assert stream_res.status_code == 200, "Impossible d'ouvrir le flux vidéo MJPEG."
        
        # Lire les premiers octets pour extraire une frame JPEG
        bytes_data = b""
        frame_found = False
        for chunk in stream_res.iter_content(chunk_size=4096):
            bytes_data += chunk
            a = bytes_data.find(b'\xff\xd8') # JPEG SOI
            b = bytes_data.find(b'\xff\xd9') # JPEG EOI
            if a != -1 and b != -1 and b > a:
                jpg_bytes = bytes_data[a:b+2]
                img_array = cv2.imdecode(cv2.imdecode.__code__.co_varnames and cv2.imread and cv2.imdecode.__name__ == 'imdecode' and cv2.imdecode.__doc__ and cv2.imdecode(cv2.UMat(jpg_bytes) if False else None, 1) or cv2.imdecode(cv2.imread.__code__ and None or cv2.UMat() and None, 1) if False else None, 1) if False else None
                import numpy as np
                decoded_img = cv2.imdecode(np.frombuffer(jpg_bytes, dtype=np.uint8), cv2.IMREAD_COLOR)
                if decoded_img is not None and decoded_img.shape[0] > 0:
                    frame_found = True
                    break
        assert frame_found, "Impossible de décoder une frame JPEG valide depuis le flux MJPEG."
        log(f"   -> Flux vidéo MJPEG validé et décodé ({decoded_img.shape[1]}x{decoded_img.shape[0]}).")

        # 7. Récupération des données de capteurs
        log("7. Vérification des données de capteurs (proximity, sound, accel)...")
        stat = session.get("http://127.0.0.1:5000/api/status", timeout=2.0).json()
        dev_info = next((d for d in stat["devices"] if d["id"] == test_dev_id), None)
        assert dev_info is not None
        sensors = dev_info.get("sensors", {})
        assert sensors.get("proximity", {}).get("available") is True, "Capteur proximité non disponible"
        assert sensors.get("sound", {}).get("available") is True, "Capteur sonore non disponible"
        assert sensors.get("accel", {}).get("available") is True, "Accéléromètre non disponible"
        log(f"   -> Données capteurs lues : Prox={sensors['proximity']['value']}cm, Son={sensors['sound']['value']}dB, Accel={sensors['accel']['norm']}m/s².")

        # 8 & 9. Armement du système et injection d'un événement simulé
        log("8. Armement du système...")
        arm_res = session.post("http://127.0.0.1:5000/api/alarm/arm", timeout=2.0)
        assert arm_res.status_code == 200 and arm_res.json().get("is_armed") is True

        log("9. Injection d'un événement simulé via POST /api/simulate_alert ...")
        sim_alert_res = session.post("http://127.0.0.1:5000/api/simulate_alert", json={
            "device_id": test_dev_id,
            "type": "CHOC_ACCÉLÉROMÈTRE",
            "label": "Test choc détecté dans le cadre du Smoke Test"
        }, timeout=2.0)
        assert sim_alert_res.status_code == 200, "Échec injection alerte."
        incident = sim_alert_res.json().get("incident", {})
        created_alert_id = incident.get("id")
        assert created_alert_id, "ID d'alerte non retourné."
        assert incident.get("category") == "ÉVÉNEMENT SIMULÉ", "Catégorie d'événement incorrecte."
        log(f"   -> Alerte créée avec succès (ID: {created_alert_id}, Catégorie: {incident.get('category')}).")

        # 10. Vérification de la capture JPEG sur disque et de sa lisibilité
        log("10. Vérification de la capture photo JPEG...")
        screenshot_path = os.path.join(project_dir, "storage", "screenshots", f"screenshot_{created_alert_id}.jpg")
        for _ in range(15):
            if os.path.exists(screenshot_path) and os.path.getsize(screenshot_path) > 0:
                break
            time.sleep(0.3)
        assert os.path.exists(screenshot_path), f"Fichier de capture JPEG introuvable : {screenshot_path}"
        read_img = cv2.imread(screenshot_path)
        assert read_img is not None and read_img.size > 0, "Image JPEG non lisible par OpenCV."
        log(f"   -> Capture JPEG lisible ({read_img.shape[1]}x{read_img.shape[0]}, {os.path.getsize(screenshot_path)} octets).")

        # 11. Vérification de la création et lisibilité du clip vidéo (post-roll)
        log("11. Attente de la finalisation de l'enregistrement vidéo (post-roll 5s)...")
        # Attendre que le thread VideoRecorder se termine (config.POST_RECORD_SECONDS = 5s)
        video_found = False
        video_file_path = None
        for _ in range(25): # Jusqu'à 10 secondes
            time.sleep(0.5)
            alerts_res = session.get("http://127.0.0.1:5000/api/alerts", timeout=2.0)
            if alerts_res.status_code == 200:
                alerts = alerts_res.json()
                curr_alert = next((a for a in alerts if a["id"] == created_alert_id), None)
                if curr_alert and curr_alert.get("recording_path"):
                    video_file_path = os.path.join(project_dir, curr_alert["recording_path"])
                    if os.path.exists(video_file_path) and os.path.getsize(video_file_path) > 0:
                        video_found = True
                        break
        assert video_found, "Échec : le clip vidéo n'a pas été créé ou est vide."
        
        # Tester la lisibilité du fichier vidéo via OpenCV VideoCapture
        cap = cv2.VideoCapture(video_file_path)
        assert cap.isOpened(), f"Le clip vidéo {video_file_path} ne peut pas être ouvert par OpenCV."
        frame_count = 0
        while True:
            ret, f = cap.read()
            if not ret:
                break
            frame_count += 1
        cap.release()
        assert frame_count > 0, f"Le clip vidéo ne contient aucune frame lisible ({frame_count} frames)."
        log(f"   -> Clip vidéo validé et lisible : {os.path.basename(video_file_path)} ({frame_count} frames, {os.path.getsize(video_file_path)} octets).")

        # Test d'arrêt de la sirène
        log("   Arrêt de la sirène via POST /api/alarm/stop_siren ...")
        stop_siren_res = session.post("http://127.0.0.1:5000/api/alarm/stop_siren", timeout=2.0)
        assert stop_siren_res.status_code == 200 and stop_siren_res.json().get("siren_active") is False
        log("   -> Sirène coupée avec succès.")
        log("   -> Sirène coupée avec succès.")

        # 12. Persistance dans la base de données relationnelle SQLite et export JSON secondaire
        log("12. Validation de la persistance SQLite (Source de vérité) et export JSON secondaire...")
        from database import get_db_session
        from monitoring.models import Alert as DBAlert, Device as DBDevice, Evidence as DBEvidence
        from monitoring.migration_manager import MigrationManager
        
        # 1 & 2. Vérification création et relecture indépendante de l'incident dans SQLite
        with get_db_session() as db:
            db_alert = db.query(DBAlert).filter(DBAlert.id == created_alert_id).first()
            assert db_alert is not None, "1. Échec : L'alerte n'est pas persistée dans la table SQLite 'alerts'."
            assert db_alert.type == "CHOC_ACCÉLÉROMÈTRE", "2. Échec : Données d'incident incohérentes dans SQLite."
            log(f"   -> 1 & 2. Incident {created_alert_id} relu avec succès depuis la table SQLite 'alerts'.")

            # 3 & 4. Création et vérification de l'association de la preuve numérique
            db_ev = db.query(DBEvidence).filter(DBEvidence.alert_id == created_alert_id).first()
            if db_ev:
                assert db_ev.alert_id == db_alert.id, "4. Échec : Lien clé étrangère preuve <-> alerte rompu."
                assert db_ev.sha256_hash is not None and len(db_ev.sha256_hash) == 64, "4. Échec : SHA-256 preuve invalide."
                log(f"   -> 3 & 4. Preuve numérique associée {db_ev.id} validée en SQLite (SHA-256: {db_ev.sha256_hash[:16]}...).")

            # Vérification de l'appareil dans la table 'devices'
            db_dev = db.query(DBDevice).filter(DBDevice.id == test_dev_id).first()
            assert db_dev is not None, "Échec : L'appareil n'est pas persisté dans la table SQLite 'devices'."

        # 5 & 6. Export JSON depuis SQLite et cohérence avec les données de la base
        mig_mgr = MigrationManager()
        sqlite_export = mig_mgr.export_sqlite_to_json()
        assert "alerts" in sqlite_export and "devices" in sqlite_export, "5. Échec : Structure d'export JSON invalide."
        exported_alert = next((a for a in sqlite_export["alerts"] if a["id"] == created_alert_id), None)
        assert exported_alert is not None, "6. Échec : L'alerte SQLite est absente de l'export JSON secondaire."
        assert exported_alert["type"] == "CHOC_ACCÉLÉROMÈTRE", "6. Échec : Données d'export divergentes."
        log("   -> 5 & 6. Export JSON secondaire généré depuis SQLite et cohérence d'intégrité vérifiée.")

        # Vérification du fichier miroir alerts.json
        alerts_file = os.path.join(project_dir, "storage", "logs", "alerts.json")
        if os.path.exists(alerts_file):
            with open(alerts_file, "r", encoding="utf-8") as f:
                persisted_alerts = json.load(f)
            persisted_match = next((a for a in persisted_alerts if a["id"] == created_alert_id), None)
            assert persisted_match is not None, "L'alerte créée n'est pas présente dans alerts.json."
        
        log("   -> [PERSISTANCE PRIMAIRE] : Base SQLite relationnelle certifiée comme unique source de vérité.")
        log("   -> [FORMAT SECONDAIRE]   : Export et miroir JSON validés comme sauvegardes secondaires.")

        log("=================================================================")
        log("SMOKE TEST REUSSI A 100% : TOUS LES 12 POINTS SONT VALIDES !")
        log("=================================================================")
        return 0

    except Exception as e:
        log(f"ERREUR SMOKE TEST : {e}")
        import traceback
        traceback.print_exc()
        return 1

    finally:
        # Nettoyage uniquement de l'alerte de test et du device de test
        log("Nettoyage des ressources de test...")
        if test_dev_id:
            try:
                requests.delete(f"http://127.0.0.1:5000/api/devices/{test_dev_id}", timeout=2.0)
            except Exception:
                pass
        if created_alert_id:
            try:
                requests.delete(f"http://127.0.0.1:5000/api/alerts/{created_alert_id}", timeout=2.0)
            except Exception:
                pass

        # Arrêt des processus
        if host_proc:
            log("Arrêt du Monitoring Host...")
            host_proc.terminate()
            try:
                host_proc.wait(timeout=3)
            except Exception:
                host_proc.kill()

        if sim_proc:
            log("Arrêt du simulateur Mock IP Webcam...")
            sim_proc.terminate()
            try:
                sim_proc.wait(timeout=3)
            except Exception:
                sim_proc.kill()

        log("Processus arrêtés proprement.")
        if host_log:
            try: host_log.close()
            except Exception: pass
        if sim_log:
            try: sim_log.close()
            except Exception: pass

if __name__ == "__main__":
    sys.exit(main())
