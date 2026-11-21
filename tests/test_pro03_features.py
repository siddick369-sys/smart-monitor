import time
import os
import io
import pytest
import numpy as np
import cv2
import config
from app import create_app
from monitoring.system_coordinator import SystemCoordinator
from monitoring.notification_manager import NotificationManager
from monitoring.pdf_report_generator import PDFReportGenerator

# 1. Test des Zones de Surveillance (CRUD & Détection)
def test_zones_crud_and_validation():
    app, coordinator = create_app()
    app.config["TESTING"] = True
    
    with app.test_client() as client:
        # Ajout d'un appareil
        dev_res = client.post('/api/devices', json={
            "name": "Caméra Zone Test",
            "ip": "127.0.0.1",
            "port": 8080
        })
        assert dev_res.status_code == 201
        dev_id = dev_res.get_json()["device"]["id"]

        # 1. Ajout d'une zone valide
        zone_res = client.post(f'/api/devices/{dev_id}/zones', json={
            "name": "Zone Porte",
            "x": 0.1,
            "y": 0.2,
            "w": 0.4,
            "h": 0.3,
            "enabled": True
        })
        assert zone_res.status_code == 201
        zone_data = zone_res.get_json()["zone"]
        assert zone_data["name"] == "Zone Porte"
        assert zone_data["x"] == 0.1
        zone_id = zone_data["id"]

        # 2. Rejet de zone avec coordonnées hors limites
        bad_zone = client.post(f'/api/devices/{dev_id}/zones', json={
            "name": "Zone Invalide",
            "x": 0.9,
            "y": 0.9,
            "w": 0.5,
            "h": 0.5
        })
        assert bad_zone.status_code == 400
        assert "dépasse les dimensions" in bad_zone.get_json()["message"]

        # 3. Modification de la zone
        put_res = client.put(f'/api/devices/{dev_id}/zones/{zone_id}', json={
            "name": "Zone Porte Renommée",
            "enabled": False
        })
        assert put_res.status_code == 200
        assert put_res.get_json()["zone"]["name"] == "Zone Porte Renommée"
        assert put_res.get_json()["zone"]["enabled"] is False

        # 4. Liste des zones
        list_res = client.get(f'/api/devices/{dev_id}/zones')
        assert list_res.status_code == 200
        assert len(list_res.get_json()["zones"]) == 1

        # 5. Suppression de la zone
        del_res = client.delete(f'/api/devices/{dev_id}/zones/{zone_id}')
        assert del_res.status_code == 200

        # Vérification suppression
        list_res2 = client.get(f'/api/devices/{dev_id}/zones')
        assert len(list_res2.get_json()["zones"]) == 0

        # Nettoyage de l'appareil de test
        client.delete(f'/api/devices/{dev_id}')

    coordinator.stop()


def test_motion_detection_with_zones():
    """Vérifie que la détection vidéo respecte les zones actives et ignore le mouvement hors zone."""
    coordinator = SystemCoordinator()
    dev = coordinator.add_device("Zone Motion Test", "127.0.0.1", 8080)
    dev_id = dev["id"]

    try:
        # Zone active dans le quadrant haut-gauche : x: 0.0, y: 0.0, w: 0.4, h: 0.4
        zone = coordinator.device_store.add_device_zone(dev_id, "Haut Gauche", 0.0, 0.0, 0.4, 0.4, enabled=True)

        engine = coordinator.detection_engine
        frame1 = np.zeros((480, 640, 3), dtype=np.uint8)
        frame2 = np.zeros((480, 640, 3), dtype=np.uint8)

        # Initialisation de l'arrière-plan
        engine.check_video_motion(dev_id, frame1, threshold_area_pct=2.0)

        # Mouvement UNIQUEMENT en bas à droite (hors de la zone active)
        cv2.rectangle(frame2, (400, 300), (600, 450), (255, 255, 255), -1)
        is_motion, pct = engine.check_video_motion(dev_id, frame2, threshold_area_pct=2.0)
        assert is_motion is False

        # Mouvement DANS la zone active (haut gauche : x: 50..200, y: 50..150)
        frame3 = frame2.copy()
        cv2.rectangle(frame3, (50, 50), (200, 150), (255, 255, 255), -1)
        is_motion2, pct2 = engine.check_video_motion(dev_id, frame3, threshold_area_pct=2.0)
        assert is_motion2 is True
        assert engine.get_last_triggered_zone(dev_id) == "Haut Gauche"
    finally:
        coordinator.delete_device(dev_id)
        coordinator.stop()


# 2. Test Chronologie & Statistiques
def test_statistics_and_timeline():
    app, coordinator = create_app()
    app.config["TESTING"] = True
    
    with app.test_client() as client:
        # Injection de 2 alertes
        client.post('/api/simulate_alert', json={"type": "INTRUSION_TEST", "label": "Test Stat 1"})
        client.post('/api/simulate_alert', json={"type": "CHOC_TEST", "label": "Test Stat 2"})

        # Route Statistiques
        res_stats = client.get('/api/statistics')
        assert res_stats.status_code == 200
        stats = res_stats.get_json()
        assert stats["total_incidents"] >= 2
        assert "by_severity" in stats
        assert "daily_stats" in stats
        assert len(stats["daily_stats"]) == 7
        assert "hourly_distribution" in stats
        assert len(stats["hourly_distribution"]) == 24

        # Route Timeline
        res_timeline = client.get('/api/timeline?period=today')
        assert res_timeline.status_code == 200
        timeline = res_timeline.get_json()
        assert isinstance(timeline, list)
        assert len(timeline) >= 2
        assert "datetime" in timeline[0]

    coordinator.stop()


# 3. Test Notifications Intelligentes
def test_smart_notifications():
    nm = NotificationManager(dedup_window_seconds=2.0)
    
    # 1. Ajout notification
    notif1 = nm.add_notification(level="CRITICAL", title="Intrusion Bureau", message="Porte forcée", device_id="dev_1")
    assert notif1 is not None
    assert notif1["level"] == "CRITICAL"
    assert notif1["read"] is False

    # 2. Protection anti-doublon dans la fenêtre temporelle
    duplicate = nm.add_notification(level="CRITICAL", title="Intrusion Bureau", message="Porte forcée", device_id="dev_1")
    assert duplicate is None  # Doit être ignoré

    # 3. Lecture et marquage
    status = nm.get_notifications()
    assert status["unread_count"] == 1
    assert status["total_count"] == 1

    # Marquer comme lue
    assert nm.mark_as_read(notif1["id"]) is True
    assert nm.get_notifications()["unread_count"] == 0

    # Test marquage global
    nm.add_notification(level="INFO", title="Système Prêt", message="Initialisation")
    assert nm.get_notifications()["unread_count"] == 1
    nm.mark_all_as_read()
    assert nm.get_notifications()["unread_count"] == 0


# 4. Test Diagnostics des Appareils
def test_device_diagnostics():
    app, coordinator = create_app()
    app.config["TESTING"] = True
    dev = coordinator.add_device("Diagnostic Phone", "127.0.0.1", 8080)
    dev_id = dev["id"]

    with app.test_client() as client:
        # Diagnostic appareil unique
        res = client.get(f'/api/devices/{dev_id}/diagnostics')
        assert res.status_code == 200
        diag = res.get_json()
        assert diag["device_id"] == dev_id
        assert "network" in diag
        assert "video" in diag
        assert "telemetry" in diag
        assert "communication" in diag
        assert diag["overall_status"] in ["CONNECTÉ", "DÉGRADÉ", "DÉCONNECTÉ"]

        # Diagnostic global
        res_all = client.get('/api/diagnostics')
        assert res_all.status_code == 200
        assert len(res_all.get_json()) >= 1

        # Nettoyage
        client.delete(f'/api/devices/{dev_id}')

    coordinator.stop()


# 5. Test Génération de Rapports PDF
def test_pdf_reports_generation():
    app, coordinator = create_app()
    app.config["TESTING"] = True

    with app.test_client() as client:
        # Créer un incident avec image
        sim_res = client.post('/api/simulate_alert', json={"type": "TEST_PDF", "label": "Alerte pour Rapport PDF"})
        alert_id = sim_res.get_json()["incident"]["id"]

        # 1. Rapport individuel PDF
        res_pdf = client.get(f'/api/reports/incident/{alert_id}/pdf')
        assert res_pdf.status_code == 200
        assert res_pdf.mimetype == "application/pdf"
        assert res_pdf.data.startswith(b'%PDF-')
        assert len(res_pdf.data) > 1000

        # 2. Rapport de synthèse PDF
        res_sum = client.get('/api/reports/summary/pdf?period=all')
        assert res_sum.status_code == 200
        assert res_sum.mimetype == "application/pdf"
        assert res_sum.data.startswith(b'%PDF-')
        assert len(res_sum.data) > 1000

    coordinator.stop()


# 6. Test Sécurité Renforcée (Sec-Fetch-Site & Path Traversal)
def test_security_hardening():
    app, coordinator = create_app()
    app.config["TESTING"] = True

    with app.test_client() as client:
        # 1. Requête POST avec Sec-Fetch-Site: cross-site -> Rejet 403 Forbidden
        cross_res = client.post('/api/alarm/arm', headers={"Sec-Fetch-Site": "cross-site"})
        assert cross_res.status_code == 403

        # 2. Tentative de traversée de répertoire sur preuve photo -> Rejet 400 ou 404
        bad_path_res = client.get('/storage/screenshots/../../windows/win.ini')
        assert bad_path_res.status_code in [400, 404]

        # 3. Identifiant d'alerte malicieux dans suppression -> Rejet 400
        bad_id_res = client.delete('/api/alerts/alert_123;DROP TABLE')
        assert bad_id_res.status_code == 400

    coordinator.stop()


# 7. Test Path Traversal Deletion & PDF Edge Cases
def test_safe_proof_deletion_and_pdf_edge_cases():
    coordinator = SystemCoordinator()
    rec_mgr = coordinator.recording_manager

    # 1. Vérification Path Traversal dans la suppression des preuves
    test_probe_file = os.path.join(config.BASE_DIR, "probe_safe_deletion.txt")
    with open(test_probe_file, "w") as f:
        f.write("Important system content")

    malicious_alert = {
        "id": "alert_traversal_test",
        "timestamp": time.time(),
        "datetime": "2026-11-13 12:00:00",
        "device_name": "Test & Attack <script>",
        "device_id": "dev_test",
        "device_ip": "127.0.0.1",
        "type": "SONORE <alarm>",
        "event_code": "SIMULATED_EVENT",
        "category": "INTRUSION & TEST",
        "severity": "CRITIQUE",
        "details": "Tentative avec caractères spéciaux : a < b & c > d 'quotes'",
        "status": "TERMINÉ",
        "screenshot_path": "probe_safe_deletion.txt", # En dehors de storage/screenshots/
        "recording_path": "probe_safe_deletion.txt"
    }

    rec_mgr.alerts.append(malicious_alert)
    rec_mgr.save_alerts()

    # Tenter la suppression via delete_alert
    success = rec_mgr.delete_alert("alert_traversal_test")
    assert success is True
    # Le fichier probe_safe_deletion.txt NE DOIT PAS avoir été supprimé !
    assert os.path.exists(test_probe_file)
    os.remove(test_probe_file)

    # 2. Test PDF avec caractères XML spéciaux et formatage complexe
    pdf_gen = PDFReportGenerator()
    pdf_bytes = pdf_gen.generate_incident_report(malicious_alert)
    assert pdf_bytes.startswith(b'%PDF-')
    assert len(pdf_bytes) > 500

    # Test PDF synthèse avec liste d'alertes complexes
    summary_bytes = pdf_gen.generate_summary_report([malicious_alert], period_label="Période & <Spéciale>")
    assert summary_bytes.startswith(b'%PDF-')
    assert len(summary_bytes) > 500

    coordinator.stop()
