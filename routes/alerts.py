import os
import re
import json
from flask import Blueprint, jsonify, request, send_from_directory, Response, abort, session
import config
from monitoring.auth_manager import login_required, roles_required
from monitoring.migration_manager import MigrationManager
from database import get_db_session
from monitoring.models import Device, Alert, Notification, Evidence

def create_alerts_blueprint(coordinator):
    bp = Blueprint('alerts', __name__)

    @bp.route('/api/alerts', methods=['GET'])
    def list_alerts():
        device_id = request.args.get('device_id')
        event_type = request.args.get('type')
        period = request.args.get('period')
        query = request.args.get('query')

        if any([device_id, event_type, period, query]):
            alerts = coordinator.recording_manager.filter_alerts(
                device_id=device_id,
                event_type=event_type,
                period=period,
                query=query
            )
        else:
            alerts = coordinator.recording_manager.get_all_alerts()
            
        return jsonify(alerts)

    @bp.route('/api/alerts/export/csv', methods=['GET'])
    def export_csv():
        csv_data = coordinator.recording_manager.export_csv()
        return Response(
            csv_data,
            mimetype="text/csv",
            headers={"Content-Disposition": "attachment; filename=journal_incidents_export.csv"}
        )

    @bp.route('/api/alerts/<alert_id>', methods=['DELETE'])
    @login_required
    @roles_required("ADMIN")
    def delete_alert(alert_id):
        # Validation rigoureuse de l'identifiant pour éviter toute injection ou traversée
        if not alert_id or not re.match(r'^[a-zA-Z0-9_-]+$', alert_id):
            return jsonify({"status": "error", "message": "Identifiant d'alerte invalide."}), 400

        success = coordinator.recording_manager.delete_alert(alert_id)
        if success:
            return jsonify({"status": "ok", "message": "Alerte et preuves supprimées."})
        return jsonify({"status": "error", "message": "Alerte non trouvée."}), 404

    @bp.route('/api/alerts/clear', methods=['POST'])
    @login_required
    @roles_required("ADMIN")
    def clear_alerts():
        coordinator.recording_manager.clear_all()
        return jsonify({"status": "ok", "message": "Historique des alertes vidé."})

    @bp.route('/api/simulate_alert', methods=['POST'])
    @login_required
    @roles_required("ADMIN", "OPERATOR")
    def simulate_alert():
        """Déclenche manuellement une alerte qualifiée d'ÉVÉNEMENT SIMULÉ."""
        data = request.get_json(silent=True) or {}
        device_id = data.get("device_id")
        event_type = data.get("type", "SIMULATION")
        custom_label = data.get("label")

        # Si aucun device_id n'est fourni, prendre le premier appareil disponible ou un identifiant de secours
        if not device_id:
            devices = coordinator.device_store.get_all_devices()
            device_id = devices[0]["id"] if devices else "dev_mock"

        incident = coordinator.detection_engine.trigger_simulated_incident(
            device_id=device_id,
            event_type=event_type,
            custom_label=custom_label
        )
        return jsonify({"status": "ok", "incident": {
            "id": incident["id"],
            "type": incident["type"],
            "category": incident["category"],
            "severity": incident.get("severity", "INFO"),
            "device_name": incident["device_name"],
            "datetime": incident["datetime"]
        }})

    @bp.route('/api/storage/stats', methods=['GET'])
    def storage_stats():
        return jsonify(coordinator.recording_manager.get_storage_stats())

    @bp.route('/api/storage/clean', methods=['POST'])
    @login_required
    @roles_required("ADMIN")
    def clean_storage():
        data = request.get_json(silent=True) or {}
        days = data.get("days", config.RETENTION_DAYS)
        try:
            days_int = int(days)
            if days_int < 1:
                return jsonify({"status": "error", "message": "Le délai de rétention doit être d'au moins 1 jour."}), 400
        except (ValueError, TypeError):
            days_int = config.RETENTION_DAYS

        coordinator.recording_manager.clean_expired_proofs(days=days_int)
        return jsonify({
            "status": "ok",
            "message": f"Preuves de plus de {days_int} jours nettoyées.",
            "stats": coordinator.recording_manager.get_storage_stats()
        })

    # ==========================================
    # FONCTIONNALITÉ 2 : CHRONOLOGIE & STATS
    # ==========================================

    @bp.route('/api/statistics', methods=['GET'])
    def statistics():
        return jsonify(coordinator.recording_manager.get_statistics())

    @bp.route('/api/timeline', methods=['GET'])
    def timeline():
        device_id = request.args.get('device_id')
        event_type = request.args.get('type')
        period = request.args.get('period')
        query = request.args.get('query')
        limit = int(request.args.get('limit', 100))
        return jsonify(coordinator.recording_manager.get_timeline(
            device_id=device_id,
            event_type=event_type,
            period=period,
            query=query,
            limit=limit
        ))

    # ==========================================
    # FONCTIONNALITÉ 3 : NOTIFICATIONS
    # ==========================================

    @bp.route('/api/notifications', methods=['GET'])
    @login_required
    def list_notifications():
        user_id = session.get("user_id")
        user_role = session.get("role")
        unread_only = request.args.get('unread_only', 'false').lower() == 'true'
        limit = int(request.args.get('limit', 50))
        return jsonify(coordinator.notification_manager.get_notifications(
            unread_only=unread_only, limit=limit, user_id=user_id, role=user_role
        ))

    @bp.route('/api/notifications/<notif_id>/read', methods=['POST'])
    @login_required
    def mark_notification_read(notif_id):
        user_id = session.get("user_id")
        user_role = session.get("role")
        success = coordinator.notification_manager.mark_as_read(notif_id, user_id=user_id, role=user_role)
        if success:
            return jsonify({"status": "ok", "message": "Notification marquée comme lue."})
        return jsonify({"status": "error", "message": "Notification introuvable ou accès non autorisé."}), 404

    @bp.route('/api/notifications/read_all', methods=['POST'])
    @login_required
    def mark_all_notifications_read():
        user_id = session.get("user_id")
        user_role = session.get("role")
        count = coordinator.notification_manager.mark_all_as_read(user_id=user_id, role=user_role)
        return jsonify({"status": "ok", "marked_count": count})

    @bp.route('/api/notifications/<notif_id>', methods=['DELETE'])
    @login_required
    def delete_notification(notif_id):
        user_id = session.get("user_id")
        user_role = session.get("role")
        success = coordinator.notification_manager.delete_notification(notif_id, user_id=user_id, role=user_role)
        if success:
            return jsonify({"status": "ok", "message": "Notification supprimée."})
        return jsonify({"status": "error", "message": "Notification introuvable ou accès non autorisé."}), 404

    # ==========================================
    # FONCTIONNALITÉ 4 : DIAGNOSTICS APPAREILS
    # ==========================================

    @bp.route('/api/diagnostics', methods=['GET'])
    def all_diagnostics():
        return jsonify(coordinator.diagnostic_manager.run_all_diagnostics())

    @bp.route('/api/devices/<device_id>/diagnostics', methods=['GET'])
    def device_diagnostic(device_id):
        diag = coordinator.diagnostic_manager.run_device_diagnostic(device_id)
        if not diag:
            return jsonify({"status": "error", "message": "Appareil introuvable pour le diagnostic."}), 404
        return jsonify(diag)

    # ==========================================
    # FONCTIONNALITÉ 5 : RAPPORTS PDF
    # ==========================================

    @bp.route('/api/reports/incident/<alert_id>/pdf', methods=['GET'])
    def export_incident_pdf(alert_id):
        alerts = coordinator.recording_manager.get_all_alerts()
        alert = next((a for a in alerts if a["id"] == alert_id), None)
        if not alert:
            abort(404, description="Incident introuvable.")

        pdf_bytes = coordinator.pdf_report_generator.generate_incident_report(alert)
        filename = f"rapport_incident_{alert_id}.pdf"
        return Response(
            pdf_bytes,
            mimetype="application/pdf",
            headers={"Content-Disposition": f"attachment; filename={filename}"}
        )

    @bp.route('/api/reports/summary/pdf', methods=['GET'])
    def export_summary_pdf():
        period = request.args.get('period', 'all')
        device_id = request.args.get('device_id')
        event_type = request.args.get('type')

        period_labels = {
            "today": "Aujourd'hui",
            "24h": "Dernières 24 heures",
            "7d": "7 derniers jours",
            "all": "Historique complet"
        }
        period_label = period_labels.get(period, "Période personnalisée")

        alerts = coordinator.recording_manager.filter_alerts(
            device_id=device_id,
            event_type=event_type,
            period=period
        )
        pdf_bytes = coordinator.pdf_report_generator.generate_summary_report(
            alerts=alerts,
            period_label=period_label
        )
        filename = f"rapport_synthese_alertes_{period}.pdf"
        return Response(
            pdf_bytes,
            mimetype="application/pdf",
            headers={"Content-Disposition": f"attachment; filename={filename}"}
        )

    # ==========================================
    # SÉCURITÉ : DISTRIBUTION SÉCURISÉE DES PREUVES
    # ==========================================

    @bp.route('/storage/screenshots/<path:filename>')
    def serve_screenshot(filename):
        safe_path = os.path.basename(filename).strip()
        if not safe_path or safe_path in [".", ".."] or "\x00" in safe_path:
            abort(400, description="Nom de fichier invalide.")
        target = os.path.abspath(os.path.join(config.SCREENSHOTS_DIR, safe_path))
        base = os.path.abspath(config.SCREENSHOTS_DIR)
        if not target.startswith(base) or not os.path.isfile(target):
            abort(404, description="Preuve photo introuvable.")
        return send_from_directory(config.SCREENSHOTS_DIR, safe_path)

    @bp.route('/storage/recordings/<path:filename>')
    def serve_recording(filename):
        safe_path = os.path.basename(filename).strip()
        if not safe_path or safe_path in [".", ".."] or "\x00" in safe_path:
            abort(400, description="Nom de fichier invalide.")
        target = os.path.abspath(os.path.join(config.RECORDINGS_DIR, safe_path))
        base = os.path.abspath(config.RECORDINGS_DIR)
        if not target.startswith(base) or not os.path.isfile(target):
            abort(404, description="Preuve vidéo introuvable.")
        return send_from_directory(config.RECORDINGS_DIR, safe_path)

    # ==========================================
    # AMÉLIORATION N°2 : INTÉGRITÉ CRYPTOGRAPHIQUE
    # ==========================================
    @bp.route('/api/integrity/verify/<proof_id>', methods=['GET'])
    def verify_proof_integrity(proof_id):
        safe_id = re.sub(r'[^a-zA-Z0-9_-]', '', proof_id)
        result = coordinator.integrity_manager.verify_evidence(safe_id)
        return jsonify(result)

    @bp.route('/api/alerts/<alert_id>/integrity', methods=['GET'])
    def verify_alert_integrity(alert_id):
        safe_id = re.sub(r'[^a-zA-Z0-9_-]', '', alert_id)
        results = coordinator.integrity_manager.verify_alert_evidences(safe_id)
        return jsonify({"status": "ok", "alert_id": safe_id, "evidences": results})

    @bp.route('/api/integrity/chain/verify', methods=['GET'])
    @login_required
    @roles_required("ADMIN", "AUDITOR")
    def verify_chain():
        result = coordinator.integrity_manager.verify_chain_integrity()
        return jsonify(result)

    @bp.route('/api/integrity/log', methods=['GET'])
    @login_required
    @roles_required("ADMIN", "AUDITOR")
    def list_integrity_log():
        limit = int(request.args.get('limit', 100))
        try:
            with get_db_session() as db:
                from monitoring.models import IntegrityLogEntry
                entries = db.query(IntegrityLogEntry).order_by(IntegrityLogEntry.id.desc()).limit(limit).all()
                return jsonify({
                    "status": "ok",
                    "count": len(entries),
                    "log": [e.to_dict() for e in entries]
                })
        except Exception as e:
            return jsonify({"status": "error", "message": str(e)}), 500

    # ==========================================
    # AMÉLIORATION N°3 : NOTIFICATIONS TELEGRAM
    # ==========================================
    @bp.route('/api/telegram/status', methods=['GET'])
    def telegram_status():
        return jsonify(coordinator.telegram_notifier.get_status())

    @bp.route('/api/telegram/test', methods=['POST'])
    @login_required
    @roles_required("ADMIN")
    def telegram_test():
        caller = session.get("username", "Admin")
        success, msg = coordinator.telegram_notifier.send_test_message(test_by=caller)
        if success:
            return jsonify({"status": "ok", "message": msg})
        return jsonify({"status": "error", "message": msg}), 400

    # ==========================================
    # AMÉLIORATION N°1 : IA QWEN VISION XKiro FREE TIER
    # ==========================================
    @bp.route('/api/qwen_vision/status', methods=['GET'])
    def qwen_vision_status():
        return jsonify(coordinator.qwen_vision_manager.get_status())

    @bp.route('/api/qwen_vision/toggle', methods=['POST'])
    @login_required
    @roles_required("ADMIN")
    def qwen_vision_toggle():
        data = request.get_json(silent=True) or {}
        enabled = data.get("enabled")
        if enabled is not None:
            coordinator.qwen_vision_manager.enabled = bool(enabled)
            coordinator.qwen_vision_manager.verify_catalog_and_select_model()
        return jsonify(coordinator.qwen_vision_manager.get_status())

    # ==========================================
    # AMÉLIORATION N°5 : MIGRATION & PERSISTANCE SQLITE
    # ==========================================
    @bp.route('/api/database/status', methods=['GET'])
    def database_status():
        try:
            with get_db_session() as db:
                dev_count = db.query(Device).count()
                alert_count = db.query(Alert).count()
                notif_count = db.query(Notification).count()
                ev_count = db.query(Evidence).count()
            return jsonify({
                "status": "ok",
                "database_engine": "SQLite 3",
                "database_path": config.DB_PATH,
                "counts": {
                    "devices": dev_count,
                    "alerts": alert_count,
                    "notifications": notif_count,
                    "evidences": ev_count
                }
            })
        except Exception as e:
            return jsonify({"status": "error", "message": str(e)}), 500

    @bp.route('/api/database/migrate', methods=['POST'])
    @login_required
    @roles_required("ADMIN")
    def database_migrate():
        mgr = MigrationManager()
        report = mgr.migrate_json_to_sqlite()
        coordinator.device_store.load()
        coordinator.recording_manager.load_alerts()
        return jsonify(report)

    @bp.route('/api/database/export', methods=['GET'])
    @login_required
    @roles_required("ADMIN", "AUDITOR")
    def database_export():
        mgr = MigrationManager()
        dump_data = mgr.export_sqlite_to_json()
        return Response(
            json.dumps(dump_data, indent=2, ensure_ascii=False),
            mimetype="application/json",
            headers={"Content-Disposition": "attachment; filename=security_monitor_backup.json"}
        )

    return bp
