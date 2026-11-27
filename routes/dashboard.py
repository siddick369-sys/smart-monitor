from flask import Blueprint, render_template, jsonify, request, session, redirect, url_for, current_app
import config
from monitoring.auth_manager import login_required, roles_required

def create_dashboard_blueprint(coordinator):
    bp = Blueprint('dashboard', __name__)

    @bp.route('/')
    def index():
        if config.AUTH_ENABLED and not session.get("user_id"):
            if not current_app.config.get("TESTING", False):
                return redirect(url_for('auth.login_page'))
        return render_template('dashboard.html')

    @bp.route('/api/status', methods=['GET'])
    @login_required
    @roles_required("ADMIN", "OPERATOR", "AUDITOR")
    def status():
        """Retourne l'état complet du système pour l'actualisation temps réel."""
        try:
            return jsonify(coordinator.get_system_status())
        except Exception:
            return jsonify({"status": "error", "message": "Erreur interne lors de la lecture du statut."}), 500

    @bp.route('/api/settings', methods=['POST'])
    @login_required
    @roles_required("ADMIN")
    def update_settings():
        data = request.get_json(silent=True) or {}
        
        # Validation rigoureuse des entrées numériques
        sanitized = {}
        for k, v in data.items():
            if k in ["proximity_threshold", "sound_threshold", "accel_shock_threshold", "motion_area_threshold", "cooldown_seconds"]:
                try:
                    val = float(v)
                    if val < 0:
                        return jsonify({"status": "error", "message": f"Le seuil {k} ne peut pas être négatif."}), 400
                    if k == "cooldown_seconds" and val < 1.0:
                        return jsonify({"status": "error", "message": "L'anti-rebond minimal est de 1.0 seconde."}), 400
                    sanitized[k] = val
                except (ValueError, TypeError):
                    return jsonify({"status": "error", "message": f"Valeur invalide pour {k}."}), 400
            elif isinstance(v, bool):
                sanitized[k] = v

        updated = coordinator.device_store.update_settings(sanitized)

        # Synchroniser l'état d'armement avec l'AlarmManager
        if "system_armed" in sanitized:
            if sanitized["system_armed"]:
                coordinator.alarm_manager.arm()
            else:
                coordinator.alarm_manager.disarm()
                
        return jsonify({"status": "ok", "settings": updated})

    @bp.route('/api/settings/demo_mode', methods=['POST'])
    @login_required
    @roles_required("ADMIN")
    def toggle_demo_mode():
        data = request.get_json(silent=True) or {}
        enabled = bool(data.get("enabled", True))
        updated = coordinator.device_store.update_settings({"demo_mode": enabled})
        return jsonify({"status": "ok", "demo_mode": updated.get("demo_mode", False)})

    @bp.route('/api/alarm/arm', methods=['POST'])
    @login_required
    @roles_required("ADMIN", "OPERATOR")
    def arm():
        coordinator.alarm_manager.arm()
        return jsonify({"status": "ok", "is_armed": True})

    @bp.route('/api/alarm/disarm', methods=['POST'])
    @login_required
    @roles_required("ADMIN", "OPERATOR")
    def disarm():
        coordinator.alarm_manager.disarm()
        return jsonify({"status": "ok", "is_armed": False})

    @bp.route('/api/alarm/stop_siren', methods=['POST'])
    @login_required
    @roles_required("ADMIN", "OPERATOR")
    def stop_siren():
        coordinator.alarm_manager.stop_siren()
        return jsonify({"status": "ok", "siren_active": False})

    @bp.route('/api/alarm/test', methods=['POST'])
    @login_required
    @roles_required("ADMIN", "OPERATOR")
    def test_alarm():
        coordinator.alarm_manager.test_siren(duration_seconds=3.0)
        return jsonify({"status": "ok", "message": "Test sonore en cours (3 secondes)"})

    @bp.route('/api/alarm/reset', methods=['POST'])
    @login_required
    @roles_required("ADMIN", "OPERATOR")
    def reset_alarm():
        coordinator.alarm_manager.reset_alarm_state()
        return jsonify({"status": "ok", "in_alarm": False})

    return bp
