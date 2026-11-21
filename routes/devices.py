from flask import Blueprint, jsonify, request, Response
import config
from monitoring.auth_manager import login_required, roles_required

def create_devices_blueprint(coordinator):
    bp = Blueprint('devices', __name__)

    @bp.route('/api/devices', methods=['GET'])
    def list_devices():
        return jsonify(coordinator.device_store.get_all_devices())

    @bp.route('/api/devices', methods=['POST'])
    @login_required
    @roles_required("ADMIN")
    def add_device():
        data = request.get_json(silent=True) or {}
        name = str(data.get("name", "")).strip()
        ip = str(data.get("ip", "")).strip()
        port = data.get("port", 8080)
        enable_torch = bool(data.get("enable_torch", False))

        if not ip:
            return jsonify({"status": "error", "message": "L'adresse IP est obligatoire."}), 400

        # Limitation raisonnable du nombre d'appareils pour préserver les ressources CPU/réseau
        if len(coordinator.device_store.get_all_devices()) >= 10:
            return jsonify({"status": "error", "message": "Limite maximale de 10 smartphones atteinte."}), 400

        try:
            device = coordinator.add_device(name, ip, port, enable_torch)
            return jsonify({"status": "ok", "device": device}), 201
        except ValueError as ve:
            return jsonify({"status": "error", "message": str(ve)}), 400
        except Exception as e:
            return jsonify({"status": "error", "message": f"Erreur interne : {str(e)}"}), 500

    @bp.route('/api/devices/<device_id>', methods=['PUT'])
    @login_required
    @roles_required("ADMIN")
    def update_device(device_id):
        data = request.get_json(silent=True) or {}
        try:
            device = coordinator.update_device(device_id, **data)
            if not device:
                return jsonify({"status": "error", "message": "Appareil non trouvé."}), 404
            return jsonify({"status": "ok", "device": device})
        except ValueError as ve:
            return jsonify({"status": "error", "message": str(ve)}), 400
        except Exception as e:
            return jsonify({"status": "error", "message": str(e)}), 500

    @bp.route('/api/devices/<device_id>', methods=['DELETE'])
    @login_required
    @roles_required("ADMIN")
    def delete_device(device_id):
        success = coordinator.delete_device(device_id)
        if success:
            return jsonify({"status": "ok", "message": "Appareil supprimé du système."})
        return jsonify({"status": "error", "message": "Appareil non trouvé."}), 404

    @bp.route('/video_feed/<device_id>')
    def video_feed(device_id):
        """Flux vidéo MJPEG en direct pour un smartphone avec en-têtes standard."""
        return Response(
            coordinator.camera_manager.generate_mjpeg_stream(device_id),
            mimetype='multipart/x-mixed-replace; boundary=frame',
            headers={
                'Cache-Control': 'no-cache, private',
                'Pragma': 'no-cache'
            }
        )

    @bp.route('/api/devices/<device_id>/torch', methods=['POST'])
    @login_required
    @roles_required("ADMIN", "OPERATOR")
    def toggle_torch(device_id):
        data = request.get_json(silent=True) or {}
        enable = bool(data.get("enable", True))
        device = coordinator.device_store.get_device(device_id)
        if not device:
            return jsonify({"status": "error", "message": "Appareil introuvable."}), 404

        coordinator.alarm_manager.set_torch(device_id, enable)
        return jsonify({
            "status": "ok",
            "torch": enable,
            "message": f"Commande torche {'activée' if enable else 'désactivée'} transmise à {device['name']}."
        })

    # ==========================================
    # FONCTIONNALITÉ 1 : ZONES DE SURVEILLANCE
    # ==========================================

    @bp.route('/api/devices/<device_id>/zones', methods=['GET'])
    def list_zones(device_id):
        device = coordinator.device_store.get_device(device_id)
        if not device:
            return jsonify({"status": "error", "message": "Appareil introuvable."}), 404
        zones = coordinator.device_store.get_device_zones(device_id)
        return jsonify({"status": "ok", "device_id": device_id, "zones": zones})

    @bp.route('/api/devices/<device_id>/zones', methods=['POST'])
    @login_required
    @roles_required("ADMIN")
    def add_zone(device_id):
        device = coordinator.device_store.get_device(device_id)
        if not device:
            return jsonify({"status": "error", "message": "Appareil introuvable."}), 404

        data = request.get_json(silent=True) or {}
        name = str(data.get("name", "")).strip()
        try:
            x = float(data.get("x", 0.1))
            y = float(data.get("y", 0.1))
            w = float(data.get("w", 0.5))
            h = float(data.get("h", 0.5))
            enabled = bool(data.get("enabled", True))
            zone = coordinator.device_store.add_device_zone(device_id, name, x, y, w, h, enabled)
            return jsonify({"status": "ok", "zone": zone}), 201
        except ValueError as ve:
            return jsonify({"status": "error", "message": str(ve)}), 400
        except Exception as e:
            return jsonify({"status": "error", "message": str(e)}), 500

    @bp.route('/api/devices/<device_id>/zones/<zone_id>', methods=['PUT'])
    @login_required
    @roles_required("ADMIN")
    def update_zone(device_id, zone_id):
        device = coordinator.device_store.get_device(device_id)
        if not device:
            return jsonify({"status": "error", "message": "Appareil introuvable."}), 404

        data = request.get_json(silent=True) or {}
        try:
            zone = coordinator.device_store.update_device_zone(device_id, zone_id, **data)
            if not zone:
                return jsonify({"status": "error", "message": "Zone introuvable."}), 404
            return jsonify({"status": "ok", "zone": zone})
        except ValueError as ve:
            return jsonify({"status": "error", "message": str(ve)}), 400
        except Exception as e:
            return jsonify({"status": "error", "message": str(e)}), 500

    @bp.route('/api/devices/<device_id>/zones/<zone_id>', methods=['DELETE'])
    @login_required
    @roles_required("ADMIN")
    def delete_zone(device_id, zone_id):
        device = coordinator.device_store.get_device(device_id)
        if not device:
            return jsonify({"status": "error", "message": "Appareil introuvable."}), 404

        success = coordinator.device_store.delete_device_zone(device_id, zone_id)
        if success:
            return jsonify({"status": "ok", "message": "Zone supprimée avec succès."})
        return jsonify({"status": "error", "message": "Zone introuvable."}), 404

    return bp
