"""
Blueprint Flask pour les fonctionnalités de l'évolution PRO-06 :
- Edge AI (YOLOv8 ONNX)
- Geofencing & Présence Réseau
- Streaming WebRTC & Signalisation
- PWA & Web Push
- Journal d'Audit SIEM
"""

from flask import Blueprint, request, jsonify, session, render_template
from monitoring.auth_manager import login_required, roles_required

def create_pro06_blueprint(coordinator):
    bp = Blueprint('pro06', __name__)

    edge_ai = coordinator.edge_ai_detector
    presence_mgr = coordinator.presence_manager
    webrtc_mgr = coordinator.webrtc_manager
    push_mgr = coordinator.push_manager
    audit = coordinator.security_audit

    # =========================================================================
    # 1. Routes Edge AI (YOLOv8-Nano / ONNX)
    # =========================================================================

    @bp.route('/api/edge_ai/status', methods=['GET'])
    @login_required
    def edge_ai_status():
        """Consulte l'état et les métriques du moteur Edge AI."""
        if not edge_ai:
            return jsonify({"status": "error", "message": "Module Edge AI non initialisé."}), 503
        return jsonify({"status": "ok", "edge_ai": edge_ai.get_status()})

    @bp.route('/api/edge_ai/mode', methods=['POST'])
    @login_required
    @roles_required("ADMIN")
    def set_edge_ai_mode():
        """Modifie la politique de décision Edge AI (OPENCV_ONLY, EDGE_AI_ASSISTED, EDGE_AI_REQUIRED)."""
        data = request.get_json(silent=True) or {}
        new_mode = data.get("mode", "").upper().strip()

        valid_modes = [edge_ai.MODE_OPENCV_ONLY, edge_ai.MODE_ASSISTED, edge_ai.MODE_REQUIRED]
        if new_mode not in valid_modes:
            return jsonify({"status": "error", "message": f"Mode invalide. Modes acceptés : {', '.join(valid_modes)}"}), 400

        old_mode = edge_ai.mode
        edge_ai.mode = new_mode

        if audit:
            audit.log_event(
                event_id="EDGE_AI_MODE_CHANGED",
                name="ConfigChange",
                actor=session.get("username", "admin"),
                action="UPDATE_CONFIG",
                outcome="SUCCESS",
                message=f"Politique Edge AI changée : {old_mode} -> {new_mode}",
                metadata={"old_mode": old_mode, "new_mode": new_mode}
            )

        return jsonify({"status": "ok", "mode": new_mode, "message": "Mode Edge AI mis à jour."})

    # =========================================================================
    # 2. Routes Geofencing & Présence Réseau
    # =========================================================================

    @bp.route('/api/presence/status', methods=['GET'])
    @login_required
    def presence_status():
        """Consulte l'état de la machine à états de présence et des appareils."""
        if not presence_mgr:
            return jsonify({"status": "error", "message": "Module de présence non disponible."}), 503
        return jsonify({"status": "ok", "presence": presence_mgr.get_status()})

    @bp.route('/api/presence/devices', methods=['GET'])
    @login_required
    def list_presence_devices():
        """Liste tous les appareils autorisés pour le géofencing."""
        if not presence_mgr:
            return jsonify([])
        return jsonify(presence_mgr.get_trusted_devices())

    @bp.route('/api/presence/devices', methods=['POST'])
    @login_required
    @roles_required("ADMIN")
    def add_presence_device():
        """Ajoute un appareil de confiance pour la présence réseau."""
        data = request.get_json(silent=True) or {}
        name = data.get("name", "").strip()
        ip = data.get("ip", "").strip()
        mac = data.get("mac", "").strip()
        device_type = data.get("type", "smartphone").strip()

        if not name or not ip:
            return jsonify({"status": "error", "message": "Nom et adresse IP requis."}), 400

        dev = presence_mgr.add_trusted_device(name, ip, mac, device_type)

        if audit:
            audit.log_event(
                event_id="TRUSTED_DEVICE_ADDED",
                name="DeviceManagement",
                actor=session.get("username", "admin"),
                action="ADD_TRUSTED_DEVICE",
                outcome="SUCCESS",
                message=f"Appareil de confiance ajouté : {name} ({ip})",
                metadata={"name": name, "ip": ip}
            )

        return jsonify({"status": "ok", "device": dev, "message": "Appareil ajouté avec succès."}), 201

    @bp.route('/api/presence/devices/<device_id>', methods=['DELETE'])
    @login_required
    @roles_required("ADMIN")
    def remove_presence_device(device_id):
        """Supprime un appareil autorisé."""
        ok = presence_mgr.remove_trusted_device(device_id)
        if not ok:
            return jsonify({"status": "error", "message": "Appareil introuvable."}), 404

        if audit:
            audit.log_event(
                event_id="TRUSTED_DEVICE_REMOVED",
                name="DeviceManagement",
                actor=session.get("username", "admin"),
                action="REMOVE_TRUSTED_DEVICE",
                outcome="SUCCESS",
                message=f"Appareil de confiance supprimé : {device_id}",
                metadata={"device_id": device_id}
            )

        return jsonify({"status": "ok", "message": "Appareil supprimé avec succès."})

    @bp.route('/api/presence/override', methods=['POST'])
    @login_required
    @roles_required("ADMIN", "OPERATOR")
    def presence_override():
        """Force manuellement l'état de présence (priorité manuelle absolue)."""
        data = request.get_json(silent=True) or {}
        target_state = data.get("state", "").upper().strip()
        reason = data.get("reason", "Intervention manuelle depuis le tableau de bord")

        ok = presence_mgr.manual_override(target_state, reason)
        if not ok:
            return jsonify({"status": "error", "message": "État cible invalide."}), 400

        if audit:
            audit.log_event(
                event_id="PRESENCE_MANUAL_OVERRIDE",
                name="PresenceOverride",
                actor=session.get("username", "admin"),
                action="OVERRIDE_PRESENCE",
                outcome="SUCCESS",
                message=f"Dérogation manuelle de présence vers {target_state}",
                metadata={"target_state": target_state, "reason": reason}
            )

        return jsonify({"status": "ok", "message": f"État forcé à {target_state}."})

    # =========================================================================
    # 3. Routes WebRTC & Signalisation
    # =========================================================================

    @bp.route('/api/webrtc/status', methods=['GET'])
    @login_required
    def webrtc_status():
        """Consulte l'état du sous-système WebRTC."""
        if not webrtc_mgr:
            return jsonify({"status": "error", "message": "WebRTC indisponible."}), 503
        return jsonify({"status": "ok", "webrtc": webrtc_mgr.get_status()})

    @bp.route('/api/webrtc/offer', methods=['POST'])
    @login_required
    def webrtc_offer():
        """Négocie une offre SDP client ou renvoie une directive de fallback MJPEG."""
        data = request.get_json(silent=True) or {}
        session_id = data.get("session_id", "")
        sdp_offer = data.get("sdp", "")
        device_id = data.get("device_id", "")

        if not device_id:
            return jsonify({"status": "error", "message": "device_id requis."}), 400

        success, sdp_answer, meta = webrtc_mgr.handle_offer(session_id, sdp_offer, device_id)

        return jsonify({
            "status": "ok" if success else "fallback",
            "sdp": sdp_answer,
            "meta": meta
        })

    @bp.route('/api/webrtc/ice_candidate', methods=['POST'])
    @login_required
    def webrtc_ice():
        """Enregistre un candidat ICE pour la session."""
        data = request.get_json(silent=True) or {}
        session_id = data.get("session_id", "")
        candidate = data.get("candidate", {})

        ok = webrtc_mgr.add_ice_candidate(session_id, candidate)
        return jsonify({"status": "ok" if ok else "error"})

    @bp.route('/api/webrtc/close', methods=['POST'])
    @login_required
    def webrtc_close():
        """Ferme une session WebRTC."""
        data = request.get_json(silent=True) or {}
        session_id = data.get("session_id", "")
        webrtc_mgr.close_session(session_id)
        return jsonify({"status": "ok"})

    # =========================================================================
    # 4. Routes PWA & Notifications Web Push
    # =========================================================================

    @bp.route('/api/push/status', methods=['GET'])
    @login_required
    def push_status():
        """Retourne l'état des abonnements PWA."""
        if not push_mgr:
            return jsonify({"status": "error", "message": "PushManager indisponible."}), 503
        return jsonify({"status": "ok", "push": push_mgr.get_status()})

    @bp.route('/api/push/subscribe', methods=['POST'])
    @login_required
    def push_subscribe():
        """Enregistre l'abonnement Web Push du navigateur."""
        data = request.get_json(silent=True) or {}
        user_id = session.get("user_id", "anonymous")
        ok = push_mgr.add_subscription(data, user_id=user_id)
        if not ok:
            return jsonify({"status": "error", "message": "Données d'abonnement invalides."}), 400
        return jsonify({"status": "ok", "message": "Abonnement PWA enregistré."})

    @bp.route('/api/push/unsubscribe', methods=['POST'])
    @login_required
    def push_unsubscribe():
        """Révoque l'abonnement Web Push."""
        data = request.get_json(silent=True) or {}
        endpoint = data.get("endpoint", "")
        ok = push_mgr.remove_subscription(endpoint)
        return jsonify({"status": "ok" if ok else "error"})

    @bp.route('/api/push/test', methods=['POST'])
    @login_required
    @roles_required("ADMIN")
    def push_test():
        """Déclenche un test de notification push pour l'administrateur."""
        res = push_mgr.send_notification(
            title="🛡️ TEST DE NOTIFICATION",
            body="Notification locale de supervision reçue avec succès !"
        )
        return jsonify({"status": "ok", "result": res})

    @bp.route('/offline', methods=['GET'])
    def offline_page():
        """Vue de secours hors-ligne servie par le Service Worker."""
        return render_template('offline.html')

    # =========================================================================
    # 5. Routes Journal d'Audit SIEM
    # =========================================================================

    @bp.route('/api/audit/logs', methods=['GET'])
    @login_required
    @roles_required("ADMIN", "AUDITOR")
    def get_audit_logs():
        """Consulte les dernières entrées du journal de sécurité Syslog / CEF."""
        if not audit:
            return jsonify([])
        limit = min(200, int(request.args.get("limit", 50)))
        return jsonify({
            "status": "ok",
            "format": audit.format_type,
            "export_enabled": audit.export_enabled,
            "logs": audit.get_recent_logs(limit=limit)
        })

    return bp
