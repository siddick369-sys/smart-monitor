"""
Blueprint Flask pour les fonctionnalités avancées PRO-07 à PRO-11 :
- PRO-07 : Anti-sabotage (Tamper Detection) et Audio AI Classifier
- PRO-08 : Recherche Vidéo Sémantique (CLIP / Vector Search)
- PRO-09 : Rapport Forensique PDF, Privacy Shield (Two-Man Rule) et Intégrité des Preuves
- PRO-10 : Jumeau Numérique 2D (Spatial Tracker) et Détection de Postures / Chute
- PRO-11 : Synchronisation P2P Store-and-Forward et Interphone / Sommation Défensive
"""

import os
import time
import numpy as np
import cv2
from flask import Blueprint, request, jsonify, session, send_from_directory, abort, current_app
from monitoring.auth_manager import login_required, roles_required
import config

def create_master_blueprint(coordinator):
    bp = Blueprint('master_api', __name__)

    tamper_det = coordinator.tamper_detector
    audio_ai = coordinator.audio_classifier
    semantic_search = coordinator.semantic_search_engine
    evidence_mgr = coordinator.evidence_integrity_mgr
    privacy_shield = coordinator.privacy_shield
    forensic_engine = coordinator.forensic_engine
    spatial_tracker = coordinator.spatial_tracker
    pose_detector = coordinator.pose_detector
    p2p_mgr = coordinator.p2p_sync_mgr
    intercom_mgr = coordinator.intercom_mgr
    audit = coordinator.security_audit

    # =========================================================================
    # 1. PRO-07 : Tamper Detection
    # =========================================================================

    @bp.route('/api/tamper/status', methods=['GET'])
    @login_required
    def tamper_status():
        """Consulte l'état global et les alertes anti-sabotage."""
        if not tamper_det:
            return jsonify({"status": "error", "message": "Module Tamper Detection non disponible."}), 503
        return jsonify({"status": "ok", "tamper": tamper_det.get_status()})

    @bp.route('/api/tamper/resolve', methods=['POST'])
    @login_required
    @roles_required("ADMIN", "OPERATOR")
    def resolve_tamper():
        """Acquitte ou réinitialise l'état d'une caméra après sabotage."""
        data = request.get_json(silent=True) or {}
        device_id = data.get("device_id")
        if not device_id:
            return jsonify({"status": "error", "message": "device_id requis."}), 400

        if tamper_det:
            tamper_det.resolve_tamper(device_id)

        if audit:
            audit.log_event(
                event_id="TAMPER_ALERT_RESOLVED",
                name="TamperResolved",
                actor=session.get("username", "admin"),
                action="UPDATE_STATUS",
                outcome="SUCCESS",
                message=f"Alerte sabotage acquittée pour la caméra {device_id}",
                metadata={"device_id": device_id}
            )

        return jsonify({"status": "ok", "message": f"Sabotage acquitté pour {device_id}."})

    # =========================================================================
    # 2. PRO-07 : Audio AI Classifier
    # =========================================================================

    @bp.route('/api/audio/status', methods=['GET'])
    @login_required
    def audio_status():
        """Consulte l'état du classificateur audio d'urgence."""
        if not audio_ai:
            return jsonify({"status": "error", "message": "Module Audio AI non disponible."}), 503
        return jsonify({"status": "ok", "audio_ai": audio_ai.get_status()})

    @bp.route('/api/audio/classify_test', methods=['POST'])
    @login_required
    def classify_audio_test():
        """Simule ou analyse un événement acoustique suspect."""
        data = request.get_json(silent=True) or {}
        event_type = data.get("simulated_sound", "SCREAM").upper()
        sample_rate = int(data.get("sample_rate", 16000))

        # Générer un signal de test selon le type demandé
        duration = 1.0
        t = np.linspace(0, duration, int(sample_rate * duration), endpoint=False)
        if event_type == "SCREAM":
            # Haute fréquence modulée 1200-1800 Hz
            signal = 0.8 * np.sin(2 * np.pi * (1200 + 400 * np.sin(2 * np.pi * 5 * t)) * t)
        elif event_type == "GLASS_BREAK":
            # Bruit blanc impulsionnel décroissant
            noise = np.random.normal(0, 1, len(t))
            env = np.exp(-15 * t)
            signal = 0.9 * noise * env
        elif event_type == "ALARM_SIREN":
            # Balayage 800 - 1000 Hz
            signal = 0.7 * np.sin(2 * np.pi * (800 + 200 * np.sin(2 * np.pi * 2 * t)) * t)
        else:
            signal = 0.05 * np.random.normal(0, 1, len(t))

        pred = audio_ai.classify_sound_event(
            device_id="test_probe",
            sound_level_db=88.0,
            audio_samples=signal,
            sample_rate=sample_rate
        )
        return jsonify({"status": "ok", "prediction": pred.to_dict()})

    # =========================================================================
    # 3. PRO-08 : Semantic Video Search
    # =========================================================================

    @bp.route('/api/search/semantic', methods=['GET'])
    @login_required
    def search_semantic():
        """Effectue une recherche sémantique multimodale en langage naturel."""
        if not semantic_search:
            return jsonify({"status": "error", "message": "Module Semantic Search non disponible."}), 503

        query = request.args.get("q", "").strip()
        if not query:
            return jsonify({"status": "error", "message": "Paramètre de recherche 'q' manquant."}), 400

        try:
            page = max(1, int(request.args.get("page", 1)))
            page_size = max(1, min(50, int(request.args.get("page_size", 10))))
            min_score = float(request.args.get("min_score", 0.15))
        except ValueError:
            return jsonify({"status": "error", "message": "Paramètres numériques invalides."}), 400

        results = semantic_search.search(
            query=query,
            top_k=50,
            min_score=min_score,
            page=page,
            page_size=page_size
        )
        return jsonify({"status": "ok", "data": results})

    @bp.route('/api/search/reindex', methods=['POST'])
    @login_required
    @roles_required("ADMIN")
    def reindex_semantic():
        """Déclenche la réindexation sémantique des alertes enregistrées."""
        if not semantic_search:
            return jsonify({"status": "error", "message": "Module Semantic Search non disponible."}), 503

        alerts = coordinator.recording_manager.get_all_alerts()
        total_indexed = 0

        for a in alerts:
            video_file = a.get("video_file")
            screenshot = a.get("screenshot")
            frames = []
            if screenshot and os.path.exists(screenshot):
                img = cv2.imread(screenshot)
                if img is not None:
                    frames.append(img)
            
            if frames or (video_file and os.path.exists(video_file)):
                cnt = semantic_search.index_video(
                    event_id=a["id"],
                    device_id=a.get("device_id", "camera"),
                    video_path=video_file or "",
                    keyframes=frames if frames else None,
                    labels=[a.get("type", ""), a.get("category", "")],
                    timestamp=a.get("timestamp")
                )
                total_indexed += cnt

        return jsonify({"status": "ok", "indexed_frames": total_indexed, "message": "Réindexation terminée."})

    # =========================================================================
    # 4. PRO-09 : Forensic Reports, Privacy Shield & Evidence Integrity
    # =========================================================================

    @bp.route('/api/forensic/generate_pdf/<alert_id>', methods=['POST'])
    @login_required
    @roles_required("ADMIN", "AUDITOR")
    def generate_forensic_pdf(alert_id):
        """Génère un rapport forensique certifié avec séparation physique/IA (réservé ADMIN et AUDITOR)."""
        alerts = coordinator.recording_manager.get_all_alerts()
        target_alert = next((a for a in alerts if a.get("id") == alert_id), None)
        if not target_alert:
            with coordinator.recording_manager._lock:
                target_alert = next((a for a in coordinator.recording_manager.alerts if a.get("id") == alert_id), None)

        if not target_alert:
            return jsonify({"status": "error", "message": "Alerte introuvable."}), 404

        proofs = []
        if target_alert.get("screenshot") and os.path.exists(target_alert["screenshot"]):
            h = evidence_mgr.calculate_file_hash(target_alert["screenshot"]) if evidence_mgr else "N/A"
            proofs.append({
                "type": "CAPTURE JPEG",
                "path": target_alert["screenshot"],
                "sha256": h,
                "size_bytes": os.path.getsize(target_alert["screenshot"])
            })

        if target_alert.get("video_file") and os.path.exists(target_alert["video_file"]):
            h = evidence_mgr.calculate_file_hash(target_alert["video_file"]) if evidence_mgr else "N/A"
            proofs.append({
                "type": "ENREGISTREMENT VIDÉO",
                "path": target_alert["video_file"],
                "sha256": h,
                "size_bytes": os.path.getsize(target_alert["video_file"])
            })

        integrity_info = {
            "tsa_source": "LOCAL_CHAINED_HMAC",
            "tsa_token": f"TSA-SIG-{int(time.time()*1000)}",
            "hmac_algorithm": "HMAC-SHA256"
        }

        report_path = forensic_engine.generate_incident_report(
            incident_data=target_alert,
            proof_files=proofs,
            ai_inference=target_alert.get("ai_analysis"),
            integrity_info=integrity_info
        )

        filename = os.path.basename(report_path)

        if audit:
            audit.log_event(
                event_id="FORENSIC_REPORT_GENERATED",
                name="ForensicReportGenerate",
                actor=session.get("username", "anonymous"),
                action="GENERATE_REPORT",
                outcome="SUCCESS",
                message=f"Rapport forensique généré pour l'alerte {alert_id} ({filename})",
                metadata={"alert_id": alert_id, "filename": filename}
            )

        return jsonify({
            "status": "ok",
            "report_path": report_path,
            "filename": filename,
            "download_url": f"/api/forensic/download/{filename}"
        })

    @bp.route('/api/forensic/download/<path:filename>', methods=['GET'])
    @login_required
    @roles_required("ADMIN", "AUDITOR")
    def download_forensic_report(filename):
        """Télécharge un rapport forensique certifié avec protection anti-IDOR et anti-path-traversal."""
        clean_filename = os.path.basename(filename)
        # Validation stricte du format et interdiction de la traversée de répertoire
        if not clean_filename or not clean_filename.endswith(".pdf") or clean_filename != filename:
            if audit:
                audit.log_event(
                    event_id="FORENSIC_DOWNLOAD_REJECTED",
                    name="ForensicReportDownload",
                    actor=session.get("username", "anonymous"),
                    action="DOWNLOAD_REPORT",
                    outcome="FAILURE",
                    message=f"Tentative de téléchargement avec nom de fichier non autorisé : {filename}"
                )
            return jsonify({"status": "error", "message": "Nom de fichier invalide ou format non autorisé."}), 400

        reports_dir = os.path.abspath(os.path.join(config.STORAGE_DIR, "reports"))
        target_path = os.path.abspath(os.path.join(reports_dir, clean_filename))

        # Vérification d'ancrage strict dans reports_dir (anti-traversal)
        if not target_path.startswith(reports_dir + os.sep) and target_path != reports_dir:
            return jsonify({"status": "error", "message": "Traversée de répertoire interdite."}), 403

        if not os.path.exists(target_path):
            return jsonify({"status": "error", "message": "Rapport introuvable."}), 404

        if audit:
            audit.log_event(
                event_id="FORENSIC_REPORT_DOWNLOADED",
                name="ForensicReportDownload",
                actor=session.get("username", "anonymous"),
                action="DOWNLOAD_REPORT",
                outcome="SUCCESS",
                message=f"Rapport forensique téléchargé : {clean_filename}",
                metadata={"filename": clean_filename}
            )

        return send_from_directory(reports_dir, clean_filename, as_attachment=True)

    @bp.route('/api/privacy/status', methods=['GET'])
    @login_required
    def privacy_status():
        """Consulte l'état du Privacy Shield et des demandes Two-Man Rule."""
        if not privacy_shield:
            return jsonify({"status": "error", "message": "Module Privacy Shield non disponible."}), 503
        return jsonify({"status": "ok", "privacy": privacy_shield.get_status()})

    @bp.route('/api/privacy/request_decryption', methods=['POST'])
    @login_required
    def request_privacy_decryption():
        """Crée une demande de déchiffrement Two-Man Rule."""
        data = request.get_json(silent=True) or {}
        resource_id = data.get("resource_id")
        reason = data.get("reason", "").strip()

        if not resource_id or not reason:
            return jsonify({"status": "error", "message": "resource_id et motif (reason) requis."}), 400

        requester = session.get("username", "operator")
        req_id = privacy_shield.create_decryption_request(
            resource_id=resource_id,
            requester=requester,
            reason=reason
        )
        req_dict = privacy_shield._requests[req_id].to_dict() if req_id in privacy_shield._requests else {"id": req_id}

        if audit:
            audit.log_event(
                event_id="PRIVACY_DECRYPTION_REQUESTED",
                name="TwoManRuleRequest",
                actor=requester,
                action="REQUEST_ACCESS",
                outcome="PENDING",
                message=f"Demande de déchiffrement {req_id} pour {resource_id} : {reason}",
                metadata={"request_id": req_id, "resource_id": resource_id}
            )

        return jsonify({"status": "ok", "request": req_dict})

    @bp.route('/api/privacy/approve_decryption', methods=['POST'])
    @login_required
    @roles_required("ADMIN")
    def approve_privacy_decryption():
        """Approuve une demande de déchiffrement Two-Man Rule (second intervenant distinct)."""
        data = request.get_json(silent=True) or {}
        request_id = data.get("request_id")
        if not request_id:
            return jsonify({"status": "error", "message": "request_id requis."}), 400

        approver = session.get("username", "admin")
        # Enforce server-side policy: self-approval is STRICTLY FORBIDDEN unconditionally (SEC-123-01)
        ok, msg = privacy_shield.approve_decryption_request(
            request_id,
            approver=approver,
            role="ADMIN",
            disallow_self_approval=True
        )
        if not ok:
            return jsonify({"status": "error", "message": msg}), 400

        if audit:
            audit.log_event(
                event_id="PRIVACY_DECRYPTION_APPROVED",
                name="TwoManRuleApprove",
                actor=approver,
                action="AUTHORIZE_ACCESS",
                outcome="SUCCESS",
                message=f"Demande de déchiffrement {request_id} approuvée par {approver}",
                metadata={"request_id": request_id}
            )

        return jsonify({"status": "ok", "message": msg})

    # =========================================================================
    # 5. PRO-10 : Spatial Tracker (2D Digital Twin) & Pose Detection
    # =========================================================================

    @bp.route('/api/spatial/floorplan', methods=['GET'])
    @login_required
    def get_spatial_floorplan():
        """Consulte les coordonnées cartographiques, zones et caméras du jumeau numérique."""
        if not spatial_tracker:
            return jsonify({"status": "error", "message": "Module Spatial Tracker non disponible."}), 503
        return jsonify({"status": "ok", "floorplan": spatial_tracker.get_floorplan_state()})

    @bp.route('/api/spatial/tracks', methods=['GET'])
    @login_required
    def get_spatial_tracks():
        """Consulte les trajectoires actives multi-caméras et les intrusions de zones."""
        if not spatial_tracker:
            return jsonify([])
        return jsonify({"status": "ok", "tracks": spatial_tracker.get_active_tracks()})

    @bp.route('/api/spatial/record_detection', methods=['POST'])
    @login_required
    def record_spatial_detection():
        """Enregistre un point de détection sur le plan et met à jour le handover."""
        data = request.get_json(silent=True) or {}
        camera_id = data.get("camera_id")
        bbox_center_x = float(data.get("bbox_center_x", 0.5))
        distance_meters = float(data.get("distance_meters", 3.0))

        if not camera_id:
            return jsonify({"status": "error", "message": "camera_id requis."}), 400

        res = spatial_tracker.record_detection(
            device_id=camera_id,
            bbox_center_x=bbox_center_x,
            distance_meters=distance_meters
        )
        return jsonify({"status": "ok", "track": res})

    @bp.route('/api/pose/status', methods=['GET'])
    @login_required
    def get_pose_status():
        """Consulte l'état du détecteur de chutes et de maraudage (loitering)."""
        if not pose_detector:
            return jsonify({"status": "error", "message": "Module Pose Detector non disponible."}), 503
        return jsonify({"status": "ok", "pose": pose_detector.get_status()})

    # =========================================================================
    # 6. PRO-11 : P2P Store-and-Forward & Intercom / Defensive Sommation
    # =========================================================================

    @bp.route('/api/p2p/status', methods=['GET'])
    @login_required
    def get_p2p_status():
        """Consulte l'état de la synchronisation P2P et de la file d'attente hors-ligne."""
        if not p2p_mgr:
            return jsonify({"status": "error", "message": "Module P2P Sync non disponible."}), 503
        return jsonify({"status": "ok", "p2p": p2p_mgr.get_status()})

    @bp.route('/api/p2p/sync_batch', methods=['POST'])
    def p2p_sync_batch():
        """Reçoit un lot d'incidents synchronisé par un pair réseau authentifié."""
        if not p2p_mgr:
            return jsonify({"status": "error", "message": "P2P non configuré."}), 503

        device_id = request.headers.get("X-Device-ID") or request.headers.get("X-Node-ID", "")
        device_token = request.headers.get("X-Device-Token") or request.headers.get("X-P2P-Signature", "")

        if not device_id or not device_token:
            abort(401, description="En-têtes d'authentification P2P manquants.")

        data = request.get_json(silent=True) or {}
        events = data.get("events", [])
        ok, accepted, ids, msg = p2p_mgr.receive_sync_batch(device_id, device_token, events)

        if not ok:
            return jsonify({"status": "error", "message": msg}), 403

        return jsonify({
            "status": "ok",
            "synced_count": accepted,
            "accepted_ids": ids,
            "message": msg
        })

    @bp.route('/api/intercom/status', methods=['GET'])
    @login_required
    def get_intercom_status():
        """Consulte l'état de l'interphone et des sommations défensives."""
        if not intercom_mgr:
            return jsonify({"status": "error", "message": "Module Intercom non disponible."}), 503
        return jsonify({"status": "ok", "intercom": intercom_mgr.get_status()})

    @bp.route('/api/intercom/session/start', methods=['POST'])
    @login_required
    @roles_required("ADMIN", "OPERATOR")
    def start_intercom_session():
        """Démarre une session d'interphonie bidirectionnelle WebRTC."""
        data = request.get_json(silent=True) or {}
        device_id = data.get("device_id")
        if not device_id:
            return jsonify({"status": "error", "message": "device_id requis."}), 400

        operator_id = session.get("username", "operator")
        sess = intercom_mgr.start_intercom_session(device_id, operator_id)

        if audit:
            audit.log_event(
                event_id="INTERCOM_SESSION_STARTED",
                name="IntercomStart",
                actor=operator_id,
                action="START_AUDIO_STREAM",
                outcome="SUCCESS",
                message=f"Session audio interphone ouverte avec {device_id}",
                metadata={"session_id": sess["session_id"], "device_id": device_id}
            )

        return jsonify({"status": "ok", "session": sess})

    @bp.route('/api/intercom/session/stop', methods=['POST'])
    @login_required
    @roles_required("ADMIN", "OPERATOR")
    def stop_intercom_session():
        """Clôture une session d'interphonie active."""
        data = request.get_json(silent=True) or {}
        session_id = data.get("session_id")
        if not session_id:
            return jsonify({"status": "error", "message": "session_id requis."}), 400

        operator_id = session.get("username", "operator")
        ok = intercom_mgr.stop_intercom_session(session_id, operator_id)
        return jsonify({"status": "ok" if ok else "not_found", "closed": ok})

    @bp.route('/api/intercom/voice_announcement', methods=['POST'])
    @login_required
    @roles_required("ADMIN", "OPERATOR")
    def voice_announcement():
        """Déclenche une sommation vocale pré-enregistrée neutre et dissuasive."""
        data = request.get_json(silent=True) or {}
        device_id = data.get("device_id", "all")
        phrase_id = data.get("phrase_id", "ZONE_SURVEILLEE")
        operator_id = session.get("username", "operator")

        res = intercom_mgr.trigger_voice_announcement(device_id=device_id, announcement_type=phrase_id, operator_username=operator_id)

        if audit:
            audit.log_event(
                event_id="DEFENSIVE_VOICE_TRIGGERED",
                name="VoiceSommation",
                actor=operator_id,
                action="TRIGGER_DEFENSE",
                outcome="SUCCESS",
                message=f"Sommation vocale '{phrase_id}' déclenchée sur {device_id}",
                metadata=res
            )

        return jsonify({"status": "ok", "announcement": res})

    @bp.route('/api/intercom/strobe', methods=['POST'])
    @login_required
    @roles_required("ADMIN", "OPERATOR")
    def trigger_strobe():
        """Active l'éblouissement stroboscopique avec sécurité anti-surchauffe."""
        data = request.get_json(silent=True) or {}
        duration = float(data.get("duration", 5.0))
        device_id = data.get("device_id", "all")
        operator_id = session.get("username", "operator")

        success, msg = intercom_mgr.trigger_strobe(device_id=device_id, duration_seconds=duration, operator_username=operator_id)

        if audit:
            audit.log_event(
                event_id="DEFENSIVE_STROBE_TRIGGERED",
                name="StrobeDefense",
                actor=operator_id,
                action="TRIGGER_DEFENSE",
                outcome="SUCCESS" if success else "REJECTED",
                message=f"Commande stroboscope ({duration}s) : {msg}",
                metadata={"duration": duration, "device_id": device_id, "result": msg}
            )

        if not success:
            return jsonify({"status": "error", "message": msg}), 429

        return jsonify({"status": "ok", "message": msg, "duration": duration})

    return bp
