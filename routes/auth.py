from flask import Blueprint, request, jsonify, session, render_template, redirect, url_for, current_app
from monitoring.auth_manager import login_required, roles_required

def create_auth_blueprint(coordinator):
    bp = Blueprint('auth', __name__)
    auth_mgr = coordinator.auth_manager

    @bp.route('/login', methods=['GET'])
    def login_page():
        if session.get("user_id"):
            return redirect(url_for('dashboard.index'))
        return render_template('login.html')

    @bp.route('/api/auth/bootstrap/status', methods=['GET'])
    def bootstrap_status():
        """Indique si un premier compte administrateur doit être initialisé."""
        return jsonify({
            "status": "ok",
            "bootstrap_required": auth_mgr.is_bootstrap_required()
        })

    @bp.route('/api/auth/bootstrap', methods=['POST'])
    def bootstrap():
        """Initialise le premier compte administrateur si aucun n'existe."""
        if not auth_mgr.is_bootstrap_required():
            return jsonify({
                "status": "error",
                "message": "Action refusée : le système est déjà initialisé. Le bootstrap d'un nouvel administrateur n'est plus autorisé."
            }), 403

        data = request.get_json(silent=True) or {}
        username = data.get("username", "admin").strip()
        password = data.get("password", "")
        confirm = data.get("confirm_password", "")
        token = data.get("token") or data.get("setup_token") or request.headers.get("X-Bootstrap-Token")
        client_ip = request.remote_addr or "127.0.0.1"

        if confirm and password != confirm:
            return jsonify({"status": "error", "message": "Les deux mots de passe ne correspondent pas."}), 400

        success, user_dict, message = auth_mgr.bootstrap_admin(username, password, client_ip, setup_token=token)
        if not success:
            status_code = 403 if "déjà" in message.lower() else 400
            return jsonify({"status": "error", "message": message}), status_code

        # Connexion automatique suite au bootstrap avec rotation de session
        import secrets
        session.clear()
        session_token = auth_mgr.create_user_session(user_dict["id"])
        session["session_token"] = session_token
        session["user_id"] = user_dict["id"]
        session["username"] = user_dict["username"]
        session["role"] = user_dict["role"]
        session["csrf_token"] = secrets.token_hex(32)
        session.permanent = True

        return jsonify({
            "status": "ok",
            "message": message,
            "user": user_dict,
            "csrf_token": session["csrf_token"]
        }), 201

    @bp.route('/api/auth/login', methods=['POST'])
    def login():
        data = request.get_json(silent=True) or {}
        username = data.get("username", "")
        password = data.get("password", "")
        totp_token = data.get("totp_token") or data.get("code")
        client_ip = request.remote_addr or "127.0.0.1"

        success, user_dict, message = auth_mgr.authenticate(username, password, client_ip, totp_token=totp_token)
        if not success:
            return jsonify({"status": "error", "message": message}), 401

        if message == "2FA_CHALLENGE":
            return jsonify({
                "status": "2fa_required",
                "message": "Code d'authentification 2FA ou code de secours requis.",
                "user": user_dict
            }), 200

        # Rotation de session anti-fixation et enregistrement de session côté serveur
        import secrets
        session.clear()
        session_token = auth_mgr.create_user_session(user_dict["id"])
        session["session_token"] = session_token
        session["user_id"] = user_dict["id"]
        session["username"] = user_dict["username"]
        session["role"] = user_dict["role"]
        session["csrf_token"] = secrets.token_hex(32)
        session.permanent = True

        return jsonify({
            "status": "ok",
            "message": "Connexion réussie.",
            "user": user_dict,
            "csrf_token": session["csrf_token"]
        })

    @bp.route('/api/auth/2fa/setup', methods=['POST'])
    @login_required
    def setup_2fa():
        """Démarre l'enrôlement 2FA pour l'utilisateur actuellement connecté."""
        user_id = session.get("user_id")
        success, data, msg = auth_mgr.setup_2fa(user_id)
        if not success:
            return jsonify({"status": "error", "message": msg}), 400
        return jsonify({"status": "ok", "data": data, "message": msg})

    @bp.route('/api/auth/2fa/enable', methods=['POST'])
    @login_required
    def enable_2fa():
        """Valide le premier code TOTP et active définitivement la 2FA."""
        user_id = session.get("user_id")
        data = request.get_json(silent=True) or {}
        secret = data.get("secret", "")
        token = data.get("token", "")
        plain_recovery_codes = data.get("recovery_codes", [])

        if not secret or not token:
            return jsonify({"status": "error", "message": "Secret et code TOTP requis."}), 400

        success, msg = auth_mgr.enable_2fa(user_id, secret, token, plain_recovery_codes)
        if not success:
            return jsonify({"status": "error", "message": msg}), 400
        return jsonify({"status": "ok", "message": msg})

    @bp.route('/api/auth/2fa/disable', methods=['POST'])
    @login_required
    def disable_2fa():
        """Désactive la 2FA avec réauthentification par mot de passe."""
        user_id = session.get("user_id")
        data = request.get_json(silent=True) or {}
        password = data.get("password", "")

        if not password:
            return jsonify({"status": "error", "message": "Mot de passe actuel requis pour désactiver la 2FA."}), 400

        success, msg = auth_mgr.disable_2fa(user_id, password)
        if not success:
            return jsonify({"status": "error", "message": msg}), 400
        return jsonify({"status": "ok", "message": msg})

    @bp.route('/api/auth/change_password', methods=['POST'])
    @login_required
    def change_password():
        data = request.get_json(silent=True) or {}
        current_password = data.get("current_password", "")
        new_password = data.get("new_password", "")
        confirm_password = data.get("confirm_password", "")

        if confirm_password and new_password != confirm_password:
            return jsonify({"status": "error", "message": "Le nouveau mot de passe et sa confirmation ne correspondent pas."}), 400

        user_id = session.get("user_id")
        current_username = session.get("username")
        current_role = session.get("role")
        success, message = auth_mgr.change_password(user_id, current_password, new_password)
        if not success:
            return jsonify({"status": "error", "message": message}), 400

        # Révocation de toutes les sessions antérieures et renouvellement de session
        import secrets
        auth_mgr.revoke_all_sessions_for_user(user_id)
        session.clear()
        new_token = auth_mgr.create_user_session(user_id)
        session["session_token"] = new_token
        session["user_id"] = user_id
        session["username"] = current_username
        session["role"] = current_role
        session["csrf_token"] = secrets.token_hex(32)
        session.permanent = True

        return jsonify({
            "status": "ok",
            "message": message,
            "csrf_token": session["csrf_token"]
        })

    @bp.route('/api/auth/logout', methods=['POST'])
    def logout_api():
        session_token = session.get("session_token")
        if session_token:
            auth_mgr.revoke_session(session_token)
        session.clear()
        resp = jsonify({"status": "ok", "message": "Déconnexion réussie."})
        resp.delete_cookie(current_app.config.get("SESSION_COOKIE_NAME", "session"))
        return resp

    @bp.route('/logout', methods=['POST'])
    def logout():
        """Route de déconnexion via formulaire POST avec protection CSRF."""
        session_token = session.get("session_token")
        if session_token:
            auth_mgr.revoke_session(session_token)
        session.clear()
        resp = redirect(url_for('auth.login_page'))
        resp.delete_cookie(current_app.config.get("SESSION_COOKIE_NAME", "session"))
        return resp

    @bp.route('/api/auth/csrf_token', methods=['GET'])
    def get_csrf_token():
        import secrets
        if not session.get("csrf_token"):
            session["csrf_token"] = secrets.token_hex(32)
        return jsonify({"status": "ok", "csrf_token": session["csrf_token"]})

    @bp.route('/api/auth/me', methods=['GET'])
    def me():
        user_id = session.get("user_id")
        session_token = session.get("session_token")
        if not user_id:
            return jsonify({"status": "error", "authenticated": False}), 401
        if session_token and not auth_mgr.validate_session(user_id, session_token):
            session.clear()
            return jsonify({"status": "error", "authenticated": False}), 401
        return jsonify({
            "status": "ok",
            "authenticated": True,
            "user": {
                "id": user_id,
                "username": session.get("username"),
                "role": session.get("role")
            }
        })

    @bp.route('/api/users', methods=['GET'])
    @login_required
    @roles_required("ADMIN")
    def list_users():
        return jsonify({"status": "ok", "users": auth_mgr.list_users()})

    @bp.route('/api/users', methods=['POST'])
    @login_required
    @roles_required("ADMIN")
    def create_user():
        data = request.get_json(silent=True) or {}
        username = data.get("username", "")
        password = data.get("password", "")
        role = data.get("role", "OPERATOR")

        success, user_dict, message = auth_mgr.create_user(username, password, role)
        if not success:
            return jsonify({"status": "error", "message": message}), 400

        return jsonify({"status": "ok", "user": user_dict, "message": message}), 201

    @bp.route('/api/users/<user_id>', methods=['DELETE'])
    @login_required
    @roles_required("ADMIN")
    def delete_user(user_id):
        current_user_id = session.get("user_id")
        success, message = auth_mgr.delete_user(user_id, current_user_id)
        if not success:
            return jsonify({"status": "error", "message": message}), 400

        return jsonify({"status": "ok", "message": message})

    return bp
