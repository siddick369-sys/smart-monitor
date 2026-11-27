import os
import atexit
import signal
import sys
import logging
from logging.handlers import TimedRotatingFileHandler
from urllib.parse import urlparse
from flask import Flask, request, abort, session
import config
from monitoring.system_coordinator import SystemCoordinator
from routes.dashboard import create_dashboard_blueprint
from routes.devices import create_devices_blueprint
from routes.alerts import create_alerts_blueprint
from routes.auth import create_auth_blueprint
from routes.pro06 import create_pro06_blueprint
from routes.master_api import create_master_blueprint
from database import init_db

def setup_logging():
    """Configure la journalisation avec rotation quotidienne."""
    logger = logging.getLogger("SmartSecurityMonitor")
    logger.setLevel(logging.INFO)
    
    # Éviter les handlers dupliqués
    if not logger.handlers:
        file_handler = TimedRotatingFileHandler(
            config.APP_LOG_FILE,
            when="midnight",
            interval=1,
            backupCount=7,
            encoding="utf-8"
        )
        formatter = logging.Formatter(
            "%(asctime)s [%(levelname)s] %(name)s: %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S"
        )
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
    return logger

def create_app(coordinator=None):
    """Usine de création de l'application Flask avec protections et journalisation."""
    # Validation obligatoire de la configuration de sécurité au démarrage (SEC-1241-02)
    # Refuse catégoriquement de démarrer si la configuration est compromise ou invalide en production
    is_prod = getattr(config, "IS_PRODUCTION", False) or os.environ.get("APP_ENV", "").lower() in ["production", "prod"]
    config.validate_security_configuration(strict_production=is_prod)

    init_db()
    app = Flask(__name__, static_folder="static", template_folder="templates")
    app.config["SECRET_KEY"] = config.SECRET_KEY
    app.config["SESSION_COOKIE_HTTPONLY"] = config.SESSION_COOKIE_HTTPONLY
    app.config["SESSION_COOKIE_SAMESITE"] = config.SESSION_COOKIE_SAMESITE
    app.config["SESSION_COOKIE_SECURE"] = config.SESSION_COOKIE_SECURE
    if config.SESSION_COOKIE_DOMAIN:
        app.config["SESSION_COOKIE_DOMAIN"] = config.SESSION_COOKIE_DOMAIN
    app.config["SESSION_COOKIE_PATH"] = config.SESSION_COOKIE_PATH
    app.config["MAX_CONTENT_LENGTH"] = 16 * 1024 * 1024  # Limite taille requêtes à 16 Mo

    # Durcissement Reverse Proxy (Werkzeug ProxyFix conditionné à une configuration explicite)
    if getattr(config, "TRUSTED_PROXIES_COUNT", 0) > 0:
        from werkzeug.middleware.proxy_fix import ProxyFix
        app.wsgi_app = ProxyFix(
            app.wsgi_app,
            x_for=config.TRUSTED_PROXIES_COUNT,
            x_proto=config.TRUSTED_PROXIES_COUNT,
            x_host=config.TRUSTED_PROXIES_COUNT,
            x_prefix=config.TRUSTED_PROXIES_COUNT
        )

    logger = setup_logging()
    app.logger = logger

    if coordinator is None:
        coordinator = SystemCoordinator()

    # Protection CSRF complète, Origin et Sec-Fetch-Site pour les requêtes de modification (POST, PUT, DELETE, PATCH)
    @app.before_request
    def check_origin_protection():
        if request.method in ["POST", "PUT", "DELETE", "PATCH"]:
            # 1. Vérification moderne Sec-Fetch-Site (protection anti-CSRF navigateur)
            sec_fetch_site = request.headers.get("Sec-Fetch-Site")
            if sec_fetch_site == "cross-site":
                app.logger.warning(f"Requête cross-site bloquée : {request.path}")
                abort(403, description="Requête inter-sites (cross-site) interdite.")

            # 2. Vérification des en-têtes Origin et Referer
            origin = request.headers.get("Origin") or request.headers.get("Referer")
            if origin:
                parsed = urlparse(origin)
                host = parsed.hostname
                # Seules les origines locales ou d'IP privées autorisées sont acceptées
                if host and not config.is_allowed_ip(host):
                    app.logger.warning(f"Requête rejetée en provenance d'une origine non autorisée : {origin}")
                    abort(403, description="Origine non autorisée pour cette action.")

            # 3. Validation stricte du jeton CSRF de session (anti-CSRF en profondeur)
            # Endpoints d'initialisation ou machine-à-machine exemptés du jeton CSRF de session navigateur :
            # NOTE : /api/auth/logout a été retiré de cette liste dans le cadre de PRO-12.4 (SEC-123-06)
            # afin d'interdire toute déconnexion forcée par CSRF.
            exempt_endpoints = [
                "/api/auth/login",
                "/api/auth/bootstrap",
                "/api/p2p/sync_batch"
            ]
            if request.path in exempt_endpoints:
                return

            user_id = session.get("user_id")
            session_csrf = session.get("csrf_token")

            # En production, la vérification CSRF est strictement obligatoire.
            # En environnement de test, elle est activée via CSRF_REQUIRED=True ou lors de la transmission d'un jeton CSRF.
            csrf_enforced = app.config.get("CSRF_REQUIRED", config.IS_PRODUCTION)

            # En mode test headless mock unitaire sans CSRF obligatoire
            is_mock_test = (app.config.get("TESTING", False) and not csrf_enforced and not request.headers.get("X-CSRF-Token"))
            if is_mock_test:
                return

            # Si le contrôle CSRF est requis (production ou test dédié)
            if csrf_enforced or request.headers.get("X-CSRF-Token"):
                if user_id or session_csrf:
                    client_token = (
                        request.headers.get("X-CSRF-Token") or
                        request.headers.get("X-CSRFToken") or
                        (request.form.get("csrf_token") if request.form else None)
                    )
                    if not client_token and request.is_json:
                        try:
                            body = request.get_json(silent=True) or {}
                            client_token = body.get("csrf_token")
                        except Exception:
                            pass

                    import hmac
                    if not session_csrf or not client_token or not hmac.compare_digest(str(session_csrf), str(client_token)):
                        app.logger.warning(f"Requête rejetée : jeton CSRF manquant ou invalide sur {request.path}")
                        abort(403, description="Jeton CSRF manquant ou invalide.")

    # En-têtes de sécurité HTTP pour durcir la console de supervision
    @app.after_request
    def set_security_headers(response):
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "SAMEORIGIN"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' https://cdn.tailwindcss.com; "
            "style-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com; "
            "font-src 'self' https://cdnjs.cloudflare.com; "
            "img-src 'self' data: blob:; "
            "media-src 'self' data: blob:; "
            "connect-src 'self'; "
            "frame-src 'self'; "
            "object-src 'none'; "
            "base-uri 'self'; "
            "form-action 'self'; "
            "frame-ancestors 'self'"
        )
        return response

    # Enregistrement des Blueprints
    app.register_blueprint(create_auth_blueprint(coordinator))
    app.register_blueprint(create_dashboard_blueprint(coordinator))
    app.register_blueprint(create_devices_blueprint(coordinator))
    app.register_blueprint(create_alerts_blueprint(coordinator))
    app.register_blueprint(create_pro06_blueprint(coordinator))
    app.register_blueprint(create_master_blueprint(coordinator))

    app.coordinator = coordinator

    return app, coordinator

app, coordinator = create_app()

def cleanup():
    print("\n[Application] Arrêt propre du Monitoring Host...")
    try:
        coordinator.stop()
    except Exception:
        pass

atexit.register(cleanup)

def signal_handler(sig, frame):
    cleanup()
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGTERM, signal_handler)

if __name__ == "__main__":
    print("=" * 60)
    print(" SMART SECURITY MONITOR - MONITORING HOST (TP4)")
    print(f" Accès au tableau de bord : http://{config.HOST}:{config.PORT}")
    print("=" * 60)
    
    coordinator.start()
    app.run(host=config.HOST, port=config.PORT, debug=config.DEBUG, threaded=True)
