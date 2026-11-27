import os
import ipaddress
from typing import Optional, Tuple, Dict, Any, List
from urllib.parse import urlparse

# Chargement automatique des variables d'environnement depuis .env
try:
    from dotenv import load_dotenv
    load_dotenv(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env"))
except ImportError:
    pass

# Répertoires de base
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
STORAGE_DIR = os.path.join(BASE_DIR, "storage")
RECORDINGS_DIR = os.path.join(STORAGE_DIR, "recordings")
SCREENSHOTS_DIR = os.path.join(STORAGE_DIR, "screenshots")
LOGS_DIR = os.path.join(STORAGE_DIR, "logs")

DEVICES_FILE = os.path.join(LOGS_DIR, "devices.json")
ALERTS_FILE = os.path.join(LOGS_DIR, "alerts.json")
SETTINGS_FILE = os.path.join(LOGS_DIR, "settings.json")
APP_LOG_FILE = os.path.join(LOGS_DIR, "security_monitor.log")
DB_PATH = os.environ.get("SSM_DB_PATH") or os.path.join(STORAGE_DIR, "security_monitor.db")
BACKUPS_DIR = os.path.join(STORAGE_DIR, "backups")
MODELS_DIR = os.path.join(STORAGE_DIR, "models")

KEYS_DIR = os.path.join(STORAGE_DIR, "keys")

# Assurer l'existence des répertoires
for directory in [STORAGE_DIR, RECORDINGS_DIR, SCREENSHOTS_DIR, LOGS_DIR, BACKUPS_DIR, MODELS_DIR, KEYS_DIR]:
    os.makedirs(directory, exist_ok=True)

# Configuration Serveur & Sessions
HOST = "127.0.0.1"
PORT = 5000
DEBUG = False

# Détection de l'environnement d'exécution (development / test / production)
APP_ENV = os.environ.get("APP_ENV", os.environ.get("FLASK_ENV", "development")).lower()
IS_PRODUCTION = APP_ENV in ["production", "prod"]
TESTING = os.environ.get("TESTING", "false").lower() == "true"
ALLOW_LOOPBACK_SIMULATOR = os.environ.get("ALLOW_LOOPBACK_SIMULATOR", "true" if not IS_PRODUCTION else "false").lower() == "true"

SECRET_KEY = os.environ.get("SECRET_KEY", "smart-security-monitor-secret-dev-2026")
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = "Lax"
SESSION_COOKIE_DOMAIN = os.environ.get("SESSION_COOKIE_DOMAIN", None)
SESSION_COOKIE_PATH = os.environ.get("SESSION_COOKIE_PATH", "/")
TRUSTED_PROXIES_COUNT = int(os.environ.get("TRUSTED_PROXIES_COUNT", "0"))

# En production HTTPS, le drapeau Secure est strictement obligatoire (refus explicite si désactivé)
raw_secure_env = os.environ.get("SESSION_COOKIE_SECURE", "").strip().lower()
raw_httponly_env = os.environ.get("SESSION_COOKIE_HTTPONLY", "").strip().lower()

if IS_PRODUCTION:
    if raw_secure_env in ["false", "0", "no"]:
        raise ValueError("SESSION_COOKIE_SECURE=False est strictement interdit en environnement de production.")
    if raw_httponly_env in ["false", "0", "no"]:
        raise ValueError("SESSION_COOKIE_HTTPONLY=False est strictement interdit en environnement de production.")
    SESSION_COOKIE_SECURE = True
    SESSION_COOKIE_HTTPONLY = True
else:
    if raw_httponly_env in ["false", "0", "no"]:
        SESSION_COOKIE_HTTPONLY = False
    SESSION_COOKIE_SECURE = raw_secure_env in ["true", "1", "yes"]

SESSION_LIFETIME_SECONDS = int(os.environ.get("SESSION_LIFETIME_SECONDS", "7200"))

# Configuration Authentification & RBAC
AUTH_ENABLED = os.environ.get("AUTH_ENABLED", "true").lower() == "true"
ADMIN_DEFAULT_USERNAME = os.environ.get("ADMIN_USERNAME", "admin")
ADMIN_DEFAULT_PASSWORD = os.environ.get("ADMIN_PASSWORD", "")  # Aucun mot de passe par défaut codé en dur

# Configuration Intégrité Cryptographique (HMAC) - PRO-09 & PRO-12
# Clé secrète obligatoire pour scellement HMAC (aucun défaut universel en production)
EVIDENCE_HMAC_KEY = os.environ.get("EVIDENCE_HMAC_KEY") or os.environ.get("INTEGRITY_SECRET_KEY") or ("test_evidence_hmac_key_32_bytes_ok" if not IS_PRODUCTION else None)
INTEGRITY_SECRET_KEY = EVIDENCE_HMAC_KEY

# Configuration Notifications Telegram
TELEGRAM_BOT_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN") or os.environ.get("bot-token-telegram") or ""
TELEGRAM_CHAT_ID = os.environ.get("TELEGRAM_CHAT_ID", "")
TELEGRAM_ENABLED = os.environ.get("TELEGRAM_ENABLED", "true" if TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID else "false").lower() == "true"
TELEGRAM_TIMEOUT = float(os.environ.get("TELEGRAM_TIMEOUT", "5.0"))
TELEGRAM_MAX_RETRIES = int(os.environ.get("TELEGRAM_MAX_RETRIES", "3"))

# Configuration IA Visuelle xKiro (FREE TIER EXCLUSIF)
XKIRO_VISION_ENABLED = os.environ.get("XKIRO_VISION_ENABLED", "true").lower() == "true"
XKIRO_API_KEY = os.environ.get("XKIRO_API_KEY", "")
XKIRO_BASE_URL = os.environ.get("XKIRO_BASE_URL", "https://api.xkiro.com/v1").rstrip("/")
XKIRO_VISION_MODEL = os.environ.get("XKIRO_VISION_MODEL", "")  # Ne jamais coder en dur sans vérification
XKIRO_VISION_TIMEOUT = float(os.environ.get("XKIRO_VISION_TIMEOUT", "8.0"))
XKIRO_VISION_MAX_REQUESTS_PER_MINUTE = int(os.environ.get("XKIRO_VISION_MAX_REQUESTS_PER_MINUTE", "10"))
XKIRO_VISION_MIN_INTERVAL = float(os.environ.get("XKIRO_VISION_MIN_INTERVAL", "3.0"))
XKIRO_VISION_IMAGE_MAX_WIDTH = int(os.environ.get("XKIRO_VISION_IMAGE_MAX_WIDTH", "640"))
XKIRO_VISION_MAX_CONCURRENT_REQUESTS = int(os.environ.get("XKIRO_VISION_MAX_CONCURRENT_REQUESTS", "1"))
XKIRO_VISION_FREE_TIER_ONLY = os.environ.get("XKIRO_VISION_FREE_TIER_ONLY", "true").lower() == "true"

# =====================================================================
# ÉVOLUTIONS PRO-06 (EDGE AI, GEOFENCING, 2FA/SIEM, WEBRTC, PWA)
# =====================================================================

# 1. Edge AI (YOLOv8-Nano / ONNX Runtime)
EDGE_AI_ENABLED = os.environ.get("EDGE_AI_ENABLED", "true").lower() == "true"
EDGE_AI_MODEL_PATH = os.environ.get("EDGE_AI_MODEL_PATH", os.path.join(MODELS_DIR, "yolov8n.onnx"))
EDGE_AI_CONFIDENCE_THRESHOLD = float(os.environ.get("EDGE_AI_CONFIDENCE_THRESHOLD", "0.45"))
EDGE_AI_IOU_THRESHOLD = float(os.environ.get("EDGE_AI_IOU_THRESHOLD", "0.45"))
EDGE_AI_MODE = os.environ.get("EDGE_AI_MODE", "EDGE_AI_ASSISTED")  # OPENCV_ONLY, EDGE_AI_ASSISTED, EDGE_AI_REQUIRED
EDGE_AI_INFERENCE_INTERVAL = float(os.environ.get("EDGE_AI_INFERENCE_INTERVAL", "0.5"))
EDGE_AI_MAX_IMAGE_WIDTH = int(os.environ.get("EDGE_AI_MAX_IMAGE_WIDTH", "640"))

# 2. Geofencing & Présence Réseau (Armement intelligent)
PRESENCE_ENABLED = os.environ.get("PRESENCE_ENABLED", "false").lower() == "true"
PRESENCE_AUTO_ARM = os.environ.get("PRESENCE_AUTO_ARM", "false").lower() == "true"
PRESENCE_GRACE_PERIOD_SECONDS = int(os.environ.get("PRESENCE_GRACE_PERIOD_SECONDS", "60"))
PRESENCE_CHECK_INTERVAL_SECONDS = int(os.environ.get("PRESENCE_CHECK_INTERVAL_SECONDS", "15"))
PRESENCE_DEVICES_FILE = os.path.join(LOGS_DIR, "presence_devices.json")

# 3. Authentification TOTP (RFC 6238) & Journal SIEM (Syslog / CEF)
TOTP_ENABLED = os.environ.get("TOTP_ENABLED", "false").lower() == "true"
TOTP_ISSUER = os.environ.get("TOTP_ISSUER", "SmartSecurityMonitor")
AUDIT_LOG_FILE = os.path.join(LOGS_DIR, "security_audit.log")
SIEM_EXPORT_ENABLED = os.environ.get("SIEM_EXPORT_ENABLED", "false").lower() == "true"
SIEM_HOST = os.environ.get("SIEM_HOST", "127.0.0.1")
SIEM_PORT = int(os.environ.get("SIEM_PORT", "514"))
SIEM_PROTOCOL = os.environ.get("SIEM_PROTOCOL", "UDP").upper()  # UDP ou TCP
SIEM_FORMAT = os.environ.get("SIEM_FORMAT", "CEF").upper()  # CEF ou SYSLOG

# 4. WebRTC Low-Latency Video Streaming
WEBRTC_ENABLED = os.environ.get("WEBRTC_ENABLED", "false").lower() == "true"
WEBRTC_STUN_SERVER = os.environ.get("WEBRTC_STUN_SERVER", "stun:stun.l.google.com:19302")

# 5. Progressive Web App (PWA) & Notifications Web Push
PWA_ENABLED = os.environ.get("PWA_ENABLED", "true").lower() == "true"
VAPID_PUBLIC_KEY = os.environ.get("VAPID_PUBLIC_KEY", "")
VAPID_PRIVATE_KEY = os.environ.get("VAPID_PRIVATE_KEY", "")
PUSH_SUBSCRIPTIONS_FILE = os.path.join(LOGS_DIR, "push_subscriptions.json")

# =====================================================================
# ÉVOLUTIONS MAJEURES PRO-07 À PRO-11
# =====================================================================

# PRO-07 : Tamper Detection & Audio AI
TAMPER_ENABLED = os.environ.get("TAMPER_ENABLED", "true").lower() == "true"
TAMPER_BLUR_THRESHOLD = float(os.environ.get("TAMPER_BLUR_THRESHOLD", "40.0"))
TAMPER_DARK_THRESHOLD = float(os.environ.get("TAMPER_DARK_THRESHOLD", "25.0"))
TAMPER_STREAM_TIMEOUT = float(os.environ.get("TAMPER_STREAM_TIMEOUT", "6.0"))

AUDIO_AI_ENABLED = os.environ.get("AUDIO_AI_ENABLED", "true").lower() == "true"
AUDIO_AI_CONFIDENCE_THRESHOLD = float(os.environ.get("AUDIO_AI_CONFIDENCE_THRESHOLD", "0.50"))

# PRO-08 : Semantic Video Search
SEMANTIC_SEARCH_ENABLED = os.environ.get("SEMANTIC_SEARCH_ENABLED", "true").lower() == "true"
SEMANTIC_DB_PATH = os.environ.get("SEMANTIC_DB_PATH", os.path.join(STORAGE_DIR, "semantic_index.db"))

# PRO-09 : Forensic, Privacy Shield & Evidence Integrity
PRIVACY_SHIELD_ENABLED = os.environ.get("PRIVACY_SHIELD_ENABLED", "true").lower() == "true"
PRIVACY_AUTO_BLUR = os.environ.get("PRIVACY_AUTO_BLUR", "false").lower() == "true"
PRIVACY_KEY_FILE = os.environ.get("PRIVACY_KEY_FILE", os.path.join(KEYS_DIR, "privacy_master.key"))
PRIVACY_MASTER_KEY = os.environ.get("PRIVACY_MASTER_KEY", None)
TSA_URL = os.environ.get("TSA_URL", "")

# PRO-10 : Spatial Tracker (2D Digital Twin) & Pose Detection
SPATIAL_TRACKER_ENABLED = os.environ.get("SPATIAL_TRACKER_ENABLED", "true").lower() == "true"
POSE_DETECTION_ENABLED = os.environ.get("POSE_DETECTION_ENABLED", "true").lower() == "true"

# PRO-11 & PRO-12 : P2P Sync & Intercom (Clé obligatoire min 32 octets, aucun défaut universel en production)
P2P_SYNC_ENABLED = os.environ.get("P2P_SYNC_ENABLED", "true").lower() == "true"
P2P_CLUSTER_SECRET = os.environ.get("P2P_CLUSTER_SECRET", "test_p2p_cluster_secret_min_32_chars_long_entropy!" if not IS_PRODUCTION else None)
INTERCOM_ENABLED = os.environ.get("INTERCOM_ENABLED", "true").lower() == "true"
INTERCOM_MAX_STROBE_DURATION = int(os.environ.get("INTERCOM_MAX_STROBE_DURATION", "30"))

# =====================================================================
# SÉCURITÉ RÉSEAU & CAMÉRAS — ANTI-SSRF STRICTE (PRO-12)
# =====================================================================
ALLOWED_CAMERA_PORTS = [8080, 8081, 4747, 8000, 8082, 554, 8554]
DISALLOWED_HOST_PORTS = [5000, 22, 23, 25, 53, 80, 443, 445, 3389, 8443]

# Seules les adresses IP privées RFC 1918 sont autorisées pour les caméras
ALLOWED_PRIVATE_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
]

def is_allowed_ip(ip_str: str, allow_loopback: Optional[bool] = None) -> bool:
    """Vérifie si l'adresse IP est une IP privée locale autorisée (anti SSRF).
    Rejette les URL avec identifiants (user:pass), protocoles arbitraires, 
    adresses link-local (169.254.x.x / cloud metadata), 0.0.0.0, multicast, etc.
    """
    if not ip_str or not isinstance(ip_str, str):
        return False
    ip_str = ip_str.strip()
    
    # Rejeter les identifiants intégrés (@) ou séparateurs d'URL
    if any(c in ip_str for c in ["@", "/", ":", "\\", "?", "#", " "]):
        return False

    can_loop = allow_loopback if allow_loopback is not None else (TESTING or ALLOW_LOOPBACK_SIMULATOR)
    if ip_str.lower() in ["localhost", "127.0.0.1"]:
        return can_loop

    try:
        ip = ipaddress.ip_address(ip_str)
        if ip.is_loopback:
            return can_loop
        # Rejeter explicitement les adresses non-assignables, multicast, link-local (cloud metadata)
        if ip.is_unspecified or ip.is_link_local or ip.is_multicast or ip.is_reserved:
            return False
        return any(ip in net for net in ALLOWED_PRIVATE_NETWORKS)
    except ValueError:
        return False

def is_allowed_camera_target(ip_str: str, port: int, is_test_env: Optional[bool] = None) -> tuple:
    """Validation stricte de destination de caméra pour éliminer tout risque SSRF."""
    if not ip_str or not isinstance(ip_str, str):
        return False, "Adresse IP requise."

    ip_str = ip_str.strip()
    try:
        port = int(port)
        if not (1 <= port <= 65535):
            return False, "Le port doit être compris entre 1 et 65535."
    except (ValueError, TypeError):
        return False, "Numéro de port invalide."

    # 1. Vérification des ports interdits du serveur hôte
    if port in DISALLOWED_HOST_PORTS:
        return False, f"Port {port} interdit pour un périphérique de surveillance (service sensible)."

    if port not in ALLOWED_CAMERA_PORTS:
        return False, f"Port {port} non autorisé pour une caméra (ports admis : {ALLOWED_CAMERA_PORTS})."

    # Déterminer si le mode test permet le loopback pour le simulateur
    can_loop = is_test_env if is_test_env is not None else (TESTING or ALLOW_LOOPBACK_SIMULATOR)

    # 2. Rejet de loopback en production
    if ip_str.lower() in ["127.0.0.1", "localhost"]:
        if not can_loop:
            return False, "L'adresse de boucle locale (127.0.0.1) est strictement interdite en production."
        if port == 5000:
            return False, "Le port du serveur d'administration (5000) ne peut pas être ciblé comme caméra."
        return True, "OK_LOOPBACK_TEST"

    # 3. Validation de l'adresse IP via ipaddress
    try:
        ip = ipaddress.ip_address(ip_str)
        if ip.is_loopback:
            if not can_loop:
                return False, "L'adresse de boucle locale est interdite en production."
            return True, "OK_LOOPBACK_TEST"
        if ip.is_unspecified:
            return False, "Adresse 0.0.0.0 non autorisée."
        if ip.is_link_local:
            return False, "Adresse link-local (169.254.x.x / metadata) interdite."
        if ip.is_multicast:
            return False, "Adresse multicast interdite."
        if ip.is_reserved:
            return False, "Adresse réservée interdite."

        # Seules les adresses RFC 1918 sont acceptées
        if not any(ip in net for net in ALLOWED_PRIVATE_NETWORKS):
            return False, f"Adresse {ip_str} non autorisée : seules les adresses privées LAN sont acceptées."

        return True, "OK"
    except ValueError:
        return False, f"Format d'adresse IP invalide : '{ip_str}'."

def validate_security_configuration(strict_production: Optional[bool] = None) -> dict:
    """Valide l'état de la configuration de sécurité sans jamais divulguer les secrets.
    En production, applique une politique stricte fail-closed interdisant tout paramètre faible, absent ou par défaut (SEC-1241-02).
    """
    raw_env = os.environ.get("APP_ENV", os.environ.get("FLASK_ENV", "")).strip().lower()
    is_prod = IS_PRODUCTION if strict_production is None else bool(strict_production)
    if raw_env in ["production", "prod"]:
        is_prod = True

    is_prod_secure_valid = (not is_prod) or (SESSION_COOKIE_SECURE and SESSION_COOKIE_HTTPONLY)

    weak_keys = {
        "smart-security-monitor-secret-dev-2026",
        "secret", "changeme", "admin", "password", "default", "123456", "dev", "test"
    }
    cur_secret = str(SECRET_KEY or "").strip()
    secret_key_safe = (not is_prod) or (
        bool(cur_secret) and
        cur_secret not in weak_keys and
        len(cur_secret) >= 32
    )

    cur_hmac = str(EVIDENCE_HMAC_KEY or "").strip()
    hmac_key_safe = bool(cur_hmac and len(cur_hmac) >= 16)

    cur_p2p = str(P2P_CLUSTER_SECRET or "").strip()
    p2p_safe = bool(cur_p2p and len(cur_p2p) >= 32)

    if is_prod:
        if not cur_secret or cur_secret in weak_keys:
            raise ValueError("SECRET_KEY absente, vide ou par défaut en production.")
        if len(cur_secret) < 32:
            raise ValueError("SECRET_KEY trop courte en production (minimum 32 caractères requis).")
        if not SESSION_COOKIE_SECURE:
            raise ValueError("Configuration de cookies non sécurisée en environnement de production (SESSION_COOKIE_SECURE requis).")
        if not SESSION_COOKIE_HTTPONLY:
            raise ValueError("Configuration de cookies non sécurisée en environnement de production (SESSION_COOKIE_HTTPONLY requis).")
        if SESSION_COOKIE_SAMESITE not in ["Lax", "Strict"]:
            raise ValueError("SESSION_COOKIE_SAMESITE invalide en production (doit être 'Lax' ou 'Strict').")
        if not hmac_key_safe:
            raise ValueError("EVIDENCE_HMAC_KEY manquant ou trop court en production (minimum 16 caractères).")
        if DEBUG:
            raise ValueError("DEBUG=True est strictement interdit en environnement de production.")
        if ALLOW_LOOPBACK_SIMULATOR:
            raise ValueError("ALLOW_LOOPBACK_SIMULATOR=True est strictement interdit en environnement de production.")

        # Contrôle des variables booléennes environnementales malformées
        for var_name in ["SESSION_COOKIE_SECURE", "SESSION_COOKIE_HTTPONLY", "DEBUG", "ALLOW_LOOPBACK_SIMULATOR"]:
            raw_val = os.environ.get(var_name, "").strip().lower()
            if raw_val and raw_val not in ["true", "1", "yes", "false", "0", "no"]:
                raise ValueError(f"Valeur booléenne invalide pour {var_name} en production : '{raw_val}'.")

    return {
        "is_production": is_prod,
        "session_cookie_secure": SESSION_COOKIE_SECURE,
        "session_cookie_httponly": SESSION_COOKIE_HTTPONLY,
        "session_cookie_samesite": SESSION_COOKIE_SAMESITE,
        "production_session_secure_valid": is_prod_secure_valid,
        "secret_key_production_safe": secret_key_safe,
        "trusted_proxies_count": TRUSTED_PROXIES_COUNT,
        "evidence_hmac_configured": hmac_key_safe,
        "p2p_secret_configured": p2p_safe,
        "privacy_master_key_configured": bool(PRIVACY_MASTER_KEY or os.path.exists(PRIVACY_KEY_FILE)),
        "loopback_allowed": ALLOW_LOOPBACK_SIMULATOR
    }

# Paramètres vidéo et tampon circulaire
CAMERA_FPS = 10
CIRCULAR_BUFFER_SECONDS = 5  # Nombre de secondes conservées en mémoire avant incident
CIRCULAR_BUFFER_SIZE = CAMERA_FPS * CIRCULAR_BUFFER_SECONDS
CAMERA_RECONNECT_INTERVAL = 2.0
CAMERA_MAX_BACKOFF = 10.0
HTTP_TIMEOUT = 2.5  # Timeout requêtes vers smartphones
STALE_TELEMETRY_SECONDS = 8.0  # Au-delà, statut dégradé/expiré

# Paramètres d'enregistrement d'incident et rétention
PRE_RECORD_SECONDS = 3
POST_RECORD_SECONDS = 5
MAX_RECORDING_DURATION = 15  # Sécurité anti-remplissage disque
RETENTION_DAYS = 7  # Durée de conservation des preuves
MAX_STORAGE_MB = 1024  # Limite d'espace alloué au stockage (en Mo)

# Codes et libellés normalisés de classification d'événements
EVENT_CODES = {
    "REAL_SENSOR_EVENT": "ÉVÉNEMENT CAPTEUR RÉEL",
    "VIDEO_MOTION_EVENT": "ÉVÉNEMENT DÉTECTÉ PAR VIDÉO",
    "SIMULATED_EVENT": "ÉVÉNEMENT SIMULÉ",
    "DEVICE_DISCONNECTED": "DÉCONNEXION APPAREIL",
    "DEVICE_RECONNECTED": "RECONNEXION APPAREIL",
    "SYSTEM_ERROR": "ERREUR SYSTÈME"
}

# Paramètres de détection par défaut
DEFAULT_SETTINGS = {
    "system_armed": True,
    "siren_enabled": True,
    "torch_on_alarm": False,
    "cooldown_seconds": 8.0,
    "proximity_threshold": 5.0,     # cm : déclenchement si distance <= 5cm
    "sound_threshold": 75.0,        # dB : seuil relatif indicatif
    "accel_shock_threshold": 4.5,   # m/s² : écart par rapport à la gravité 9.81
    "motion_area_threshold": 1.5,   # % : pourcentage de surface d'image en mouvement
    "enable_proximity": True,
    "enable_sound": True,
    "enable_accel": True,
    "enable_motion": True,
    "demo_mode": False              # Mode démonstration explicite
}
