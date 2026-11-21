import os
import time
import json
import pytest
from unittest.mock import MagicMock, patch

from monitoring.totp_manager import TOTPManager
from monitoring.security_audit import SecurityAudit

def test_totp_secret_generation_and_token_cycle():
    """Vérifie la génération de secret Base32 et le calcul d'un token valide RFC 6238."""
    totp = TOTPManager(issuer="SmartSecurityMonitor", time_step=30, digits=6)
    secret = totp.generate_secret(20)
    
    assert len(secret) >= 16
    
    # Génération du token pour l'instant présent
    token = totp.generate_token(secret)
    assert len(token) == 6
    assert token.isdigit()
    
    # Vérification immédiate
    valid, counter = totp.verify_token(secret, token)
    assert valid is True
    assert counter is not None

def test_totp_window_clock_drift():
    """Vérifie la tolérance de dérive d'horloge (+/- 1 pas de temps)."""
    totp = TOTPManager(time_step=30)
    secret = totp.generate_secret(20)
    
    current_counter = totp.get_time_counter()
    
    # Token du pas précédent (drift -1)
    past_token = totp.generate_token(secret, current_counter - 1)
    valid_past, _ = totp.verify_token(secret, past_token, window=1)
    assert valid_past is True
    
    # Token du pas futur (drift +1)
    future_token = totp.generate_token(secret, current_counter + 1)
    valid_future, _ = totp.verify_token(secret, future_token, window=1)
    assert valid_future is True
    
    # Token trop ancien (drift -3) -> Rejeté
    too_old_token = totp.generate_token(secret, current_counter - 3)
    valid_old, _ = totp.verify_token(secret, too_old_token, window=1)
    assert valid_old is False

def test_totp_anti_replay_protection():
    """Vérifie l'interdiction stricte de réutiliser le même token dans le même pas de temps."""
    totp = TOTPManager(time_step=30)
    secret = totp.generate_secret(20)
    
    token = totp.generate_token(secret)
    
    # Première utilisation -> Validé et retourne le counter
    valid1, counter1 = totp.verify_token(secret, token, last_counter=None)
    assert valid1 is True
    
    # Seconde tentative immédiate avec last_counter enregistré -> REJET ANTI-REJEU
    valid2, counter2 = totp.verify_token(secret, token, last_counter=counter1)
    assert valid2 is False

def test_totp_recovery_codes():
    """Vérifie la création et la consommation à usage unique des codes de secours."""
    totp = TOTPManager()
    plain_codes, hashed_codes = totp.generate_recovery_codes(count=4)
    
    assert len(plain_codes) == 4
    assert len(hashed_codes) == 4
    
    code_to_use = plain_codes[0]
    
    # Utilisation d'un code valide
    valid, remaining = totp.verify_recovery_code(code_to_use, hashed_codes)
    assert valid is True
    assert len(remaining) == 3
    
    # Deuxième tentative avec le MÊME code -> REJETÉ (déjà consommé)
    valid_reused, remaining2 = totp.verify_recovery_code(code_to_use, remaining)
    assert valid_reused is False
    assert len(remaining2) == 3
    
    # Code bidon -> REJETÉ
    valid_bogus, _ = totp.verify_recovery_code("FAKE-CODE", remaining)
    assert valid_bogus is False

def test_security_audit_syslog_rfc5424(tmp_path):
    """Vérifie le respect du format Syslog RFC 5424 et la présence des champs obligatoires."""
    audit_file = str(tmp_path / "audit.log")
    audit = SecurityAudit(log_file=audit_file, format_type="SYSLOG")
    
    event = audit.log_event(
        event_id="AUTH_LOGIN_SUCCESS",
        name="UserLogin",
        actor="admin",
        action="LOGIN",
        outcome="SUCCESS",
        message="Authentification réussie pour admin",
        severity=SecurityAudit.SEV_NOTICE,
        metadata={"src_ip": "192.168.1.42"}
    )
    
    syslog = event["syslog"]
    # Vérification du PRI (<37> = 4 * 8 + 5 = 37)
    assert syslog.startswith("<37>1 ")
    assert "SmartSecurityMonitor" in syslog
    assert "AUTH_LOGIN_SUCCESS" in syslog
    assert '[audit@48577 action="LOGIN" actor="admin"' in syslog
    assert 'src_ip="192.168.1.42"' in syslog

def test_security_audit_cef_format(tmp_path):
    """Vérifie le respect du format Common Event Format (CEF)."""
    audit_file = str(tmp_path / "audit.log")
    audit = SecurityAudit(log_file=audit_file, format_type="CEF")
    
    event = audit.log_event(
        event_id="ALARM_ARMED",
        name="AlarmStateChange",
        actor="operator_1",
        action="ARM",
        outcome="SUCCESS",
        message="Système armé manuellement",
        severity=SecurityAudit.SEV_WARNING,
        metadata={"device_id": "dev_123", "mode": "AWAY"}
    )
    
    cef = event["cef"]
    assert cef.startswith("CEF:0|SmartSecurityMonitor|TP4|1.0|ALARM_ARMED|AlarmStateChange|6|")
    assert "suser=operator_1" in cef
    assert "act=ARM" in cef
    assert "deviceExternalId=dev_123" in cef
    assert "cs_mode=AWAY" in cef

def test_security_audit_masking_sensitive_keys(tmp_path):
    """Vérifie qu'aucun secret, mot de passe ou jeton n'est inscrit en clair dans les logs."""
    audit_file = str(tmp_path / "audit.log")
    audit = SecurityAudit(log_file=audit_file)
    
    meta_with_secrets = {
        "user_id": "usr_1",
        "password": "SuperSecretPassword123!",
        "totp_secret": "JBSWY3DPEHPK3PXP",
        "api_key": "sk-123456789",
        "normal_key": "safe_value"
    }
    
    sanitized = audit.sanitize_metadata(meta_with_secrets)
    assert sanitized["password"] == "[MASQUÉ]"
    assert sanitized["totp_secret"] == "[MASQUÉ]"
    assert sanitized["api_key"] == "[MASQUÉ]"
    assert sanitized["normal_key"] == "safe_value"
