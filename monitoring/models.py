import time
import json
from sqlalchemy.orm import declarative_base, relationship
from sqlalchemy import Column, String, Integer, Float, Boolean, Text, ForeignKey, Index, UniqueConstraint

Base = declarative_base()

class User(Base):
    __tablename__ = 'users'

    id = Column(String(64), primary_key=True)
    username = Column(String(64), unique=True, nullable=False, index=True)
    password_hash = Column(String(256), nullable=False)
    role = Column(String(20), nullable=False, default='OPERATOR')  # 'ADMIN', 'OPERATOR', 'AUDITOR'
    is_active = Column(Boolean, default=True, nullable=False)
    created_at = Column(Float, default=time.time)
    last_login = Column(Float, nullable=True)

    # Champs 2FA TOTP (RFC 6238)
    totp_enabled = Column(Boolean, default=False, nullable=False)
    totp_secret = Column(String(128), nullable=True)
    totp_recovery_codes = Column(Text, nullable=True)  # JSON list of hashed single-use recovery codes
    totp_last_counter = Column(Integer, nullable=True)

    def to_dict(self):
        return {
            "id": self.id,
            "username": self.username,
            "role": self.role,
            "is_active": self.is_active,
            "created_at": self.created_at,
            "last_login": self.last_login,
            "totp_enabled": bool(self.totp_enabled)
        }

class Device(Base):
    __tablename__ = 'devices'

    id = Column(String(64), primary_key=True)
    name = Column(String(128), nullable=False)
    ip = Column(String(64), nullable=False)
    port = Column(Integer, nullable=False, default=8080)
    protocol = Column(String(32), default='ANDROID_IPWEBCAM')
    rtsp_uri = Column(String(256), nullable=True)
    zones_json = Column(Text, default='[]')
    created_at = Column(Float, default=time.time)
    updated_at = Column(Float, default=time.time)

    alerts = relationship("Alert", back_populates="device", cascade="all, delete-orphan")

    def get_zones(self):
        try:
            return json.loads(self.zones_json) if self.zones_json else []
        except Exception:
            return []

    def set_zones(self, zones):
        self.zones_json = json.dumps(zones)

    def to_dict(self):
        return {
            "id": self.id,
            "name": self.name,
            "ip": self.ip,
            "port": self.port,
            "protocol": self.protocol or "ANDROID_IPWEBCAM",
            "rtsp_uri": self.rtsp_uri,
            "zones": self.get_zones(),
            "created_at": self.created_at,
            "updated_at": self.updated_at
        }

class Alert(Base):
    __tablename__ = 'alerts'

    id = Column(String(64), primary_key=True)
    timestamp = Column(Float, nullable=False, index=True)
    datetime = Column(String(32), nullable=False)
    device_id = Column(String(64), ForeignKey('devices.id', ondelete='SET NULL'), nullable=True, index=True)
    device_name = Column(String(128), nullable=False)
    device_ip = Column(String(64), nullable=False)
    type = Column(String(64), nullable=False)
    event_code = Column(String(64), nullable=False, default="SIMULATED_EVENT")
    category = Column(String(128), nullable=False)
    severity = Column(String(20), nullable=False, index=True, default="INFO")
    details = Column(Text, nullable=True)
    measured_value = Column(Float, nullable=True)
    threshold = Column(Float, nullable=True)
    status = Column(String(64), default="TERMINÉ")
    screenshot_path = Column(String(256), nullable=True)
    recording_path = Column(String(256), nullable=True)
    sha256_hash = Column(String(64), nullable=True)
    ai_analysis_json = Column(Text, nullable=True)

    device = relationship("Device", back_populates="alerts")
    evidences = relationship("Evidence", back_populates="alert", cascade="all, delete-orphan")

    def get_ai_analysis(self):
        try:
            return json.loads(self.ai_analysis_json) if self.ai_analysis_json else None
        except Exception:
            return None

    def set_ai_analysis(self, data):
        self.ai_analysis_json = json.dumps(data) if data else None

    def to_dict(self):
        return {
            "id": self.id,
            "timestamp": self.timestamp,
            "datetime": self.datetime,
            "device_id": self.device_id,
            "device_name": self.device_name,
            "device_ip": self.device_ip,
            "type": self.type,
            "event_code": self.event_code,
            "category": self.category,
            "severity": self.severity,
            "details": self.details,
            "measured_value": self.measured_value,
            "threshold": self.threshold,
            "status": self.status,
            "screenshot_path": self.screenshot_path,
            "recording_path": self.recording_path,
            "sha256_hash": self.sha256_hash,
            "ai_analysis": self.get_ai_analysis()
        }

class Notification(Base):
    __tablename__ = 'notifications'

    id = Column(String(64), primary_key=True)
    timestamp = Column(Float, nullable=False, index=True)
    datetime = Column(String(32), nullable=False)
    title = Column(String(128), nullable=False)
    message = Column(Text, nullable=False)
    level = Column(String(20), nullable=False, default='INFO')
    category = Column(String(64), nullable=False, default='SYSTEM')
    read = Column(Boolean, default=False, nullable=False)
    user_id = Column(String(64), ForeignKey('users.id', ondelete='CASCADE'), nullable=True, index=True)

    def to_dict(self):
        return {
            "id": self.id,
            "timestamp": self.timestamp,
            "datetime": self.datetime,
            "title": self.title,
            "message": self.message,
            "level": self.level,
            "category": self.category,
            "read": self.read,
            "user_id": self.user_id
        }

class Evidence(Base):
    __tablename__ = 'evidences'

    id = Column(String(64), primary_key=True)
    alert_id = Column(String(64), ForeignKey('alerts.id', ondelete='CASCADE'), nullable=True, index=True)
    filename = Column(String(128), nullable=False)
    filepath = Column(String(256), nullable=False, unique=True)
    file_type = Column(String(16), nullable=False)  # 'IMAGE', 'VIDEO', 'PDF'
    file_size = Column(Integer, nullable=False)
    sha256_hash = Column(String(64), nullable=False)
    hmac_signature = Column(String(64), nullable=True)
    created_at = Column(Float, default=time.time)

    alert = relationship("Alert", back_populates="evidences")

    def to_dict(self):
        return {
            "id": self.id,
            "alert_id": self.alert_id,
            "filename": self.filename,
            "filepath": self.filepath,
            "file_type": self.file_type,
            "file_size": self.file_size,
            "sha256_hash": self.sha256_hash,
            "hmac_signature": self.hmac_signature,
            "created_at": self.created_at
        }

class IntegrityLogEntry(Base):
    __tablename__ = 'integrity_log'

    id = Column(Integer, primary_key=True, autoincrement=True)
    proof_id = Column(String(64), nullable=False, index=True)
    alert_id = Column(String(64), nullable=True)
    file_path = Column(String(256), nullable=False)
    file_hash = Column(String(64), nullable=False)
    prev_hash = Column(String(64), nullable=False)
    entry_hash = Column(String(64), nullable=False)
    hmac_sig = Column(String(64), nullable=True)
    created_at = Column(Float, default=time.time)

    def to_dict(self):
        return {
            "id": self.id,
            "proof_id": self.proof_id,
            "alert_id": self.alert_id,
            "file_path": self.file_path,
            "file_hash": self.file_hash,
            "prev_hash": self.prev_hash,
            "entry_hash": self.entry_hash,
            "hmac_sig": self.hmac_sig,
            "created_at": self.created_at
        }

class DecryptionRequestModel(Base):
    __tablename__ = 'decryption_requests'

    id = Column(String(64), primary_key=True)
    resource_id = Column(String(256), nullable=False)
    requester = Column(String(64), nullable=False)
    reason = Column(Text, nullable=False)
    required_approvals = Column(Integer, default=2, nullable=False)
    status = Column(String(20), default="PENDING", nullable=False, index=True)
    created_at = Column(Float, default=time.time, nullable=False)
    expires_at = Column(Float, nullable=False)
    consumed_at = Column(Float, nullable=True)

    approvals = relationship("DecryptionApprovalModel", back_populates="request", cascade="all, delete-orphan", lazy="joined")

    def to_dict(self):
        now = time.time()
        is_expired = now > self.expires_at
        effective_status = "EXPIRED" if (is_expired and self.status == "PENDING") else self.status
        return {
            "id": self.id,
            "resource_id": self.resource_id,
            "requester": self.requester,
            "reason": self.reason,
            "required_approvals": self.required_approvals,
            "approvers_count": len(self.approvals) if self.approvals else 0,
            "approvers": [a.to_dict() for a in self.approvals] if self.approvals else [],
            "status": effective_status,
            "created_at": self.created_at,
            "expires_at": self.expires_at,
            "consumed_at": self.consumed_at
        }

class DecryptionApprovalModel(Base):
    __tablename__ = 'decryption_approvals'

    id = Column(Integer, primary_key=True, autoincrement=True)
    request_id = Column(String(64), ForeignKey('decryption_requests.id', ondelete='CASCADE'), nullable=False, index=True)
    approver = Column(String(64), nullable=False)
    role = Column(String(20), nullable=False)
    approved_at = Column(Float, default=time.time, nullable=False)

    request = relationship("DecryptionRequestModel", back_populates="approvals")

    __table_args__ = (
        UniqueConstraint('request_id', 'approver', name='uq_request_approver'),
    )

    def to_dict(self):
        return {
            "username": self.approver,
            "role": self.role,
            "approved_at": self.approved_at
        }

class SystemBootstrap(Base):
    """Sentinelle singleton (id=1) garantissant l'atomicité multi-processus du bootstrap administrateur."""
    __tablename__ = 'system_bootstrap'

    id = Column(Integer, primary_key=True, default=1)
    bootstrapped_at = Column(Float, default=time.time, nullable=False)
    bootstrapped_by = Column(String(64), nullable=False)
    admin_user_id = Column(String(64), nullable=False)

    def to_dict(self):
        return {
            "bootstrapped_at": self.bootstrapped_at,
            "bootstrapped_by": self.bootstrapped_by,
            "admin_user_id": self.admin_user_id
        }

class UserSession(Base):
    """Enregistre les sessions actives pour permettre la révocation côté serveur."""
    __tablename__ = 'user_sessions'

    session_token = Column(String(64), primary_key=True)
    user_id = Column(String(64), ForeignKey('users.id', ondelete='CASCADE'), nullable=False, index=True)
    created_at = Column(Float, default=time.time, nullable=False)
    last_activity = Column(Float, default=time.time, nullable=False)
    revoked = Column(Boolean, default=False, nullable=False, index=True)

    def to_dict(self):
        return {
            "session_token": self.session_token[:8] + "...",
            "user_id": self.user_id,
            "created_at": self.created_at,
            "last_activity": self.last_activity,
            "revoked": self.revoked
        }

class P2PReceivedEvent(Base):
    """Journal persistant des événements P2P pour déduplication et protection anti-rejeu inter-redémarrages."""
    __tablename__ = 'p2p_received_events'

    event_id = Column(String(128), primary_key=True)
    device_id = Column(String(64), nullable=False)
    received_at = Column(Float, default=time.time, nullable=False, index=True)

    def to_dict(self):
        return {
            "event_id": self.event_id,
            "device_id": self.device_id,
            "received_at": self.received_at
        }

class FailedAuthAttempt(Base):
    """Enregistrement partagé multi-processus des échecs d'authentification pour rate limiting."""
    __tablename__ = 'failed_auth_attempts'

    id = Column(Integer, primary_key=True, autoincrement=True)
    key = Column(String(128), nullable=False, index=True)
    attempted_at = Column(Float, default=time.time, nullable=False, index=True)
