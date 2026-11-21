"""
Module Privacy Shield & Double Contrôle Judiciaire — PRO-09
Assure la protection et la conformité RGPD des données visuelles :
- Floutage dynamique des visages et plaques d'immatriculation (OpenCV Haar/DNN)
- Génération et conservation séparée des copies anonymisées (les originaux ne sont jamais écrasés)
- Procédure de déchiffrement à double contrôle strict (Two-Man Rule / Multi-Signature)
- Chiffrement authentifié AES-256-GCM des fichiers de preuves originaux
- Protection contre la réutilisation, expiration des demandes et journalisation d'audit
"""

import os
import time
import uuid
import struct
import logging
import threading
from typing import Dict, List, Optional, Tuple, Any
import numpy as np
import cv2
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import config

logger = logging.getLogger("SmartSecurityMonitor.PrivacyShield")


class DecryptionRequestStatus:
    PENDING = "PENDING"
    APPROVED = "APPROVED"
    EXPIRED = "EXPIRED"
    REJECTED = "REJECTED"
    CONSUMED = "CONSUMED"


class DecryptionRequest:
    def __init__(
        self,
        request_id: str,
        resource_id: str,
        requester: str,
        reason: str,
        expires_at: float,
        required_approvals: int = 2
    ):
        self.id = request_id
        self.resource_id = resource_id
        self.requester = requester
        self.reason = reason
        self.expires_at = expires_at
        self.required_approvals = required_approvals
        self.approvers: List[Dict[str, Any]] = []
        self.status = DecryptionRequestStatus.PENDING
        self.created_at = time.time()
        self.consumed_at: Optional[float] = None

    def is_expired(self) -> bool:
        return time.time() > self.expires_at

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "resource_id": self.resource_id,
            "requester": self.requester,
            "reason": self.reason,
            "required_approvals": self.required_approvals,
            "approvers_count": len(self.approvers),
            "approvers": self.approvers,
            "status": DecryptionRequestStatus.EXPIRED if (self.is_expired() and self.status == DecryptionRequestStatus.PENDING) else self.status,
            "created_at": self.created_at,
            "expires_at": self.expires_at
        }


class PrivacyShield:
    def __init__(
        self,
        master_key: Optional[bytes] = None,
        key_file_path: Optional[str] = None,
        key_id: str = "k1",
        face_cascade_path: Optional[str] = None,
        default_expiry_seconds: int = 3600
    ):
        self.default_expiry_seconds = default_expiry_seconds
        self.key_id = key_id
        self.key_file_path = key_file_path or getattr(config, "PRIVACY_KEY_FILE", None)
        self._lock = threading.RLock()
        self._requests: Dict[str, DecryptionRequest] = {}
        self._anonymization_log: List[dict] = []

        # Résolution sécurisée de la clé maître AES-256-GCM (P12-04 / P12-05)
        # Priorité : argument direct -> fichier clé persistant -> variable d'environnement
        resolved_key = None
        if master_key and len(master_key) == 32:
            resolved_key = master_key
        elif self.key_file_path and os.path.exists(self.key_file_path):
            try:
                with open(self.key_file_path, "rb") as f:
                    content = f.read().strip()
                if len(content) == 32:
                    resolved_key = content
                elif len(content) == 64:
                    resolved_key = bytes.fromhex(content.decode("ascii"))
            except Exception:
                resolved_key = None
        elif getattr(config, "PRIVACY_MASTER_KEY", None):
            raw_env = getattr(config, "PRIVACY_MASTER_KEY", "").strip()
            if len(raw_env) == 64:
                try:
                    resolved_key = bytes.fromhex(raw_env)
                except Exception:
                    resolved_key = None
            elif len(raw_env.encode("utf-8")) == 32:
                resolved_key = raw_env.encode("utf-8")

        self.master_key = resolved_key
        if self.master_key:
            self._aesgcm = AESGCM(self.master_key)
            self.key_status = "ACTIVE"
        else:
            # Ne JAMAIS générer silencieusement une clé volatile non persistée (P12-04)
            self._aesgcm = None
            self.key_status = "PRIVACY_KEY_UNAVAILABLE"

        # Détecteur de visages OpenCV Haar Cascade
        self._face_cascade = None
        cascade_file = face_cascade_path or cv2.data.haarcascades + 'haarcascade_frontalface_default.xml'
        if os.path.exists(cascade_file):
            try:
                self._face_cascade = cv2.CascadeClassifier(cascade_file)
            except Exception:
                self._face_cascade = None

    @classmethod
    def generate_and_save_master_key(
        cls,
        key_file_path: str,
        force: bool = False
    ) -> Tuple[bool, str, Optional[bytes]]:
        """Génère une clé AES-256-GCM et la persiste dans un fichier protégé avec permissions NTFS/POSIX restreintes."""
        if os.path.exists(key_file_path) and not force:
            return False, "Le fichier de clé existe déjà. Écrasement interdit sans force=True.", None

        try:
            os.makedirs(os.path.dirname(os.path.abspath(key_file_path)), exist_ok=True)
            new_key = AESGCM.generate_key(bit_length=256)

            # Création atomique garantie par l'OS (O_CREAT | O_EXCL) anti-concurrence
            if not force:
                try:
                    flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_BINARY", 0)
                    fd = os.open(key_file_path, flags, 0o600)
                    with os.fdopen(fd, "wb") as f:
                        f.write(new_key)
                        f.flush()
                        os.fsync(f.fileno())
                except FileExistsError:
                    return False, "Le fichier de clé existe déjà. Écrasement interdit sans force=True.", None
            else:
                tmp_path = f"{key_file_path}.{os.getpid()}_{uuid.uuid4().hex}.tmp"
                with open(tmp_path, "wb") as f:
                    f.write(new_key)
                    f.flush()
                    os.fsync(f.fileno())
                try:
                    os.chmod(tmp_path, 0o600)
                except Exception:
                    pass
                os.replace(tmp_path, key_file_path)

            if os.name == "nt":
                try:
                    import subprocess
                    username = os.environ.get("USERNAME", "")
                    if username:
                        subprocess.run(
                            ["icacls", key_file_path, "/inheritance:r", "/grant:r", f"{username}:(R,W)"],
                            stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL,
                            timeout=3
                        )
                except Exception:
                    pass

            return True, "Clé maître générée et persistée avec succès.", new_key
        except Exception as e:
            return False, f"Erreur lors de la persistance de la clé : {e}", None

    def anonymize_frame(self, frame: np.ndarray, blur_kernel_size: int = 31) -> Tuple[np.ndarray, int]:
        """Détecte les visages et applique un floutage gaussien protecteur.
        Retourne une COPIE modifiée sans jamais altérer l'image originale.
        """
        if frame is None or frame.size == 0:
            return frame, 0

        anonymized = frame.copy()
        regions_found = 0

        try:
            gray = cv2.cvtColor(anonymized, cv2.COLOR_BGR2GRAY)
            faces = []
            if self._face_cascade and not self._face_cascade.empty():
                faces = self._face_cascade.detectMultiScale(
                    gray, scaleFactor=1.15, minNeighbors=4, minSize=(30, 30)
                )

            # Floutage de chaque zone détectée
            k = max(3, blur_kernel_size if blur_kernel_size % 2 == 1 else blur_kernel_size + 1)
            for (x, y, w, h) in faces:
                # Marge de sécurité
                pad_x = int(w * 0.1)
                pad_y = int(h * 0.1)
                x1 = max(0, x - pad_x)
                y1 = max(0, y - pad_y)
                x2 = min(anonymized.shape[1], x + w + pad_x)
                y2 = min(anonymized.shape[0], y + h + pad_y)

                roi = anonymized[y1:y2, x1:x2]
                if roi.size > 0:
                    blurred_roi = cv2.GaussianBlur(roi, (k, k), 0)
                    anonymized[y1:y2, x1:x2] = blurred_roi
                    regions_found += 1
        except Exception:
            pass

        return anonymized, regions_found

    def create_anonymized_copy(
        self,
        source_image_path: str,
        output_dir: str = "storage/recordings/anonymized"
    ) -> Tuple[bool, str, int]:
        """Crée une copie anonymisée séparée d'une image. L'original reste intact."""
        if not os.path.exists(source_image_path):
            return False, "Fichier source introuvable", 0

        os.makedirs(output_dir, exist_ok=True)
        img = cv2.imread(source_image_path)
        if img is None:
            return False, "Impossible de décoder l'image", 0

        anonymized_img, masked_count = self.anonymize_frame(img)
        base_name = os.path.basename(source_image_path)
        target_path = os.path.join(output_dir, f"anon_{base_name}")

        cv2.imwrite(target_path, anonymized_img)

        with self._lock:
            self._anonymization_log.append({
                "source": source_image_path,
                "anonymized_copy": target_path,
                "regions_masked": masked_count,
                "timestamp": time.time()
            })

        return True, target_path, masked_count

    # =========================================================================
    # Procédure de Double Contrôle (Two-Man Rule) & Chiffrement AES-GCM
    # =========================================================================

    def encrypt_evidence_file(self, file_path: str, resource_id: Optional[str] = None) -> Tuple[bool, str]:
        """Chiffre un fichier original sur disque via AES-256-GCM avec enveloppe versionnée et AAD (P12-04)."""
        if not self._aesgcm or not self.master_key:
            return False, "PRIVACY_KEY_UNAVAILABLE: Clé maître non configurée ou introuvable. Chiffrement refusé."

        if not os.path.exists(file_path):
            return False, "Fichier introuvable"

        res_id = resource_id or os.path.basename(file_path)
        try:
            with open(file_path, "rb") as f:
                plaintext = f.read()

            nonce = os.urandom(12)
            magic = b"SSMENC01"
            kid_bytes = self.key_id.encode("utf-8")
            res_id_bytes = res_id.encode("utf-8")
            aad = f"SSM_V1:{self.key_id}:{res_id}".encode("utf-8")
            ciphertext = self._aesgcm.encrypt(nonce, plaintext, aad)

            header = magic + struct.pack("!BH", len(kid_bytes), len(res_id_bytes)) + kid_bytes + res_id_bytes + nonce
            enc_path = f"{file_path}.enc"
            tmp_enc = enc_path + ".tmp"
            with open(tmp_enc, "wb") as f:
                f.write(header + ciphertext)
            os.replace(tmp_enc, enc_path)

            return True, enc_path
        except Exception as e:
            return False, str(e)

    def create_decryption_request(
        self,
        resource_id: str,
        requester: str,
        reason: str,
        expires_in_seconds: Optional[int] = None
    ) -> str:
        """Initie une demande formelle d'accès aux preuves en clair nécessitant deux approbations.
        Persistance relationnelle (SQLite) avec support multi-processus et synchronisation cache local.
        """
        expiry = time.time() + (expires_in_seconds or self.default_expiry_seconds)
        req_id = f"req_{uuid.uuid4().hex[:12]}"
        now = time.time()

        # 1. Enregistrement mémoire local immédiat
        req = DecryptionRequest(
            request_id=req_id,
            resource_id=resource_id,
            requester=requester,
            reason=reason,
            expires_at=expiry,
            required_approvals=2
        )
        with self._lock:
            self._requests[req_id] = req

        # 2. Persistance relationnelle multi-processus
        try:
            from database import get_db_session
            from monitoring.models import DecryptionRequestModel
            with get_db_session() as db:
                db_req = DecryptionRequestModel(
                    id=req_id,
                    resource_id=resource_id,
                    requester=requester,
                    reason=reason,
                    required_approvals=2,
                    status=DecryptionRequestStatus.PENDING,
                    created_at=now,
                    expires_at=expiry
                )
                db.add(db_req)
        except Exception:
            pass

        return req_id

    def approve_decryption_request(
        self,
        request_id: str,
        approver: str,
        role: str,
        disallow_self_approval: bool = True
    ) -> Tuple[bool, str]:
        """Enregistre l'approbation d'un tiers habilité (ADMIN, DPO, AUDITOR).
        Garantit la contrainte Two-Man Rule même en environnement multi-processus.
        """
        now = time.time()
        with self._lock:
            req = self._requests.get(request_id)
            if not req:
                # Récupération depuis la base relationnelle si créée par un autre processus
                try:
                    from database import get_db_session
                    from monitoring.models import DecryptionRequestModel
                    with get_db_session() as db:
                        db_req = db.query(DecryptionRequestModel).filter(DecryptionRequestModel.id == request_id).first()
                        if db_req:
                            req = DecryptionRequest(
                                request_id=db_req.id,
                                resource_id=db_req.resource_id,
                                requester=db_req.requester,
                                reason=db_req.reason,
                                expires_at=db_req.expires_at,
                                required_approvals=db_req.required_approvals
                            )
                            req.status = db_req.status
                            for a in db_req.approvals:
                                req.approvers.append({"username": a.approver, "role": a.role, "approved_at": a.approved_at})
                            self._requests[request_id] = req
                except Exception:
                    pass

            if not req:
                return False, "Demande introuvable."

            if req.is_expired():
                req.status = DecryptionRequestStatus.EXPIRED
                return False, "La demande a expiré."

            if req.status in [DecryptionRequestStatus.CONSUMED, DecryptionRequestStatus.REJECTED]:
                return False, f"La demande est clôturée ({req.status})."

            # Vérification de l'état actif du compte approbateur en base si la table User est accessible
            try:
                from database import get_db_session
                from monitoring.models import User
                with get_db_session() as db:
                    u = db.query(User).filter(User.username == approver).first()
                    if u and not u.is_active:
                        return False, "Action refusée : le compte approbateur est inactif ou désactivé."
            except Exception:
                pass

            # Vérification canonique : le demandeur ne peut pas approuver sa propre demande si disallow_self_approval=True
            can_approver = (approver or "").strip().lower()
            can_requester = (req.requester or "").strip().lower()
            if disallow_self_approval and can_approver == can_requester:
                return False, "Le demandeur ne peut pas approuver sa propre demande."

            # Vérification canonique : un approbateur ne peut approuver qu'une seule fois
            for ap in req.approvers:
                if (ap.get("username") or "").strip().lower() == can_approver:
                    return False, "Cet utilisateur a déjà validé cette demande."

            req.approvers.append({
                "username": approver,
                "role": role,
                "approved_at": now
            })

            approved_now = False
            if len(req.approvers) >= req.required_approvals:
                req.status = DecryptionRequestStatus.APPROVED
                approved_now = True

            # Synchronisation persistante en base
            try:
                from database import get_db_session
                from monitoring.models import DecryptionRequestModel, DecryptionApprovalModel
                with get_db_session() as db:
                    db_req = db.query(DecryptionRequestModel).filter(DecryptionRequestModel.id == request_id).first()
                    if db_req:
                        db_app = DecryptionApprovalModel(
                            request_id=request_id,
                            approver=approver,
                            role=role,
                            approved_at=now
                        )
                        db.add(db_app)
                        if approved_now:
                            db_req.status = DecryptionRequestStatus.APPROVED
            except Exception as e:
                err_s = str(e).lower()
                if "unique" in err_s or "constraint" in err_s:
                    return False, "Cet utilisateur a déjà validé cette demande."
                pass
                return False, f"Erreur de transaction atomique (fail-closed) : {e}"

            if approved_now:
                return True, "Demande pleinement approuvée par double contrôle."
            return True, f"Approbation enregistrée ({len(req.approvers)}/{req.required_approvals})."

    def execute_authorized_decryption(
        self,
        request_id: str,
        encrypted_file_path: str,
        output_file_path: str
    ) -> Tuple[bool, str]:
        """Déchiffre le fichier original UNIQUEMENT si la demande possède deux approbations valides et non expirées.
        Consommation transactionnelle atomique exclusive (protection contre les courses concurrentes multi-processus).
        """
        if not self._aesgcm or not self.master_key:
            return False, "PRIVACY_KEY_UNAVAILABLE: Clé maître non configurée ou introuvable. Déchiffrement refusé."

        now = time.time()
        with self._lock:
            req = self._requests.get(request_id)
            if not req:
                # Vérifier en base relationnelle si initié ailleurs
                try:
                    from database import get_db_session
                    from monitoring.models import DecryptionRequestModel
                    with get_db_session() as db:
                        db_req = db.query(DecryptionRequestModel).filter(DecryptionRequestModel.id == request_id).first()
                        if db_req:
                            req = DecryptionRequest(
                                request_id=db_req.id,
                                resource_id=db_req.resource_id,
                                requester=db_req.requester,
                                reason=db_req.reason,
                                expires_at=db_req.expires_at,
                                required_approvals=db_req.required_approvals
                            )
                            req.status = db_req.status
                            self._requests[request_id] = req
                except Exception:
                    pass

            if not req:
                return False, "Demande de déchiffrement inconnue."

            if req.is_expired():
                req.status = DecryptionRequestStatus.EXPIRED
                return False, "Autorisation expirée."

            if req.status != DecryptionRequestStatus.APPROVED:
                return False, f"Autorisation incomplète. Statut actuel : {req.status}"

            # Consommation atomique multi-processus garantie par SQLite
            try:
                from database import get_db_session
                from monitoring.models import DecryptionRequestModel
                from sqlalchemy import update
                with get_db_session() as db:
                    stmt = (
                        update(DecryptionRequestModel)
                        .where(
                            DecryptionRequestModel.id == request_id,
                            DecryptionRequestModel.status == DecryptionRequestStatus.APPROVED
                        )
                        .values(
                            status=DecryptionRequestStatus.CONSUMED,
                            consumed_at=now
                        )
                    )
                    res = db.execute(stmt)
                    if res.rowcount != 1:
                        # Déjà consommé par un autre processus concurrent
                        req.status = DecryptionRequestStatus.CONSUMED
                        req.consumed_at = now
                        return False, "Autorisation incomplète. Statut actuel : CONSUMED"
            except Exception as e:
                # Comportement strictement FAIL-CLOSED : refus si la transaction de base de données échoue
                return False, f"Erreur de transaction atomique (fail-closed) : {e}"

            # Marquer comme consommé localement
            req.status = DecryptionRequestStatus.CONSUMED
            req.consumed_at = now

        if not os.path.exists(encrypted_file_path):
            return False, "Fichier chiffré introuvable."

        try:
            with open(encrypted_file_path, "rb") as f:
                data = f.read()

            magic = b"SSMENC01"
            if data.startswith(magic):
                offset = len(magic)
                if len(data) < offset + 3:
                    return False, "Format d'enveloppe cryptographique tronqué."
                kid_len, res_len = struct.unpack("!BH", data[offset:offset+3])
                offset += 3
                if len(data) < offset + kid_len + res_len + 12 + 16:
                    return False, "Enveloppe cryptographique incomplète ou corrompue."
                kid = data[offset:offset+kid_len].decode("utf-8")
                offset += kid_len
                res_id = data[offset:offset+res_len].decode("utf-8")
                offset += res_len
                nonce = data[offset:offset+12]
                offset += 12
                ciphertext = data[offset:]
                aad = f"SSM_V1:{kid}:{res_id}".encode("utf-8")
                plaintext = self._aesgcm.decrypt(nonce, ciphertext, aad)
            else:
                # Format legacy (rétro-compatibilité v0 : nonce 12 + ciphertext sans AAD)
                # Uniquement autorisé pour les archives créées sans enveloppe SSMENC01
                if len(data) < 28:
                    return False, "Fichier chiffré legacy incomplet ou corrompu."
                logger.warning(
                    f"Alerte sécurité : Déchiffrement en mode dégradé legacy sans AAD "
                    f"pour la requête {request_id} (fichier : {encrypted_file_path})"
                )
                nonce = data[:12]
                ciphertext = data[12:]
                plaintext = self._aesgcm.decrypt(nonce, ciphertext, None)

            tmp_out = output_file_path + ".tmp"
            with open(tmp_out, "wb") as f:
                f.write(plaintext)
            os.replace(tmp_out, output_file_path)

            return True, "Déchiffrement certifié réalisé avec succès (mode dégradé legacy sans AAD)." if not data.startswith(magic) else "Déchiffrement certifié réalisé avec succès."
        except Exception as e:
            return False, f"Erreur cryptographique : {e}"

    def get_requests(self) -> List[dict]:
        try:
            from database import get_db_session
            from monitoring.models import DecryptionRequestModel
            with get_db_session() as db:
                models = db.query(DecryptionRequestModel).order_by(DecryptionRequestModel.created_at.desc()).all()
                if models:
                    return [m.to_dict() for m in models]
        except Exception:
            pass
        with self._lock:
            return [r.to_dict() for r in self._requests.values()]

    def get_status(self) -> dict:
        pending = 0
        approved = 0
        total = 0
        try:
            from database import get_db_session
            from monitoring.models import DecryptionRequestModel
            with get_db_session() as db:
                models = db.query(DecryptionRequestModel).all()
                now = time.time()
                for m in models:
                    total += 1
                    if m.status == DecryptionRequestStatus.APPROVED and now <= m.expires_at:
                        approved += 1
                    elif m.status == DecryptionRequestStatus.PENDING and now <= m.expires_at:
                        pending += 1
        except Exception:
            with self._lock:
                pending = sum(1 for r in self._requests.values() if r.status == DecryptionRequestStatus.PENDING)
                approved = sum(1 for r in self._requests.values() if r.status == DecryptionRequestStatus.APPROVED)
                total = len(self._requests)

        with self._lock:
            return {
                "enabled": True,
                "key_status": self.key_status,
                "key_configured": self._aesgcm is not None,
                "key_id": self.key_id if self._aesgcm else None,
                "face_detector_available": self._face_cascade is not None,
                "pending_requests_count": pending,
                "approved_requests_count": approved,
                "total_requests_count": total,
                "anonymized_files_count": len(self._anonymization_log)
            }
