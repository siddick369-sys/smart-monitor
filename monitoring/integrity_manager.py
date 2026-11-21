import os
import time
import hashlib
import hmac
import uuid
import threading
from typing import Dict, Any, Optional, Tuple, List
import config
from database import get_db_session
from monitoring.models import Evidence, IntegrityLogEntry, Alert

class IntegrityManager:
    """Gestionnaire d'intégrité cryptographique des preuves avec chaînage SHA-256 et HMAC."""

    GENESIS_HASH = "0000000000000000000000000000000000000000000000000000000000000000"
    _lock = threading.Lock()

    # Statuts explicites normalisés
    STATUS_INTEGRITY_VALID = "INTEGRITY_VALID"
    STATUS_TAMPERED = "TAMPERED"
    STATUS_MISSING = "MISSING"
    STATUS_UNVERIFIABLE = "UNVERIFIABLE"

    def __init__(self, secret_key: Optional[str] = config.INTEGRITY_SECRET_KEY):
        self.secret_key = secret_key

    def calculate_file_sha256(self, filepath: str) -> Optional[str]:
        """Calcule l'empreinte SHA-256 d'un fichier par blocs de 64 Ko."""
        if not os.path.exists(filepath) or not os.path.isfile(filepath):
            return None
        sha256 = hashlib.sha256()
        try:
            with open(filepath, "rb") as f:
                while chunk := f.read(65536):
                    sha256.update(chunk)
            return sha256.hexdigest()
        except Exception as e:
            print(f"[IntegrityManager] Erreur calcul SHA-256 pour {filepath} : {e}")
            return None

    def _generate_hmac(self, message: str) -> Optional[str]:
        """Calcule la signature HMAC-SHA256 si la clé secrète est configurée."""
        if not self.secret_key:
            return None
        try:
            return hmac.new(self.secret_key.encode("utf-8"), message.encode("utf-8"), hashlib.sha256).hexdigest()
        except Exception:
            return None

    def register_evidence(self, filepath: str, file_type: str, alert_id: Optional[str] = None) -> Optional[dict]:
        """Enregistre une preuve avec son empreinte SHA-256 et son insertion dans le journal chaîné."""
        full_path = os.path.normpath(os.path.abspath(filepath))
        if not os.path.exists(full_path):
            return None

        file_hash = self.calculate_file_sha256(full_path)
        if not file_hash:
            return None

        file_size = os.path.getsize(full_path)
        filename = os.path.basename(full_path)
        now = time.time()
        proof_id = f"ev_{uuid.uuid4().hex[:12]}"
        
        # Chemin relatif propre par rapport à BASE_DIR
        rel_path = os.path.relpath(full_path, config.BASE_DIR).replace("\\", "/")

        try:
            with self._lock:
                with get_db_session() as db:
                    # 0. Vérifier la validité de la clé étrangère alert_id
                    target_alert_id = alert_id
                    if target_alert_id:
                        if not db.query(Alert).filter(Alert.id == target_alert_id).first():
                            target_alert_id = None

                    # 1. Récupérer le hash de la dernière entrée pour le chaînage
                    last_entry = db.query(IntegrityLogEntry).order_by(IntegrityLogEntry.id.desc()).first()
                    prev_hash = last_entry.entry_hash if last_entry else self.GENESIS_HASH

                    # 2. Calcul du hash de l'entrée chaînée : SHA256(proof_id + file_hash + prev_hash + timestamp)
                    entry_data = f"{proof_id}|{file_hash}|{prev_hash}|{now}"
                    entry_hash = hashlib.sha256(entry_data.encode("utf-8")).hexdigest()
                    hmac_sig = self._generate_hmac(entry_hash)

                    # 3. Enregistrer ou mettre à jour l'Evidence (gestion idempotente du filepath unique)
                    existing_ev = db.query(Evidence).filter(Evidence.filepath == rel_path).first()
                    if existing_ev:
                        existing_ev.file_size = file_size
                        existing_ev.sha256_hash = file_hash
                        existing_ev.hmac_signature = hmac_sig
                        existing_ev.created_at = now
                        evidence = existing_ev
                    else:
                        evidence = Evidence(
                            id=proof_id,
                            alert_id=target_alert_id,
                            filename=filename,
                            filepath=rel_path,
                            file_type=file_type.upper(),
                            file_size=file_size,
                            sha256_hash=file_hash,
                            hmac_signature=hmac_sig,
                            created_at=now
                        )
                        db.add(evidence)

                    # 4. Enregistrer dans le journal chaîné
                    log_entry = IntegrityLogEntry(
                        proof_id=proof_id,
                        alert_id=target_alert_id,
                        file_path=rel_path,
                        file_hash=file_hash,
                        prev_hash=prev_hash,
                        entry_hash=entry_hash,
                        hmac_sig=hmac_sig,
                        created_at=now
                    )
                    db.add(log_entry)
                    db.flush()

                    return evidence.to_dict()
        except Exception as e:
            print(f"[IntegrityManager] Erreur enregistrement preuve {filename} : {e}")
            return None

    def verify_evidence(self, proof_id: str) -> Dict[str, Any]:
        """Vérifie l'intégrité complète d'une preuve : présence, taille, SHA-256, chaîne et HMAC."""
        result = {
            "proof_id": proof_id,
            "status": self.STATUS_UNVERIFIABLE,
            "status_fr": "NON VÉRIFIABLE",
            "file_exists": False,
            "size_match": False,
            "hash_match": False,
            "chain_valid": False,
            "hmac_valid": None,
            "expected_hash": None,
            "current_hash": None,
            "verified_at": time.time(),
            "details": ""
        }

        try:
            with get_db_session() as db:
                evidence = db.query(Evidence).filter(Evidence.id == proof_id).first()
                if not evidence:
                    result["details"] = "Preuve introuvable dans le registre d'intégrité."
                    return result

                result["expected_hash"] = evidence.sha256_hash
                full_path = os.path.normpath(os.path.join(config.BASE_DIR, evidence.filepath))

                # 1. Vérification de présence physique
                if not os.path.exists(full_path):
                    result["status"] = self.STATUS_MISSING
                    result["status_fr"] = "MANQUANT"
                    result["details"] = "Fichier physique de preuve introuvable sur le disque."
                    return result
                result["file_exists"] = True

                # 2. Vérification de taille
                current_size = os.path.getsize(full_path)
                result["size_match"] = (current_size == evidence.file_size)

                # 3. Vérification de l'empreinte SHA-256
                current_hash = self.calculate_file_sha256(full_path)
                result["current_hash"] = current_hash
                result["hash_match"] = (current_hash == evidence.sha256_hash)

                if not result["hash_match"]:
                    result["status"] = self.STATUS_TAMPERED
                    result["status_fr"] = "ALTÉRÉ"
                    result["details"] = "L'empreinte du fichier sur disque ne correspond pas à l'empreinte originale certifiée."
                    return result

                # 4. Vérification de la chaîne d'intégrité
                entry = db.query(IntegrityLogEntry).filter(IntegrityLogEntry.proof_id == proof_id).first()
                if entry:
                    recomputed_data = f"{entry.proof_id}|{entry.file_hash}|{entry.prev_hash}|{entry.created_at}"
                    expected_entry_hash = hashlib.sha256(recomputed_data.encode("utf-8")).hexdigest()
                    result["chain_valid"] = (expected_entry_hash == entry.entry_hash)

                    # 5. Vérification HMAC à temps constant avec hmac.compare_digest
                    if self.secret_key and entry.hmac_sig:
                        expected_hmac = self._generate_hmac(entry.entry_hash)
                        if expected_hmac:
                            result["hmac_valid"] = hmac.compare_digest(expected_hmac, entry.hmac_sig)
                        else:
                            result["hmac_valid"] = False
                    elif entry.hmac_sig and not self.secret_key:
                        result["hmac_valid"] = None  # Non vérifiable sans la clé secrète

                # Statut final
                if result["file_exists"] and result["hash_match"] and result["chain_valid"]:
                    if self.secret_key and result["hmac_valid"] is False:
                        result["status"] = self.STATUS_TAMPERED
                        result["status_fr"] = "ALTÉRÉ"
                        result["details"] = "Signature HMAC invalide : suspicion de corruption du journal."
                    else:
                        result["status"] = self.STATUS_INTEGRITY_VALID
                        result["status_fr"] = "INTÈGRE"
                        result["details"] = "Preuve numérique certifiée conforme, intègre et inaltérée."
                else:
                    result["status"] = self.STATUS_TAMPERED
                    result["status_fr"] = "ALTÉRÉ"

        except Exception as e:
            result["status"] = self.STATUS_UNVERIFIABLE
            result["details"] = f"Erreur lors de la vérification : {e}"

        return result

    def verify_alert_evidences(self, alert_id: str) -> List[Dict[str, Any]]:
        """Vérifie toutes les preuves associées à un identifiant d'alerte donné."""
        results = []
        try:
            with get_db_session() as db:
                evidences = db.query(Evidence).filter(Evidence.alert_id == alert_id).all()
                for ev in evidences:
                    results.append(self.verify_evidence(ev.id))
        except Exception as e:
            print(f"[IntegrityManager] Erreur vérification preuves alerte {alert_id} : {e}")
        return results

    def verify_chain_integrity(self, check_hmac: bool = False) -> Dict[str, Any]:
        """Vérifie l'intégrité globale de l'ensemble de la chaîne du journal de preuves."""
        try:
            with get_db_session() as db:
                entries = db.query(IntegrityLogEntry).order_by(IntegrityLogEntry.id.asc()).all()
                if not entries:
                    return {
                        "status": "EMPTY",
                        "total_entries": 0,
                        "valid_chain": True,
                        "details": "Aucune entrée dans le journal chaîné."
                    }

                prev_hash = self.GENESIS_HASH
                for idx, entry in enumerate(entries):
                    # 1. Vérifier le chaînage
                    if entry.prev_hash != prev_hash:
                        return {
                            "status": self.STATUS_TAMPERED,
                            "total_entries": len(entries),
                            "broken_at_entry_id": entry.id,
                            "valid_chain": False,
                            "details": f"Rupture de chaîne détectée à l'entrée #{entry.id}."
                        }

                    # 2. Vérifier le calcul du hash de l'entrée
                    recomputed_data = f"{entry.proof_id}|{entry.file_hash}|{entry.prev_hash}|{entry.created_at}"
                    expected_hash = hashlib.sha256(recomputed_data.encode("utf-8")).hexdigest()
                    if expected_hash != entry.entry_hash:
                        return {
                            "status": self.STATUS_TAMPERED,
                            "total_entries": len(entries),
                            "broken_at_entry_id": entry.id,
                            "valid_chain": False,
                            "details": f"Empreinte de journal invalide à l'entrée #{entry.id}."
                        }

                    # 3. Vérifier HMAC uniquement si explicitement demandé et clé configurée
                    if check_hmac and self.secret_key and entry.hmac_sig:
                        expected_hmac = self._generate_hmac(entry.entry_hash)
                        if not expected_hmac or not hmac.compare_digest(expected_hmac, entry.hmac_sig):
                            return {
                                "status": self.STATUS_TAMPERED,
                                "total_entries": len(entries),
                                "broken_at_entry_id": entry.id,
                                "valid_chain": False,
                                "details": f"Signature HMAC altérée à l'entrée #{entry.id}."
                            }

                    prev_hash = entry.entry_hash

                return {
                    "status": self.STATUS_INTEGRITY_VALID,
                    "total_entries": len(entries),
                    "valid_chain": True,
                    "last_hash": prev_hash,
                    "details": f"Chaîne de {len(entries)} entrées vérifiée avec succès."
                }
        except Exception as e:
            return {
                "status": self.STATUS_UNVERIFIABLE,
                "total_entries": 0,
                "valid_chain": False,
                "details": f"Erreur vérification chaîne : {e}"
            }
