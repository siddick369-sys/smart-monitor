import os
import time
import json
import hashlib
import hmac
import uuid
import sqlite3
import threading
from typing import Dict, Any, Optional, Tuple, List
import config
from database import get_db_session
from monitoring.models import Evidence, IntegrityLogEntry, Alert

class IntegrityManager:
    """Gestionnaire d'intégrité cryptographique des preuves avec chaînage SHA-256 et HMAC (v1/v2)."""

    GENESIS_HASH = "0000000000000000000000000000000000000000000000000000000000000000"
    _lock = threading.Lock()

    # Statuts explicites normalisés (rétrocompatibilité)
    STATUS_INTEGRITY_VALID = "INTEGRITY_VALID"
    STATUS_TAMPERED = "TAMPERED"
    STATUS_MISSING = "MISSING"
    STATUS_UNVERIFIABLE = "UNVERIFIABLE"

    # Statuts cryptographiques granulaires (PRO-13 A.4.4 Lot B)
    STATUS_HASH_VALID = "HASH_VALID"
    STATUS_HASH_INVALID = "HASH_INVALID"
    STATUS_HMAC_VALID = "HMAC_VALID"
    STATUS_HMAC_INVALID = "HMAC_INVALID"
    STATUS_HMAC_MISSING = "HMAC_MISSING"
    STATUS_LEGACY_UNVERIFIABLE = "LEGACY_UNVERIFIABLE"
    STATUS_MANIFEST_VALID = "MANIFEST_VALID"
    STATUS_MANIFEST_INVALID = "MANIFEST_INVALID"
    STATUS_KEY_UNAVAILABLE = "KEY_UNAVAILABLE"

    DEFAULT_ALGORITHM_V2 = "SHA256+HMAC-SHA256"

    def __init__(self, secret_key: Optional[str] = config.INTEGRITY_SECRET_KEY, key_id: Optional[str] = None):
        self.secret_key = secret_key
        self.key_id = key_id if key_id is not None else ("k_active_v2" if secret_key else None)

    @staticmethod
    def compute_entry_hash(
        proof_id: str,
        file_hash: str,
        prev_hash: str,
        created_at: float,
        format_version: int = 1,
        algorithm: Optional[str] = None,
        key_id: Optional[str] = None
    ) -> str:
        """Calcule l'empreinte canonique d'une entrée selon sa version de format (v1 ou v2)."""
        if int(format_version or 1) >= 2:
            algo = algorithm or IntegrityManager.DEFAULT_ALGORITHM_V2
            kid = key_id or ""
            entry_data = f"v2|{proof_id}|{file_hash}|{prev_hash}|{created_at}|{algo}|{kid}"
        else:
            entry_data = f"{proof_id}|{file_hash}|{prev_hash}|{created_at}"
        return hashlib.sha256(entry_data.encode("utf-8")).hexdigest()

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

                    # 2. Calcul du hash de l'entrée chaînée (format versionné v2)
                    fmt_ver = 2
                    algo = self.DEFAULT_ALGORITHM_V2
                    kid = self.key_id if self.secret_key else None
                    entry_hash = self.compute_entry_hash(
                        proof_id=proof_id,
                        file_hash=file_hash,
                        prev_hash=prev_hash,
                        created_at=now,
                        format_version=fmt_ver,
                        algorithm=algo,
                        key_id=kid
                    )
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

                    # 4. Enregistrer dans le journal chaîné (v2)
                    log_entry = IntegrityLogEntry(
                        proof_id=proof_id,
                        alert_id=target_alert_id,
                        file_path=rel_path,
                        file_hash=file_hash,
                        prev_hash=prev_hash,
                        entry_hash=entry_hash,
                        hmac_sig=hmac_sig,
                        created_at=now,
                        format_version=fmt_ver,
                        algorithm=algo,
                        key_id=kid
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

                # 4. Vérification de la chaîne d'intégrité (v1 ou v2)
                entry = db.query(IntegrityLogEntry).filter(IntegrityLogEntry.proof_id == proof_id).first()
                if entry:
                    expected_entry_hash = self.compute_entry_hash(
                        proof_id=entry.proof_id,
                        file_hash=entry.file_hash,
                        prev_hash=entry.prev_hash,
                        created_at=entry.created_at,
                        format_version=getattr(entry, "format_version", 1),
                        algorithm=getattr(entry, "algorithm", None),
                        key_id=getattr(entry, "key_id", None)
                    )
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

    def verify_entry_cryptography(
        self,
        entry: IntegrityLogEntry,
        key_ring: Optional[Dict[str, str]] = None
    ) -> Dict[str, Any]:
        """Vérifie séparément le hash canonique et la signature HMAC d'une entrée (v1/v2)."""
        fmt_ver = int(getattr(entry, "format_version", 1) or 1)
        algo = getattr(entry, "algorithm", None)
        kid = getattr(entry, "key_id", None)

        expected_hash = self.compute_entry_hash(
            proof_id=entry.proof_id,
            file_hash=entry.file_hash,
            prev_hash=entry.prev_hash,
            created_at=entry.created_at,
            format_version=fmt_ver,
            algorithm=algo,
            key_id=kid
        )
        hash_status = self.STATUS_HASH_VALID if expected_hash == entry.entry_hash else self.STATUS_HASH_INVALID

        # Politique stricte HMAC selon version et disponibilité de clé
        if not entry.hmac_sig:
            hmac_status = self.STATUS_LEGACY_UNVERIFIABLE if fmt_ver < 2 else self.STATUS_HMAC_MISSING
            return {"hash_status": hash_status, "hmac_status": hmac_status, "format_version": fmt_ver, "key_id": kid}

        # Résolution de la clé de vérification
        verify_key = None
        if key_ring is not None:
            if kid and kid in key_ring:
                verify_key = key_ring[kid]
            elif fmt_ver < 2 and "__legacy__" in key_ring:
                verify_key = key_ring["__legacy__"]
            else:
                return {"hash_status": hash_status, "hmac_status": self.STATUS_KEY_UNAVAILABLE, "format_version": fmt_ver, "key_id": kid}
        else:
            if fmt_ver >= 2 and kid and self.key_id and kid != self.key_id:
                return {"hash_status": hash_status, "hmac_status": self.STATUS_KEY_UNAVAILABLE, "format_version": fmt_ver, "key_id": kid}
            verify_key = self.secret_key

        if not verify_key:
            return {"hash_status": hash_status, "hmac_status": self.STATUS_KEY_UNAVAILABLE, "format_version": fmt_ver, "key_id": kid}

        expected_hmac = hmac.new(verify_key.encode("utf-8"), entry.entry_hash.encode("utf-8"), hashlib.sha256).hexdigest()
        hmac_status = self.STATUS_HMAC_VALID if hmac.compare_digest(expected_hmac, entry.hmac_sig) else self.STATUS_HMAC_INVALID
        return {"hash_status": hash_status, "hmac_status": hmac_status, "format_version": fmt_ver, "key_id": kid}

    def verify_chain_integrity(self, check_hmac: bool = False, key_ring: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
        """Vérifie l'intégrité globale de l'ensemble de la chaîne du journal de preuves."""
        try:
            with get_db_session() as db:
                entries = db.query(IntegrityLogEntry).order_by(IntegrityLogEntry.id.asc()).all()
                if not entries:
                    return {
                        "status": "EMPTY",
                        "hash_status": self.STATUS_HASH_VALID,
                        "hmac_status": self.STATUS_HMAC_VALID if check_hmac else None,
                        "total_entries": 0,
                        "valid_chain": True,
                        "details": "Aucune entrée dans le journal chaîné."
                    }

                prev_hash = self.GENESIS_HASH
                for entry in entries:
                    # 1. Vérifier le chaînage
                    if entry.prev_hash != prev_hash:
                        return {
                            "status": self.STATUS_TAMPERED,
                            "hash_status": self.STATUS_HASH_INVALID,
                            "total_entries": len(entries),
                            "broken_at_entry_id": entry.id,
                            "valid_chain": False,
                            "details": f"Rupture de chaîne détectée à l'entrée #{entry.id}."
                        }

                    # 2. Vérifier le calcul du hash de l'entrée (v1 ou v2)
                    crypto_res = self.verify_entry_cryptography(entry, key_ring=key_ring)
                    if crypto_res["hash_status"] != self.STATUS_HASH_VALID:
                        return {
                            "status": self.STATUS_TAMPERED,
                            "hash_status": self.STATUS_HASH_INVALID,
                            "total_entries": len(entries),
                            "broken_at_entry_id": entry.id,
                            "valid_chain": False,
                            "details": f"Empreinte de journal invalide à l'entrée #{entry.id}."
                        }

                    # 3. Vérifier HMAC uniquement si explicitement demandé
                    if check_hmac:
                        hstat = crypto_res["hmac_status"]
                        if hstat != self.STATUS_HMAC_VALID:
                            return {
                                "status": self.STATUS_TAMPERED if hstat == self.STATUS_HMAC_INVALID else hstat,
                                "hash_status": self.STATUS_HASH_VALID,
                                "hmac_status": hstat,
                                "total_entries": len(entries),
                                "broken_at_entry_id": entry.id,
                                "valid_chain": False,
                                "details": f"Contrôle HMAC non valide à l'entrée #{entry.id} ({hstat})."
                            }

                    prev_hash = entry.entry_hash

                return {
                    "status": self.STATUS_INTEGRITY_VALID,
                    "hash_status": self.STATUS_HASH_VALID,
                    "hmac_status": self.STATUS_HMAC_VALID if check_hmac else None,
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

    def create_continuity_manifest(
        self,
        db_path: str,
        manifest_key: Optional[str],
        manifest_key_id: str,
        mission_id: str = "SSM-PRO13-A4-4",
        db_identifier: str = "security_monitor.db",
        output_path: Optional[str] = None
    ) -> Dict[str, Any]:
        """Génère un manifeste de continuité signé en lecture seule sans modifier la base historique."""
        if not manifest_key:
            return {"status": self.STATUS_KEY_UNAVAILABLE, "details": "Clé de signature du manifeste absente."}
        if self.secret_key and hmac.compare_digest(str(manifest_key), str(self.secret_key)):
            raise ValueError("La clé du manifeste doit être strictement distincte de la clé HMAC historique.")
        if not os.path.exists(db_path):
            return {"status": self.STATUS_MISSING, "details": "Base SQLite cible introuvable."}

        db_sha256 = self.calculate_file_sha256(db_path)

        # Lecture strictement en mode read-only URI
        abs_db = os.path.abspath(db_path).replace("\\", "/")
        conn = sqlite3.connect(f"file:{abs_db}?mode=ro", uri=True)
        try:
            cur = conn.cursor()
            cur.execute("PRAGMA table_info(integrity_log);")
            cols = [r[1] for r in cur.fetchall()]
            has_v2 = all(c in cols for c in ("format_version", "algorithm", "key_id"))
            if has_v2:
                cur.execute(
                    "SELECT id, proof_id, file_hash, prev_hash, entry_hash, hmac_sig, created_at, format_version, algorithm, key_id "
                    "FROM integrity_log ORDER BY id ASC"
                )
            else:
                cur.execute(
                    "SELECT id, proof_id, file_hash, prev_hash, entry_hash, hmac_sig, created_at "
                    "FROM integrity_log ORDER BY id ASC"
                )
            rows = cur.fetchall()
        finally:
            conn.close()

        seq_hasher = hashlib.sha256()
        hmac_valid_count = 0
        hmac_invalid_count = 0
        hmac_missing_count = 0
        sha256_valid_count = 0
        algorithms_seen = set()

        prev_hash = self.GENESIS_HASH
        for row in rows:
            if has_v2:
                eid, pid, fhash, phash, ehash, hsig, cat, fmt_ver, algo, kid = row
            else:
                eid, pid, fhash, phash, ehash, hsig, cat = row
                fmt_ver, algo, kid = 1, None, None

            algorithms_seen.add(algo or "SHA256-v1")
            expected_h = self.compute_entry_hash(pid, fhash, phash, cat, fmt_ver or 1, algo, kid)
            if phash == prev_hash and expected_h == ehash:
                sha256_valid_count += 1
            prev_hash = ehash
            seq_hasher.update(f"{eid}:{ehash}:{hsig or ''}|".encode("utf-8"))

            if not hsig:
                hmac_missing_count += 1
            elif self.secret_key:
                exp_hmac = hmac.new(self.secret_key.encode("utf-8"), ehash.encode("utf-8"), hashlib.sha256).hexdigest()
                if hmac.compare_digest(exp_hmac, hsig):
                    hmac_valid_count += 1
                else:
                    hmac_invalid_count += 1
            else:
                hmac_invalid_count += 1

        payload = {
            "manifest_format_version": 1,
            "mission_id": mission_id,
            "created_at": time.time(),
            "db_identifier": db_identifier,
            "db_sha256": db_sha256,
            "total_entries": len(rows),
            "sha256_valid_count": sha256_valid_count,
            "first_entry_id": rows[0][0] if rows else None,
            "last_entry_id": rows[-1][0] if rows else None,
            "first_entry_hash": rows[0][4] if rows else None,
            "last_entry_hash": rows[-1][4] if rows else None,
            "canonical_sequence_sha256": seq_hasher.hexdigest(),
            "hmac_missing_count": hmac_missing_count,
            "hmac_valid_count": hmac_valid_count,
            "hmac_invalid_count": hmac_invalid_count,
            "algorithms": sorted(algorithms_seen),
            "signature_algorithm": "HMAC-SHA256",
            "manifest_key_id": manifest_key_id,
            "trust_anchor_type": "LOCAL_TRUST_ANCHOR_ONLY"
        }
        canonical_json = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        signature = hmac.new(manifest_key.encode("utf-8"), canonical_json.encode("utf-8"), hashlib.sha256).hexdigest()
        manifest = {"payload": payload, "signature": signature}

        if output_path:
            os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
            with open(output_path, "w", encoding="utf-8") as f:
                json.dump(manifest, f, indent=2)

        return {"status": self.STATUS_MANIFEST_VALID, "manifest": manifest}

    @staticmethod
    def verify_continuity_manifest(manifest: Dict[str, Any], manifest_key: Optional[str]) -> Dict[str, Any]:
        """Vérifie indépendamment la signature d'un manifeste de continuité sans modifier la base."""
        if not manifest_key:
            return {"status": IntegrityManager.STATUS_KEY_UNAVAILABLE, "valid": False, "details": "Clé de vérification absente."}
        if not isinstance(manifest, dict) or "payload" not in manifest or "signature" not in manifest:
            return {"status": IntegrityManager.STATUS_MANIFEST_INVALID, "valid": False, "details": "Structure de manifeste invalide."}
        try:
            canonical_json = json.dumps(manifest["payload"], sort_keys=True, separators=(",", ":"))
            expected_sig = hmac.new(
                manifest_key.encode("utf-8"),
                canonical_json.encode("utf-8"),
                hashlib.sha256
            ).hexdigest()
            if hmac.compare_digest(expected_sig, str(manifest["signature"])):
                return {
                    "status": IntegrityManager.STATUS_MANIFEST_VALID,
                    "valid": True,
                    "manifest_key_id": manifest["payload"].get("manifest_key_id"),
                    "trust_anchor_type": manifest["payload"].get("trust_anchor_type")
                }
            return {"status": IntegrityManager.STATUS_MANIFEST_INVALID, "valid": False, "details": "Signature du manifeste invalide."}
        except Exception as e:
            return {"status": IntegrityManager.STATUS_MANIFEST_INVALID, "valid": False, "details": f"Erreur vérification manifeste : {e}"}
