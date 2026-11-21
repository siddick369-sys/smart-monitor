import os
import time
import uuid
import pytest
import config
from monitoring.integrity_manager import IntegrityManager
from database import init_db, get_db_session
from monitoring.models import Evidence, IntegrityLogEntry
from app import create_app

def test_evidence_registration_and_verification(tmp_path):
    """Vérifie le calcul d'empreinte SHA-256, le chaînage et la détection d'intégrité."""
    init_db()
    mgr = IntegrityManager(secret_key="test-secret-hmac-key")

    # 1. Créer un fichier de test
    test_file = os.path.join(tmp_path, "sample_proof.jpg")
    with open(test_file, "wb") as f:
        f.write(b"ORIGINAL_JPEG_BINARY_DATA_123456789")

    # 2. Enregistrer la preuve
    proof = mgr.register_evidence(test_file, "IMAGE", alert_id="alert_test_001")
    assert proof is not None
    assert "id" in proof
    assert len(proof["sha256_hash"]) == 64
    proof_id = proof["id"]

    # 3. Vérification immédiate du fichier intact -> INTEGRITY_VALID / INTÈGRE
    res_intact = mgr.verify_evidence(proof_id)
    assert res_intact["status"] == IntegrityManager.STATUS_INTEGRITY_VALID
    assert res_intact["status_fr"] == "INTÈGRE"
    assert res_intact["file_exists"] is True
    assert res_intact["hash_match"] is True
    assert res_intact["chain_valid"] is True
    assert res_intact["hmac_valid"] is True

    # 4. Altération du fichier physique -> TAMPERED / ALTÉRÉ
    with open(test_file, "wb") as f:
        f.write(b"CORRUPTED_OR_TAMPERED_DATA_XXXXX")

    res_tampered = mgr.verify_evidence(proof_id)
    assert res_tampered["status"] == IntegrityManager.STATUS_TAMPERED
    assert res_tampered["status_fr"] == "ALTÉRÉ"
    assert res_tampered["hash_match"] is False

    # 5. Suppression du fichier physique -> MISSING / MANQUANT
    os.remove(test_file)
    res_missing = mgr.verify_evidence(proof_id)
    assert res_missing["status"] == IntegrityManager.STATUS_MISSING
    assert res_missing["status_fr"] == "MANQUANT"
    assert res_missing["file_exists"] is False

def test_chained_integrity_log():
    """Vérifie que chaque entrée intègre l'empreinte de la précédente (chaînage cryptographique)."""
    init_db()
    mgr = IntegrityManager(secret_key="chain-test-key")

    # Créer deux fichiers temporaires pour tester le chaînage en direct
    uid = uuid.uuid4().hex[:6]
    f1 = os.path.join(config.STORAGE_DIR, f"chain_test_1_{uid}.tmp")
    f2 = os.path.join(config.STORAGE_DIR, f"chain_test_2_{uid}.tmp")
    with open(f1, "wb") as f:
        f.write(b"CHAIN_BLOCK_1")
    with open(f2, "wb") as f:
        f.write(b"CHAIN_BLOCK_2")

    try:
        e1 = mgr.register_evidence(f1, "TMP")
        e2 = mgr.register_evidence(f2, "TMP")
        assert e1 is not None and e2 is not None

        with get_db_session() as db:
            log1 = db.query(IntegrityLogEntry).filter(IntegrityLogEntry.proof_id == e1["id"]).first()
            log2 = db.query(IntegrityLogEntry).filter(IntegrityLogEntry.proof_id == e2["id"]).first()
            assert log2.prev_hash == log1.entry_hash

            entries = db.query(IntegrityLogEntry).order_by(IntegrityLogEntry.id.asc()).all()
            if len(entries) >= 2:
                for i in range(1, len(entries)):
                    assert entries[i].prev_hash == entries[i-1].entry_hash
        
        # Test vérification globale de chaîne
        chain_res = mgr.verify_chain_integrity()
        assert chain_res["valid_chain"] is True
        assert chain_res["status"] == IntegrityManager.STATUS_INTEGRITY_VALID
    finally:
        if os.path.exists(f1):
            os.remove(f1)
        if os.path.exists(f2):
            os.remove(f2)

def test_missing_secret_key_and_tampered_hmac(tmp_path):
    """Vérifie le comportement en cas d'absence de clé secrète et de signature altérée."""
    init_db()
    # Gestionnaire sans clé secrète configurée
    mgr_no_key = IntegrityManager(secret_key=None)

    test_file = os.path.join(tmp_path, "no_key_proof.jpg")
    with open(test_file, "wb") as f:
        f.write(b"IMAGE_CONTENT_WITHOUT_HMAC_KEY")

    proof = mgr_no_key.register_evidence(test_file, "IMAGE", alert_id="alert_nokey")
    assert proof is not None
    res = mgr_no_key.verify_evidence(proof["id"])
    assert res["status"] == IntegrityManager.STATUS_INTEGRITY_VALID
    # hmac_valid doit être None en l'absence de clé secrète
    assert res["hmac_valid"] is None

def test_api_integrity_endpoints():
    """Vérifie les routes API de vérification d'intégrité."""
    app, coordinator = create_app()
    app.config["TESTING"] = True

    # Simuler un incident avec preuve
    with app.test_client() as client:
        sim_res = client.post('/api/simulate_alert', json={"type": "TEST_INTEGRITY"})
        alert_id = sim_res.get_json()["incident"]["id"]

        # Interroger l'intégrité de l'alerte
        res = client.get(f'/api/alerts/{alert_id}/integrity')
        assert res.status_code == 200
        data = res.get_json()
        assert data["status"] == "ok"
        assert "evidences" in data
