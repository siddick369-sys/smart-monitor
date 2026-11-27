"""
Tests de continuité cryptographique, format v2 et manifeste (PRO-13-A.4.4 Lot B).
"""

import os
import json
import time
import hashlib
import pytest

import config
from database import get_db_session
from monitoring.models import IntegrityLogEntry
from monitoring.integrity_manager import IntegrityManager


def test_a44_hmac_01_new_v2_entry_format_and_verification(isolated_test_db, tmp_path):
    """Vérifie qu'une nouvelle preuve utilise le format versionné v2 avec key_id et algorithm."""
    mgr = IntegrityManager(secret_key="v2_secret_key_for_test_only_1234", key_id="k_v2_test")
    proof_file = tmp_path / "proof_v2.jpg"
    proof_file.write_bytes(b"V2_JPEG_CONTENT")

    ev = mgr.register_evidence(str(proof_file), "IMAGE")
    assert ev is not None

    with get_db_session() as db:
        entry = db.query(IntegrityLogEntry).filter(IntegrityLogEntry.proof_id == ev["id"]).first()
        assert entry is not None
        assert entry.format_version == 2
        assert entry.algorithm == IntegrityManager.DEFAULT_ALGORITHM_V2
        assert entry.key_id == "k_v2_test"
        assert entry.hmac_sig is not None

        res = mgr.verify_entry_cryptography(entry)
        assert res["hash_status"] == IntegrityManager.STATUS_HASH_VALID
        assert res["hmac_status"] == IntegrityManager.STATUS_HMAC_VALID


def test_a44_hmac_02_legacy_entry_preserved_and_unverifiable(isolated_test_db):
    """Vérifie qu'une entrée héritée v1 sans HMAC est classée LEGACY_UNVERIFIABLE et non HMAC_VALID."""
    with get_db_session() as db:
        h = IntegrityManager.compute_entry_hash("p_leg", "a" * 64, IntegrityManager.GENESIS_HASH, 100.0, format_version=1)
        leg = IntegrityLogEntry(
            proof_id="p_leg", file_path="storage/x.jpg", file_hash="a" * 64,
            prev_hash=IntegrityManager.GENESIS_HASH, entry_hash=h, hmac_sig=None,
            created_at=100.0, format_version=1, algorithm=None, key_id=None
        )
        db.add(leg)
        db.flush()

        mgr = IntegrityManager(secret_key="some_key", key_id="k_v2")
        res = mgr.verify_entry_cryptography(leg)
        assert res["hash_status"] == IntegrityManager.STATUS_HASH_VALID
        assert res["hmac_status"] == IntegrityManager.STATUS_LEGACY_UNVERIFIABLE


def test_a44_hmac_03_v2_missing_hmac_and_wrong_hmac_and_unknown_key(isolated_test_db):
    """Vérifie les détections HMAC_MISSING, HMAC_INVALID et KEY_UNAVAILABLE sur v2."""
    mgr = IntegrityManager(secret_key="v2_key_alpha", key_id="k_alpha")
    with get_db_session() as db:
        h_miss = IntegrityManager.compute_entry_hash(
            "p_miss", "b" * 64, IntegrityManager.GENESIS_HASH, 200.0,
            format_version=2, algorithm=IntegrityManager.DEFAULT_ALGORITHM_V2, key_id="k_alpha"
        )
        e_miss = IntegrityLogEntry(
            proof_id="p_miss", file_path="storage/m.jpg", file_hash="b" * 64,
            prev_hash=IntegrityManager.GENESIS_HASH, entry_hash=h_miss, hmac_sig=None,
            created_at=200.0, format_version=2, algorithm=IntegrityManager.DEFAULT_ALGORITHM_V2, key_id="k_alpha"
        )
        assert mgr.verify_entry_cryptography(e_miss)["hmac_status"] == IntegrityManager.STATUS_HMAC_MISSING

        e_bad_sig = IntegrityLogEntry(
            proof_id="p_bad", file_path="storage/b.jpg", file_hash="b" * 64,
            prev_hash=IntegrityManager.GENESIS_HASH, entry_hash=h_miss, hmac_sig="0" * 64,
            created_at=200.0, format_version=2, algorithm=IntegrityManager.DEFAULT_ALGORITHM_V2, key_id="k_alpha"
        )
        assert mgr.verify_entry_cryptography(e_bad_sig)["hmac_status"] == IntegrityManager.STATUS_HMAC_INVALID

        e_unknown_key = IntegrityLogEntry(
            proof_id="p_unk", file_path="storage/u.jpg", file_hash="b" * 64,
            prev_hash=IntegrityManager.GENESIS_HASH, entry_hash=h_miss, hmac_sig="f" * 64,
            created_at=200.0, format_version=2, algorithm=IntegrityManager.DEFAULT_ALGORITHM_V2, key_id="k_unknown"
        )
        assert mgr.verify_entry_cryptography(e_unknown_key)["hmac_status"] == IntegrityManager.STATUS_KEY_UNAVAILABLE


def test_a44_hmac_04_field_and_order_tampering_detected(isolated_test_db):
    """Détecte toute altération de champ ou de sérialisation canonique (HASH_INVALID)."""
    h_orig = IntegrityManager.compute_entry_hash(
        "p_1", "c" * 64, IntegrityManager.GENESIS_HASH, 300.0,
        format_version=2, algorithm=IntegrityManager.DEFAULT_ALGORITHM_V2, key_id="k_1"
    )
    tampered = IntegrityLogEntry(
        proof_id="p_1_modified", file_path="storage/c.jpg", file_hash="c" * 64,
        prev_hash=IntegrityManager.GENESIS_HASH, entry_hash=h_orig, hmac_sig=None,
        created_at=300.0, format_version=2, algorithm=IntegrityManager.DEFAULT_ALGORITHM_V2, key_id="k_1"
    )
    mgr = IntegrityManager(secret_key="k", key_id="k_1")
    assert mgr.verify_entry_cryptography(tampered)["hash_status"] == IntegrityManager.STATUS_HASH_INVALID


def test_a44_hmac_05_continuity_manifest_creation_and_verification(tmp_path):
    """Vérifie la création en lecture seule et la vérification du manifeste sur la base historique."""
    prod_db = os.path.join(config.STORAGE_DIR, "security_monitor.db")
    before_hash = hashlib.sha256(open(prod_db, "rb").read()).hexdigest()

    mgr = IntegrityManager(secret_key=config.INTEGRITY_SECRET_KEY)
    manifest_key = "distinct_manifest_signing_key_test_only_9876"
    manifest_file = str(tmp_path / "continuity_manifest.json")

    res = mgr.create_continuity_manifest(
        db_path=prod_db,
        manifest_key=manifest_key,
        manifest_key_id="mk_2026_11",
        mission_id="SSM-PRO13-A4-4",
        output_path=manifest_file
    )
    assert res["status"] == IntegrityManager.STATUS_MANIFEST_VALID
    manifest = res["manifest"]
    payload = manifest["payload"]

    # Vérification stricte des métriques historiques préservées
    assert payload["total_entries"] >= 1031
    assert payload["sha256_valid_count"] == payload["total_entries"]
    assert payload["hmac_valid_count"] >= 478
    assert payload["hmac_invalid_count"] == 176
    assert payload["hmac_missing_count"] == 377
    assert payload["trust_anchor_type"] == "LOCAL_TRUST_ANCHOR_ONLY"

    # Vérification valide
    v_ok = IntegrityManager.verify_continuity_manifest(manifest, manifest_key)
    assert v_ok["status"] == IntegrityManager.STATUS_MANIFEST_VALID
    assert v_ok["valid"] is True

    # Altération du manifeste -> MANIFEST_INVALID
    tampered_manifest = json.loads(json.dumps(manifest))
    tampered_manifest["payload"]["hmac_missing_count"] = 0
    v_tampered = IntegrityManager.verify_continuity_manifest(tampered_manifest, manifest_key)
    assert v_tampered["status"] == IntegrityManager.STATUS_MANIFEST_INVALID
    assert v_tampered["valid"] is False

    # Mauvaise clé -> MANIFEST_INVALID
    v_wrong_key = IntegrityManager.verify_continuity_manifest(manifest, "wrong_manifest_key")
    assert v_wrong_key["status"] == IntegrityManager.STATUS_MANIFEST_INVALID

    # Clé absente -> KEY_UNAVAILABLE
    v_no_key = IntegrityManager.verify_continuity_manifest(manifest, None)
    assert v_no_key["status"] == IntegrityManager.STATUS_KEY_UNAVAILABLE

    # Refus de réutiliser la clé HMAC comme clé de manifeste
    with pytest.raises(ValueError):
        mgr.create_continuity_manifest(prod_db, config.INTEGRITY_SECRET_KEY, "mk_bad")

    # Preuve que la base historique n'a subi aucune écriture
    after_hash = hashlib.sha256(open(prod_db, "rb").read()).hexdigest()
    assert before_hash == after_hash
