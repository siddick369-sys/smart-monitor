"""
Bancs de Tests pour PRO-09 : Forensique, Confidentialité et Intégrité
Valide les fonctionnalités :
- Moteur de rapports forensiques ReportLab (ForensicReportEngine)
- Floutage et protection de la vie privée (PrivacyShield)
- Procédure de déchiffrement à double contrôle (Two-Man Rule)
- Manifeste d'intégrité, tatouage numérique et horodatage (EvidenceIntegrityManager)
"""

import os
import time
import tempfile
import numpy as np
import cv2
import pytest
from monitoring.forensic_engine import ForensicReportEngine
from monitoring.privacy_shield import PrivacyShield, DecryptionRequestStatus
from monitoring.evidence_integrity import EvidenceIntegrityManager


def test_forensic_report_generation_pdf():
    with tempfile.TemporaryDirectory() as tmp_dir:
        engine = ForensicReportEngine(output_dir=tmp_dir)

        incident = {
            "id": "inc_test_999",
            "datetime": "2026-11-19 10:15:00",
            "device_name": "Salon Principal",
            "type": "MOUVEMENT_OPENCV",
            "severity": "CRITIQUE",
            "status": "CONFIRMÉ",
            "facts": {
                "motion_pct": 14.2,
                "sound_db": 82.5,
                "accel_norm": 15.3
            },
            "vlm_description": "Une silhouette humaine vêtue d'un manteau sombre a été détectée devant la fenêtre."
        }

        proofs = [
            {"path": "proof_1.jpg", "sha256": "abcdef1234567890abcdef1234567890", "status": "CERTIFIÉ INTÈGRE"}
        ]

        ai_info = {"classes_detected": "person (0.91), backpack (0.78)", "confidence": 0.91}
        audio_info = {"predicted_class": "GLASS_BREAK", "confidence": 0.85}

        pdf_path = engine.generate_incident_report(
            incident_data=incident,
            proof_files=proofs,
            ai_inference=ai_info,
            audio_event=audio_info
        )

        assert os.path.exists(pdf_path)
        assert os.path.getsize(pdf_path) > 1000  # Fichier PDF valide et non-vide


def test_privacy_shield_anonymization_and_encryption():
    with tempfile.TemporaryDirectory() as tmp_dir:
        shield = PrivacyShield()

        # Création d'une image test avec un visage synthétique (cercle clair sur fond sombre)
        img = np.zeros((200, 200, 3), dtype=np.uint8)
        cv2.circle(img, (100, 100), 40, (200, 200, 200), -1)

        source_path = os.path.join(tmp_dir, "face_original.jpg")
        cv2.imwrite(source_path, img)

        # 1. Copie anonymisée séparée
        ok, anon_path, masked = shield.create_anonymized_copy(source_path, output_dir=tmp_dir)
        assert ok
        assert os.path.exists(anon_path)
        assert os.path.exists(source_path)  # L'original n'a PAS été écrasé

        # 2. Chiffrement AES-GCM de l'original
        enc_ok, enc_path = shield.encrypt_evidence_file(source_path)
        assert enc_ok
        assert os.path.exists(enc_path)


def test_privacy_shield_dual_control_workflow():
    with tempfile.TemporaryDirectory() as tmp_dir:
        shield = PrivacyShield()

        # Création d'un fichier secret
        secret_file = os.path.join(tmp_dir, "secret_evidence.txt")
        with open(secret_file, "w") as f:
            f.write("CONFIDENTIAL EVIDENCE DATA")

        _, enc_path = shield.encrypt_evidence_file(secret_file)

        # 1. Création de la demande
        req_id = shield.create_decryption_request(
            resource_id="ev_001",
            requester="operator1",
            reason="Réquisition légale / enquête",
            expires_in_seconds=300
        )

        # 2. Première tentative de déchiffrement sans approbations -> REFUSÉ
        out_file = os.path.join(tmp_dir, "decrypted.txt")
        ok1, msg1 = shield.execute_authorized_decryption(req_id, enc_path, out_file)
        assert not ok1
        assert "Autorisation incomplète" in msg1

        # 3. Première approbation par ADMIN
        app1_ok, _ = shield.approve_decryption_request(req_id, approver="admin", role="ADMIN")
        assert app1_ok

        # Même approbateur ne peut pas valider une 2ème fois
        app_dup_ok, _ = shield.approve_decryption_request(req_id, approver="admin", role="ADMIN")
        assert not app_dup_ok

        # 4. Seconde approbation par DPO -> APPROUVÉ
        app2_ok, _ = shield.approve_decryption_request(req_id, approver="dpo_officer", role="DPO")
        assert app2_ok

        # 5. Déchiffrement autorisé
        dec_ok, dec_msg = shield.execute_authorized_decryption(req_id, enc_path, out_file)
        assert dec_ok
        assert os.path.exists(out_file)
        with open(out_file, "r") as f:
            assert f.read() == "CONFIDENTIAL EVIDENCE DATA"

        # 6. Protection contre la réutilisation -> REFUSÉ (CONSUMED)
        reuse_ok, reuse_msg = shield.execute_authorized_decryption(req_id, enc_path, out_file)
        assert not reuse_ok
        assert "CONSUMED" in reuse_msg


def test_evidence_integrity_manifest_and_watermarking():
    with tempfile.TemporaryDirectory() as tmp_dir:
        integrity_mgr = EvidenceIntegrityManager(secret_key="test_secret_key_123")

        # Fichier image test
        img_path = os.path.join(tmp_dir, "test_capture.jpg")
        img = np.full((150, 200, 3), 128, dtype=np.uint8)
        cv2.imwrite(img_path, img)

        # Génération du manifeste & watermarking
        manifest = integrity_mgr.generate_manifest(
            proof_id="proof_test_001",
            file_path=img_path,
            watermark=True,
            output_dir=tmp_dir
        )

        assert manifest.sha256_hash is not None
        assert len(manifest.sha256_hash) == 64
        assert manifest.watermarked_path is not None
        assert os.path.exists(manifest.watermarked_path)

        # Vérification d'intégrité initiale -> VALIDE
        is_valid, msg = integrity_mgr.verify_manifest(manifest)
        assert is_valid
        assert msg == "INTÈGRE_ET_CONFORME"

        # Altération volontaire d'un octet dans le fichier
        with open(img_path, "r+b") as f:
            f.seek(10)
            f.write(b"\xFF\x00")

        # Vérification après altération -> DÉTECTÉE
        tampered_valid, tampered_msg = integrity_mgr.verify_manifest(manifest)
        assert not tampered_valid
        assert "ALTÉRATION_DÉTECTÉE" in tampered_msg
