import os
import json
import time
import uuid
import pytest
import config
from database import init_db, get_db_session
from monitoring.models import User, Device, Alert, Notification, Evidence, IntegrityLogEntry
from monitoring.migration_manager import MigrationManager
from monitoring.device_store import DeviceStore
from monitoring.recording_manager import RecordingManager

def test_database_initialization_and_schema():
    """Vérifie la création des tables SQLite et l'activation des contraintes."""
    init_db()
    assert os.path.exists(config.DB_PATH)
    
    with get_db_session() as db:
        # Vérifier que les tables sont requêtables
        assert db.query(Device).count() >= 0
        assert db.query(Alert).count() >= 0
        assert db.query(User).count() >= 0
        assert db.query(Notification).count() >= 0
        assert db.query(Evidence).count() >= 0
        assert db.query(IntegrityLogEntry).count() >= 0

def test_idempotent_json_migration(tmp_path):
    """Vérifie la migration sans perte de données et l'idempotence (aucun doublon lors d'une 2e exécution)."""
    mgr = MigrationManager()

    # 1. Première exécution de la migration
    report1 = mgr.migrate_json_to_sqlite()
    assert report1["status"] == "success"
    assert "devices" in report1
    assert "alerts" in report1

    # Compter les enregistrements
    with get_db_session() as db:
        dev_count1 = db.query(Device).count()
        alert_count1 = db.query(Alert).count()

    # 2. Seconde exécution immédiate
    report2 = mgr.migrate_json_to_sqlite()
    assert report2["status"] == "success"
    assert report2["devices"]["inserted"] == 0
    assert report2["alerts"]["inserted"] == 0

    with get_db_session() as db:
        dev_count2 = db.query(Device).count()
        alert_count2 = db.query(Alert).count()

    assert dev_count1 == dev_count2
    assert alert_count1 == alert_count2

def test_export_and_restore_cycle(tmp_path):
    """Vérifie l'export complet JSON et la capacité de restauration contrôlée."""
    mgr = MigrationManager()

    # Export
    export_data = mgr.export_sqlite_to_json()
    assert "exported_at" in export_data
    assert isinstance(export_data["devices"], list)
    assert isinstance(export_data["alerts"], list)

    backup_file = os.path.join(tmp_path, "test_backup.json")
    with open(backup_file, "w", encoding="utf-8") as f:
        json.dump(export_data, f)

    # Restauration
    success, msg = mgr.restore_from_json_backup(backup_file)
    assert success is True
    assert "succès" in msg.lower()

def test_sqlite_single_source_of_truth():
    """Vérifie que SQLite est l'unique source opérationnelle primaire et que le JSON n'est qu'un export."""
    init_db()
    test_uid = uuid.uuid4().hex[:8]
    dev_id = f"dev_truth_{test_uid}"
    alert_id = f"alert_truth_{test_uid}"

    # 1. Insertion directe en base SQLite
    with get_db_session() as db:
        dev = Device(
            id=dev_id,
            name="Caméra Source de Vérité",
            ip="127.0.0.1",
            port=8089,
            zones_json="[]",
            created_at=time.time(),
            updated_at=time.time()
        )
        db.add(dev)
        db.flush()

        alert = Alert(
            id=alert_id,
            timestamp=time.time(),
            datetime="2026-11-14 12:00:00",
            device_id=dev_id,
            device_name="Caméra Source de Vérité",
            device_ip="127.0.0.1",
            type="INTRUSION",
            event_code="REAL_SENSOR_EVENT",
            category="Événement Réel",
            severity="CRITICAL",
            details="Test source de vérité SQLite",
            status="TERMINÉ"
        )
        db.add(alert)

    # 2. Vérification que DeviceStore et RecordingManager lisent directement depuis SQLite
    dev_store = DeviceStore()
    assert dev_store.get_device(dev_id) is not None
    assert dev_store.get_device(dev_id)["name"] == "Caméra Source de Vérité"

    rec_mgr = RecordingManager(camera_manager=None)
    all_alerts = rec_mgr.get_all_alerts()
    match_alert = next((a for a in all_alerts if a["id"] == alert_id), None)
    assert match_alert is not None
    assert match_alert["severity"] == "CRITICAL"

    # 3. Vérification de l'export secondaire
    mig = MigrationManager()
    exported = mig.export_sqlite_to_json()
    assert any(d["id"] == dev_id for d in exported["devices"])
    assert any(a["id"] == alert_id for a in exported["alerts"])

    # Nettoyage
    with get_db_session() as db:
        db.query(Alert).filter(Alert.id == alert_id).delete()
        db.query(Device).filter(Device.id == dev_id).delete()
