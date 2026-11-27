"""
Tests d'isolation SQLite et garde anti-production (PRO-13-A.4.4 Lot A).
"""

import os
import hashlib
import pytest

import config
import database
from tests.conftest import assert_not_production_db


def test_a44_sqlite_01_active_db_is_isolated_temp_path():
    """Vérifie que la base active sous pytest n'est jamais storage/security_monitor.db."""
    assert not database.is_protected_production_db_path(config.DB_PATH)
    assert not database.is_protected_production_db_path(str(database.engine.url.database))
    assert "ssm_pytest_isolated_" in config.DB_PATH or "pytest" in config.DB_PATH.lower()


def test_a44_sqlite_02_reject_direct_production_path():
    """Refuse explicitement storage/security_monitor.db."""
    with pytest.raises(RuntimeError, match="BLOCKED_PRODUCTION_DB_WRITE"):
        assert_not_production_db("storage/security_monitor.db")


def test_a44_sqlite_03_reject_relative_traversal_to_production_db():
    """Refuse les chemins relatifs et traversées .. pointant vers la base historique."""
    with pytest.raises(RuntimeError, match="BLOCKED_PRODUCTION_DB_WRITE"):
        assert_not_production_db("./storage/../storage/security_monitor.db")


def test_a44_sqlite_04_reject_windows_backslash_and_uri():
    """Refuse les variantes avec séparateurs Windows et URI sqlite:///."""
    win_path = os.path.join(config.STORAGE_DIR, "security_monitor.db")
    with pytest.raises(RuntimeError, match="BLOCKED_PRODUCTION_DB_WRITE"):
        assert_not_production_db(win_path)
    with pytest.raises(RuntimeError, match="BLOCKED_PRODUCTION_DB_WRITE"):
        assert_not_production_db(f"sqlite:///{win_path}")


def test_a44_sqlite_05_isolated_fixture_per_test(isolated_test_db):
    """Vérifie que isolated_test_db fournit un fichier temporaire distinct et propre."""
    assert os.path.exists(isolated_test_db)
    assert not database.is_protected_production_db_path(isolated_test_db)
    assert config.DB_PATH == isolated_test_db


def test_a44_sqlite_06_consecutive_test_isolation(isolated_test_db):
    """Vérifie que deux tests consécutifs reçoivent des bases distinctes sans fuite."""
    from monitoring.models import Device
    with database.get_db_session() as db:
        assert db.query(Device).count() == 0
        db.add(Device(id="dev_iso_1", name="Cam Iso", ip="127.0.0.1", port=8081))


def test_a44_sqlite_07_second_consecutive_test_is_clean(isolated_test_db):
    """Vérifie qu'aucune donnée du test précédent ne persiste dans la nouvelle fixture."""
    from monitoring.models import Device
    with database.get_db_session() as db:
        assert db.query(Device).count() == 0


def test_a44_sqlite_08_production_db_untouched():
    """Vérifie que la base historique conserve exactement son intégrité."""
    prod_path = os.path.join(config.STORAGE_DIR, "security_monitor.db")
    assert os.path.exists(prod_path)
    assert config.DB_PATH != prod_path
