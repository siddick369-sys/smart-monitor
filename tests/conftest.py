"""
Configuration globale Pytest — Isolation stricte SQLite (PRO-13-A.4.4 Lot A).
Garantit qu'aucun test automatisé ne lit ou n'écrit dans storage/security_monitor.db.
"""

import os
import shutil
import tempfile
import pytest

# Dossier temporaire de session créé avant tout import applicatif
_SESSION_TEST_DB_DIR = tempfile.mkdtemp(prefix="ssm_pytest_isolated_")
_SESSION_TEST_DB_PATH = os.path.join(_SESSION_TEST_DB_DIR, "test_security_monitor.db")
os.environ["SSM_DB_PATH"] = _SESSION_TEST_DB_PATH

import config
import database


def assert_not_production_db(candidate_path: str) -> None:
    """Garde anti-production : échoue immédiatement si le chemin cible la base historique."""
    if database.is_protected_production_db_path(candidate_path):
        raise RuntimeError(
            f"BLOCKED_PRODUCTION_DB_WRITE: Le chemin '{candidate_path}' pointe vers la base "
            "historique protégée storage/security_monitor.db, ce qui est strictement interdit en test."
        )


def pytest_configure(config):
    """Vérifie dès le démarrage de pytest que la base active n'est pas la base historique."""
    import time
    import uuid
    from werkzeug.security import generate_password_hash
    import config as app_config
    from monitoring.models import User

    assert_not_production_db(app_config.DB_PATH)
    assert_not_production_db(str(database.engine.url.database or ""))
    database.init_db()

    # Pré-alimenter un compte admin de test dans la base isolée temporaire
    # (nécessaire pour les tests historiques qui supposent un admin déjà amorcé)
    with database.get_db_session() as db:
        if db.query(User).filter(User.role == "ADMIN").count() == 0:
            admin_pwd = app_config.ADMIN_DEFAULT_PASSWORD or "AdminSecurity2026!"
            db.add(User(
                id=f"user_test_admin_{uuid.uuid4().hex[:6]}",
                username=app_config.ADMIN_DEFAULT_USERNAME,
                password_hash=generate_password_hash(admin_pwd),
                role="ADMIN",
                is_active=True,
                created_at=time.time()
            ))


def pytest_unconfigure(config):
    """Libère les connexions SQLite et nettoie le répertoire temporaire de session."""
    try:
        database.SessionLocal.remove()
        database.engine.dispose()
    except Exception:
        pass
    shutil.rmtree(_SESSION_TEST_DB_DIR, ignore_errors=True)


@pytest.fixture
def isolated_test_db(tmp_path):
    """Fournit une base SQLite temporaire isolée par test et restaure la base de session ensuite."""
    prev_path = config.DB_PATH
    db_file = str(tmp_path / "isolated_test.db")
    assert_not_production_db(db_file)
    database.rebind_database(db_file, initialize=True)
    try:
        yield db_file
    finally:
        assert_not_production_db(prev_path)
        database.rebind_database(prev_path, initialize=False)
