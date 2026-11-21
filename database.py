import os
import sqlite3
from contextlib import contextmanager
from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker, scoped_session
from sqlalchemy.engine import Engine
import config
from monitoring.models import Base

# Configuration du moteur SQLite avec support concurrent
engine = create_engine(
    f"sqlite:///{config.DB_PATH}",
    connect_args={"check_same_thread": False, "timeout": 15},
    echo=False
)

# Activation automatique de WAL, des Foreign Keys et du busy_timeout sur chaque connexion SQLite
@event.listens_for(Engine, "connect")
def set_sqlite_pragma(dbapi_connection, connection_record):
    if isinstance(dbapi_connection, sqlite3.Connection):
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA journal_mode=WAL;")
        cursor.execute("PRAGMA foreign_keys=ON;")
        cursor.execute("PRAGMA busy_timeout=5000;")
        cursor.close()

# Session scoped thread-safe
SessionLocal = scoped_session(sessionmaker(autocommit=False, autoflush=False, bind=engine))

def init_db():
    """Initialise le schéma de base de données SQLite et applique les migrations légères."""
    os.makedirs(os.path.dirname(config.DB_PATH), exist_ok=True)
    Base.metadata.create_all(bind=engine)

    # Migration idempotente des colonnes 2FA TOTP si la table 'users' existait déjà
    try:
        raw_conn = sqlite3.connect(config.DB_PATH)
        cursor = raw_conn.cursor()
        cursor.execute("PRAGMA table_info(users);")
        existing_cols = [row[1] for row in cursor.fetchall()]

        if "totp_enabled" not in existing_cols:
            cursor.execute("ALTER TABLE users ADD COLUMN totp_enabled BOOLEAN DEFAULT 0;")
        if "totp_secret" not in existing_cols:
            cursor.execute("ALTER TABLE users ADD COLUMN totp_secret VARCHAR(128);")
        if "totp_recovery_codes" not in existing_cols:
            cursor.execute("ALTER TABLE users ADD COLUMN totp_recovery_codes TEXT;")
        if "totp_last_counter" not in existing_cols:
            cursor.execute("ALTER TABLE users ADD COLUMN totp_last_counter INTEGER;")

        # Migration idempotente de la colonne 'user_id' dans 'notifications' (SEC-123-03)
        cursor.execute("PRAGMA table_info(notifications);")
        existing_notif_cols = [row[1] for row in cursor.fetchall()]
        if "user_id" not in existing_notif_cols:
            cursor.execute("ALTER TABLE notifications ADD COLUMN user_id VARCHAR(64);")

        raw_conn.commit()
        cursor.close()
        raw_conn.close()
    except Exception:
        pass

@contextmanager
def get_db_session():
    """Fournit un gestionnaire de contexte transactionnel pour les opérations de base de données."""
    session = SessionLocal()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()

def get_db():
    """Générateur de session pour Flask ou scripts."""
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()
