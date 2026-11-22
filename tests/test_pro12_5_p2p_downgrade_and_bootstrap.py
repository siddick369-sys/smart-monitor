"""
Suite de tests de certification et de validation adversariale — PRO-12.5
Mission ID: SSM-PRO12.5-P2P-DOWNGRADE-ELIMINATION-AND-SECURITY-BOOTSTRAP-01

Couverture exhaustive :
- Lot A & B : Élimination définitive du downgrade P2P et politique de version stricte (SEC-1241-01)
- Lot C : Canonicalisation robuste, rejet NaN/Inf/profondeur, validation avant tout effet secondaire
- Lot D : Anti-replay persistant, déduplication et intégrité post-redémarrage
- Lot E : Reproduction et neutralisation du PoC PRO-12.4.1 (toutes variantes v1/null/vide/inconnue)
- Lot F : Validation fail-closed de la configuration de sécurité au démarrage Flask (SEC-1241-02)
- Intégration HTTP réelle sur /api/p2p/sync_batch
"""

import os
import time
import json
import hmac
import hashlib
import tempfile
import unittest.mock as mock
import pytest

import config
from monitoring.p2p_sync import P2PSyncManager, SyncEvent
from database import init_db, get_db_session
from monitoring.models import P2PReceivedEvent
from app import create_app


# =============================================================================
# FIXTURES ET UTILITAIRES
# =============================================================================

@pytest.fixture
def p2p_cluster_secret():
    return "a_super_secret_p2p_cluster_entropy_key_32_bytes_ok!"


@pytest.fixture
def p2p_manager(p2p_cluster_secret):
    mgr = P2PSyncManager(cluster_secret=p2p_cluster_secret, persist_events=False)
    mgr.register_device("dev_sensor_01", "token_dev_sensor_secret_9988")
    return mgr


def _rebind_test_db(db_path: str):
    """Rebinds SQLAlchemy engine to an isolated temporary database path."""
    import database
    database.SessionLocal.remove()
    database.engine.dispose()
    config.DB_PATH = db_path
    database.engine = database.create_engine(
        f"sqlite:///{db_path}",
        connect_args={"check_same_thread": False, "timeout": 15},
        echo=False
    )
    database.SessionLocal = database.scoped_session(
        database.sessionmaker(autocommit=False, autoflush=False, bind=database.engine)
    )


@pytest.fixture
def test_db_session():
    """Crée une session SQLite isolée pour tester la persistance P2P."""
    orig_db = config.DB_PATH
    with tempfile.TemporaryDirectory() as tmp_dir:
        test_db_path = os.path.join(tmp_dir, "test_p2p_persist.db")
        try:
            _rebind_test_db(test_db_path)
            init_db()
            yield test_db_path
        finally:
            _rebind_test_db(orig_db)


# =============================================================================
# LOT E.1 : MATRICE DE TESTS DE VERSION P2P (SEC-1241-01)
# =============================================================================

def test_p2p_version_matrix_e01_valid_ssmp2p02(p2p_manager, p2p_cluster_secret):
    """E01: SSMP2P02 valide avec signature couvrant le payload -> ACCEPTÉ."""
    dev_id = "dev_sensor_01"
    tok = "token_dev_sensor_secret_9988"
    now = time.time()
    payload = {"alert_level": "CRITICAL", "zone": "Zone_Nord"}
    sig = p2p_manager.compute_event_signature(
        event_id="ev_e01", device_id=dev_id, sequence_num=1,
        event_type="ALERT", timestamp=now, payload=payload, proto_version="SSMP2P02"
    )
    batch = [{
        "event_id": "ev_e01", "device_id": dev_id, "sequence_num": 1,
        "event_type": "ALERT", "timestamp": now, "payload": payload,
        "proto_version": "SSMP2P02", "signature": sig
    }]
    ok, count, ids, _ = p2p_manager.receive_sync_batch(dev_id, tok, batch, require_event_signatures=True)
    assert ok is True
    assert count == 1
    assert "ev_e01" in ids


@pytest.mark.parametrize("invalid_version,desc", [
    (None, "E02: Version absente"),
    ("null", "E03: Version chaîne 'null'"),
    ("", "E04: Version chaîne vide"),
    ("v1", "E05: Version legacy v1"),
    ("SSMP2P01", "E06: Version intermédiaire SSMP2P01"),
    ("SSMP2P00", "E06b: Version obsolète SSMP2P00"),
    ("SSMP2P99", "E07: Version inconnue"),
    (2, "E08: Version numérique entière"),
    (2.0, "E08b: Version flottante"),
    (True, "E09: Version booléenne True"),
    (False, "E09b: Version booléenne False"),
    (" SSMP2P02 ", "E10: Version avec espaces de tête/queue"),
    ("ssmp2p02", "E11: Version avec casse minuscule"),
    ("SSMP2P02\n", "E11b: Version avec saut de ligne"),
    (["SSMP2P02"], "E12: Version sous forme de tableau"),
    ({"ver": "SSMP2P02"}, "E12b: Version sous forme d'objet"),
])
def test_p2p_version_matrix_rejection(p2p_manager, invalid_version, desc):
    """E02-E12: Rejet strict et inconditionnel de toute version non rigoureusement égale à 'SSMP2P02'."""
    dev_id = "dev_sensor_01"
    tok = "token_dev_sensor_secret_9988"
    now = time.time()
    payload = {"status": "TEST"}

    batch = [{
        "event_id": f"ev_ver_{hash(str(invalid_version)) % 10000}",
        "device_id": dev_id,
        "sequence_num": 1,
        "event_type": "TEST",
        "timestamp": now,
        "payload": payload,
        "proto_version": invalid_version,
        "signature": "a" * 64
    }]
    ok, count, ids, _ = p2p_manager.receive_sync_batch(dev_id, tok, batch, require_event_signatures=True)
    assert count == 0, f"Échec de sécurité sur {desc} : l'événement a été indûment accepté."


# =============================================================================
# LOT E.2 : MATRICE DE FALSIFICATION DE MESSAGE (PAYLOAD & MÉTADONNÉES)
# =============================================================================

def test_p2p_tampering_matrix(p2p_manager):
    """E.2: Toute altération d'un champ signé doit provoquer le rejet immédiat."""
    dev_id = "dev_sensor_01"
    tok = "token_dev_sensor_secret_9988"
    now = time.time()
    original_payload = {
        "zone": "Entrée",
        "count": 3,
        "verified": True,
        "tags": ["alarm", "perimeter"],
        "metadata": {"source": "camera_01", "score": 0.88}
    }
    sig = p2p_manager.compute_event_signature(
        event_id="ev_tamp_base", device_id=dev_id, sequence_num=10,
        event_type="DETECTION", timestamp=now, payload=original_payload, proto_version="SSMP2P02"
    )

    # 1. Altération de champ imbriqué dans le payload
    tampered_nested = dict(original_payload)
    tampered_nested["metadata"] = {"source": "camera_01", "score": 0.99}  # Score altéré
    b1 = [{
        "event_id": "ev_tamp_1", "device_id": dev_id, "sequence_num": 10,
        "event_type": "DETECTION", "timestamp": now, "payload": tampered_nested,
        "proto_version": "SSMP2P02", "signature": sig
    }]
    assert p2p_manager.receive_sync_batch(dev_id, tok, b1, require_event_signatures=True)[1] == 0

    # 2. Altération d'une valeur booléenne
    tampered_bool = dict(original_payload)
    tampered_bool["verified"] = False
    b2 = [{
        "event_id": "ev_tamp_2", "device_id": dev_id, "sequence_num": 10,
        "event_type": "DETECTION", "timestamp": now, "payload": tampered_bool,
        "proto_version": "SSMP2P02", "signature": sig
    }]
    assert p2p_manager.receive_sync_batch(dev_id, tok, b2, require_event_signatures=True)[1] == 0

    # 3. Altération d'un tableau
    tampered_list = dict(original_payload)
    tampered_list["tags"] = ["alarm", "interior"]
    b3 = [{
        "event_id": "ev_tamp_3", "device_id": dev_id, "sequence_num": 10,
        "event_type": "DETECTION", "timestamp": now, "payload": tampered_list,
        "proto_version": "SSMP2P02", "signature": sig
    }]
    assert p2p_manager.receive_sync_batch(dev_id, tok, b3, require_event_signatures=True)[1] == 0

    # 4. Altération de la séquence
    b4 = [{
        "event_id": "ev_tamp_4", "device_id": dev_id, "sequence_num": 11,  # 11 au lieu de 10
        "event_type": "DETECTION", "timestamp": now, "payload": original_payload,
        "proto_version": "SSMP2P02", "signature": sig
    }]
    assert p2p_manager.receive_sync_batch(dev_id, tok, b4, require_event_signatures=True)[1] == 0

    # 5. Altération du timestamp
    b5 = [{
        "event_id": "ev_tamp_5", "device_id": dev_id, "sequence_num": 10,
        "event_type": "DETECTION", "timestamp": now + 0.5,  # Horodatage altéré
        "payload": original_payload, "proto_version": "SSMP2P02", "signature": sig
    }]
    assert p2p_manager.receive_sync_batch(dev_id, tok, b5, require_event_signatures=True)[1] == 0

    # 6. Altération du type d'événement
    b6 = [{
        "event_id": "ev_tamp_6", "device_id": dev_id, "sequence_num": 10,
        "event_type": "INTRUSION",  # INTRUSION au lieu de DETECTION
        "timestamp": now, "payload": original_payload,
        "proto_version": "SSMP2P02", "signature": sig
    }]
    assert p2p_manager.receive_sync_batch(dev_id, tok, b6, require_event_signatures=True)[1] == 0


# =============================================================================
# LOT E.3 : TESTS DE SIGNATURES MALFORMÉES ET ABSENTES
# =============================================================================

@pytest.mark.parametrize("bad_sig,desc", [
    (None, "Signature absente (None)"),
    ("", "Signature chaîne vide"),
    ("a" * 32, "Signature tronquée (32 chars)"),
    ("a" * 128, "Signature trop longue (128 chars)"),
    ("g" * 64, "Signature non hexadécimale ('g')"),
    ("ZZZZ" * 16, "Signature non hexadécimale ('Z')"),
    (12345678901234567890, "Signature de type int"),
    (["a" * 64], "Signature de type list"),
    ({"sig": "a" * 64}, "Signature de type dict"),
])
def test_p2p_malformed_signatures_rejected(p2p_manager, bad_sig, desc):
    """E.3: Rejet immédiat de toute signature malformée."""
    dev_id = "dev_sensor_01"
    tok = "token_dev_sensor_secret_9988"
    now = time.time()
    batch = [{
        "event_id": "ev_badsig", "device_id": dev_id, "sequence_num": 1,
        "event_type": "TEST", "timestamp": now, "payload": {},
        "proto_version": "SSMP2P02", "signature": bad_sig
    }]
    _, count, _, _ = p2p_manager.receive_sync_batch(dev_id, tok, batch, require_event_signatures=True)
    assert count == 0, f"Échec sur {desc} : signature malformée acceptée."


# =============================================================================
# LOT E.4 : CANONICALISATION, ROBUSTESSE JSON ET LIMITES
# =============================================================================

def test_p2p_canonicalization_keys_order_deterministic(p2p_manager):
    """E.4a: Deux dictionnaires avec des clés dans un ordre différent doivent produire la même signature."""
    dev_id = "dev_sensor_01"
    now = time.time()
    payload_a = {"z_first": 1, "a_last": 2, "m_mid": 3}
    payload_b = {"a_last": 2, "m_mid": 3, "z_first": 1}

    sig_a = p2p_manager.compute_event_signature("ev_can_1", dev_id, 1, "T", now, payload_a, "SSMP2P02")
    sig_b = p2p_manager.compute_event_signature("ev_can_1", dev_id, 1, "T", now, payload_b, "SSMP2P02")
    assert sig_a == sig_b


def test_p2p_canonicalization_rejects_nan_and_infinity(p2p_manager):
    """E.4b: Les valeurs NaN et Infinity doivent être strictement rejetées par canonicalize_payload."""
    with pytest.raises(ValueError, match="NaN et Infinity"):
        p2p_manager.canonicalize_payload({"val": float("nan")})

    with pytest.raises(ValueError, match="NaN et Infinity"):
        p2p_manager.canonicalize_payload({"val": float("inf")})

    with pytest.raises(ValueError, match="NaN et Infinity"):
        p2p_manager.canonicalize_payload({"val": float("-inf")})


def test_p2p_canonicalization_rejects_excessive_depth(p2p_manager):
    """E.4c: Les payloads dépassant la profondeur autorisée (>10) doivent être rejetés."""
    deep_payload = {"a": {"b": {"c": {"d": {"e": {"f": {"g": {"h": {"i": {"j": {"k": "trop_profond"}}}}}}}}}}}
    with pytest.raises(ValueError, match="Profondeur maximale"):
        p2p_manager.canonicalize_payload(deep_payload)


def test_p2p_rejects_colons_in_identifiers(p2p_manager):
    """E.4d: Injection de ':' dans les identifiants pour tenter une collision de représentation -> Rejet."""
    now = time.time()
    with pytest.raises(ValueError, match="séparateur interdit"):
        p2p_manager.compute_event_signature("ev:id:injected", "dev", 1, "TYPE", now, {}, "SSMP2P02")

    with pytest.raises(ValueError, match="séparateur interdit"):
        p2p_manager.compute_event_signature("ev", "dev:injected", 1, "TYPE", now, {}, "SSMP2P02")

    with pytest.raises(ValueError, match="séparateur interdit"):
        p2p_manager.compute_event_signature("ev", "dev", 1, "TYPE:injected", now, {}, "SSMP2P02")


# =============================================================================
# LOT E.5 : NEUTRALISATION DU POC ADVERSARIAL PRO-12.4.1 (DOWNGRADE ATTACK)
# =============================================================================

def test_poc_pro12_4_1_downgrade_attack_neutralized(p2p_manager, p2p_cluster_secret):
    """E.5: Reproduction exacte de l'attaque PoC PRO-12.4.1 :
    Un attaquant forge un paquet v1 sans proto_version avec un payload altéré.
    Le système DOIT STRICTEMENT REJETER ce paquet sans aucun effet secondaire.
    """
    dev_id = "dev_sensor_01"
    tok = "token_dev_sensor_secret_9988"
    now = time.time()
    ev_id = "poc_attack_ev_001"

    # Signature calculée selon la formule legacy v1 historique (sans payload)
    msg_v1 = f"{ev_id}:{dev_id}:1:ALARM_STATE:{now}"
    sig_v1 = hmac.new(p2p_cluster_secret.encode("utf-8"), msg_v1.encode("utf-8"), hashlib.sha256).hexdigest()

    # Payload malveillant injecté par l'attaquant
    hostile_payload = {
        "status": "DISARMED",
        "sensor_id": 999,
        "security_override": True,
        "message": "Faux désarmement par injection v1"
    }

    # Scénario A : Omission totale de proto_version
    attack_batch_a = [{
        "event_id": ev_id,
        "device_id": dev_id,
        "sequence_num": 1,
        "event_type": "ALARM_STATE",
        "timestamp": now,
        "payload": hostile_payload,
        "signature": sig_v1
        # proto_version absent !
    }]
    ok_a, count_a, ids_a, _ = p2p_manager.receive_sync_batch(dev_id, tok, attack_batch_a, require_event_signatures=True)
    assert count_a == 0, "VULNÉRABILITÉ CONFIRMÉE : le paquet sans proto_version a été accepté !"
    assert ev_id not in ids_a
    assert ev_id not in p2p_manager._received_event_ids

    # Scénario B : proto_version explicite fixé à 'v1'
    attack_batch_b = [{
        "event_id": ev_id + "_b",
        "device_id": dev_id,
        "sequence_num": 1,
        "event_type": "ALARM_STATE",
        "timestamp": now,
        "payload": hostile_payload,
        "proto_version": "v1",  # Tentative explicite de downgrade v1
        "signature": sig_v1
    }]
    ok_b, count_b, ids_b, _ = p2p_manager.receive_sync_batch(dev_id, tok, attack_batch_b, require_event_signatures=True)
    assert count_b == 0, "VULNÉRABILITÉ CONFIRMÉE : le paquet avec proto_version='v1' a été accepté !"
    assert (ev_id + "_b") not in ids_b


# =============================================================================
# LOT D : ANTI-REPLAY ET PERSISTANCE POST-REDÉMARRAGE
# =============================================================================

def test_p2p_persistent_anti_replay_across_restart(test_db_session, p2p_cluster_secret):
    """Lot D: Vérifie que les événements déjà intégrés ne peuvent pas être rejoués après redémarrage."""
    dev_id = "dev_sensor_01"
    tok = "token_dev_sensor_secret_9988"
    now = time.time()
    payload = {"state": "NORMAL"}
    ev_id = "ev_persist_restart_01"

    # Instance 1
    p2p_1 = P2PSyncManager(cluster_secret=p2p_cluster_secret, persist_events=True)
    p2p_1.register_device(dev_id, tok)

    sig = p2p_1.compute_event_signature(ev_id, dev_id, 1, "STATUS", now, payload, "SSMP2P02")
    batch = [{
        "event_id": ev_id, "device_id": dev_id, "sequence_num": 1,
        "event_type": "STATUS", "timestamp": now, "payload": payload,
        "proto_version": "SSMP2P02", "signature": sig
    }]

    # Première intégration -> SUCCÈS
    ok1, count1, ids1, _ = p2p_1.receive_sync_batch(dev_id, tok, batch, require_event_signatures=True)
    assert ok1 is True
    assert count1 == 1

    # Instance 2 (simulation de redémarrage complet sans état mémoire)
    p2p_2 = P2PSyncManager(cluster_secret=p2p_cluster_secret, persist_events=True)
    p2p_2.register_device(dev_id, tok)
    assert ev_id not in p2p_2._received_event_ids  # Mémoire vide

    # Rejeu du même lot -> REJET ANTI-REPLAY VIA LA BASE
    ok2, count2, ids2, _ = p2p_2.receive_sync_batch(dev_id, tok, batch, require_event_signatures=True)
    assert ok2 is True
    assert count2 == 0, "Le rejeu après redémarrage aurait dû être détecté et rejeté !"


# =============================================================================
# LOT F : VALIDATION DE CONFIGURATION AU DÉMARRAGE FLASK (SEC-1241-02)
# =============================================================================

def test_config_f01_prod_missing_secret_key_refuses_startup():
    """F01: En production, SECRET_KEY absente ou vide -> Refus immédiat de create_app()."""
    with mock.patch("config.IS_PRODUCTION", True), \
         mock.patch("config.SECRET_KEY", ""), \
         mock.patch.dict(os.environ, {"APP_ENV": "production", "SECRET_KEY": ""}):
        with pytest.raises(ValueError, match="SECRET_KEY absente, vide ou par défaut"):
            create_app()


def test_config_f03_prod_default_secret_key_refuses_startup():
    """F03: En production, SECRET_KEY par défaut de dev -> Refus immédiat de create_app()."""
    with mock.patch("config.IS_PRODUCTION", True), \
         mock.patch("config.SECRET_KEY", "smart-security-monitor-secret-dev-2026"), \
         mock.patch.dict(os.environ, {"APP_ENV": "production", "SECRET_KEY": "smart-security-monitor-secret-dev-2026"}):
        with pytest.raises(ValueError, match="SECRET_KEY absente, vide ou par défaut"):
            create_app()


def test_config_f04_prod_short_secret_key_refuses_startup():
    """F04: En production, SECRET_KEY < 32 caractères -> Refus immédiat de create_app()."""
    with mock.patch("config.IS_PRODUCTION", True), \
         mock.patch("config.SECRET_KEY", "court_seulement_20_caract"), \
         mock.patch.dict(os.environ, {"APP_ENV": "production", "SECRET_KEY": "court_seulement_20_caract"}):
        with pytest.raises(ValueError, match="SECRET_KEY trop courte"):
            create_app()


def test_config_f05_prod_insecure_cookies_refuses_startup():
    """F05: En production, SESSION_COOKIE_SECURE=False -> Refus immédiat de create_app()."""
    valid_key = "a" * 32
    with mock.patch("config.IS_PRODUCTION", True), \
         mock.patch("config.SECRET_KEY", valid_key), \
         mock.patch("config.SESSION_COOKIE_SECURE", False), \
         mock.patch.dict(os.environ, {"APP_ENV": "production", "SECRET_KEY": valid_key}):
        with pytest.raises(ValueError, match="SESSION_COOKIE_SECURE requis"):
            create_app()


def test_config_f09_prod_debug_true_refuses_startup():
    """F09: En production, DEBUG=True -> Refus immédiat de create_app()."""
    valid_key = "a" * 32
    with mock.patch("config.IS_PRODUCTION", True), \
         mock.patch("config.SECRET_KEY", valid_key), \
         mock.patch("config.SESSION_COOKIE_SECURE", True), \
         mock.patch("config.SESSION_COOKIE_HTTPONLY", True), \
         mock.patch("config.DEBUG", True), \
         mock.patch.dict(os.environ, {"APP_ENV": "production", "SECRET_KEY": valid_key}):
        with pytest.raises(ValueError, match="DEBUG=True est strictement interdit"):
            create_app()


def test_config_f10_prod_loopback_allowed_refuses_startup():
    """F10: En production, ALLOW_LOOPBACK_SIMULATOR=True -> Refus immédiat de create_app()."""
    valid_key = "a" * 32
    with mock.patch("config.IS_PRODUCTION", True), \
         mock.patch("config.SECRET_KEY", valid_key), \
         mock.patch("config.SESSION_COOKIE_SECURE", True), \
         mock.patch("config.SESSION_COOKIE_HTTPONLY", True), \
         mock.patch("config.DEBUG", False), \
         mock.patch("config.ALLOW_LOOPBACK_SIMULATOR", True), \
         mock.patch.dict(os.environ, {"APP_ENV": "production", "SECRET_KEY": valid_key}):
        with pytest.raises(ValueError, match="ALLOW_LOOPBACK_SIMULATOR=True est strictement interdit"):
            create_app()


def test_config_f11_prod_malformed_boolean_env_refuses_startup():
    """F11: En production, variable booléenne environnementale malformée -> Refus immédiat."""
    valid_key = "a" * 32
    with mock.patch("config.IS_PRODUCTION", True), \
         mock.patch("config.SECRET_KEY", valid_key), \
         mock.patch("config.SESSION_COOKIE_SECURE", True), \
         mock.patch("config.SESSION_COOKIE_HTTPONLY", True), \
         mock.patch("config.DEBUG", False), \
         mock.patch("config.ALLOW_LOOPBACK_SIMULATOR", False), \
         mock.patch("config.EVIDENCE_HMAC_KEY", "b" * 32), \
         mock.patch.dict(os.environ, {"APP_ENV": "production", "SECRET_KEY": valid_key, "SESSION_COOKIE_SECURE": "not_a_boolean"}):
        with pytest.raises(ValueError, match="Valeur booléenne invalide"):
            create_app()


def test_config_f06_prod_valid_config_starts_successfully():
    """F06: En production, configuration valide -> create_app() s'initialise avec succès."""
    valid_key = "x" * 48
    with mock.patch("config.IS_PRODUCTION", True), \
         mock.patch("config.SECRET_KEY", valid_key), \
         mock.patch("config.SESSION_COOKIE_SECURE", True), \
         mock.patch("config.SESSION_COOKIE_HTTPONLY", True), \
         mock.patch("config.DEBUG", False), \
         mock.patch("config.ALLOW_LOOPBACK_SIMULATOR", False), \
         mock.patch("config.EVIDENCE_HMAC_KEY", "b" * 32), \
         mock.patch.dict(os.environ, {"APP_ENV": "production", "SECRET_KEY": valid_key}):
        app, coord = create_app()
        assert app is not None
        assert app.config["SECRET_KEY"] == valid_key


def test_config_f07_dev_mode_starts_without_production_restrictions():
    """F07: En mode développement, create_app() démarre normalement."""
    with mock.patch("config.IS_PRODUCTION", False), \
         mock.patch.dict(os.environ, {"APP_ENV": "development"}):
        app, coord = create_app()
        assert app is not None


# =============================================================================
# LOT G : INTÉGRATION HTTP RÉELLE SUR /api/p2p/sync_batch
# =============================================================================

def test_http_p2p_sync_batch_route_rejects_v1_and_accepts_v2(p2p_cluster_secret):
    """Lot G: Vérification end-to-end via le client de test Flask de la route /api/p2p/sync_batch."""
    from monitoring.system_coordinator import SystemCoordinator
    coord = SystemCoordinator()
    coord.p2p_sync_mgr = P2PSyncManager(cluster_secret=p2p_cluster_secret, persist_events=False)
    dev_id = "http_dev_01"
    tok = "tok_http_secret_9988"
    coord.p2p_sync_mgr.register_device(dev_id, tok)

    app, _ = create_app(coordinator=coord)
    app.config["TESTING"] = True

    client = app.test_client()
    headers = {
        "X-Device-ID": dev_id,
        "X-Device-Token": tok,
        "Content-Type": "application/json"
    }
    now = time.time()

    # 1. Requête avec un paquet v1 sans proto_version -> synched_count doit être 0
    msg_v1 = f"ev_http_v1:{dev_id}:1:ALERT:{now}"
    sig_v1 = hmac.new(p2p_cluster_secret.encode("utf-8"), msg_v1.encode("utf-8"), hashlib.sha256).hexdigest()
    res_v1 = client.post("/api/p2p/sync_batch", headers=headers, json={
        "events": [{
            "event_id": "ev_http_v1", "sequence_num": 1, "event_type": "ALERT",
            "timestamp": now, "payload": {"data": "hostile"}, "signature": sig_v1
        }]
    })
    assert res_v1.status_code == 200
    data_v1 = res_v1.get_json()
    assert data_v1["synced_count"] == 0, "Le paquet v1 via HTTP aurait dû être rejeté !"

    # 2. Requête avec un paquet SSMP2P02 valide -> synched_count doit valoir 1
    sig_v2 = coord.p2p_sync_mgr.compute_event_signature(
        "ev_http_v2", dev_id, 2, "ALERT", now, {"data": "legit"}, "SSMP2P02"
    )
    res_v2 = client.post("/api/p2p/sync_batch", headers=headers, json={
        "events": [{
            "event_id": "ev_http_v2", "device_id": dev_id, "sequence_num": 2,
            "event_type": "ALERT", "timestamp": now, "payload": {"data": "legit"},
            "proto_version": "SSMP2P02", "signature": sig_v2
        }]
    })
    assert res_v2.status_code == 200
    data_v2 = res_v2.get_json()
    assert data_v2["synced_count"] == 1
    assert "ev_http_v2" in data_v2["accepted_ids"]
