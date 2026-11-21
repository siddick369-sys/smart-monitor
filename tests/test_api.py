import pytest
import json
from app import create_app

@pytest.fixture
def client():
    app, coordinator = create_app()
    app.config["TESTING"] = True
    with app.test_client() as client:
        yield client
    # Nettoyage
    coordinator.stop()

def test_index_route(client):
    """Vérifie l'affichage de la page d'accueil."""
    res = client.get('/')
    assert res.status_code == 200
    assert b"SMART SECURITY MONITOR" in res.data

def test_api_status(client):
    """Vérifie la route d'état du système."""
    res = client.get('/api/status')
    assert res.status_code == 200
    data = res.get_json()
    assert "is_armed" in data
    assert "in_alarm" in data
    assert "siren_active" in data
    assert "devices" in data

def test_device_crud_and_ip_validation(client):
    """Vérifie l'ajout, la validation d'IP locale/sécurisée et la suppression de smartphone."""
    # 1. IP publique rejetée (anti-SSRF / sécurité réseau)
    bad_res = client.post('/api/devices', json={
        "name": "Attacker IP",
        "ip": "8.8.8.8",
        "port": 8080
    })
    assert bad_res.status_code == 400
    assert "Adresse IP non autorisée" in bad_res.get_json()["message"]

    # 2. IP locale valide acceptée
    good_res = client.post('/api/devices', json={
        "name": "Test Salon",
        "ip": "192.168.1.55",
        "port": 8080,
        "enable_torch": True
    })
    assert good_res.status_code == 201
    dev = good_res.get_json()["device"]
    dev_id = dev["id"]
    assert dev["name"] == "Test Salon"
    assert dev["ip"] == "192.168.1.55"

    # 3. Lister les appareils
    list_res = client.get('/api/devices')
    devices = list_res.get_json()
    assert any(d["id"] == dev_id for d in devices)

    # 4. Supprimer l'appareil
    del_res = client.delete(f'/api/devices/{dev_id}')
    assert del_res.status_code == 200
    assert del_res.get_json()["status"] == "ok"

def test_alarm_arming_and_siren_controls(client):
    """Vérifie l'armement, le désarmement et l'arrêt de la sirène."""
    # Armer
    res = client.post('/api/alarm/arm')
    assert res.status_code == 200
    assert res.get_json()["is_armed"] is True

    # Désarmer
    res = client.post('/api/alarm/disarm')
    assert res.status_code == 200
    assert res.get_json()["is_armed"] is False

    # Arrêt sirène
    res = client.post('/api/alarm/stop_siren')
    assert res.status_code == 200
    assert res.get_json()["siren_active"] is False

def test_alert_simulation_and_history(client):
    """Vérifie le déclenchement d'un incident simulé et son archivage."""
    # Déclencher une simulation
    sim_res = client.post('/api/simulate_alert', json={
        "type": "ACOUSTIQUE",
        "label": "Test Bris de vitre"
    })
    assert sim_res.status_code == 200
    inc = sim_res.get_json()["incident"]
    assert inc["category"] == "ÉVÉNEMENT SIMULÉ"
    assert inc["type"] == "ACOUSTIQUE"

    # Consulter l'historique
    alerts_res = client.get('/api/alerts')
    alerts = alerts_res.get_json()
    assert len(alerts) > 0
    assert alerts[0]["type"] == "ACOUSTIQUE"

    # Vider l'historique
    clear_res = client.post('/api/alerts/clear')
    assert clear_res.status_code == 200
    assert len(client.get('/api/alerts').get_json()) == 0
