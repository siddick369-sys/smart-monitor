import pytest
from monitoring.sensor_manager import SensorParser, SensorPoller

def test_parse_complete_valid_payload():
    """Vérifie le parsing complet d'un payload type IP Webcam."""
    payload = {
        "proximity": {
            "unit": "cm",
            "data": [[1700000000000, [3.5]]]
        },
        "sound": {
            "unit": "dB",
            "data": [[1700000000000, [68.4]]]
        },
        "accel": {
            "unit": "m/s2",
            "data": [[1700000000000, [0.1, -0.2, 9.8]]]
        },
        "light": {
            "unit": "lx",
            "data": [[1700000000000, [350.0]]]
        },
        "battery_level": {
            "unit": "%",
            "data": [[1700000000000, [88.0]]]
        }
    }

    parsed = SensorParser.parse_payload(payload)

    # Proximité
    assert parsed["proximity"]["available"] is True
    assert parsed["proximity"]["value"] == 3.5
    assert parsed["proximity"]["unit"] == "cm"
    assert parsed["proximity"]["is_simulated"] is False

    # Son
    assert parsed["sound"]["available"] is True
    assert parsed["sound"]["value"] == 68.4
    assert parsed["sound"]["unit"] == "dB"

    # Accéléromètre
    assert parsed["accel"]["available"] is True
    assert parsed["accel"]["value"] == {"x": 0.1, "y": -0.2, "z": 9.8}
    assert parsed["accel"]["norm"] is not None
    assert 9.7 < parsed["accel"]["norm"] < 9.9

    # Batterie
    assert parsed["battery"]["available"] is True
    assert parsed["battery"]["value"] == 88.0


def test_parse_missing_and_empty_sensors():
    """Exigence non négociable : capteurs absents clairement identifiés sans inventer de mesure."""
    empty_payload = {}
    parsed = SensorParser.parse_payload(empty_payload)

    for sensor_key in ["proximity", "sound", "accel", "light", "battery"]:
        assert parsed[sensor_key]["available"] is False
        assert parsed[sensor_key]["status"] == "CAPTEUR NON DISPONIBLE"
        assert parsed[sensor_key]["value"] is None

    # Payload corrompu avec data vide
    corrupt_payload = {
        "proximity": {"unit": "cm", "data": []},
        "sound": {"unit": "dB", "data": None},
        "accel": "invalid_string"
    }
    parsed_corrupt = SensorParser.parse_payload(corrupt_payload)
    assert parsed_corrupt["proximity"]["available"] is False
    assert parsed_corrupt["sound"]["available"] is False
    assert parsed_corrupt["accel"]["available"] is False


def test_alternative_sensor_keys():
    """Vérifie la tolérance aux clés alternatives d'IP Webcam (audio, accelerometer)."""
    payload = {
        "audio": {
            "unit": "dB",
            "data": [[1700000000000, [75.0]]]
        },
        "accelerometer": {
            "unit": "m/s2",
            "data": [[1700000000000, [1.0, 2.0, 9.8]]]
        }
    }
    parsed = SensorParser.parse_payload(payload)
    assert parsed["sound"]["available"] is True
    assert parsed["sound"]["value"] == 75.0
    assert parsed["accel"]["available"] is True
    assert parsed["accel"]["value"]["x"] == 1.0


def test_simulated_override_flag():
    """Vérifie que les valeurs simulées portent impérativement le drapeau is_simulated=True."""
    poller = SensorPoller("dev_test", "http://127.0.0.1:9999/sensors.json")
    poller.set_simulation_override("proximity", 1.2, duration_seconds=5.0)

    sensors = poller.get_sensors()
    assert sensors["proximity"]["available"] is True
    assert sensors["proximity"]["is_simulated"] is True
    assert sensors["proximity"]["status"] == "DISPONIBLE (SIMULÉ)"
    assert sensors["proximity"]["value"] == 1.2
