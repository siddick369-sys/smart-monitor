import requests
import threading
import time
from collections import deque
from typing import Dict, Any, Optional, List, Callable
import config

class SensorParser:
    """Analyseur résilient et tolérant du JSON de capteurs émis par IP Webcam."""

    @staticmethod
    def extract_latest_vector(sensor_obj: Any) -> Optional[list]:
        """Extrait la liste de valeurs numériques les plus récentes d'un objet capteur."""
        if not isinstance(sensor_obj, dict):
            return None
        data = sensor_obj.get("data")
        if not isinstance(data, list) or len(data) == 0:
            return None
        latest_entry = data[-1]
        if isinstance(latest_entry, list) and len(latest_entry) >= 2:
            vals = latest_entry[1]
            if isinstance(vals, list) and len(vals) > 0:
                return vals
            elif isinstance(vals, (int, float)):
                return [vals]
        return None

    @classmethod
    def parse_payload(cls, payload: Any, is_stale: bool = False) -> Dict[str, dict]:
        """Analyse le dictionnaire JSON complet et renvoie l'état normalisé des capteurs."""
        parsed = {
            "proximity": {"available": False, "status": "CAPTEUR NON DISPONIBLE", "value": None, "unit": "cm", "is_simulated": False},
            "sound": {"available": False, "status": "CAPTEUR NON DISPONIBLE", "value": None, "unit": "dB", "is_simulated": False},
            "accel": {"available": False, "status": "CAPTEUR NON DISPONIBLE", "value": None, "unit": "m/s2", "norm": None, "is_simulated": False},
            "light": {"available": False, "status": "CAPTEUR NON DISPONIBLE", "value": None, "unit": "lx", "is_simulated": False},
            "battery": {"available": False, "status": "CAPTEUR NON DISPONIBLE", "value": None, "unit": "%", "is_simulated": False}
        }

        if not isinstance(payload, dict) or not payload:
            return parsed

        status_label = "DONNÉE EXPIRÉE" if is_stale else "DONNÉE RÉELLE"

        # 1. Proximité
        prox_raw = payload.get("proximity")
        vals = cls.extract_latest_vector(prox_raw)
        if vals is not None and len(vals) > 0 and vals[0] is not None:
            try:
                val = float(vals[0])
                unit = prox_raw.get("unit", "cm") if isinstance(prox_raw, dict) else "cm"
                parsed["proximity"] = {
                    "available": not is_stale,
                    "status": status_label,
                    "value": round(val, 2),
                    "unit": unit,
                    "is_simulated": False
                }
            except (ValueError, TypeError):
                pass

        # 2. Niveau Sonore
        sound_raw = payload.get("sound") or payload.get("audio") or payload.get("audio_level")
        vals = cls.extract_latest_vector(sound_raw)
        if vals is not None and len(vals) > 0 and vals[0] is not None:
            try:
                val = float(vals[0])
                unit = sound_raw.get("unit", "dB") if isinstance(sound_raw, dict) else "dB"
                parsed["sound"] = {
                    "available": not is_stale,
                    "status": status_label,
                    "value": round(val, 2),
                    "unit": unit,
                    "is_simulated": False
                }
            except (ValueError, TypeError):
                pass

        # 3. Accéléromètre
        accel_raw = payload.get("accel") or payload.get("accelerometer")
        vals = cls.extract_latest_vector(accel_raw)
        if vals is not None and len(vals) >= 3:
            try:
                ax, ay, az = float(vals[0]), float(vals[1]), float(vals[2])
                norm = (ax**2 + ay**2 + az**2) ** 0.5
                unit = accel_raw.get("unit", "m/s2") if isinstance(accel_raw, dict) else "m/s2"
                parsed["accel"] = {
                    "available": not is_stale,
                    "status": status_label,
                    "value": {"x": round(ax, 2), "y": round(ay, 2), "z": round(az, 2)},
                    "norm": round(norm, 2),
                    "unit": unit,
                    "is_simulated": False
                }
            except (ValueError, TypeError):
                pass

        # 4. Capteur de luminosité
        light_raw = payload.get("light")
        vals = cls.extract_latest_vector(light_raw)
        if vals is not None and len(vals) > 0 and vals[0] is not None:
            try:
                val = float(vals[0])
                unit = light_raw.get("unit", "lx") if isinstance(light_raw, dict) else "lx"
                parsed["light"] = {
                    "available": not is_stale,
                    "status": status_label,
                    "value": round(val, 1),
                    "unit": unit,
                    "is_simulated": False
                }
            except (ValueError, TypeError):
                pass

        # 5. Batterie
        batt_raw = payload.get("battery_level") or payload.get("battery")
        vals = cls.extract_latest_vector(batt_raw)
        if vals is not None and len(vals) > 0 and vals[0] is not None:
            try:
                val = float(vals[0])
                unit = "%"
                parsed["battery"] = {
                    "available": not is_stale,
                    "status": status_label,
                    "value": round(val, 0),
                    "unit": unit,
                    "is_simulated": False
                }
            except (ValueError, TypeError):
                pass

        return parsed


class SensorPoller(threading.Thread):
    """Thread interrogeant /sensors.json avec détection d'expiration et historique glissant."""

    def __init__(self, device_id: str, sensors_url: str, poll_interval: float = 0.4,
                 on_state_change: Optional[Callable[[str, str, str], None]] = None):
        super().__init__(name=f"SensorPoller-{device_id}", daemon=True)
        self.device_id = device_id
        self.sensors_url = sensors_url
        self.poll_interval = poll_interval
        self.on_state_change = on_state_change

        self._stop_event = threading.Event()
        self._lock = threading.Lock()

        self.status = "DÉCONNECTÉ"
        self.last_update_time = 0.0
        self.last_error = ""
        self.reconnect_attempts = 0
        
        self.raw_payload: dict = {}
        self.sensor_data: Dict[str, dict] = SensorParser.parse_payload({})
        self.simulated_overrides: Dict[str, dict] = {}
        
        # Historiques glissants pour visualisations sparklines
        self.sound_history = deque(maxlen=20)
        self.accel_history = deque(maxlen=20)

    def _set_status(self, new_status: str, error_msg: str = ""):
        old_status = self.status
        self.status = new_status
        self.last_error = error_msg
        if old_status != new_status and self.on_state_change:
            try:
                self.on_state_change(self.device_id, old_status, new_status)
            except Exception as e:
                print(f"[SensorPoller-{self.device_id}] Erreur callback état : {e}")

    def set_simulation_override(self, sensor_type: str, value: Any, duration_seconds: float = 3.0):
        """Injecte temporairement une valeur simulée pour test/démonstration."""
        with self._lock:
            self.simulated_overrides[sensor_type] = {
                "value": value,
                "expire_at": time.time() + duration_seconds,
                "is_simulated": True
            }

    def run(self):
        from urllib.parse import urlparse
        while not self._stop_event.is_set():
            try:
                # Validation anti-SSRF au point de connexion effectif
                if isinstance(self.sensors_url, str) and "://" in self.sensors_url:
                    parsed = urlparse(self.sensors_url)
                    if parsed.hostname:
                        port = parsed.port or (80 if parsed.scheme == "http" else 443)
                        ok_target, reason = config.is_allowed_camera_target(parsed.hostname, port)
                        if not ok_target:
                            self._set_status("ERREUR DE CONNEXION", f"SSRF bloqué : {reason}")
                            time.sleep(self.poll_interval)
                            continue

                resp = requests.get(self.sensors_url, timeout=config.HTTP_TIMEOUT, allow_redirects=False)
                if resp.status_code == 200:
                    try:
                        raw_json = resp.json()
                        now = time.time()
                        parsed = SensorParser.parse_payload(raw_json, is_stale=False)
                        with self._lock:
                            self.raw_payload = raw_json
                            self.sensor_data = parsed
                            self.last_update_time = now
                            self.reconnect_attempts = 0
                            self._set_status("CONNECTÉ", "")
                            
                            # Historiser
                            if parsed["sound"]["available"] and parsed["sound"]["value"] is not None:
                                self.sound_history.append((now, parsed["sound"]["value"]))
                            if parsed["accel"]["available"] and parsed["accel"]["norm"] is not None:
                                self.accel_history.append((now, parsed["accel"]["norm"]))
                    except Exception as parse_err:
                        with self._lock:
                            self._set_status("ERREUR DE CONNEXION", f"Erreur décodage JSON : {parse_err}")
                else:
                    with self._lock:
                        self._set_status("ERREUR DE CONNEXION", f"Code HTTP {resp.status_code}")
            except requests.exceptions.RequestException as req_err:
                with self._lock:
                    self.reconnect_attempts += 1
                    self._set_status("DÉCONNECTÉ", f"Échec réseau : {req_err}")
            except Exception as e:
                with self._lock:
                    self._set_status("ERREUR DE CONNEXION", str(e))

            time.sleep(self.poll_interval)

    def stop(self):
        self._stop_event.set()

    def get_sensors(self) -> dict:
        """Retourne les capteurs avec vérification de fraîcheur et surcharges simulées."""
        with self._lock:
            now = time.time()
            is_stale = (now - self.last_update_time) > config.STALE_TELEMETRY_SECONDS if self.last_update_time > 0 else False
            
            # Si périmé, ré-analyser avec flag is_stale
            if is_stale:
                base_sensors = SensorParser.parse_payload(self.raw_payload, is_stale=True)
            else:
                base_sensors = {k: dict(v) for k, v in self.sensor_data.items()}

            # Appliquer les surcharges simulées non expirées
            expired = []
            for sensor_type, sim_info in self.simulated_overrides.items():
                if now < sim_info["expire_at"]:
                    val = sim_info["value"]
                    if sensor_type == "accel":
                        norm = (val.get("x", 0)**2 + val.get("y", 0)**2 + val.get("z", 0)**2) ** 0.5
                        base_sensors["accel"] = {
                            "available": True,
                            "status": "DISPONIBLE (SIMULÉ)",
                            "value": val,
                            "norm": round(norm, 2),
                            "unit": "m/s2",
                            "is_simulated": True
                        }
                    else:
                        unit = "cm" if sensor_type == "proximity" else ("dB" if sensor_type == "sound" else "")
                        base_sensors[sensor_type] = {
                            "available": True,
                            "status": "DISPONIBLE (SIMULÉ)",
                            "value": val,
                            "unit": unit,
                            "is_simulated": True
                        }
                else:
                    expired.append(sensor_type)

            for exp in expired:
                del self.simulated_overrides[exp]

            return base_sensors

    def get_telemetry_history(self) -> dict:
        with self._lock:
            return {
                "sound": list(self.sound_history),
                "accel": list(self.accel_history)
            }


class SensorManager:
    """Gestionnaire central de surveillance des capteurs pour tous les téléphones."""

    def __init__(self, on_state_change: Optional[Callable[[str, str, str], None]] = None):
        self._pollers: Dict[str, SensorPoller] = {}
        self._lock = threading.RLock()
        self.on_state_change = on_state_change

    def start_sensor_polling(self, device_id: str, sensors_url: str):
        with self._lock:
            self.stop_sensor_polling(device_id)
            poller = SensorPoller(device_id, sensors_url, on_state_change=self.on_state_change)
            self._pollers[device_id] = poller
            poller.start()

    def stop_sensor_polling(self, device_id: str):
        with self._lock:
            if device_id in self._pollers:
                poller = self._pollers.pop(device_id)
                poller.stop()
                if poller.is_alive():
                    poller.join(timeout=1.0)

    def stop_all(self):
        with self._lock:
            for dev_id, poller in list(self._pollers.items()):
                poller.stop()
            for dev_id, poller in list(self._pollers.items()):
                if poller.is_alive():
                    poller.join(timeout=1.0)
            self._pollers.clear()

    def get_device_sensors(self, device_id: str) -> dict:
        with self._lock:
            poller = self._pollers.get(device_id)
            if not poller:
                return {
                    "status": "DÉCONNECTÉ",
                    "error": "Non surveillé",
                    "last_update_age": None,
                    "last_update_time": None,
                    "sensors": SensorParser.parse_payload({}),
                    "history": {"sound": [], "accel": []}
                }
            
            now = time.time()
            age = round(now - poller.last_update_time, 1) if poller.last_update_time else None
            status = poller.status
            if status == "CONNECTÉ" and age is not None and age > config.STALE_TELEMETRY_SECONDS:
                status = "DÉGRADÉ"

            return {
                "status": status,
                "error": poller.last_error,
                "last_update_age": age,
                "last_update_time": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(poller.last_update_time)) if poller.last_update_time else None,
                "sensors": poller.get_sensors(),
                "history": poller.get_telemetry_history()
            }

    def simulate_sensor_event(self, device_id: str, sensor_type: str, value: Any, duration_seconds: float = 3.0):
        with self._lock:
            poller = self._pollers.get(device_id)
            if poller:
                poller.set_simulation_override(sensor_type, value, duration_seconds)
