import json
import os
import threading
import uuid
import time
from typing import Dict, List, Optional
import config
from database import get_db_session
from monitoring.models import Device

class DeviceStore:
    """Gestionnaire persistant et thread-safe des smartphones enregistrés et des paramètres avec SQLite."""
    
    def __init__(self, devices_file: str = config.DEVICES_FILE, settings_file: str = config.SETTINGS_FILE):
        self.devices_file = devices_file
        self.settings_file = settings_file
        self._lock = threading.RLock()
        self._devices: Dict[str, dict] = {}
        self._settings: dict = dict(config.DEFAULT_SETTINGS)
        self.load()

    def load(self):
        with self._lock:
            # 1. Charger depuis SQLite si disponible
            loaded_from_db = False
            try:
                with get_db_session() as db:
                    db_devs = db.query(Device).all()
                    if db_devs:
                        self._devices = {}
                        for d in db_devs:
                            proto = getattr(d, "protocol", "ANDROID_IPWEBCAM") or "ANDROID_IPWEBCAM"
                            rtsp = getattr(d, "rtsp_uri", None)
                            if proto in ["RTSP", "ONVIF"]:
                                video_url = rtsp or f"rtsp://{d.ip}:{d.port}/live/ch0"
                                sensors_url = ""
                            else:
                                video_url = f"http://{d.ip}:{d.port}/video"
                                sensors_url = f"http://{d.ip}:{d.port}/sensors.json"

                            self._devices[d.id] = {
                                "id": d.id,
                                "name": d.name,
                                "ip": d.ip,
                                "port": d.port,
                                "protocol": proto,
                                "rtsp_uri": rtsp,
                                "enable_torch": False,
                                "enabled": True,
                                "video_url": video_url,
                                "sensors_url": sensors_url,
                                "zones": d.get_zones()
                            }
                        loaded_from_db = True
            except Exception as sqle:
                print(f"[DeviceStore] Info lecture SQLite : {sqle}")

            # 2. Si SQLite vide ou inaccessible, charger devices.json
            if not loaded_from_db:
                if os.path.exists(self.devices_file):
                    try:
                        with open(self.devices_file, "r", encoding="utf-8") as f:
                            self._devices = json.load(f)
                        for dev in self._devices.values():
                            if "zones" not in dev or not isinstance(dev["zones"], list):
                                dev["zones"] = []
                        # Sauvegarder dans SQLite pour synchronisation
                        self.save_devices()
                    except Exception as e:
                        print(f"[DeviceStore] Erreur chargement devices.json : {e}")
                        self._devices = {}
                else:
                    self._devices = {}

            # Charger les paramètres
            if os.path.exists(self.settings_file):
                try:
                    with open(self.settings_file, "r", encoding="utf-8") as f:
                        saved_settings = json.load(f)
                        self._settings.update(saved_settings)
                except Exception as e:
                    print(f"[DeviceStore] Erreur chargement settings.json : {e}")
            else:
                self.save_settings()

    def save_devices(self):
        with self._lock:
            # Synchronisation SQLite
            try:
                with get_db_session() as db:
                    for dev_id, dev_data in self._devices.items():
                        db_dev = db.query(Device).filter(Device.id == dev_id).first()
                        if not db_dev:
                            db_dev = Device(
                                id=dev_id,
                                name=dev_data.get("name", "Camera"),
                                ip=dev_data.get("ip", "127.0.0.1"),
                                port=int(dev_data.get("port", 8080)),
                                protocol=dev_data.get("protocol", "ANDROID_IPWEBCAM"),
                                rtsp_uri=dev_data.get("rtsp_uri"),
                                zones_json=json.dumps(dev_data.get("zones", [])),
                                created_at=time.time(),
                                updated_at=time.time()
                            )
                            db.add(db_dev)
                        else:
                            db_dev.name = dev_data.get("name", db_dev.name)
                            db_dev.ip = dev_data.get("ip", db_dev.ip)
                            db_dev.port = int(dev_data.get("port", db_dev.port))
                            db_dev.protocol = dev_data.get("protocol", getattr(db_dev, "protocol", "ANDROID_IPWEBCAM"))
                            db_dev.rtsp_uri = dev_data.get("rtsp_uri", getattr(db_dev, "rtsp_uri", None))
                            db_dev.zones_json = json.dumps(dev_data.get("zones", []))
                            db_dev.updated_at = time.time()
            except Exception as sqle:
                pass

            # Miroir devices.json
            try:
                with open(self.devices_file, "w", encoding="utf-8") as f:
                    json.dump(self._devices, f, indent=2, ensure_ascii=False)
            except Exception as e:
                print(f"[DeviceStore] Erreur sauvegarde devices.json : {e}")

    def save_settings(self):
        with self._lock:
            try:
                with open(self.settings_file, "w", encoding="utf-8") as f:
                    json.dump(self._settings, f, indent=2, ensure_ascii=False)
            except Exception as e:
                print(f"[DeviceStore] Erreur sauvegarde settings.json : {e}")

    def get_all_devices(self) -> List[dict]:
        """Retourne la liste des smartphones directement depuis la source de vérité SQLite."""
        with self._lock:
            try:
                with get_db_session() as db:
                    db_devs = db.query(Device).all()
                    if db_devs is not None:
                        return [{
                            "id": d.id,
                            "name": d.name,
                            "ip": d.ip,
                            "port": d.port,
                            "enable_torch": bool(self._devices.get(d.id, {}).get("enable_torch", False)),
                            "enabled": bool(self._devices.get(d.id, {}).get("enabled", True)),
                            "video_url": f"http://{d.ip}:{d.port}/video",
                            "sensors_url": f"http://{d.ip}:{d.port}/sensors.json",
                            "zones": d.get_zones()
                        } for d in db_devs]
            except Exception:
                pass
            return list(self._devices.values())

    def get_device(self, device_id: str) -> Optional[dict]:
        """Récupère un smartphone par son identifiant depuis la source de vérité SQLite."""
        with self._lock:
            try:
                with get_db_session() as db:
                    d = db.query(Device).filter(Device.id == device_id).first()
                    if d:
                        return {
                            "id": d.id,
                            "name": d.name,
                            "ip": d.ip,
                            "port": d.port,
                            "enable_torch": bool(self._devices.get(d.id, {}).get("enable_torch", False)),
                            "enabled": bool(self._devices.get(d.id, {}).get("enabled", True)),
                            "video_url": f"http://{d.ip}:{d.port}/video",
                            "sensors_url": f"http://{d.ip}:{d.port}/sensors.json",
                            "zones": d.get_zones()
                        }
            except Exception:
                pass
            return self._devices.get(device_id)

    def add_device(self, name: str, ip: str, port: int, enable_torch: bool = False, protocol: str = "ANDROID_IPWEBCAM", rtsp_uri: Optional[str] = None) -> dict:
        with self._lock:
            ip = ip.strip()
            try:
                port = int(port)
            except (ValueError, TypeError):
                raise ValueError("Numéro de port invalide.")

            # Validation stricte anti-SSRF (IP + Port autorisés) - PRO-12
            allowed, reason = config.is_allowed_camera_target(ip, port)
            if not allowed:
                raise ValueError(f"Adresse IP non autorisée ou port invalide : {reason}")

            proto_normalized = str(protocol or "ANDROID_IPWEBCAM").strip().upper()
            if proto_normalized in ["RTSP", "ONVIF"]:
                video_url = rtsp_uri or f"rtsp://{ip}:{port}/live/ch0"
                sensors_url = ""
                enable_torch = False
            else:
                proto_normalized = "ANDROID_IPWEBCAM"
                video_url = f"http://{ip}:{port}/video"
                sensors_url = f"http://{ip}:{port}/sensors.json"

            device_id = f"dev_{uuid.uuid4().hex[:8]}"
            device_data = {
                "id": device_id,
                "name": name.strip() or f"Caméra {len(self._devices) + 1}",
                "ip": ip,
                "port": port,
                "protocol": proto_normalized,
                "rtsp_uri": rtsp_uri,
                "enable_torch": bool(enable_torch),
                "enabled": True,
                "video_url": video_url,
                "sensors_url": sensors_url,
                "zones": []
            }
            self._devices[device_id] = device_data
            self.save_devices()
            return device_data

    def update_device(self, device_id: str, **kwargs) -> Optional[dict]:
        with self._lock:
            if device_id not in self._devices:
                return None
            device = self._devices[device_id]

            target_ip = device["ip"]
            target_port = device["port"]
            if "ip" in kwargs:
                target_ip = str(kwargs["ip"]).strip()
            if "port" in kwargs:
                try:
                    target_port = int(kwargs["port"])
                except (ValueError, TypeError):
                    raise ValueError("Port invalide.")

            if "ip" in kwargs or "port" in kwargs:
                allowed, reason = config.is_allowed_camera_target(target_ip, target_port)
                if not allowed:
                    raise ValueError(f"Modification refusée : {reason}")
                device["ip"] = target_ip
                device["port"] = target_port

            if "name" in kwargs:
                device["name"] = str(kwargs["name"]).strip()
            if "enable_torch" in kwargs:
                device["enable_torch"] = bool(kwargs["enable_torch"])
            if "enabled" in kwargs:
                device["enabled"] = bool(kwargs["enabled"])

            device["video_url"] = f"http://{device['ip']}:{device['port']}/video"
            device["sensors_url"] = f"http://{device['ip']}:{device['port']}/sensors.json"
            self.save_devices()
            return device

    def delete_device(self, device_id: str) -> bool:
        with self._lock:
            if device_id in self._devices:
                del self._devices[device_id]
                try:
                    with get_db_session() as db:
                        dev = db.query(Device).filter(Device.id == device_id).first()
                        if dev:
                            db.delete(dev)
                except Exception as sqle:
                    pass
                self.save_devices()
                return True
            return False

    def get_device_zones(self, device_id: str) -> List[dict]:
        with self._lock:
            device = self._devices.get(device_id)
            if not device:
                return []
            return list(device.get("zones", []))

    def add_device_zone(self, device_id: str, name: str, x: float, y: float, w: float, h: float, enabled: bool = True) -> dict:
        with self._lock:
            device = self._devices.get(device_id)
            if not device:
                raise ValueError(f"Appareil {device_id} introuvable.")

            # Conversion et normalisation si reçu en pourcentages (ex: 50 -> 0.5)
            x, y, w, h = float(x), float(y), float(w), float(h)
            if x > 1.0 or y > 1.0 or w > 1.0 or h > 1.0:
                x, y, w, h = x / 100.0, y / 100.0, w / 100.0, h / 100.0

            if not (0.0 <= x < 1.0 and 0.0 <= y < 1.0 and 0.0 < w <= 1.0 and 0.0 < h <= 1.0):
                raise ValueError("Coordonnées de zone invalides : doivent être comprises entre 0.0 et 1.0.")

            if (x + w) > 1.02 or (y + h) > 1.02:
                raise ValueError("La zone dépasse les dimensions de l'image (x+w > 1.0 ou y+h > 1.0).")

            # Limite à 8 zones par smartphone
            if len(device.get("zones", [])) >= 8:
                raise ValueError("Limite maximale de 8 zones de surveillance atteinte pour cet appareil.")

            zone_id = f"zone_{uuid.uuid4().hex[:6]}"
            zone = {
                "id": zone_id,
                "name": (name or f"Zone {len(device.get('zones', [])) + 1}").strip(),
                "enabled": bool(enabled),
                "x": round(max(0.0, min(1.0, x)), 3),
                "y": round(max(0.0, min(1.0, y)), 3),
                "w": round(max(0.01, min(1.0 - x, w)), 3),
                "h": round(max(0.01, min(1.0 - y, h)), 3)
            }
            device.setdefault("zones", []).append(zone)
            self.save_devices()
            return zone

    def update_device_zone(self, device_id: str, zone_id: str, **kwargs) -> Optional[dict]:
        with self._lock:
            device = self._devices.get(device_id)
            if not device:
                return None

            zone = next((z for z in device.get("zones", []) if z["id"] == zone_id), None)
            if not zone:
                return None

            if "name" in kwargs:
                zone["name"] = str(kwargs["name"]).strip()
            if "enabled" in kwargs:
                zone["enabled"] = bool(kwargs["enabled"])
            
            for coord in ["x", "y", "w", "h"]:
                if coord in kwargs:
                    val = float(kwargs[coord])
                    if val > 1.0: val = val / 100.0
                    zone[coord] = round(max(0.0, min(1.0, val)), 3)

            self.save_devices()
            return zone

    def delete_device_zone(self, device_id: str, zone_id: str) -> bool:
        with self._lock:
            device = self._devices.get(device_id)
            if not device:
                return False

            initial_len = len(device.get("zones", []))
            device["zones"] = [z for z in device.get("zones", []) if z["id"] != zone_id]
            if len(device["zones"]) < initial_len:
                self.save_devices()
                return True
            return False

    def get_settings(self) -> dict:
        with self._lock:
            return dict(self._settings)

    def update_settings(self, new_settings: dict) -> dict:
        with self._lock:
            for k, v in new_settings.items():
                if k in self._settings:
                    # Conversion appropriée selon le type existant
                    cur_type = type(self._settings[k])
                    if cur_type == bool:
                        self._settings[k] = bool(v)
                    elif cur_type == float:
                        self._settings[k] = float(v)
                    elif cur_type == int:
                        self._settings[k] = int(v)
                    else:
                        self._settings[k] = v
            self.save_settings()
            return dict(self._settings)
