import time
import socket
from typing import Dict, List, Optional
import config

class DiagnosticManager:
    """Gestionnaire d'inspection approfondie et de diagnostic technique pour les smartphones et capteurs."""

    def __init__(self, coordinator):
        self.coordinator = coordinator

    def run_device_diagnostic(self, device_id: str) -> Optional[dict]:
        """Exécute un diagnostic exhaustif d'un smartphone spécifique."""
        device = self.coordinator.device_store.get_device(device_id)
        if not device:
            return None

        now = time.time()
        ip = device["ip"]
        port = device["port"]

        # 1. Diagnostic Réseau (Socket check rapide et latence TCP)
        net_reachable = False
        latency_ms = None
        t0 = time.time()
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1.0)
            result = s.connect_ex((ip, port))
            s.close()
            elapsed = (time.time() - t0) * 1000.0
            if result == 0:
                net_reachable = True
                latency_ms = round(elapsed, 1)
        except Exception:
            net_reachable = False

        # 2. Diagnostic Vidéo
        cam_stat = self.coordinator.camera_manager.get_status(device_id)
        video_available = (cam_stat.get("status") == "CONNECTÉ")
        video_fps = config.CAMERA_FPS if video_available else 0
        video_age = cam_stat.get("last_frame_age")

        # 3. Diagnostic Capteurs
        sensor_info = self.coordinator.sensor_manager.get_device_sensors(device_id)
        raw_sensors = sensor_info.get("sensors", {})
        sensor_age = sensor_info.get("last_update_age")

        sensors_diag = {}
        expected_sensors = ["proximity", "sound", "accel", "battery", "light"]
        
        available_count = 0
        for s_key in expected_sensors:
            s_data = raw_sensors.get(s_key, {})
            is_avail = bool(s_data.get("available", False))
            s_status = s_data.get("status", "CAPTEUR NON DISPONIBLE")
            val = s_data.get("value") if s_key != "accel" else s_data.get("norm")
            unit = s_data.get("unit", "")

            # Respect strict des exigences :
            # - Si non disponible -> "CAPTEUR NON DISPONIBLE"
            # - Si données trop anciennes (> 8s) -> "DONNÉE EXPIRÉE"
            # - Données simulées identifiées sans jamais remplacer une valeur manquante
            if not is_avail:
                s_status = "CAPTEUR NON DISPONIBLE"
            elif sensor_age is not None and sensor_age > config.STALE_TELEMETRY_SECONDS:
                s_status = "DONNÉE EXPIRÉE"

            if is_avail and s_status in ["DONNÉE RÉELLE", "DISPONIBLE", "DISPONIBLE (SIMULÉ)"]:
                available_count += 1

            sensors_diag[s_key] = {
                "available": is_avail,
                "status": s_status,
                "value": val,
                "unit": unit,
                "is_simulated": bool(s_data.get("is_simulated", False))
            }

        # 4. Temps écoulé depuis dernière communication globale
        comm_ages = [a for a in [video_age, sensor_age] if a is not None]
        last_comm_age = min(comm_ages) if comm_ages else None
        last_comm_time = None
        if last_comm_age is not None:
            last_comm_time = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(now - last_comm_age))

        # 5. Détection appareil silencieux
        is_silent = False
        if device.get("enabled", True):
            if last_comm_age is None or last_comm_age > config.STALE_TELEMETRY_SECONDS:
                is_silent = True

        # 6. État général normalisé
        # CONNECTÉ : vidéo et capteurs reçus récemment
        # DÉGRADÉ : l'un des flux est silencieux ou incomplet
        # DÉCONNECTÉ : aucun flux n'est reçu
        if not device.get("enabled", True):
            overall_status = "DÉSACTIVÉ"
        elif video_available and not is_silent and available_count > 0:
            overall_status = "CONNECTÉ"
        elif net_reachable or video_available or (sensor_age is not None and sensor_age < 30.0):
            overall_status = "DÉGRADÉ"
        else:
            overall_status = "DÉCONNECTÉ"

        return {
            "device_id": device_id,
            "name": device["name"],
            "ip": ip,
            "port": port,
            "enabled": device.get("enabled", True),
            "overall_status": overall_status,
            "is_silent": is_silent,
            "network": {
                "reachable": net_reachable,
                "latency_ms": latency_ms,
                "url": f"http://{ip}:{port}"
            },
            "video": {
                "available": video_available,
                "status": cam_stat.get("status", "DÉCONNECTÉ"),
                "fps": video_fps,
                "last_frame_age_seconds": video_age,
                "last_frame_time": cam_stat.get("last_frame_time"),
                "error": cam_stat.get("error", "")
            },
            "telemetry": {
                "status": sensor_info.get("status", "DÉCONNECTÉ"),
                "last_update_age_seconds": sensor_age,
                "available_sensors_count": available_count,
                "total_sensors_tested": len(expected_sensors),
                "sensors": sensors_diag
            },
            "communication": {
                "last_seen_seconds": last_comm_age,
                "last_seen_time": last_comm_time,
                "reconnect_attempts": cam_stat.get("reconnect_attempts", 0),
                "error_message": cam_stat.get("error") or sensor_info.get("error") or ""
            },
            "diagnostic_timestamp": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(now))
        }

    def run_all_diagnostics(self) -> List[dict]:
        """Exécute le diagnostic pour l'ensemble des smartphones enregistrés."""
        devices = self.coordinator.device_store.get_all_devices()
        results = []
        for dev in devices:
            diag = self.run_device_diagnostic(dev["id"])
            if diag:
                results.append(diag)
        return results
