"""
Module Jumeau Numérique 2D & Suivi Multi-Caméras (Spatial Tracker) — PRO-10
Gère la représentation spatiale des zones surveillées et le suivi de trajectoire inter-caméras :
- Modélisation du plan de masse 2D (pièces, caméras, orientation, champs de vision FOV)
- Estimation des positions spatiales des détections sans reconnaissance faciale
- Algorithme de passage de témoin (Handover) entre caméras contiguës
- Délimitation de zones sensibles et traçage de fil d'Ariane spatio-temporel
"""

import math
import time
import uuid
import threading
from typing import Dict, List, Optional, Tuple, Any


class SpatialZone:
    def __init__(self, zone_id: str, name: str, polygon: List[Tuple[float, float]], is_restricted: bool = False):
        self.id = zone_id
        self.name = name
        self.polygon = polygon  # Coordonnées (x, y) normalisées ou en mètres [0, 100]
        self.is_restricted = is_restricted

    def contains_point(self, x: float, y: float) -> bool:
        """Algorithme Ray-Casting pour tester si un point est à l'intérieur du polygone."""
        n = len(self.polygon)
        inside = False
        p1x, p1y = self.polygon[0]
        for i in range(n + 1):
            p2x, p2y = self.polygon[i % n]
            if y > min(p1y, p2y):
                if y <= max(p1y, p2y):
                    if x <= max(p1x, p2x):
                        if p1y != p2y:
                            xinters = (y - p1y) * (p2x - p1x) / (p2y - p1y) + p1x
                        if p1x == p2x or x <= xinters:
                            inside = not inside
            p1x, p1y = p2x, p2y
        return inside


class CameraNodeSpatial:
    def __init__(
        self,
        device_id: str,
        name: str,
        x: float,
        y: float,
        orientation_deg: float = 0.0,
        fov_deg: float = 75.0,
        range_meters: float = 12.0
    ):
        self.device_id = device_id
        self.name = name
        self.x = x
        self.y = y
        self.orientation_deg = orientation_deg
        self.fov_deg = fov_deg
        self.range_meters = range_meters

    def estimate_target_position(self, bbox_x_center_ratio: float, distance_estimate: float = 3.5) -> Tuple[float, float]:
        """Estime les coordonnées (x, y) d'une cible vue dans la caméra."""
        # bbox_x_center_ratio dans [0, 1] où 0.5 est le centre optique
        angle_offset = (bbox_x_center_ratio - 0.5) * self.fov_deg
        total_angle_rad = math.radians(self.orientation_deg + angle_offset)
        dist = min(self.range_meters, max(0.5, distance_estimate))

        target_x = self.x + dist * math.cos(total_angle_rad)
        target_y = self.y + dist * math.sin(total_angle_rad)
        return round(target_x, 2), round(target_y, 2)


class TrajectoryTrack:
    def __init__(self, track_id: str, initial_camera: str, initial_pos: Tuple[float, float], timestamp: float):
        self.track_id = track_id
        self.cameras_seen = [initial_camera]
        self.positions = [(initial_pos[0], initial_pos[1], timestamp)]
        self.last_update = timestamp
        self.status = "ACTIVE"

    def add_point(self, camera_id: str, pos: Tuple[float, float], timestamp: float):
        if camera_id not in self.cameras_seen:
            self.cameras_seen.append(camera_id)
        self.positions.append((pos[0], pos[1], timestamp))
        self.last_update = timestamp


class SpatialTracker:
    def __init__(
        self,
        handover_max_delay: float = 8.0,
        handover_max_dist: float = 15.0
    ):
        self.handover_max_delay = handover_max_delay
        self.handover_max_dist = handover_max_dist
        self._lock = threading.RLock()

        self._cameras: Dict[str, CameraNodeSpatial] = {}
        self._zones: Dict[str, SpatialZone] = {}
        self._tracks: Dict[str, TrajectoryTrack] = {}

    def add_camera(
        self,
        device_id: str,
        name: str,
        x: float,
        y: float,
        orientation_deg: float = 0.0,
        fov_deg: float = 75.0,
        range_meters: float = 10.0
    ):
        with self._lock:
            self._cameras[device_id] = CameraNodeSpatial(
                device_id, name, x, y, orientation_deg, fov_deg, range_meters
            )

    def add_zone(self, zone_id: str, name: str, polygon: List[Tuple[float, float]], is_restricted: bool = False):
        with self._lock:
            self._zones[zone_id] = SpatialZone(zone_id, name, polygon, is_restricted)

    def record_detection(
        self,
        device_id: str,
        bbox_center_x: float = 0.5,
        distance_meters: float = 3.0,
        timestamp: Optional[float] = None
    ) -> dict:
        """Enregistre une détection, projette sa position et effectue l'association temporelle inter-caméras (Handover)."""
        now = timestamp or time.time()

        with self._lock:
            cam = self._cameras.get(device_id)
            if not cam:
                # Position par défaut si la caméra n'a pas été calibrée spatialement
                pos = (0.0, 0.0)
            else:
                pos = cam.estimate_target_position(bbox_center_x, distance_meters)

            # Recherche d'une trajectoire existante pour handover
            matched_track = None
            for track in self._tracks.values():
                if track.status == "ACTIVE" and (now - track.last_update <= self.handover_max_delay):
                    last_x, last_y, _ = track.positions[-1]
                    dist = math.hypot(pos[0] - last_x, pos[1] - last_y)
                    if dist <= self.handover_max_dist:
                        matched_track = track
                        break

            is_handover = False
            if matched_track:
                if device_id not in matched_track.cameras_seen:
                    is_handover = True
                matched_track.add_point(device_id, pos, now)
                track_id = matched_track.track_id
            else:
                track_id = f"traj_{uuid.uuid4().hex[:8]}"
                new_track = TrajectoryTrack(track_id, device_id, pos, now)
                self._tracks[track_id] = new_track

            # Détection de violation de zone sensible
            zone_alert = None
            for z in self._zones.values():
                if z.is_restricted and z.contains_point(pos[0], pos[1]):
                    zone_alert = z.name
                    break

            # Nettoyage des anciennes trajectoires (> 60s)
            for t in list(self._tracks.values()):
                if now - t.last_update > 60.0:
                    t.status = "COMPLETED"

            return {
                "track_id": track_id,
                "device_id": device_id,
                "estimated_position": {"x": pos[0], "y": pos[1]},
                "is_handover": is_handover,
                "cameras_involved": self._tracks[track_id].cameras_seen,
                "restricted_zone_alert": zone_alert,
                "timestamp": now
            }

    def get_floorplan_state(self) -> dict:
        """Retourne l'état complet du jumeau numérique 2D pour l'IHM."""
        with self._lock:
            cameras_data = [
                {
                    "device_id": c.device_id,
                    "name": c.name,
                    "x": c.x,
                    "y": c.y,
                    "orientation_deg": c.orientation_deg,
                    "fov_deg": c.fov_deg,
                    "range_meters": c.range_meters
                }
                for c in self._cameras.values()
            ]

            zones_data = [
                {
                    "id": z.id,
                    "name": z.name,
                    "polygon": z.polygon,
                    "is_restricted": z.is_restricted
                }
                for z in self._zones.values()
            ]

            active_tracks = [
                {
                    "track_id": t.track_id,
                    "cameras_seen": t.cameras_seen,
                    "path": [(p[0], p[1]) for p in t.positions],
                    "last_seen_age": round(time.time() - t.last_update, 1)
                }
                for t in self._tracks.values()
                if t.status == "ACTIVE"
            ]

            return {
                "cameras": cameras_data,
                "zones": zones_data,
                "active_tracks": active_tracks
            }

    def get_active_tracks(self) -> List[dict]:
        """Retourne la liste des trajectoires actives."""
        return self.get_floorplan_state()["active_tracks"]

    def get_status(self) -> dict:
        with self._lock:
            active_count = sum(1 for t in self._tracks.values() if t.status == "ACTIVE")
            return {
                "enabled": True,
                "configured_cameras_count": len(self._cameras),
                "defined_zones_count": len(self._zones),
                "active_tracks_count": active_count
            }
