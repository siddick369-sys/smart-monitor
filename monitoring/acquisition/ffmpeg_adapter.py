"""
Adaptateur de flux vidéo RTSP supervisé basé sur FFmpeg avec DNS Pinning et buffer circulaire.
Architecture NVR universelle PRO-13.
"""

import os
import sys
import time
import shutil
import atexit
import signal
import logging
import threading
import subprocess
import io
from collections import deque
from typing import Optional, Tuple, List, Dict, Any
import numpy as np
import cv2

import config
from monitoring.acquisition.interfaces import (
    VideoSource, VideoFrame, VideoSourceHealth, VideoSourceMetadata,
    CameraProtocol, VideoSourceStatus, CameraConnectionConfig,
    SSRFBlockedError, ConnectionTimeoutError, StreamStalledError, CodecError
)
from monitoring.acquisition.security import validate_video_target, sanitize_uri, pin_uri_to_ip
from monitoring.acquisition.egress_policy import (
    EgressPolicy, EgressEnforcementStatus, check_egress_enforcement_status,
    PolicyConfigurationError
)

logger = logging.getLogger("SmartSecurityMonitor.NVR.FFmpeg")


# =============================================================================
# CONSTANTES DE SÉCURITÉ ET DE TRANSPORT NVR (PRO-13 A.3)
# =============================================================================

# Transport réseau RTSP strict : seul le mode TCP entrelacé est autorisé (élimine l'évasion UDP)
DEFAULT_RTSP_TRANSPORT: str = "tcp"

# Whitelist stricte des protocoles autorisés pour libavformat (anti-SSRF / anti-protocol injection)
ALLOWED_RTSP_PROTOCOLS: str = "tcp,rtp,rtsp"
ALLOWED_RTSPS_PROTOCOLS: str = "tcp,rtp,rtsp,tls,crypto"

# Plafonds de diagnostic IPC pour la consommation continue de stderr (anti-deadlock A21-003)
MAX_DIAGNOSTIC_LINES: int = 100
MAX_DIAGNOSTIC_BYTES: int = 64 * 1024  # 64 Ko maximum en mémoire


class FFmpegRTSPAdapter(VideoSource):
    """Adaptateur RTSP robuste supervisant un sous-processus FFmpeg indépendant.
    Garanties de sécurité et de robustesse (PRO-13 A.2) :
    1. Isolation stricte via sous-processus FFmpeg (arguments structurés, shell=False, absence de fuite d'orphelins).
    2. DNS Pinning effectif : réécriture de l'URI avec l'adresse IP validée pour éliminer la fenêtre TOCTOU.
    3. Re-validation anti-SSRF systématique avant chaque tentative de reconnexion.
    4. Interdiction absolue du fallback OpenCV in-process en environnement de production (politique fail-closed).
    5. Gestion de buffer circulaire deque(maxlen=2) thread-safe avec fraîcheur garantie.
    """

    def __init__(self, config_obj: CameraConnectionConfig, ffmpeg_bin: Optional[str] = None):
        self.config = config_obj
        self.source_id = config_obj.source_id
        self.uri = config_obj.uri
        self.sanitized_uri = sanitize_uri(self.uri)
        self.ffmpeg_bin = ffmpeg_bin or getattr(self.config, "custom_params", {}).get("ffmpeg_path", "ffmpeg")

        self._width = config_obj.target_width
        self._height = config_obj.target_height
        self._target_fps = max(1, config_obj.target_fps)
        self._frame_bytes = self._width * self._height * 3

        # État et synchronisation
        self._status = VideoSourceStatus.DISCONNECTED
        self._is_connected = False
        self._lock = threading.RLock()
        self._stop_event = threading.Event()
        self._worker_thread: Optional[threading.Thread] = None
        self._process: Optional[subprocess.Popen] = None

        # Télémétrie de santé et buffer circulaire (A1-006)
        self._frame_buffer: deque[VideoFrame] = deque(maxlen=2)
        self._latest_frame: Optional[VideoFrame] = None
        self._frame_sequence = 0
        self._fps_measured = 0.0
        self._dropped_frames = 0
        self._reconnect_count = 0
        self._last_error = ""
        self._connect_time = 0.0
        self._last_frame_time = 0.0
        self._consecutive_read_failures = 0
        self._current_backoff = 1.0

        # Tampon de diagnostic IPC borné et thread-safe pour stderr (A21-003)
        self._diagnostic_lines: deque[str] = deque(maxlen=MAX_DIAGNOSTIC_LINES)
        self._diagnostic_bytes: int = 0
        self._diag_lock = threading.Lock()
        self._stderr_thread: Optional[threading.Thread] = None
        self._process_generation: int = 0

        # DNS Pinning (A1-002)
        self._validated_ip: Optional[str] = None
        self._effective_uri: Optional[str] = None

        # Résolution du chemin absolu du binaire FFmpeg (PRO-13 A.4)
        resolved_bin = shutil.which(self.ffmpeg_bin)
        if resolved_bin:
            self.ffmpeg_bin = os.path.abspath(resolved_bin)
            self._has_ffmpeg_binary = True
        else:
            self._has_ffmpeg_binary = False

        # En production, le fallback OpenCV in-process est STRICTEMENT INTERDIT (P13-A1-003)
        # En développement/test, il n'est activé que si explicitement spécifié
        is_prod = getattr(config, "IS_PRODUCTION", False)
        allow_opencv_opt = bool(getattr(self.config, "custom_params", {}).get("allow_opencv_fallback", False))
        self._allow_opencv_fallback = allow_opencv_opt and (not is_prod)

        # Politique de confinement d'egress et détection de l'isolation (PRO-13 A.4)
        self.egress_policy: Optional[EgressPolicy] = getattr(self.config, "custom_params", {}).get("egress_policy", None)
        allowed_dests = getattr(self.config, "custom_params", {}).get("allowed_destinations", None)
        if self.egress_policy is None and allowed_dests is not None:
            self.egress_policy = EgressPolicy(
                allowed_destinations=allowed_dests,
                allow_loopback=self.config.allow_loopback,
                is_production=is_prod
            )

        self.require_os_egress_confinement: bool = bool(
            getattr(self.config, "custom_params", {}).get(
                "require_os_egress_confinement",
                getattr(config, "REQUIRE_OS_EGRESS_CONFINEMENT", False)
            )
        )
        self._enforcement_status, self._enforcement_reason = check_egress_enforcement_status()

        # Enregistrement pour nettoyage d'urgence à l'arrêt du programme (anti-processus orphelins)
        atexit.register(self.close)

    def is_healthy(self) -> bool:
        with self._lock:
            now = time.time()
            is_recent = (now - self._last_frame_time) <= (self.config.read_timeout * 1.5)
            return self._is_connected and is_recent and self._status == VideoSourceStatus.CONNECTED

    def get_health(self) -> VideoSourceHealth:
        with self._lock:
            now = time.time()
            uptime = (now - self._connect_time) if self._is_connected else 0.0
            latency = (now - self._last_frame_time) * 1000.0 if (self._last_frame_time > 0) else 0.0
            return VideoSourceHealth(
                status=self._status,
                is_connected=self._is_connected,
                fps_measured=round(self._fps_measured, 2),
                dropped_frames=self._dropped_frames,
                reconnect_count=self._reconnect_count,
                latency_ms=round(latency, 1),
                last_error=self._last_error,
                uptime_seconds=round(uptime, 1),
                consecutive_read_failures=self._consecutive_read_failures
            )

    def get_metadata(self) -> VideoSourceMetadata:
        with self._lock:
            model_str = "Universal RTSP Stream"
            if not self._has_ffmpeg_binary and self._allow_opencv_fallback:
                model_str += " (Dev/Test OpenCV Fallback)"

            return VideoSourceMetadata(
                source_id=self.source_id,
                protocol=CameraProtocol.RTSP,
                sanitized_uri=self.sanitized_uri,
                codec="H.264/RAW",
                width=self._width,
                height=self._height,
                nominal_fps=float(self._target_fps),
                manufacturer="ONVIF/RTSP Compatible",
                model=model_str,
                firmware="N/A"
            )

    def connect(self) -> bool:
        """Démarre la validation anti-SSRF, le DNS pinning et la supervision du flux."""
        with self._lock:
            if self._worker_thread and self._worker_thread.is_alive():
                return True

            # 0. Vérification du confinement OS / conteneur requis (PRO-13 A.4 / A.4.2)
            if self.require_os_egress_confinement:
                # Ré-évaluation dynamique pour interdire tout démarrage si la politique a été révoquée
                self._enforcement_status, self._enforcement_reason = check_egress_enforcement_status(
                    expected_executable=self.ffmpeg_bin,
                    expected_destinations=self.egress_policy.raw_allowed_destinations if self.egress_policy else None,
                    expected_ports=list(self.egress_policy.allowed_ports) if self.egress_policy else None
                )
                if self._enforcement_status != EgressEnforcementStatus.ENFORCED:
                    self._status = VideoSourceStatus.BLOCKED_SSRF
                    self._last_error = (
                        f"Confinement réseau OS/conteneur obligatoire mais inactif ({self._enforcement_status.value}) : "
                        f"{self._enforcement_reason}. Connexion rejetée en mode fail-closed."
                    )
                    logger.error(f"[{self.source_id}] {self._last_error}")
                    return False

            # 1. Validation Anti-SSRF stricte et extraction de l'IP validée (A1-001 & A.4)
            valid, reason, resolved_ip = validate_video_target(
                self.uri,
                allow_loopback=self.config.allow_loopback,
                egress_policy=self.egress_policy
            )
            if not valid:
                self._status = VideoSourceStatus.BLOCKED_SSRF
                self._last_error = f"SSRF bloqué : {reason}"
                logger.warning(f"[{self.source_id}] Connexion refusée par la sécurité anti-SSRF ({self.sanitized_uri}) : {reason}")
                return False

            # 2. DNS Pinning effectif (A1-002) : la destination contactée est liée à l'IP validée
            self._validated_ip = resolved_ip
            self._effective_uri = pin_uri_to_ip(self.uri, resolved_ip)

            # 3. Vérification de la disponibilité de FFmpeg et politique fail-closed (A1-003)
            if not self._has_ffmpeg_binary:
                if not self._allow_opencv_fallback:
                    self._status = VideoSourceStatus.ERROR
                    self._last_error = (
                        f"Binaire FFmpeg introuvable ('{self.ffmpeg_bin}'). "
                        "Le fallback OpenCV in-process est désactivé par sécurité pour garantir l'isolation des processus."
                    )
                    logger.error(f"[{self.source_id}] {self._last_error}")
                    return False
                else:
                    logger.warning(
                        f"[{self.source_id}] Binaire FFmpeg absent : activation du fallback OpenCV (Mode DEV/TEST uniquement)."
                    )

            self._stop_event.clear()
            self._worker_thread = threading.Thread(
                target=self._supervision_loop,
                name=f"FFmpegWorker-{self.source_id}",
                daemon=True
            )
            self._worker_thread.start()
            return True

    @property
    def allowed_protocols(self) -> str:
        """Détermine la whitelist stricte des protocoles libavformat selon le schéma."""
        if self.uri and self.uri.lower().startswith("rtsps://"):
            return ALLOWED_RTSPS_PROTOCOLS
        return ALLOWED_RTSP_PROTOCOLS

    def _build_ffmpeg_cmd(self) -> List[str]:
        """Construit les arguments structurés pour exécuter FFmpeg sans injection shell.
        Garanties de sécurité et durcissement (PRO-13 A.3) :
        1. Utilisation exclusive de l'URI épinglée (_effective_uri) pour neutraliser le DNS rebinding.
        2. Whitelist stricte des protocoles libavformat via -protocol_whitelist.
        3. Transport RTP interleaved forcé sur TCP (-rtsp_transport tcp) sans bascule silencieuse vers UDP.
        4. Priorisation explicite du transport TCP via -rtsp_flags +prefer_tcp.
        5. Absence de commande shell (shell=False) et arguments élémentaires en liste.
        """
        timeout_us = int(self.config.connect_timeout * 1_000_000)
        target_input = self._effective_uri or self.uri

        cmd = [
            self.ffmpeg_bin,
            "-hide_banner",
            "-loglevel", "error",
            "-nostdin",
            "-protocol_whitelist", self.allowed_protocols,
            "-rtsp_transport", DEFAULT_RTSP_TRANSPORT,
            "-rtsp_flags", "+prefer_tcp",
            "-stimeout", str(timeout_us),
            "-i", target_input,
            "-an",
            "-sn",
            "-vf", f"scale={self._width}:{self._height}",
            "-r", str(self._target_fps),
            "-f", "rawvideo",
            "-pix_fmt", "bgr24",
            "pipe:1"
        ]
        return cmd

    def _stderr_drain_worker(self, proc: subprocess.Popen, generation: int):
        """Consomme continuellement le tube stderr du sous-processus FFmpeg (A21-003).
        Prévient tout interblocage (Deadlock) IPC dû à la saturation du tampon système (4 Ko sous Windows).
        Masque immédiatement tout identifiant ou secret présent dans les logs.
        Maintient un tampon de diagnostic borné en mémoire (max 64 Ko et 100 lignes).
        """
        if not proc or not proc.stderr:
            return

        try:
            for raw_line in iter(proc.stderr.readline, b""):
                if self._stop_event.is_set():
                    break
                # Ignorer si une nouvelle génération de processus a été démarrée
                with self._lock:
                    if generation != self._process_generation:
                        break

                text = raw_line.decode("utf-8", errors="replace").rstrip()
                if not text:
                    continue

                # Masquage des identifiants et secrets
                sanitized_text = sanitize_uri(text)

                with self._diag_lock:
                    line_len = len(sanitized_text.encode("utf-8"))
                    self._diagnostic_lines.append(sanitized_text)
                    self._diagnostic_bytes += line_len
                    # Élagage si la taille dépasse le plafond configuré
                    while self._diagnostic_bytes > MAX_DIAGNOSTIC_BYTES and len(self._diagnostic_lines) > 1:
                        removed = self._diagnostic_lines.popleft()
                        self._diagnostic_bytes -= len(removed.encode("utf-8"))
        except (ValueError, OSError, io.UnsupportedOperation):
            # Tube fermé lors de l'arrêt normal du processus
            pass
        except Exception as e:
            logger.debug(f"[{self.source_id}] Exception lecteur stderr (gen {generation}) : {e}")

    def get_recent_diagnostics(self, max_lines: int = 10) -> str:
        """Retourne les dernières lignes de diagnostic nettoyées."""
        with self._diag_lock:
            lines = list(self._diagnostic_lines)
            tail = lines[-max_lines:] if len(lines) >= max_lines else lines
            return "\n".join(tail)

    @staticmethod
    def _read_exact(stream, n_bytes: int) -> Optional[bytes]:
        """Lit exactement n_bytes depuis un flux bloquant ou retourne None en cas d'EOF."""
        chunks = []
        bytes_read = 0
        while bytes_read < n_bytes:
            chunk = stream.read(n_bytes - bytes_read)
            if not chunk:
                return None
            chunks.append(chunk)
            bytes_read += len(chunk)
        return b"".join(chunks)

    def _supervision_loop(self):
        """Boucle de supervision continue avec re-validation anti-SSRF à chaque reconnexion."""
        while not self._stop_event.is_set():
            try:
                # A1-002 & A.4: Re-validation stricte anti-SSRF/DNS/Egress avant chaque tentative
                valid, reason, revalidated_ip = validate_video_target(
                    self.uri,
                    allow_loopback=self.config.allow_loopback,
                    egress_policy=self.egress_policy
                )
                if not valid:
                    self._status = VideoSourceStatus.BLOCKED_SSRF
                    self._last_error = f"Reconnexion bloquée par sécurité anti-SSRF/DNS : {reason}"
                    logger.warning(f"[{self.source_id}] Reconnexion refusée (SSRF/DNS) : {reason}")
                    break

                self._validated_ip = revalidated_ip
                self._effective_uri = pin_uri_to_ip(self.uri, revalidated_ip)

                # Si le binaire FFmpeg n'est pas disponible sur le système hôte
                if not self._has_ffmpeg_binary:
                    if not self._allow_opencv_fallback:
                        self._status = VideoSourceStatus.ERROR
                        self._last_error = "Binaire FFmpeg introuvable et fallback OpenCV non autorisé."
                        break
                    self._run_cv2_fallback_loop()
                else:
                    self._run_ffmpeg_subprocess_loop()
            except Exception as e:
                self._last_error = f"Exception supervision : {str(e)}"
                logger.error(f"[{self.source_id}] Erreur supervision FFmpeg : {e}")

            if self._stop_event.is_set():
                break

            # Application du backoff exponentiel avant reconnexion
            self._reconnect_count += 1
            self._status = VideoSourceStatus.CONNECTING
            logger.info(f"[{self.source_id}] Tentative de reconnexion dans {self._current_backoff:.1f}s...")
            self._stop_event.wait(self._current_backoff)
            self._current_backoff = min(self._current_backoff * 1.5, self.config.max_backoff)

        self._cleanup_process()
        with self._lock:
            if self._status != VideoSourceStatus.BLOCKED_SSRF and self._status != VideoSourceStatus.ERROR:
                self._status = VideoSourceStatus.CLOSED

    @staticmethod
    def _build_sanitized_subprocess_env() -> dict:
        """Construit un environnement isolé pour FFmpeg sans variables de proxy (PRO-13 A.4.4)."""
        env = os.environ.copy()
        for proxy_var in (
            "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "FTP_PROXY", "NO_PROXY",
            "http_proxy", "https_proxy", "all_proxy", "ftp_proxy", "no_proxy"
        ):
            env.pop(proxy_var, None)
        return env

    def _run_ffmpeg_subprocess_loop(self):
        """Lance et supervise le sous-processus FFmpeg avec drain stderr asynchrone."""
        with self._lock:
            self._process_generation += 1
            generation = self._process_generation

        cmd = self._build_ffmpeg_cmd()
        self._status = VideoSourceStatus.CONNECTING

        try:
            # Création du sous-processus sans shell et avec environnement purgé des proxies
            self._process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                stdin=subprocess.DEVNULL,
                bufsize=self._frame_bytes * 2,
                shell=False,
                env=self._build_sanitized_subprocess_env()
            )
        except FileNotFoundError:
            self._has_ffmpeg_binary = False
            self._last_error = "Binaire FFmpeg introuvable sur le système hôte."
            return
        except Exception as e:
            self._last_error = f"Impossible de lancer FFmpeg : {e}"
            return

        # Démarrage du thread lecteur de stderr dès l'instanciation du sous-processus (A21-003)
        self._stderr_thread = threading.Thread(
            target=self._stderr_drain_worker,
            args=(self._process, generation),
            name=f"FFmpegStderr-{self.source_id}-gen{generation}",
            daemon=True
        )
        self._stderr_thread.start()

        self._status = VideoSourceStatus.CONNECTED
        self._is_connected = True
        self._connect_time = time.time()
        self._current_backoff = 1.0  # Réinitialisation du backoff lors du succès

        fps_timer = time.time()
        frame_counter = 0

        # Lecture continue depuis stdout
        while not self._stop_event.is_set():
            if self._process.poll() is not None:
                # Le sous-processus s'est terminé inopinément
                rc = self._process.returncode
                diag_msg = self.get_recent_diagnostics(max_lines=3)
                self._last_error = f"FFmpeg terminé (code {rc}) : {diag_msg[:200]}" if diag_msg else f"FFmpeg terminé inopinément (code {rc})"
                break

            # Lecture exacte d'une trame BGR24 brute via helper anti-troncature
            try:
                raw_frame = self._read_exact(self._process.stdout, self._frame_bytes)
            except Exception as e:
                self._last_error = f"Erreur lecture pipe stdout : {e}"
                break

            if not raw_frame:
                # Fin de flux ou trame tronquée
                self._consecutive_read_failures += 1
                if self._consecutive_read_failures > 5:
                    self._status = VideoSourceStatus.STALLED
                    diag_tail = self.get_recent_diagnostics(max_lines=2)
                    self._last_error = f"Flux vidéo interrompu ou trames incomplètes. {diag_tail}".strip()
                    break
                time.sleep(0.05)
                continue

            now = time.time()
            self._consecutive_read_failures = 0
            self._last_frame_time = now
            self._frame_sequence += 1

            # Conversion du buffer brut en tableau NumPy
            img = np.frombuffer(raw_frame, dtype=np.uint8).reshape((self._height, self._width, 3))

            frame_obj = VideoFrame(
                data=img,
                timestamp_utc=now,
                sequence_num=self._frame_sequence,
                width=self._width,
                height=self._height,
                channels=3,
                is_placeholder=False
            )

            with self._lock:
                self._frame_buffer.append(frame_obj)
                self._latest_frame = frame_obj

            frame_counter += 1
            if now - fps_timer >= 1.0:
                self._fps_measured = frame_counter / (now - fps_timer)
                frame_counter = 0
                fps_timer = now

        self._cleanup_process()

    def _run_cv2_fallback_loop(self):
        """Mode de repli utilisant OpenCV (Dev/Test uniquement). Utilise l'URI épinglée."""
        self._status = VideoSourceStatus.CONNECTING
        target_input = self._effective_uri or self.uri

        # Configuration des timeouts réseau OpenCV FFmpeg backend
        os.environ["OPENCV_FFMPEG_CAPTURE_OPTIONS"] = f"timeout;{int(self.config.connect_timeout * 1_000_000)}"

        cap = cv2.VideoCapture(target_input)
        cap.set(cv2.CAP_PROP_BUFFERSIZE, 1)

        if not cap.isOpened():
            self._status = VideoSourceStatus.ERROR
            self._last_error = f"Impossible d'ouvrir le flux RTSP ({self.sanitized_uri})"
            cap.release()
            return

        self._status = VideoSourceStatus.CONNECTED
        self._is_connected = True
        self._connect_time = time.time()
        self._current_backoff = 1.0

        fps_timer = time.time()
        frame_counter = 0

        while not self._stop_event.is_set():
            ret, frame = cap.read()
            if not ret or frame is None:
                self._consecutive_read_failures += 1
                if self._consecutive_read_failures > 10:
                    self._status = VideoSourceStatus.STALLED
                    self._last_error = "Perte de signal vidéo RTSP."
                    break
                time.sleep(0.05)
                continue

            now = time.time()
            self._consecutive_read_failures = 0
            self._last_frame_time = now
            self._frame_sequence += 1

            if frame.shape[0] != self._height or frame.shape[1] != self._width:
                frame = cv2.resize(frame, (self._width, self._height))

            frame_obj = VideoFrame(
                data=frame,
                timestamp_utc=now,
                sequence_num=self._frame_sequence,
                width=self._width,
                height=self._height,
                channels=3,
                is_placeholder=False
            )

            with self._lock:
                self._frame_buffer.append(frame_obj)
                self._latest_frame = frame_obj

            frame_counter += 1
            if now - fps_timer >= 1.0:
                self._fps_measured = frame_counter / (now - fps_timer)
                frame_counter = 0
                fps_timer = now

            # Régulation de cadence
            sleep_time = max(0.001, (1.0 / self._target_fps) - 0.01)
            time.sleep(sleep_time)

        cap.release()
        self._is_connected = False

    def _cleanup_process(self):
        """Arrêt strict et propre du sous-processus FFmpeg, vidange et fermeture des descripteurs."""
        with self._lock:
            self._is_connected = False
            proc = self._process
            self._process = None
            reader_t = self._stderr_thread
            self._stderr_thread = None

        if proc:
            # 1. Fermeture des descripteurs de flux
            try:
                if proc.stdin:
                    proc.stdin.close()
            except Exception:
                pass
            try:
                if proc.stdout:
                    proc.stdout.close()
            except Exception:
                pass
            try:
                if proc.stderr:
                    proc.stderr.close()
            except Exception:
                pass

            # 2. Arrêt gracieux (terminate / SIGTERM)
            try:
                proc.terminate()
                proc.wait(timeout=1.0)
            except (subprocess.TimeoutExpired, Exception):
                try:
                    # Arrêt forcé (kill / SIGKILL)
                    proc.kill()
                    proc.wait(timeout=1.0)
                except Exception:
                    pass

        # 3. Attente bornée de la terminaison du thread lecteur stderr
        if reader_t and reader_t.is_alive():
            if threading.current_thread() != reader_t:
                reader_t.join(timeout=1.0)

    def read_frame(self, timeout: Optional[float] = None) -> Tuple[bool, Optional[VideoFrame], str]:
        """Lit la dernière frame disponible depuis le buffer circulaire avec contrôle d'obsolescence."""
        with self._lock:
            if not self._is_connected or not self._frame_buffer:
                # Si le flux est indisponible, renvoyer une mire stylisée tout en indiquant l'erreur
                placeholder = self._generate_placeholder(self._last_error or "FLUX EN ATTENTE")
                return False, placeholder, self._last_error or "Source déconnectée."

            latest = self._frame_buffer[-1]
            now = time.time()
            age = now - latest.timestamp_utc
            effective_timeout = timeout or self.config.read_timeout

            if age > effective_timeout:
                self._dropped_frames += 1
                placeholder = self._generate_placeholder(f"FLUX FIGÉ ({age:.1f}S)")
                return False, placeholder, f"Trame périmée ({age:.2f}s > {effective_timeout:.2f}s)."

            return True, latest, ""

    def _generate_placeholder(self, message: str) -> VideoFrame:
        """Produit une mire sobre et professionnelle lors des interruptions."""
        img = np.zeros((self._height, self._width, 3), dtype=np.uint8)
        img[::40, :, :] = (20, 20, 25)
        img[:, ::40, :] = (20, 20, 25)
        cv2.putText(img, "SMART SECURITY MONITOR // NVR RTSP", (20, 35),
                    cv2.FONT_HERSHEY_DUPLEX, 0.55, (0, 200, 255), 1)
        cv2.putText(img, f"SOURCE: {self.source_id}", (20, 60),
                    cv2.FONT_HERSHEY_SIMPLEX, 0.4, (160, 160, 160), 1)

        txt_size = cv2.getTextSize(message, cv2.FONT_HERSHEY_SIMPLEX, 0.6, 2)[0]
        tx = max(10, (self._width - txt_size[0]) // 2)
        ty = self._height // 2
        cv2.putText(img, message, (tx, ty), cv2.FONT_HERSHEY_SIMPLEX, 0.6, (0, 140, 255), 2)

        return VideoFrame(
            data=img,
            timestamp_utc=time.time(),
            sequence_num=0,
            width=self._width,
            height=self._height,
            channels=3,
            is_placeholder=True
        )

    def close(self) -> None:
        """Arrête définitivement la supervision et libère toutes les ressources."""
        self._stop_event.set()
        self._cleanup_process()
        if self._worker_thread and self._worker_thread.is_alive():
            if threading.current_thread() != self._worker_thread:
                self._worker_thread.join(timeout=3.0)
        with self._lock:
            self._frame_buffer.clear()
            self._latest_frame = None
            self._status = VideoSourceStatus.CLOSED
            self._is_connected = False
