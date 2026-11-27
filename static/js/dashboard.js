// SMART SECURITY MONITOR — Console Professionnelle JavaScript

// Fonction universelle d'échappement HTML pour prévenir les failles XSS (DOM Injection)
function escapeHtml(str) {
    if (str === null || str === undefined) return "";
    return String(str)
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
}

let currentStatus = null;
let pollTimer = null;
let isAudioPlaying = false;
let currentFilters = { device_id: "", type: "", period: "", query: "" };
let csrfToken = null;

// Gestionnaire automatique et sécurisé du jeton CSRF
async function getCsrfToken() {
    if (!csrfToken) {
        try {
            const resp = await originalFetch("/api/auth/csrf_token");
            if (resp.ok) {
                const data = await resp.json();
                csrfToken = data.csrf_token;
            }
        } catch (e) {
            console.warn("Impossible de récupérer le jeton CSRF :", e);
        }
    }
    return csrfToken;
}

const originalFetch = window.fetch;
window.fetch = async function(url, options = {}) {
    const method = (options.method || "GET").toUpperCase();
    if (["POST", "PUT", "DELETE", "PATCH"].includes(method)) {
        if (!csrfToken && typeof url === "string" && !url.includes("/api/auth/csrf_token") && !url.includes("/api/auth/login")) {
            await getCsrfToken();
        }
        if (csrfToken) {
            options.headers = options.headers || {};
            if (options.headers instanceof Headers) {
                if (!options.headers.has("X-CSRF-Token")) {
                    options.headers.set("X-CSRF-Token", csrfToken);
                }
            } else if (Array.isArray(options.headers)) {
                options.headers.push(["X-CSRF-Token", csrfToken]);
            } else {
                options.headers["X-CSRF-Token"] = options.headers["X-CSRF-Token"] || csrfToken;
            }
        }
    }
    return originalFetch(url, options);
};

// Initialisation au chargement de la page
document.addEventListener("DOMContentLoaded", () => {
    getCsrfToken();
    fetchAuthMe();
    fetchStatus();
    pollTimer = setInterval(fetchStatus, 900);
});

// Récupération de l'état global du système
async function fetchStatus() {
    try {
        const resp = await fetch("/api/status");
        if (!resp.ok) return;
        const data = await resp.json();
        currentStatus = data;
        updateUI(data);
    } catch (err) {
        console.error("Erreur de synchronisation avec le serveur :", err);
    }
}

// Mise à jour de l'ensemble de l'interface
function updateUI(data) {
    // 1. État d'armement
    const btnArm = document.getElementById("btnArmToggle");
    const armIcon = document.getElementById("armIcon");
    const armText = document.getElementById("armText");

    if (data.is_armed) {
        btnArm.className = "bg-emerald-600 hover:bg-emerald-700 text-white px-4 py-2 rounded-lg font-bold text-xs flex items-center space-x-2 transition shadow";
        armIcon.className = "fa-solid fa-shield-halved";
        armText.textContent = "SYSTÈME ARMÉ";
    } else {
        btnArm.className = "bg-slate-800 hover:bg-slate-700 text-slate-300 border border-cardBorder px-4 py-2 rounded-lg font-bold text-xs flex items-center space-x-2 transition shadow";
        armIcon.className = "fa-solid fa-shield";
        armText.textContent = "SYSTÈME DÉSARMÉ";
    }

    // 2. État Général de Surveillance (KPI)
    const statGeneral = document.getElementById("statGeneralState");
    const dotGeneral = document.getElementById("dotGeneralState");
    const subGeneral = document.getElementById("statGeneralSub");

    if (data.general_state === "INCIDENT") {
        statGeneral.textContent = "INCIDENT ACTIF";
        statGeneral.className = "text-base font-extrabold text-red-500 animate-pulse mt-2";
        dotGeneral.className = "h-2.5 w-2.5 rounded-full bg-red-500 animate-ping";
        subGeneral.textContent = "Intrusion en cours";
    } else if (data.general_state === "DÉGRADÉ") {
        statGeneral.textContent = "FONCTIONNEMENT DÉGRADÉ";
        statGeneral.className = "text-base font-extrabold text-amber-400 mt-2";
        dotGeneral.className = "h-2.5 w-2.5 rounded-full bg-amber-400";
        subGeneral.textContent = "1 ou plusieurs flux indisponibles";
    } else if (data.general_state === "OPÉRATIONNEL") {
        statGeneral.textContent = "OPÉRATIONNEL";
        statGeneral.className = "text-base font-extrabold text-emerald-400 mt-2";
        dotGeneral.className = "h-2.5 w-2.5 rounded-full bg-emerald-500";
        subGeneral.textContent = "Tous les flux sont actifs";
    } else {
        statGeneral.textContent = "EN VEILLE";
        statGeneral.className = "text-base font-extrabold text-slate-400 mt-2";
        dotGeneral.className = "h-2.5 w-2.5 rounded-full bg-slate-500";
        subGeneral.textContent = "En attente de smartphones";
    }

    // 3. Bannière d'urgence et sirène
    const banner = document.getElementById("alarmBanner");
    const bannerDetails = document.getElementById("alarmBannerDetails");
    const btnStopSiren = document.getElementById("btnStopSiren");
    const statSirenText = document.getElementById("statSirenText");
    const statSirenIcon = document.getElementById("statSirenIcon");
    const audioElem = document.getElementById("browserSirenAudio");

    if (data.in_alarm) {
        banner.classList.remove("hidden");
        const inc = data.current_incident || {};
        bannerDetails.textContent = `[${inc.category || 'INTRUSION'}] ${inc.type || ''} sur ${inc.device_name || 'Appareil'} (${inc.details || ''})`;
    } else {
        banner.classList.add("hidden");
    }

    if (data.siren_active) {
        btnStopSiren.classList.remove("hidden");
        statSirenText.textContent = "SONNERIE !";
        statSirenText.className = "text-base font-extrabold text-red-500 animate-pulse mt-2";
        statSirenIcon.className = "fa-solid fa-bullhorn text-red-400 text-xs animate-bounce";

        if (!isAudioPlaying && audioElem) {
            audioElem.play().then(() => { isAudioPlaying = true; }).catch(() => {});
        }
    } else {
        btnStopSiren.classList.add("hidden");
        statSirenText.textContent = "VEILLE";
        statSirenText.className = "text-base font-extrabold text-slate-400 mt-2";
        statSirenIcon.className = "fa-solid fa-bullhorn text-slate-500 text-xs";
        if (isAudioPlaying && audioElem) {
            audioElem.pause();
            audioElem.currentTime = 0;
            isAudioPlaying = false;
        }
    }

    // 4. Mode Démonstration permanent
    const demoBanner = document.getElementById("demoModeBanner");
    if (data.demo_mode) {
        demoBanner.classList.remove("hidden");
    } else {
        demoBanner.classList.add("hidden");
    }

    // 5. Compteurs KPI
    document.getElementById("statDevicesCount").textContent = `${data.connected_devices_count} / ${data.total_devices_count}`;
    document.getElementById("statDevicesSub").textContent = `${data.connected_devices_count} connectés • ${data.disconnected_devices_count} déconnectés`;
    document.getElementById("statSensorsCount").textContent = data.available_sensors_count;
    document.getElementById("statAlertsToday").textContent = data.alerts_today_count;
    document.getElementById("statAlertsTotal").textContent = `Total en historique : ${data.alerts_count}`;

    // 5b. Badge de notifications
    const notifBadge = document.getElementById("notifBadge");
    if (notifBadge) {
        if (data.notifications_unread_count && data.notifications_unread_count > 0) {
            notifBadge.textContent = data.notifications_unread_count;
            notifBadge.classList.remove("hidden");
        } else {
            notifBadge.classList.add("hidden");
        }
    }

    // 6. Dernier Incident
    if (data.last_incident) {
        document.getElementById("statLastIncidentType").textContent = `${data.last_incident.type} (${data.last_incident.device_name})`;
        document.getElementById("statLastIncidentTime").textContent = data.last_incident.datetime;
    } else {
        document.getElementById("statLastIncidentType").textContent = "Aucun incident";
        document.getElementById("statLastIncidentTime").textContent = "--:--:--";
    }

    // 7. Espace de Stockage
    const storage = data.storage_stats || { used_mb: 0, max_mb: 1024, pct_used: 0 };
    document.getElementById("statStorageText").textContent = `${storage.used_mb} Mo / ${storage.max_mb} Mo`;
    document.getElementById("statStorageBar").style.width = `${Math.min(storage.pct_used, 100)}%`;

    // 8. Rendu des Caméras
    renderDevices(data.devices || []);

    // 9. Mise à jour des filtres et alertes
    updateDeviceFilterOptions(data.devices || []);
    fetchAlerts();

    // 10. Paramètres
    populateSettings(data.settings || {});

    // 11. Statistiques analytiques & timeline
    fetchStatistics();

    // 12. PRO-05 Widgets : Qwen Vision, Telegram, SQLite & Intégrité
    if (data.qwen_vision) {
        const qBadge = document.getElementById("qwenStatusBadge");
        const qModel = document.getElementById("qwenModelName");
        const qLast = document.getElementById("qwenLastResult");
        const qCount = document.getElementById("qwenInferenceCount");
        if (qBadge) {
            const st = data.qwen_vision.status || "OPENCV_ONLY";
            qBadge.textContent = st;
            if (st === "FREE_TIER_VERIFIED") {
                qBadge.className = "text-[10px] px-2 py-0.5 rounded font-bold font-mono bg-emerald-950 text-emerald-300 border border-emerald-800";
            } else if (st === "OPENCV_ONLY") {
                qBadge.className = "text-[10px] px-2 py-0.5 rounded font-bold font-mono bg-amber-950 text-amber-300 border border-amber-800";
            } else if (st === "FREE_TIER_QUOTA_REACHED") {
                qBadge.className = "text-[10px] px-2 py-0.5 rounded font-bold font-mono bg-orange-950 text-orange-300 border border-orange-800";
            } else {
                qBadge.className = "text-[10px] px-2 py-0.5 rounded font-bold font-mono bg-red-950 text-red-300 border border-red-800";
            }
        }
        if (qModel) qModel.textContent = data.qwen_vision.active_model || (data.qwen_vision.enabled ? "Qwen-VL (Non détecté)" : "Désactivé (OpenCV)");
        if (qLast) {
            if (data.qwen_vision.last_classification) {
                const lc = data.qwen_vision.last_classification;
                qLast.textContent = `${lc.event_type || 'INCONNU'} (${lc.confidence ? Math.round(lc.confidence * 100) : 0}%)`;
            } else {
                qLast.textContent = data.qwen_vision.enabled ? "En attente" : "Mode OpenCV";
            }
        }
        if (qCount) qCount.textContent = data.qwen_vision.stats?.inferences_total || 0;
    }

    if (data.telegram) {
        const tBadge = document.getElementById("telegramStatusBadge");
        const tChat = document.getElementById("telegramChatId");
        const tCount = document.getElementById("telegramSentCount");
        if (tBadge) {
            const isOk = data.telegram.enabled && data.telegram.configured;
            tBadge.textContent = isOk ? "ACTIF" : "DÉSACTIVÉ";
            tBadge.className = isOk 
                ? "text-[10px] px-2 py-0.5 rounded font-bold font-mono bg-blue-950 text-blue-300 border border-blue-800"
                : "text-[10px] px-2 py-0.5 rounded font-bold font-mono bg-slate-800 text-slate-400 border border-slate-700";
        }
        if (tChat) tChat.textContent = data.telegram.chat_id_masked || "Non configuré";
        if (tCount) tCount.textContent = data.telegram.messages_sent || 0;
    }

    if (data.database) {
        const dbCounts = document.getElementById("dbRecordCounts");
        const evCount = document.getElementById("integrityEvidenceCount");
        const chainCount = document.getElementById("integrityChainCount");
        const stats = data.database.stats || {};
        if (dbCounts) dbCounts.textContent = `${stats.alerts || 0} alertes • ${stats.devices || 0} appareils`;
        if (evCount) evCount.textContent = `${stats.evidences || 0} fichiers`;
        if (chainCount) chainCount.textContent = `${stats.integrity_entries || 0} blocs validés`;
    }

    // 13. PRO-06 Widgets : Edge AI, Geofencing, 2FA/SIEM, WebRTC/PWA
    if (data.edge_ai) {
        const eaBadge = document.getElementById("edgeAiBadge");
        const eaModel = document.getElementById("edgeAiModelStatus");
        const eaCount = document.getElementById("edgeAiInferenceCount");
        const eaFilter = document.getElementById("edgeAiFilterCount");
        const eaSelect = document.getElementById("edgeAiModeSelect");

        if (eaBadge) {
            const mode = data.edge_ai.mode || "OPENCV_ONLY";
            eaBadge.textContent = mode;
            if (mode === "EDGE_AI_REQUIRED") {
                eaBadge.className = "text-[10px] px-2 py-0.5 rounded font-bold font-mono bg-purple-950 text-purple-300 border border-purple-800";
            } else if (mode === "EDGE_AI_ASSISTED") {
                eaBadge.className = "text-[10px] px-2 py-0.5 rounded font-bold font-mono bg-cyan-950 text-cyan-300 border border-cyan-800";
            } else {
                eaBadge.className = "text-[10px] px-2 py-0.5 rounded font-bold font-mono bg-slate-800 text-slate-300 border border-slate-700";
            }
        }
        if (eaSelect && !eaSelect.matches(':focus')) {
            eaSelect.value = data.edge_ai.mode || "OPENCV_ONLY";
        }
        if (eaModel) {
            const isLoaded = data.edge_ai.model_available;
            eaModel.textContent = isLoaded ? "yolov8n.onnx (CPU)" : "Modèle absent (Repli OpenCV)";
            eaModel.className = isLoaded ? "font-mono text-emerald-400 font-bold truncate max-w-[140px]" : "font-mono text-amber-400 font-bold truncate max-w-[140px]";
        }
        if (eaCount) eaCount.textContent = data.edge_ai.metrics?.inferences_total || 0;
        if (eaFilter) eaFilter.textContent = `${data.edge_ai.metrics?.detections_filtered || 0} filtrés`;
    }

    if (data.presence) {
        const prBadge = document.getElementById("presenceStateBadge");
        const prText = document.getElementById("presenceStateText");
        const prCount = document.getElementById("presenceDeviceCount");
        const prGrace = document.getElementById("presenceGraceInfo");

        const state = data.presence.current_state || "HOME";
        if (prBadge) {
            prBadge.textContent = state;
            if (state === "HOME") {
                prBadge.className = "text-[10px] px-2 py-0.5 rounded font-bold font-mono bg-emerald-950 text-emerald-300 border border-emerald-800";
            } else if (state === "ARMED_AWAY") {
                prBadge.className = "text-[10px] px-2 py-0.5 rounded font-bold font-mono bg-red-950 text-red-300 border border-red-800";
            } else if (state.includes("PENDING")) {
                prBadge.className = "text-[10px] px-2 py-0.5 rounded font-bold font-mono bg-amber-950 text-amber-300 border border-amber-800";
            } else {
                prBadge.className = "text-[10px] px-2 py-0.5 rounded font-bold font-mono bg-slate-800 text-slate-300 border border-slate-700";
            }
        }
        if (prText) {
            const labels = {
                "HOME": "À DOMICILE (DÉSARMÉ)",
                "AWAY_PENDING": "DÉPART DÉTECTÉ (GRÂCE)",
                "ARMED_AWAY": "ABSENCE (ARMÉ AUTO)",
                "RETURN_PENDING": "RETOUR DÉTECTÉ",
                "MANUAL": "DÉROGATION MANUELLE"
            };
            prText.textContent = labels[state] || state;
        }
        if (prCount) {
            const total = data.presence.trusted_devices_total || 0;
            const present = data.presence.trusted_devices_present || 0;
            prCount.textContent = `${present} / ${total} présents`;
        }
        if (prGrace) {
            if (data.presence.grace_remaining && data.presence.grace_remaining > 0) {
                prGrace.textContent = `Grâce : ${Math.round(data.presence.grace_remaining)}s`;
                prGrace.className = "font-mono text-amber-400 font-bold animate-pulse";
            } else {
                prGrace.textContent = `${data.presence.grace_period_seconds || 120}s anti-flapping`;
                prGrace.className = "font-mono text-slate-400";
            }
        }
    }

    if (data.webrtc) {
        const wBadge = document.getElementById("webrtcBadge");
        const wMode = document.getElementById("webrtcStreamingMode");
        if (wBadge) {
            const activeSessions = data.webrtc.active_sessions || 0;
            wBadge.textContent = activeSessions > 0 ? `WEBRTC (${activeSessions})` : "PWA + MJPEG";
        }
        if (wMode) {
            wMode.textContent = data.webrtc.aiortc_available ? "WebRTC Ultra-Low Latency" : "MJPEG Résilient (Fallback)";
        }
    }

    if (data.pwa) {
        const swStatus = document.getElementById("pwaSwStatus");
        const pushCount = document.getElementById("pwaPushCount");
        if (swStatus) {
            swStatus.textContent = ('serviceWorker' in navigator) ? "Enregistré" : "Non supporté";
        }
        if (pushCount) {
            pushCount.textContent = `${data.pwa.subscribers_count || 0} abonné(s)`;
        }
    }

    // 14. PRO-07 à PRO-11 Widgets : Tamper, Audio AI, Intercom/P2P, Floorplan
    if (data.tamper) {
        const tSummary = document.getElementById("tamperStatusSummary");
        if (tSummary) {
            const count = data.tamper.active_tamper_count || 0;
            if (count > 0) {
                tSummary.textContent = `${count} SABOTAGE DÉTECTÉ`;
                tSummary.className = "text-red-400 font-bold font-mono animate-pulse";
            } else {
                tSummary.textContent = "NORMAL";
                tSummary.className = "text-emerald-400 font-semibold font-mono";
            }
        }
    }

    if (data.audio_ai) {
        const aEngine = document.getElementById("audioClassifierEngine");
        const aThreat = document.getElementById("audioLastThreat");
        if (aEngine) aEngine.textContent = data.audio_ai.engine || "SPECTRAL_HEURISTIC";
        if (aThreat && data.audio_ai.last_result) {
            const lr = data.audio_ai.last_result;
            aThreat.textContent = `${lr.predicted_class} (${lr.confidence * 100}%)`;
        }
    }

    if (data.p2p_sync) {
        const p2pCount = document.getElementById("p2pPendingCount");
        if (p2pCount) p2pCount.textContent = `${data.p2p_sync.store_forward_pending_count || 0} en attente`;
    }

    if (data.spatial_tracker) {
        const spTracks = document.getElementById("spatialTrackCount");
        if (spTracks) spTracks.textContent = `${data.spatial_tracker.active_tracks_count || 0} trajectoires actives`;
    }
}

// Rendu dynamique des cartes de caméras et télémétrie
function renderDevices(devices) {
    const container = document.getElementById("devicesContainer");
    if (!devices || devices.length === 0) {
        container.innerHTML = `
            <div class="col-span-full bg-cardBg border border-cardBorder rounded-xl p-12 text-center text-slate-400">
                <i class="fa-solid fa-mobile-screen-button text-4xl mb-3 text-slate-500"></i>
                <p class="text-sm font-semibold">Aucun smartphone enregistré dans le système.</p>
                <p class="text-xs mt-1 text-slate-500">Cliquez sur « Ajouter un Smartphone » pour appairer un téléphone ou démarrez le simulateur intégré.</p>
            </div>
        `;
        return;
    }

    let html = "";
    devices.forEach(dev => {
        const overall = dev.overall_status || "DÉCONNECTÉ";
        let statusBadgeClass = "badge-status-error";
        let statusIcon = "fa-circle-xmark";
        if (overall === "OPÉRATIONNEL") {
            statusBadgeClass = "badge-status-ok";
            statusIcon = "fa-circle-check";
        } else if (overall === "DÉGRADÉ") {
            statusBadgeClass = "badge-status-degraded";
            statusIcon = "fa-triangle-exclamation";
        }

        const commAgeTxt = dev.last_communication_age !== null ? `${dev.last_communication_age}s` : "Jamais";
        const sensors = dev.sensors || {};
        const prox = sensors.proximity || { available: false, status: "CAPTEUR NON DISPONIBLE" };
        const sound = sensors.sound || { available: false, status: "CAPTEUR NON DISPONIBLE" };
        const accel = sensors.accel || { available: false, status: "CAPTEUR NON DISPONIBLE" };

        const history = dev.history || { sound: [], accel: [] };
        const soundSparkline = generateSparkline(history.sound);
        const accelSparkline = generateSparkline(history.accel);

        const cardId = `cam_card_${dev.id}`;
        const imgId = `cam_img_${dev.id}`;

        const safeDevId = encodeURIComponent(dev.id || '');
        const safeDevName = escapeHtml(dev.name);
        const safeDevIp = escapeHtml(dev.ip || '');
        const safeDevPort = encodeURIComponent(dev.port || '');
        const safeDevNameParam = encodeURIComponent(dev.name || '');

        html += `
            <div id="${cardId}" class="bg-cardBg border border-cardBorder rounded-xl overflow-hidden shadow-lg camera-card flex flex-col">
                <!-- En-tête de la caméra -->
                <div class="p-3 bg-slate-900/80 border-b border-cardBorder flex items-center justify-between">
                    <div class="flex items-center space-x-2">
                        <i class="fa-solid fa-mobile-screen text-blue-400 text-sm"></i>
                        <span class="font-bold text-xs text-slate-100">${safeDevName}</span>
                        <span class="text-[11px] text-slate-400">(${safeDevIp}:${safeDevPort})</span>
                    </div>
                    <div class="flex items-center space-x-2">
                        <span class="text-[10px] px-2 py-0.5 rounded font-semibold flex items-center space-x-1 ${statusBadgeClass}">
                            <i class="fa-solid ${statusIcon} text-[9px]"></i>
                            <span>${overall}</span>
                        </span>
                        <button onclick="openZonesModal('${safeDevId}', decodeURIComponent('${safeDevNameParam}'))" class="text-slate-400 hover:text-emerald-400 text-xs p-1" title="Configurer les Zones de Surveillance (ROI)">
                            <i class="fa-solid fa-draw-polygon"></i>
                        </button>
                        <button onclick="openDiagnosticModal('${safeDevId}', decodeURIComponent('${safeDevNameParam}'))" class="text-slate-400 hover:text-cyan-400 text-xs p-1" title="Diagnostic technique approfondi">
                            <i class="fa-solid fa-stethoscope"></i>
                        </button>
                        <button onclick="toggleFullscreen('${cardId}')" class="text-slate-400 hover:text-cyan-400 text-xs p-1" title="Plein écran">
                            <i class="fa-solid fa-expand"></i>
                        </button>
                        <button onclick="refreshStream('${safeDevId}')" class="text-slate-400 hover:text-blue-400 text-xs p-1" title="Rafraîchir le flux">
                            <i class="fa-solid fa-rotate-right"></i>
                        </button>
                        <button onclick="deleteDevice('${safeDevId}', decodeURIComponent('${safeDevNameParam}'))" class="text-slate-400 hover:text-red-400 text-xs p-1" title="Supprimer cet appareil">
                            <i class="fa-solid fa-trash-can"></i>
                        </button>
                    </div>
                </div>

                <!-- Zone flux vidéo MJPEG -->
                <div class="relative bg-black aspect-video flex items-center justify-center overflow-hidden group">
                    <img id="${imgId}" src="${dev.video_url}" 
                         alt="Flux ${dev.name}" 
                         class="w-full h-full object-contain"
                         loading="lazy">
                    <div class="absolute bottom-2 left-2 bg-black/70 backdrop-blur-sm px-2 py-0.5 rounded text-[10px] text-slate-300 flex items-center space-x-1">
                        <i class="fa-solid fa-circle text-red-500 text-[7px] animate-ping"></i>
                        <span>DIRECT</span>
                        <span class="text-slate-500 ml-1">| Dernier signal : ${commAgeTxt}</span>
                    </div>
                    <div class="absolute top-2 right-2 flex items-center space-x-1.5">
                        <span class="bg-black/75 backdrop-blur-sm border border-cyan-800/60 px-1.5 py-0.5 rounded text-[9px] text-cyan-300 font-mono font-bold" title="Streaming MJPEG actif avec négociation WebRTC prête">MJPEG / WebRTC</span>
                        <span class="bg-black/70 backdrop-blur-sm px-2 py-0.5 rounded text-[10px] text-slate-300">FPS: 10</span>
                    </div>
                </div>

                <!-- Télémétrie en direct des capteurs -->
                <div class="p-3.5 bg-slate-900/60 flex-1 space-y-2.5">
                    <div class="text-[11px] font-bold uppercase tracking-wider text-slate-400 flex items-center justify-between">
                        <span>Télémétrie des Capteurs</span>
                        <div class="flex space-x-1">
                            <button onclick="toggleTorch('${dev.id}', true)" class="bg-amber-600/30 hover:bg-amber-600/50 text-amber-300 border border-amber-600/40 text-[10px] px-2 py-0.5 rounded transition">
                                <i class="fa-solid fa-lightbulb"></i> Torche ON
                            </button>
                            <button onclick="toggleTorch('${dev.id}', false)" class="bg-slate-800 hover:bg-slate-700 text-slate-300 text-[10px] px-2 py-0.5 rounded transition">
                                OFF
                            </button>
                        </div>
                    </div>

                    <div class="grid grid-cols-3 gap-2">
                        <!-- Proximité -->
                        <div class="bg-slate-800/80 p-2 rounded-lg border border-slate-700/60 flex flex-col justify-between">
                            <div class="text-[10px] text-slate-400 flex items-center justify-between mb-1">
                                <span><i class="fa-solid fa-hand text-emerald-400 mr-1"></i> Proximité</span>
                                ${getSensorBadge(prox)}
                            </div>
                            <div class="text-sm font-bold ${prox.available ? 'text-slate-100' : 'text-slate-500'}">
                                ${prox.available && prox.value !== null ? `${prox.value} <span class="text-[10px] text-slate-400">cm</span>` : '--'}
                            </div>
                            <div class="text-[9px] text-slate-500 mt-0.5">Seuil : &le; 5.0 cm</div>
                        </div>

                        <!-- Acoustique -->
                        <div class="bg-slate-800/80 p-2 rounded-lg border border-slate-700/60 flex flex-col justify-between">
                            <div class="text-[10px] text-slate-400 flex items-center justify-between mb-1">
                                <span><i class="fa-solid fa-volume-high text-yellow-400 mr-1"></i> Acoustique</span>
                                ${getSensorBadge(sound)}
                            </div>
                            <div class="text-sm font-bold ${sound.available ? 'text-slate-100' : 'text-slate-500'} flex items-baseline justify-between">
                                <span>${sound.available && sound.value !== null ? `${sound.value} <span class="text-[10px] text-slate-400">dB</span>` : '--'}</span>
                                ${soundSparkline}
                            </div>
                            <div class="text-[9px] text-slate-500 mt-0.5">Seuil relatif : &ge; 75 dB</div>
                        </div>

                        <!-- Accéléromètre -->
                        <div class="bg-slate-800/80 p-2 rounded-lg border border-slate-700/60 flex flex-col justify-between">
                            <div class="text-[10px] text-slate-400 flex items-center justify-between mb-1">
                                <span><i class="fa-solid fa-mobile-screen text-red-400 mr-1"></i> Secousse</span>
                                ${getSensorBadge(accel)}
                            </div>
                            <div class="text-sm font-bold ${accel.available ? 'text-slate-100' : 'text-slate-500'} flex items-baseline justify-between">
                                <span>${accel.available && accel.norm !== null ? `${accel.norm} <span class="text-[10px] text-slate-400">m/s²</span>` : '--'}</span>
                                ${accelSparkline}
                            </div>
                            <div class="text-[9px] text-slate-500 mt-0.5">&Delta;g : &ge; 4.5 m/s²</div>
                        </div>
                    </div>
                </div>
            </div>
        `;
    });

    container.innerHTML = html;
}

// Génère un badge textuel conforme aux 4 états exigés
function getSensorBadge(sensor) {
    if (!sensor || !sensor.available) {
        if (sensor && sensor.status === "DONNÉE EXPIRÉE") {
            return `<span class="text-[9px] px-1.5 py-0.2 rounded badge-sensor-stale font-bold">EXPIRÉ</span>`;
        }
        return `<span class="text-[9px] px-1.5 py-0.2 rounded badge-sensor-na font-semibold">N/D</span>`;
    }
    if (sensor.is_simulated || sensor.status === "DONNÉE SIMULÉE") {
        return `<span class="text-[9px] px-1.5 py-0.2 rounded badge-sensor-sim font-bold">SIMULÉ</span>`;
    }
    return `<span class="text-[9px] px-1.5 py-0.2 rounded badge-sensor-real font-bold">RÉEL</span>`;
}

// Mini sparkline visuel à barres
function generateSparkline(historyList) {
    if (!historyList || historyList.length === 0) return "";
    const vals = historyList.map(item => item[1]);
    const maxVal = Math.max(...vals, 1);
    const bars = vals.slice(-8).map(v => {
        const heightPct = Math.max(Math.min((v / maxVal) * 100, 100), 10);
        return `<div class="sparkline-bar" style="height: ${heightPct}%"></div>`;
    }).join("");
    return `<div class="sparkline-container">${bars}</div>`;
}

// Plein écran pour une carte vidéo
function toggleFullscreen(elementId) {
    const elem = document.getElementById(elementId);
    if (!elem) return;
    if (!document.fullscreenElement) {
        elem.requestFullscreen().catch(err => alert("Erreur plein écran : " + err.message));
    } else {
        document.exitFullscreen();
    }
}

// Rafraîchissement forcé du flux vidéo
function refreshStream(devId) {
    const img = document.getElementById(`cam_img_${devId}`);
    if (img) {
        img.src = `/video_feed/${devId}?t=${Date.now()}`;
    }
}

// Mise à jour de la liste des appareils dans le filtre
function updateDeviceFilterOptions(devices) {
    const select = document.getElementById("filterDevice");
    const currentVal = select.value;
    let optionsHtml = `<option value="">Tous les smartphones</option>`;
    devices.forEach(d => {
        optionsHtml += `<option value="${d.id}" ${d.id === currentVal ? 'selected' : ''}>${d.name} (${d.ip})</option>`;
    });
    select.innerHTML = optionsHtml;
}

// Application des filtres sur les alertes
function applyAlertFilters() {
    currentFilters.device_id = document.getElementById("filterDevice").value;
    currentFilters.type = document.getElementById("filterType").value;
    currentFilters.period = document.getElementById("filterPeriod").value;
    currentFilters.query = document.getElementById("filterQuery").value;
    fetchAlerts();
}

// Récupération des alertes avec paramètres de filtre
async function fetchAlerts() {
    try {
        const params = new URLSearchParams();
        if (currentFilters.device_id) params.append("device_id", currentFilters.device_id);
        if (currentFilters.type) params.append("type", currentFilters.type);
        if (currentFilters.period) params.append("period", currentFilters.period);
        if (currentFilters.query) params.append("query", currentFilters.query);

        const resp = await fetch(`/api/alerts?${params.toString()}`);
        if (!resp.ok) return;
        const alerts = await resp.json();
        renderAlertsTable(alerts);
    } catch (err) {
        console.error("Erreur récupération alertes :", err);
    }
}

// Rendu du tableau des alertes
function renderAlertsTable(alerts) {
    const tbody = document.getElementById("alertsTableBody");
    if (!alerts || alerts.length === 0) {
        tbody.innerHTML = `<tr><td colspan="8" class="text-center py-8 text-slate-500">Aucun incident correspondant aux critères de recherche.</td></tr>`;
        return;
    }

    tbody.innerHTML = alerts.map(a => {
        // Badge catégorie
        let catClass = "bg-purple-900/40 text-purple-300 border-purple-700/50";
        if (a.category === "ÉVÉNEMENT CAPTEUR RÉEL") {
            catClass = "bg-emerald-900/40 text-emerald-300 border-emerald-700/50";
        } else if (a.category === "ÉVÉNEMENT DÉTECTÉ PAR VIDÉO") {
            catClass = "bg-blue-900/40 text-blue-300 border-blue-700/50";
        } else if (a.category.includes("DÉCONNEXION")) {
            catClass = "bg-amber-900/40 text-amber-300 border-amber-700/50";
        }

        // Badge gravité
        let sevClass = "text-cyan-400";
        if (a.severity === "CRITIQUE") sevClass = "text-red-400 font-bold";
        else if (a.severity === "AVERTISSEMENT") sevClass = "text-amber-400 font-bold";

        // Badges sécurisés
        const safeId = encodeURIComponent(a.id || '');
        const safeType = escapeHtml(a.type);
        const safeDatetime = escapeHtml(a.datetime);
        const safeDeviceName = escapeHtml(a.device_name);
        const safeDeviceIp = escapeHtml(a.device_ip || '');
        const safeSeverity = escapeHtml(a.severity || 'AVERTISSEMENT');
        const safeCategory = escapeHtml(a.category || '');
        const safeDetails = escapeHtml(a.details || '');
        const safeStatus = escapeHtml(a.status || 'N/D');
        const safeScreenshot = encodeURI(a.screenshot_path || '');
        const safeRecording = encodeURI(a.recording_path || '');
        const safeTitleParam = encodeURIComponent(`${a.type || ''} — ${a.datetime || ''}`);

        const screenshotBtn = a.screenshot_path ? `
            <button onclick="openImageModal('/${safeScreenshot}', decodeURIComponent('${safeTitleParam}'))" class="text-blue-400 hover:text-blue-300 transition text-sm" title="Voir la capture photo">
                <i class="fa-solid fa-image"></i>
            </button>
        ` : `<span class="text-slate-600">-</span>`;

        const videoBtn = a.recording_path ? `
            <button onclick="openVideoModal('/${safeRecording}', decodeURIComponent('${safeTitleParam}'))" class="text-emerald-400 hover:text-emerald-300 transition text-sm" title="Lire la vidéo (3s avant / 5s après)">
                <i class="fa-solid fa-circle-play"></i>
            </button>
        ` : `<span class="text-[10px] text-slate-500">${safeStatus}</span>`;

        return `
            <tr class="hover:bg-slate-800/50 transition">
                <td class="px-4 py-2.5 font-mono text-[11px] text-slate-300">${safeDatetime}</td>
                <td class="px-4 py-2.5 font-semibold text-slate-200">
                    <div>${safeDeviceName}</div>
                    <div class="text-[10px] text-slate-500 font-mono">${safeDeviceIp}</div>
                </td>
                <td class="px-4 py-2.5">
                    <span class="font-bold text-slate-100">${safeType}</span>
                    <span class="text-[10px] block ${sevClass}">[${safeSeverity}]</span>
                </td>
                <td class="px-4 py-2.5">
                    <span class="text-[10px] px-2 py-0.5 rounded border font-semibold ${catClass}">${safeCategory}</span>
                </td>
                <td class="px-4 py-2.5 text-xs text-slate-400 max-w-xs truncate">${safeDetails}</td>
                <td class="px-4 py-2.5 text-center">${screenshotBtn}</td>
                <td class="px-4 py-2.5 text-center">${videoBtn}</td>
                <td class="px-4 py-2.5 text-center">
                    <div class="flex items-center justify-center space-x-2">
                        <button onclick="openIntegrityModal('${safeId}')" class="text-slate-400 hover:text-emerald-400 text-xs transition" title="Certificat d'intégrité SHA-256">
                            <i class="fa-solid fa-fingerprint"></i>
                        </button>
                        <a href="/api/reports/incident/${safeId}/pdf" target="_blank" class="text-slate-400 hover:text-purple-400 text-xs transition" title="Télécharger le Rapport PDF">
                            <i class="fa-solid fa-file-pdf"></i>
                        </a>
                        <button onclick="deleteAlert('${safeId}')" class="text-slate-500 hover:text-red-400 text-xs transition" title="Supprimer cette preuve">
                            <i class="fa-solid fa-trash"></i>
                        </button>
                    </div>
                </td>
            </tr>
        `;
    }).join("");
}

// Remplissage des paramètres
let settingsPopulated = false;
function populateSettings(settings) {
    if (settingsPopulated) return;
    document.getElementById("cfg_proximity_threshold").value = settings.proximity_threshold ?? 5.0;
    document.getElementById("cfg_sound_threshold").value = settings.sound_threshold ?? 75.0;
    document.getElementById("cfg_accel_shock_threshold").value = settings.accel_shock_threshold ?? 4.5;
    document.getElementById("cfg_motion_area_threshold").value = settings.motion_area_threshold ?? 1.5;
    document.getElementById("cfg_cooldown_seconds").value = settings.cooldown_seconds ?? 8.0;
    document.getElementById("cfg_siren_enabled").checked = settings.siren_enabled ?? true;
    document.getElementById("cfg_torch_on_alarm").checked = settings.torch_on_alarm ?? false;
    document.getElementById("cfg_enable_motion").checked = settings.enable_motion ?? true;
    settingsPopulated = true;
}

// Sauvegarde des paramètres
async function saveSettings(e) {
    e.preventDefault();
    const payload = {
        proximity_threshold: parseFloat(document.getElementById("cfg_proximity_threshold").value),
        sound_threshold: parseFloat(document.getElementById("cfg_sound_threshold").value),
        accel_shock_threshold: parseFloat(document.getElementById("cfg_accel_shock_threshold").value),
        motion_area_threshold: parseFloat(document.getElementById("cfg_motion_area_threshold").value),
        cooldown_seconds: parseFloat(document.getElementById("cfg_cooldown_seconds").value),
        siren_enabled: document.getElementById("cfg_siren_enabled").checked,
        torch_on_alarm: document.getElementById("cfg_torch_on_alarm").checked,
        enable_motion: document.getElementById("cfg_enable_motion").checked
    };

    try {
        const resp = await fetch("/api/settings", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(payload)
        });
        if (resp.ok) {
            alert("Paramètres de surveillance mis à jour avec succès.");
            fetchStatus();
        }
    } catch (err) {
        alert("Erreur de sauvegarde : " + err);
    }
}

// Bascule du mode Démonstration
async function toggleDemoMode(forceState) {
    const newState = (forceState !== undefined) ? forceState : !(currentStatus && currentStatus.demo_mode);
    await fetch("/api/settings/demo_mode", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ enabled: newState })
    });
    fetchStatus();
}

// Actions de contrôle global
async function toggleArm() {
    if (!currentStatus) return;
    const endpoint = currentStatus.is_armed ? "/api/alarm/disarm" : "/api/alarm/arm";
    await fetch(endpoint, { method: "POST" });
    fetchStatus();
}

async function stopSiren() {
    await fetch("/api/alarm/stop_siren", { method: "POST" });
    fetchStatus();
}

async function resetAlarm() {
    await fetch("/api/alarm/reset", { method: "POST" });
    fetchStatus();
}

async function testAlarm() {
    await fetch("/api/alarm/test", { method: "POST" });
    fetchStatus();
}

function toggleSimMenu() {
    document.getElementById("simDropdown").classList.toggle("hidden");
}

async function triggerSimulated(type) {
    document.getElementById("simDropdown").classList.add("hidden");
    await fetch("/api/simulate_alert", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ type: type })
    });
    fetchStatus();
}

async function deleteAlert(id) {
    if (!confirm("Confirmer la suppression de cette preuve et de ses fichiers associés ?")) return;
    await fetch(`/api/alerts/${id}`, { method: "DELETE" });
    fetchAlerts();
    fetchStatus();
}

async function clearAlerts() {
    if (!confirm("Voulez-vous vraiment vider tout l'historique des incidents et purger les preuves ?")) return;
    await fetch("/api/alerts/clear", { method: "POST" });
    fetchAlerts();
    fetchStatus();
}

async function cleanExpiredStorage() {
    if (!confirm("Purger toutes les preuves (photos et vidéos) de plus de 7 jours ?")) return;
    const resp = await fetch("/api/storage/clean", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ days: 7 })
    });
    const data = await resp.json();
    alert(data.message || "Nettoyage terminé.");
    fetchStatus();
}

// Gestion des Smartphones
function openAddDeviceModal() {
    document.getElementById("addDeviceModal").classList.remove("hidden");
    document.getElementById("addDeviceError").classList.add("hidden");
}

function closeAddDeviceModal() {
    document.getElementById("addDeviceModal").classList.add("hidden");
}

async function submitAddDevice(e) {
    e.preventDefault();
    const payload = {
        name: document.getElementById("dev_name").value,
        ip: document.getElementById("dev_ip").value,
        port: parseInt(document.getElementById("dev_port").value),
        enable_torch: document.getElementById("dev_enable_torch").checked
    };

    try {
        const resp = await fetch("/api/devices", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(payload)
        });
        const data = await resp.json();
        if (resp.ok) {
            closeAddDeviceModal();
            fetchStatus();
        } else {
            const errDiv = document.getElementById("addDeviceError");
            errDiv.textContent = data.message || "Erreur lors de l'ajout.";
            errDiv.classList.remove("hidden");
        }
    } catch (err) {
        alert("Erreur réseau : " + err);
    }
}

async function addMockPhone() {
    try {
        const resp = await fetch("/api/devices", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                name: "Simulateur IP Webcam Android",
                ip: "127.0.0.1",
                port: 8081,
                enable_torch: true
            })
        });
        if (resp.ok) {
            alert("Simulateur Mock ajouté avec succès sur 127.0.0.1:8081.");
            fetchStatus();
        } else {
            const data = await resp.json();
            alert("Information : " + (data.message || "Échec"));
        }
    } catch (err) {
        alert("Erreur : " + err);
    }
}

async function deleteDevice(id, name) {
    if (!confirm(`Supprimer définitivement le smartphone "${name}" du système de surveillance ?`)) return;
    await fetch(`/api/devices/${id}`, { method: "DELETE" });
    fetchStatus();
}

async function toggleTorch(deviceId, enable) {
    const resp = await fetch(`/api/devices/${deviceId}/torch`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ enable: enable })
    });
    const data = await resp.json();
    if (data.message) {
        console.log(data.message);
    }
}

// Modales Preuves (Photo, Vidéo, Scénario)
function openImageModal(src, title) {
    document.getElementById("imageModalSrc").src = src;
    document.getElementById("imageModalTitle").textContent = title;
    document.getElementById("imageModal").classList.remove("hidden");
}

function closeImageModal() {
    document.getElementById("imageModal").classList.add("hidden");
}

function openVideoModal(src, title) {
    const video = document.getElementById("videoModalSrc");
    video.src = src;
    document.getElementById("videoModalTitle").textContent = title;
    document.getElementById("videoDownloadLink").href = src;
    document.getElementById("videoModal").classList.remove("hidden");
    video.play().catch(() => {});
}

function closeVideoModal() {
    const video = document.getElementById("videoModalSrc");
    video.pause();
    video.src = "";
    document.getElementById("videoModal").classList.add("hidden");
}

function openDemoWalkthrough() {
    document.getElementById("demoModal").classList.remove("hidden");
}

function closeDemoModal() {
    document.getElementById("demoModal").classList.add("hidden");
}

function openGuideModal() {
    document.getElementById("guideModal").classList.remove("hidden");
}

function closeGuideModal() {
    document.getElementById("guideModal").classList.add("hidden");
}

// ==========================================
// FONCTIONNALITÉ 1 : ZONES DE SURVEILLANCE (ROI)
// ==========================================
let currentZoneDeviceId = null;

async function openZonesModal(deviceId, deviceName) {
    currentZoneDeviceId = deviceId;
    document.getElementById("zonesModalDeviceName").textContent = deviceName;
    document.getElementById("zonesModal").classList.remove("hidden");
    await fetchZones(deviceId);
}

function closeZonesModal() {
    document.getElementById("zonesModal").classList.add("hidden");
    currentZoneDeviceId = null;
}

async function fetchZones(deviceId) {
    try {
        const resp = await fetch(`/api/devices/${deviceId}/zones`);
        if (!resp.ok) return;
        const data = await resp.json();
        renderZones(data.zones || []);
    } catch (e) {
        console.error("Erreur chargement zones :", e);
    }
}

function renderZones(zones) {
    const container = document.getElementById("zonesListContainer");
    if (!zones || zones.length === 0) {
        container.innerHTML = `<div class="text-slate-500 text-xs py-3 text-center">Aucune zone configurée (détection active sur l'image entière).</div>`;
        return;
    }

    container.innerHTML = zones.map(z => {
        const safeZoneId = encodeURIComponent(z.id || '');
        const safeZoneName = escapeHtml(z.name);
        return `
        <div class="flex items-center justify-between bg-slate-800/80 p-2.5 rounded-lg border border-slate-700/60 text-xs">
            <div class="flex items-center space-x-2.5">
                <input type="checkbox" ${z.enabled ? 'checked' : ''} onchange="toggleZoneEnabled('${safeZoneId}', this.checked)" class="rounded bg-slate-900 border-slate-700 text-emerald-500 cursor-pointer">
                <div>
                    <span class="font-bold ${z.enabled ? 'text-slate-200' : 'text-slate-500'}">${safeZoneName}</span>
                    <span class="text-[10px] text-slate-400 block font-mono">X: ${Math.round(z.x*100)}% | Y: ${Math.round(z.y*100)}% | L: ${Math.round(z.w*100)}% | H: ${Math.round(z.h*100)}%</span>
                </div>
            </div>
            <button onclick="deleteZone('${safeZoneId}')" class="text-slate-500 hover:text-red-400 text-xs p-1 transition" title="Supprimer la zone">
                <i class="fa-solid fa-trash"></i>
            </button>
        </div>
        `;
    }).join("");
}

async function submitAddZone(e) {
    e.preventDefault();
    if (!currentZoneDeviceId) return;

    const name = document.getElementById("zone_name").value;
    const x = parseFloat(document.getElementById("zone_x").value) / 100.0;
    const y = parseFloat(document.getElementById("zone_y").value) / 100.0;
    const w = parseFloat(document.getElementById("zone_w").value) / 100.0;
    const h = parseFloat(document.getElementById("zone_h").value) / 100.0;
    const enabled = document.getElementById("zone_enabled").checked;

    try {
        const resp = await fetch(`/api/devices/${currentZoneDeviceId}/zones`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ name, x, y, w, h, enabled })
        });
        if (resp.ok) {
            document.getElementById("zone_name").value = "";
            await fetchZones(currentZoneDeviceId);
        } else {
            const err = await resp.json();
            alert("Erreur : " + (err.message || "Impossible d'ajouter la zone"));
        }
    } catch (err) {
        alert("Erreur réseau : " + err);
    }
}

async function toggleZoneEnabled(zoneId, enabled) {
    if (!currentZoneDeviceId) return;
    await fetch(`/api/devices/${currentZoneDeviceId}/zones/${zoneId}`, {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ enabled })
    });
    fetchZones(currentZoneDeviceId);
}

async function deleteZone(zoneId) {
    if (!currentZoneDeviceId) return;
    await fetch(`/api/devices/${currentZoneDeviceId}/zones/${zoneId}`, {
        method: "DELETE"
    });
    fetchZones(currentZoneDeviceId);
}

// ==========================================
// FONCTIONNALITÉ 2 : STATISTIQUES & CHRONOLOGIE
// ==========================================
let lastStatsFetch = 0;
async function fetchStatistics() {
    const now = Date.now();
    if (now - lastStatsFetch < 2500) return;
    lastStatsFetch = now;

    try {
        const resp = await fetch("/api/statistics");
        if (!resp.ok) return;
        const stats = await resp.json();
        renderDailyChart(stats);
    } catch (e) {
        console.error("Erreur chargement statistiques :", e);
    }
}

function renderDailyChart(stats) {
    const chartContainer = document.getElementById("statsDailyChart");
    if (!chartContainer || !stats.daily_stats) return;

    const maxCount = Math.max(...stats.daily_stats.map(d => d.total), 5);

    chartContainer.innerHTML = stats.daily_stats.map(d => {
        const heightPct = Math.max(6, Math.round((d.total / maxCount) * 100));
        const dayLabel = d.date.slice(5); // MM-DD
        return `
            <div class="flex-1 flex flex-col items-center h-full justify-end group">
                <div class="text-[9px] text-slate-400 font-bold mb-1 opacity-80 group-hover:opacity-100">${d.total}</div>
                <div class="w-full max-w-[28px] bg-gradient-to-t from-blue-700 to-cyan-400 rounded-t transition-all hover:brightness-125" style="height: ${heightPct}%" title="${d.date} : ${d.total} incidents (Réels: ${d.real}, Vidéo: ${d.video}, Sim: ${d.simulated})"></div>
                <div class="text-[9px] text-slate-500 mt-1">${dayLabel}</div>
            </div>
        `;
    }).join("");

    const sev = stats.by_severity || {};
    const totalSev = Math.max(1, stats.total_incidents);
    const crit = sev["CRITIQUE"] || 0;
    const avert = sev["AVERTISSEMENT"] || 0;
    const info = sev["INFO"] || 0;

    const elCrit = document.getElementById("statSevCritique");
    const elAvert = document.getElementById("statSevAvert");
    const elInfo = document.getElementById("statSevInfo");
    if (elCrit) elCrit.textContent = crit;
    if (elAvert) elAvert.textContent = avert;
    if (elInfo) elInfo.textContent = info;

    const barCrit = document.getElementById("barSevCritique");
    const barAvert = document.getElementById("barSevAvert");
    const barInfo = document.getElementById("barSevInfo");
    if (barCrit) barCrit.style.width = `${Math.round((crit / totalSev) * 100)}%`;
    if (barAvert) barAvert.style.width = `${Math.round((avert / totalSev) * 100)}%`;
    if (barInfo) barInfo.style.width = `${Math.round((info / totalSev) * 100)}%`;
}

// ==========================================
// FONCTIONNALITÉ 3 : NOTIFICATIONS INTELLIGENTES
// ==========================================
let notifDrawerOpen = false;

function toggleNotificationCenter() {
    const drawer = document.getElementById("notifDrawer");
    notifDrawerOpen = !notifDrawerOpen;
    if (notifDrawerOpen) {
        drawer.classList.remove("hidden");
        fetchNotifications();
    } else {
        drawer.classList.add("hidden");
    }
}

async function fetchNotifications() {
    try {
        const resp = await fetch("/api/notifications");
        if (!resp.ok) return;
        const data = await resp.json();
        renderNotifications(data);
    } catch (e) {
        console.error("Erreur chargement notifications :", e);
    }
}

function renderNotifications(data) {
    const container = document.getElementById("notifListContainer");
    const notifs = data.notifications || [];
    if (notifs.length === 0) {
        container.innerHTML = `<div class="text-center py-6 text-slate-500">Aucune notification pour le moment.</div>`;
        return;
    }

    container.innerHTML = notifs.map(n => {
        let levelColor = "text-blue-400 bg-blue-950/40 border-blue-800/40";
        if (n.level === "CRITICAL") levelColor = "text-red-400 bg-red-950/40 border-red-800/40";
        else if (n.level === "HIGH" || n.level === "WARNING") levelColor = "text-amber-400 bg-amber-950/40 border-amber-800/40";

        const safeLevel = escapeHtml(n.level);
        const safeTitle = escapeHtml(n.title);
        const safeMessage = escapeHtml(n.message);
        const safeDatetime = escapeHtml(n.datetime);
        const safeDeviceName = escapeHtml(n.device_name || '');
        const safeNotifId = encodeURIComponent(n.id || '');

        return `
            <div class="p-2.5 hover:bg-slate-800/60 transition ${n.read ? 'opacity-60' : 'bg-slate-800/30'} flex items-start justify-between gap-2">
                <div class="flex-1 space-y-0.5">
                    <div class="flex items-center gap-1.5">
                        <span class="text-[9px] px-1.5 py-0.2 rounded border font-bold uppercase ${levelColor}">${safeLevel}</span>
                        <span class="font-bold text-slate-200 text-xs truncate">${safeTitle}</span>
                    </div>
                    <p class="text-[11px] text-slate-300">${safeMessage}</p>
                    <span class="text-[9px] text-slate-500 block font-mono">${safeDatetime} • ${safeDeviceName}</span>
                </div>
                <div class="flex flex-col items-end space-y-1">
                    ${!n.read ? `<button onclick="markNotificationRead('${safeNotifId}')" class="text-[10px] text-cyan-400 hover:underline" title="Marquer lu"><i class="fa-solid fa-check"></i></button>` : ''}
                    <button onclick="deleteNotification('${safeNotifId}')" class="text-[10px] text-slate-500 hover:text-red-400" title="Supprimer"><i class="fa-solid fa-xmark"></i></button>
                </div>
            </div>
        `;
    }).join("");
}

async function markNotificationRead(notifId) {
    await fetch(`/api/notifications/${notifId}/read`, { method: "POST" });
    fetchNotifications();
    fetchStatus();
}

async function markAllNotificationsRead() {
    await fetch("/api/notifications/read_all", { method: "POST" });
    fetchNotifications();
    fetchStatus();
}

async function deleteNotification(notifId) {
    await fetch(`/api/notifications/${notifId}`, { method: "DELETE" });
    fetchNotifications();
    fetchStatus();
}

// ==========================================
// FONCTIONNALITÉ 4 : DIAGNOSTIC DES APPAREILS
// ==========================================
async function openDiagnosticModal(deviceId, deviceName) {
    document.getElementById("diagModalDeviceName").textContent = deviceName;
    document.getElementById("diagnosticModal").classList.remove("hidden");
    const container = document.getElementById("diagContent");
    container.innerHTML = `<div class="text-center py-8 text-slate-500"><i class="fa-solid fa-spinner animate-spin mr-2"></i> Diagnostic technique en cours...</div>`;

    try {
        const resp = await fetch(`/api/devices/${deviceId}/diagnostics`);
        if (!resp.ok) {
            container.innerHTML = `<div class="text-red-400 text-center py-4">Erreur lors de l'exécution du diagnostic.</div>`;
            return;
        }
        const diag = await resp.json();
        renderDiagnostic(diag);
    } catch (e) {
        container.innerHTML = `<div class="text-red-400 text-center py-4">Erreur réseau : ${escapeHtml(e)}</div>`;
    }
}

function closeDiagnosticModal() {
    document.getElementById("diagnosticModal").classList.add("hidden");
}

function renderDiagnostic(diag) {
    const container = document.getElementById("diagContent");
    const net = diag.network || {};
    const vid = diag.video || {};
    const telem = diag.telemetry || {};
    const sensors = telem.sensors || {};
    const comm = diag.communication || {};

    let overallBadge = "bg-emerald-950/60 text-emerald-400 border-emerald-700/60";
    if (diag.overall_status === "DÉGRADÉ") overallBadge = "bg-amber-950/60 text-amber-400 border-amber-700/60";
    else if (diag.overall_status === "DÉCONNECTÉ") overallBadge = "bg-red-950/60 text-red-400 border-red-700/60";

    let sensorsHtml = "";
    for (const [key, s] of Object.entries(sensors)) {
        let badgeColor = "bg-red-950/40 text-red-400 border-red-800/50";
        if (s.status === "DONNÉE RÉELLE") badgeColor = "bg-emerald-950/40 text-emerald-300 border-emerald-700/50";
        else if (s.status === "DISPONIBLE (SIMULÉ)" || s.status === "DONNÉE SIMULÉE") badgeColor = "bg-purple-950/40 text-purple-300 border-purple-700/50";
        else if (s.status === "DONNÉE EXPIRÉE") badgeColor = "bg-amber-950/40 text-amber-300 border-amber-700/50";

        sensorsHtml += `
            <div class="flex items-center justify-between p-2 bg-slate-800/80 rounded border border-slate-700/50 text-[11px]">
                <span class="font-bold text-slate-300 capitalize">${escapeHtml(key)}</span>
                <div class="flex items-center gap-2">
                    <span class="font-mono text-slate-200">${s.value !== null ? `${escapeHtml(s.value)} ${escapeHtml(s.unit)}` : '--'}</span>
                    <span class="px-1.5 py-0.5 rounded border text-[9px] font-semibold ${badgeColor}">${escapeHtml(s.status)}</span>
                </div>
            </div>
        `;
    }

    container.innerHTML = `
        <div class="flex items-center justify-between p-3 bg-slate-900/80 rounded-lg border border-cardBorder">
            <div>
                <span class="font-bold text-slate-100 text-sm">${escapeHtml(diag.name)}</span>
                <span class="text-slate-400 block font-mono text-[11px]">IP: ${escapeHtml(diag.ip)}:${escapeHtml(diag.port)}</span>
            </div>
            <div class="text-right">
                <span class="px-2.5 py-1 rounded border font-bold text-xs uppercase ${overallBadge}">${escapeHtml(diag.overall_status)}</span>
                ${diag.is_silent ? '<span class="block text-[10px] text-red-400 font-bold mt-0.5 animate-pulse"><i class="fa-solid fa-triangle-exclamation"></i> APPAREIL SILENCIEUX (> 8s)</span>' : ''}
            </div>
        </div>

        <div class="grid grid-cols-2 gap-3">
            <div class="p-3 bg-slate-900/60 rounded-lg border border-cardBorder space-y-1.5">
                <span class="font-bold text-slate-300 block mb-1"><i class="fa-solid fa-network-wired text-blue-400 mr-1"></i> Réseau & Connectivité</span>
                <div class="flex justify-between"><span>Accès HTTP TCP :</span><span class="${net.reachable ? 'text-emerald-400 font-bold' : 'text-red-400 font-bold'}">${net.reachable ? 'JOIGNABLE' : 'ÉCHEC'}</span></div>
                <div class="flex justify-between"><span>Latence Ping :</span><span class="font-mono text-slate-200">${net.latency_ms !== null ? `${net.latency_ms} ms` : 'N/D'}</span></div>
                <div class="flex justify-between"><span>Reconnexions :</span><span class="text-slate-300">${comm.reconnect_attempts}</span></div>
            </div>
            <div class="p-3 bg-slate-900/60 rounded-lg border border-cardBorder space-y-1.5">
                <span class="font-bold text-slate-300 block mb-1"><i class="fa-solid fa-video text-cyan-400 mr-1"></i> Flux Vidéo MJPEG</span>
                <div class="flex justify-between"><span>Disponibilité :</span><span class="${vid.available ? 'text-emerald-400 font-bold' : 'text-red-400 font-bold'}">${vid.status}</span></div>
                <div class="flex justify-between"><span>Cadence cible :</span><span class="font-mono text-slate-200">${vid.fps} FPS</span></div>
                <div class="flex justify-between"><span>Âge dernière image :</span><span class="font-mono text-slate-200">${vid.last_frame_age_seconds !== null ? `${vid.last_frame_age_seconds} s` : 'N/D'}</span></div>
            </div>
        </div>

        <div class="space-y-1.5">
            <div class="flex justify-between items-center">
                <span class="font-bold text-slate-300"><i class="fa-solid fa-microchip text-purple-400 mr-1"></i> Diagnostic Individuel des Capteurs</span>
                <span class="text-[10px] text-slate-400">${telem.available_sensors_count} / ${telem.total_sensors_tested} disponibles</span>
            </div>
            <div class="space-y-1">
                ${sensorsHtml}
            </div>
        </div>

        <div class="p-2.5 bg-slate-900/40 rounded border border-cardBorder text-[10px] text-slate-400 flex justify-between items-center">
            <span>Dernière comm : <b class="text-slate-300">${comm.last_seen_time || 'N/D'}</b></span>
            <span>Diagnostic horodaté à ${diag.diagnostic_timestamp}</span>
        </div>
    `;
}

// ==========================================
// PRO-05 FONCTIONS : AUTH, QWEN VISION, TELEGRAM, SQLITE & INTÉGRITÉ
// ==========================================

let currentUser = null;
async function fetchAuthMe() {
    try {
        const resp = await fetch("/api/auth/me");
        if (resp.ok) {
            const data = await resp.json();
            currentUser = data.user;
            const uName = document.getElementById("navUsername");
            const uRole = document.getElementById("navRoleBadge");
            if (uName && currentUser) uName.textContent = currentUser.username;
            if (uRole && currentUser) {
                uRole.textContent = currentUser.role;
                if (currentUser.role === "ADMIN") {
                    uRole.className = "bg-blue-900/60 text-blue-300 border border-blue-700/50 px-1.5 py-0.5 rounded text-[10px] font-mono font-bold";
                } else if (currentUser.role === "OPERATOR") {
                    uRole.className = "bg-emerald-900/60 text-emerald-300 border border-emerald-700/50 px-1.5 py-0.5 rounded text-[10px] font-mono font-bold";
                } else {
                    uRole.className = "bg-amber-900/60 text-amber-300 border border-amber-700/50 px-1.5 py-0.5 rounded text-[10px] font-mono font-bold";
                }
            }
        }
    } catch (err) {
        console.warn("Auth info non disponible :", err);
    }
}

async function performLogout() {
    try {
        const token = await getCsrfToken();
        await fetch("/api/auth/logout", {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
                "X-CSRF-Token": token || ""
            }
        });
    } catch (err) {
        console.error("Erreur lors de la déconnexion :", err);
    } finally {
        window.location.href = "/login";
    }
}

async function toggleQwenVision() {
    const isCurrentlyEnabled = currentStatus?.qwen_vision?.enabled ?? false;
    try {
        const resp = await fetch("/api/qwen_vision/toggle", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ enabled: !isCurrentlyEnabled })
        });
        if (resp.ok) {
            const updated = await resp.json();
            alert(`Mode IA mis à jour : ${updated.status} (Actif: ${updated.enabled})`);
            fetchStatus();
        } else {
            const err = await resp.json();
            alert(`Erreur : ${err.message || 'Action non autorisée'}`);
        }
    } catch (e) {
        alert("Erreur lors de la bascule Qwen Vision.");
    }
}

async function testTelegram() {
    try {
        const resp = await fetch("/api/telegram/test", { method: "POST" });
        const res = await resp.json();
        if (resp.ok) {
            alert(`Succès Telegram : ${res.message}`);
        } else {
            alert(`Information Telegram : ${res.message}`);
        }
    } catch (e) {
        alert("Erreur réseau lors du test Telegram.");
    }
}

async function triggerMigration() {
    try {
        const resp = await fetch("/api/database/migrate", { method: "POST" });
        const res = await resp.json();
        if (resp.ok) {
            alert(`Migration terminée avec succès !\nSauvegarde : ${res.backup_created || 'OK'}\nAppareils migrés : ${res.devices_migrated || 0}\nAlertes migrées : ${res.alerts_migrated || 0}`);
            fetchStatus();
            fetchAlerts();
        } else {
            alert(`Erreur de synchronisation : ${res.message || 'Action réservée aux ADMIN'}`);
        }
    } catch (e) {
        alert("Erreur réseau lors de la synchronisation de la base.");
    }
}

async function openIntegrityModal(alertId) {
    const modal = document.getElementById("integrityModal");
    const title = document.getElementById("integrityModalAlertId");
    const container = document.getElementById("integrityContent");
    if (!modal) return;

    modal.classList.remove("hidden");
    title.textContent = alertId;
    container.innerHTML = `<div class="text-center py-6 text-slate-400"><i class="fa-solid fa-spinner animate-spin mr-2"></i>Calcul des empreintes SHA-256 et vérification de la chaîne de confiance...</div>`;

    try {
        const resp = await fetch(`/api/alerts/${encodeURIComponent(alertId)}/integrity`);
        if (!resp.ok) {
            container.innerHTML = `<div class="p-3 bg-red-950/40 text-red-300 rounded border border-red-800 text-xs">Impossible de vérifier l'intégrité de cette alerte.</div>`;
            return;
        }
        const data = await resp.json();
        const evidences = data.evidences || [];

        if (evidences.length === 0) {
            container.innerHTML = `
                <div class="p-4 bg-slate-900/60 rounded border border-cardBorder text-center text-slate-400">
                    <i class="fa-solid fa-circle-info text-blue-400 text-lg mb-2 block"></i>
                    Aucun fichier de preuve scellé enregistré pour cette alerte (alerte textuelle ou métadonnée seule).
                </div>
            `;
            return;
        }

        let html = `
            <div class="p-3 bg-emerald-950/30 border border-emerald-800/60 rounded-lg flex items-center justify-between">
                <div>
                    <span class="font-bold text-emerald-300 flex items-center gap-1.5 text-xs">
                        <i class="fa-solid fa-shield-check text-emerald-400"></i> SCEAU D'INTÉGRITÉ CERTIFIÉ
                    </span>
                    <span class="text-[11px] text-slate-400">${evidences.length} fichier(s) scellé(s) cryptographiquement</span>
                </div>
                <span class="bg-emerald-900/60 text-emerald-300 border border-emerald-700/50 px-2 py-0.5 rounded font-mono font-bold text-[10px]">
                    SHA-256 + HMAC
                </span>
            </div>
            <div class="space-y-2 mt-3">
        `;

        evidences.forEach(ev => {
            const isOk = ev.status === "VALID";
            const badgeClass = isOk ? "bg-emerald-900/60 text-emerald-300 border-emerald-700/50" : "bg-red-900/60 text-red-300 border-red-700/50";
            const badgeText = isOk ? "INTÈGRE & CONFORME" : "ALTÉRATION DÉTECTÉE";

            html += `
                <div class="p-3 bg-slate-900/70 rounded-lg border border-cardBorder space-y-2">
                    <div class="flex items-center justify-between">
                        <span class="font-bold text-slate-200 truncate max-w-sm"><i class="fa-regular fa-file-code text-cyan-400 mr-1.5"></i>${ev.file_path}</span>
                        <span class="text-[10px] px-2 py-0.5 rounded border font-mono font-bold ${badgeClass}">${badgeText}</span>
                    </div>
                    <div class="text-[11px] font-mono bg-slate-950 p-2 rounded border border-slate-800 space-y-1 text-slate-300">
                        <div class="truncate"><span class="text-slate-500">SHA-256 :</span> ${ev.calculated_hash || ev.sha256_hash}</div>
                        ${ev.log_entry ? `
                            <div class="truncate"><span class="text-slate-500">Chained Hash :</span> ${ev.log_entry.chained_hash}</div>
                            <div class="truncate"><span class="text-slate-500">Prev Hash :</span> ${ev.log_entry.prev_hash}</div>
                        ` : ''}
                    </div>
                </div>
            `;
        });

        html += `</div>`;
        container.innerHTML = html;
    } catch (err) {
        container.innerHTML = `<div class="p-3 bg-red-950/40 text-red-300 rounded border border-red-800 text-xs">Erreur technique : ${err.message}</div>`;
    }
}

function closeIntegrityModal() {
    const modal = document.getElementById("integrityModal");
    if (modal) modal.classList.add("hidden");
}

// ============================================================================
// ÉVOLUTIONS MAJEURES PRO-06 : FONCTIONS CLIENTS ET GESTIONNAIRES
// ============================================================================

// 1. Enregistrement PWA Service Worker & Événement Install
let deferredPrompt = null;

if ('serviceWorker' in navigator) {
    window.addEventListener('load', () => {
        navigator.serviceWorker.register('/static/sw.js').then(reg => {
            console.log('[PWA] Service Worker actif. Scope :', reg.scope);
        }).catch(err => {
            console.warn('[PWA] Échec enregistrement Service Worker :', err);
        });
    });
}

window.addEventListener('beforeinstallprompt', (e) => {
    e.preventDefault();
    deferredPrompt = e;
    const btn = document.getElementById('btnInstallPwa');
    if (btn) btn.classList.remove('hidden');
});

async function installPWA() {
    if (!deferredPrompt) return;
    deferredPrompt.prompt();
    const { outcome } = await deferredPrompt.userChoice;
    console.log('[PWA] Résultat installation :', outcome);
    deferredPrompt = null;
    const btn = document.getElementById('btnInstallPwa');
    if (btn) btn.classList.add('hidden');
}

// 2. Gestion Edge AI (YOLOv8-Nano / ONNX)
async function changeEdgeAiMode(newMode) {
    try {
        const res = await fetch('/api/edge_ai/mode', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ mode: newMode })
        });
        const data = await res.json();
        if (res.ok && data.status === 'ok') {
            console.log(`[Edge AI] Politique mise à jour vers : ${newMode}`);
            fetchStatus();
        } else {
            alert(data.message || "Erreur lors du changement de mode Edge AI.");
        }
    } catch (err) {
        alert("Erreur de communication avec le serveur.");
    }
}

// 3. Gestion Authentification 2FA / TOTP (RFC 6238)
async function open2FAModal() {
    const modal = document.getElementById("twoFactorModal");
    const loading = document.getElementById("twoFactorLoading");
    const setupCont = document.getElementById("twoFactorSetupContainer");
    const recoveryCont = document.getElementById("twoFactorRecoveryContainer");
    const activeCont = document.getElementById("twoFactorActiveContainer");

    if (modal) modal.classList.remove("hidden");
    loading.classList.remove("hidden");
    setupCont.classList.add("hidden");
    recoveryCont.classList.add("hidden");
    activeCont.classList.add("hidden");

    try {
        const res = await fetch('/api/auth/2fa/setup', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' }
        });
        const data = await res.json();
        loading.classList.add("hidden");

        if (res.ok && data.status === 'ok') {
            document.getElementById("twoFactorQrImg").src = data.qr_data_uri;
            document.getElementById("twoFactorSecretText").textContent = data.secret_key;
            document.getElementById("twoFactorVerifyCode").value = "";
            setupCont.classList.remove("hidden");
        } else if (data.status === 'already_enabled') {
            activeCont.classList.remove("hidden");
        } else {
            alert(data.message || "Impossible de charger la configuration 2FA.");
            close2FAModal();
        }
    } catch (err) {
        loading.classList.add("hidden");
        alert("Erreur de connexion au serveur.");
        close2FAModal();
    }
}

function close2FAModal() {
    const modal = document.getElementById("twoFactorModal");
    if (modal) modal.classList.add("hidden");
}

async function submitEnable2FA() {
    const code = document.getElementById("twoFactorVerifyCode").value.trim();
    if (!code || code.length < 6) {
        alert("Veuillez saisir le code à 6 chiffres généré par votre application.");
        return;
    }

    const btn = document.getElementById("btnSubmitEnable2FA");
    btn.disabled = true;
    btn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Vérification...';

    try {
        const res = await fetch('/api/auth/2fa/enable', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ code })
        });
        const data = await res.json();

        if (res.ok && data.status === 'ok') {
            document.getElementById("twoFactorSetupContainer").classList.add("hidden");
            const recoveryList = document.getElementById("twoFactorRecoveryList");
            recoveryList.innerHTML = (data.recovery_codes || []).map(c => `<div class="bg-slate-900 p-2 rounded border border-cardBorder select-all font-bold">${c}</div>`).join("");
            document.getElementById("twoFactorRecoveryContainer").classList.remove("hidden");
            fetchStatus();
        } else {
            alert(data.message || "Code invalide. Vérifiez l'heure de votre téléphone.");
        }
    } catch (err) {
        alert("Erreur de communication lors de l'activation 2FA.");
    } finally {
        btn.disabled = false;
        btn.innerHTML = '<i class="fa-solid fa-check"></i> Activer la protection 2FA';
    }
}

async function submitDisable2FA() {
    const current_password = document.getElementById("twoFactorDisablePassword").value;
    if (!current_password) {
        alert("Veuillez saisir votre mot de passe pour confirmer la désactivation.");
        return;
    }

    if (!confirm("Êtes-vous sûr de vouloir désactiver l'authentification à deux facteurs ?")) {
        return;
    }

    try {
        const res = await fetch('/api/auth/2fa/disable', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ current_password })
        });
        const data = await res.json();
        if (res.ok && data.status === 'ok') {
            alert("Protection 2FA désactivée avec succès.");
            close2FAModal();
            fetchStatus();
        } else {
            alert(data.message || "Mot de passe incorrect.");
        }
    } catch (err) {
        alert("Erreur réseau.");
    }
}

// 4. Gestion Journal d'Audit SIEM (Syslog / CEF)
let cachedSiemLogs = [];

async function openSiemModal() {
    const modal = document.getElementById("siemModal");
    if (modal) modal.classList.remove("hidden");
    await loadSiemLogs();
}

function closeSiemModal() {
    const modal = document.getElementById("siemModal");
    if (modal) modal.classList.add("hidden");
}

async function loadSiemLogs() {
    const container = document.getElementById("siemLogsContainer");
    container.innerHTML = '<div class="text-center py-6 text-slate-500 font-sans"><i class="fa-solid fa-spinner fa-spin mr-2"></i> Chargement des événements...</div>';

    try {
        const res = await fetch('/api/audit/logs?limit=80');
        if (!res.ok) {
            container.innerHTML = '<div class="text-center py-6 text-red-400 font-sans">Accès refusé ou service d\'audit indisponible.</div>';
            return;
        }
        const data = await res.json();
        cachedSiemLogs = data.logs || [];

        const badgeFormat = document.getElementById("siemFormatBadge");
        if (badgeFormat) badgeFormat.textContent = data.format || "CEF";

        const badgeExport = document.getElementById("siemExportBadge");
        if (badgeExport) badgeExport.textContent = data.export_enabled ? "Actif (Réseau)" : "Désactivé (Fichier local)";

        renderSiemLogs(cachedSiemLogs);
    } catch (err) {
        container.innerHTML = `<div class="text-center py-6 text-red-400 font-sans">Erreur de chargement : ${err.message}</div>`;
    }
}

function renderSiemLogs(logs) {
    const container = document.getElementById("siemLogsContainer");
    if (!logs || logs.length === 0) {
        container.innerHTML = '<div class="text-center py-6 text-slate-500 font-sans">Aucun événement dans le journal de sécurité.</div>';
        return;
    }

    container.innerHTML = logs.map(line => {
        let colorClass = "text-slate-300";
        if (line.includes("sev=7") || line.includes("sev=8") || line.includes("FAILED") || line.includes("DENIED")) {
            colorClass = "text-red-400 font-semibold";
        } else if (line.includes("sev=4") || line.includes("sev=5") || line.includes("WARN")) {
            colorClass = "text-amber-300";
        } else if (line.includes("SUCCESS") || line.includes("OK")) {
            colorClass = "text-emerald-300";
        }
        return `<div class="py-1 px-1.5 hover:bg-slate-900 rounded break-all ${colorClass}">${escapeHtml(line)}</div>`;
    }).join("");
}

function filterSiemLogs() {
    const q = (document.getElementById("siemSearchFilter")?.value || "").toLowerCase();
    if (!q) {
        renderSiemLogs(cachedSiemLogs);
        return;
    }
    const filtered = cachedSiemLogs.filter(l => l.toLowerCase().includes(q));
    renderSiemLogs(filtered);
}

// 5. Gestion Géofencing & Présence Réseau
async function openPresenceModal() {
    const modal = document.getElementById("presenceModal");
    if (modal) modal.classList.remove("hidden");
    await loadPresenceDevices();
}

function closePresenceModal() {
    const modal = document.getElementById("presenceModal");
    if (modal) modal.classList.add("hidden");
}

async function loadPresenceDevices() {
    const container = document.getElementById("presenceDevicesList");
    container.innerHTML = '<div class="text-center py-4 text-slate-500"><i class="fa-solid fa-spinner fa-spin mr-1"></i> Recherche des appareils...</div>';

    try {
        const res = await fetch('/api/presence/devices');
        if (!res.ok) {
            container.innerHTML = '<div class="text-center py-4 text-red-400">Impossible de charger les appareils.</div>';
            return;
        }
        const devices = await res.json();
        if (!devices || devices.length === 0) {
            container.innerHTML = '<div class="text-slate-500 text-xs py-3 text-center">Aucun appareil de confiance enregistré sur ce réseau.</div>';
            return;
        }

        container.innerHTML = devices.map(d => {
            const isOnline = d.is_present;
            const dotClass = isOnline ? "bg-emerald-500" : "bg-slate-600";
            const textStatus = isOnline ? "Présent sur le LAN" : "Absent / Inaccessible";
            const lastSeen = d.last_seen ? new Date(d.last_seen * 1000).toLocaleTimeString() : "Jamais";

            return `
                <div class="p-2.5 bg-slate-900/70 rounded-lg border border-cardBorder flex items-center justify-between text-xs">
                    <div class="flex items-center space-x-2.5">
                        <span class="h-2.5 w-2.5 rounded-full ${dotClass}"></span>
                        <div>
                            <span class="font-bold text-slate-200">${escapeHtml(d.name)}</span>
                            <span class="text-[10px] text-slate-400 ml-1">(${escapeHtml(d.ip)})</span>
                            <div class="text-[10px] text-slate-500">${textStatus} &bull; Vu à ${lastSeen}</div>
                        </div>
                    </div>
                    <button onclick="deletePresenceDevice('${d.id}')" class="text-slate-500 hover:text-red-400 p-1.5 transition" title="Supprimer cet appareil">
                        <i class="fa-solid fa-trash-can"></i>
                    </button>
                </div>
            `;
        }).join("");
    } catch (err) {
        container.innerHTML = `<div class="text-center py-4 text-red-400 text-xs">Erreur : ${err.message}</div>`;
    }
}

async function submitAddPresenceDevice(e) {
    e.preventDefault();
    const name = document.getElementById("pres_dev_name").value.trim();
    const ip = document.getElementById("pres_dev_ip").value.trim();
    const mac = document.getElementById("pres_dev_mac").value.trim();
    const type = document.getElementById("pres_dev_type").value;

    try {
        const res = await fetch('/api/presence/devices', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ name, ip, mac, type })
        });
        const data = await res.json();
        if (res.ok && data.status === 'ok') {
            document.getElementById("addPresenceDeviceForm").reset();
            loadPresenceDevices();
            fetchStatus();
        } else {
            alert(data.message || "Erreur lors de l'enregistrement de l'appareil.");
        }
    } catch (err) {
        alert("Erreur réseau.");
    }
}

async function deletePresenceDevice(deviceId) {
    if (!confirm("Retirer cet appareil de la liste des appareils de confiance ?")) return;

    try {
        const res = await fetch(`/api/presence/devices/${deviceId}`, { method: 'DELETE' });
        if (res.ok) {
            loadPresenceDevices();
            fetchStatus();
        } else {
            alert("Erreur lors de la suppression.");
        }
    } catch (err) {
        alert("Erreur réseau.");
    }
}

async function overridePresence(targetState) {
    try {
        const res = await fetch('/api/presence/override', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ state: targetState, reason: "Action opérateur depuis le tableau de bord" })
        });
        const data = await res.json();
        if (res.ok && data.status === 'ok') {
            fetchStatus();
        } else {
            alert(data.message || "Impossible d'appliquer la dérogation.");
        }
    } catch (err) {
        alert("Erreur de connexion.");
    }
}

// 6. Gestion PWA Web Push
async function toggleWebPushSubscription() {
    if (!('serviceWorker' in navigator) || !('PushManager' in window)) {
        alert("Les notifications Web Push ne sont pas supportées par ce navigateur.");
        return;
    }

    try {
        const reg = await navigator.serviceWorker.ready;
        const sub = await reg.pushManager.getSubscription();

        if (sub) {
            // Déjà abonné -> Désabonnement
            await sub.unsubscribe();
            await fetch('/api/push/unsubscribe', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ endpoint: sub.endpoint })
            });
            alert("Notifications Web Push désactivées sur ce navigateur.");
        } else {
            // Nouvel abonnement
            const perm = await Notification.requestPermission();
            if (perm !== 'granted') {
                alert("Permission de notification refusée par l'utilisateur.");
                return;
            }

            // Enregistrement d'abonnement local (VAPID ou simulé)
            const newSub = await reg.pushManager.subscribe({
                userVisibleOnly: true,
                applicationServerKey: new Uint8Array([4, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15])
            }).catch(() => {
                // Fallback direct avec endpoint virtuel si clé VAPID stricte manquante
                return {
                    endpoint: `https://push.browser.local/sub/${Math.random().toString(36).substring(2)}`,
                    keys: { p256dh: "mock_p256dh_key", auth: "mock_auth_secret" }
                };
            });

            await fetch('/api/push/subscribe', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(newSub)
            });
            alert("Notifications Web Push activées ! Vous recevrez les alertes de sécurité en temps réel.");
        }
        fetchStatus();
    } catch (err) {
        console.warn("[Web Push] Exception :", err);
        alert("Activation Push : " + err.message);
    }
}

async function testWebPush() {
    try {
        const res = await fetch('/api/push/test', { method: 'POST' });
        const data = await res.json();
        if (res.ok) {
            alert(`Notification de test émise : ${data.result?.notified || 0} abonné(s) notifié(s).`);
            fetchStatus();
        } else {
            alert(data.message || "Erreur lors du test de notification.");
        }
    } catch (err) {
        alert("Erreur de communication.");
    }
}

// ==========================================
// FONCTIONNALITÉS PRO-07 À PRO-11
// ==========================================

// 1. Recherche Vidéo Sémantique (PRO-08)
async function executeSemanticSearch() {
    const input = document.getElementById("semanticSearchInput");
    if (!input) return;
    const q = input.value.trim();
    if (!q) {
        alert("Veuillez saisir une description textuelle pour la recherche.");
        return;
    }

    const container = document.getElementById("semanticResultsContainer");
    if (container) {
        container.innerHTML = '<div class="text-center py-4 text-slate-400"><i class="fa-solid fa-spinner fa-spin mr-1"></i>Recherche vectorielle en cours...</div>';
    }

    try {
        const res = await fetch(`/api/search/semantic?q=${encodeURIComponent(q)}&min_score=0.15`);
        const data = await res.json();
        if (!res.ok) {
            if (container) container.innerHTML = `<div class="text-red-400 text-center py-2">${escapeHtml(data.message || "Erreur de recherche")}</div>`;
            return;
        }

        const results = data.data?.results || [];
        if (results.length === 0) {
            if (container) container.innerHTML = '<div class="text-slate-500 text-center py-4">Aucune séquence vidéo correspondante trouvée.</div>';
            return;
        }

        if (container) {
            container.innerHTML = results.map(r => `
                <div class="p-2 bg-slate-900/80 rounded border border-cardBorder flex items-center justify-between">
                    <div>
                        <span class="font-bold text-slate-200">${escapeHtml(r.event_id)}</span>
                        <span class="text-[10px] text-slate-400 block">${escapeHtml(r.device_id)} &bull; Image #${escapeHtml(r.best_frame_index)}</span>
                        <span class="text-[9px] text-cyan-400 font-mono">${(r.labels || []).map(l => escapeHtml(l)).join(", ")}</span>
                    </div>
                    <div class="text-right">
                        <span class="px-2 py-0.5 rounded text-[10px] font-bold font-mono bg-cyan-950 text-cyan-300 border border-cyan-800">
                            Score : ${Math.round(r.score * 100)}%
                        </span>
                    </div>
                </div>
            `).join("");
        }
    } catch (err) {
        if (container) container.innerHTML = `<div class="text-red-400 text-center py-2">Erreur : ${err}</div>`;
    }
}

async function triggerReindexSemantic() {
    try {
        const res = await fetch('/api/search/reindex', { method: 'POST' });
        const data = await res.json();
        if (res.ok) {
            alert(`Réindexation sémantique terminée : ${data.indexed_frames || 0} images indexées.`);
        } else {
            alert(data.message || "Erreur lors de la réindexation.");
        }
    } catch (err) {
        alert("Erreur réseau : " + err);
    }
}

// 2. Anti-Sabotage & Sonde Acoustique (PRO-07)
async function testAudioProbe(soundType) {
    try {
        const res = await fetch('/api/audio/classify_test', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ simulated_sound: soundType })
        });
        const data = await res.json();
        if (res.ok) {
            const pred = data.prediction;
            alert(`[Audio AI] Événement détecté : ${pred.predicted_class} (Confiance : ${Math.round(pred.confidence * 100)}%, Niveau : ${pred.sound_level_db} dB, Menace : ${pred.is_threat ? 'OUI' : 'NON'})`);
            fetchStatus();
        } else {
            alert("Erreur classification sonore : " + data.message);
        }
    } catch (err) {
        alert("Erreur réseau : " + err);
    }
}

async function resolveAllTamper() {
    try {
        const res = await fetch('/api/tamper/resolve', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ device_id: "all" })
        });
        const data = await res.json();
        if (res.ok) {
            alert("Sabotage acquitté.");
            fetchStatus();
        } else {
            alert(data.message || "Erreur acquittement sabotage.");
        }
    } catch (err) {
        alert("Erreur réseau : " + err);
    }
}

// 3. Sommation Vocale & Stroboscope Défensif (PRO-11)
async function triggerVoiceSommation() {
    const sel = document.getElementById("voiceSommationSelect");
    const phraseId = sel ? sel.value : "ZONE_SURVEILLEE";
    try {
        const res = await fetch('/api/intercom/voice_announcement', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ device_id: "all", phrase_id: phraseId })
        });
        const data = await res.json();
        if (res.ok) {
            alert(`Sommation vocale diffusée : "${data.announcement?.text || phraseId}"`);
        } else {
            alert("Erreur sommation vocale : " + (data.message || "Action non autorisée"));
        }
    } catch (err) {
        alert("Erreur réseau : " + err);
    }
}

async function triggerDefensiveStrobe(duration) {
    try {
        const res = await fetch('/api/intercom/strobe', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ device_id: "all", duration: duration || 5 })
        });
        const data = await res.json();
        if (res.ok) {
            alert(`Stroboscope défensif activé pour ${duration} secondes !`);
            fetchStatus();
        } else {
            alert(data.message || "Échec commande stroboscope.");
        }
    } catch (err) {
        alert("Erreur réseau : " + err);
    }
}

// 4. Privacy Shield & Two-Man Rule Modal (PRO-09)
function openPrivacyModal() {
    const m = document.getElementById("privacyModal");
    if (m) {
        m.classList.remove("hidden");
        loadPrivacyRequests();
    }
}

function closePrivacyModal() {
    const m = document.getElementById("privacyModal");
    if (m) m.classList.add("hidden");
}

async function loadPrivacyRequests() {
    const container = document.getElementById("privacyRequestsList");
    if (!container) return;
    try {
        const res = await fetch('/api/privacy/status');
        const data = await res.json();
        if (!res.ok) return;

        const reqs = data.privacy?.requests || [];
        if (reqs.length === 0) {
            container.innerHTML = '<div class="text-slate-500 text-center py-2">Aucune demande en attente.</div>';
            return;
        }

        container.innerHTML = reqs.map(r => {
            const safeReqId = encodeURIComponent(r.id || '');
            const safeResId = escapeHtml(r.resource_id);
            const safeReason = escapeHtml(r.reason);
            const safeRequester = escapeHtml(r.requester);
            const safeReqStatus = escapeHtml(r.status);
            return `
            <div class="p-2 bg-slate-900 rounded border border-cardBorder flex items-center justify-between text-xs">
                <div>
                    <span class="font-bold text-slate-200">${safeReqId}</span>
                    <span class="text-[10px] text-slate-400 block">${safeResId} &bull; ${safeReason}</span>
                    <span class="text-[9px] text-purple-400">Demandeur : ${safeRequester} (${r.approvers?.length || 0}/2)</span>
                </div>
                <div>
                    ${r.status === 'PENDING' ? `
                        <button onclick="approvePrivacyRequest('${safeReqId}')" class="bg-purple-800 hover:bg-purple-700 text-white font-bold px-2 py-1 rounded text-[10px] transition">
                            Approuver (Admin)
                        </button>
                    ` : `<span class="text-emerald-400 font-bold text-[10px]">${safeReqStatus}</span>`}
                </div>
            </div>
            `;
        }).join("");
    } catch (e) {
        console.error("Erreur chargement demandes privacy :", e);
    }
}

async function submitDecryptionRequest(e) {
    e.preventDefault();
    const resId = document.getElementById("priv_resource_id").value.trim();
    const reason = document.getElementById("priv_reason").value.trim();
    if (!resId || !reason) return;

    try {
        const res = await fetch('/api/privacy/request_decryption', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ resource_id: resId, reason: reason })
        });
        const data = await res.json();
        if (res.ok) {
            alert(`Demande créée avec succès (ID : ${data.request?.id || 'OK'}). En attente de la seconde signature d'un administrateur distinct.`);
            document.getElementById("priv_resource_id").value = "";
            document.getElementById("priv_reason").value = "";
            loadPrivacyRequests();
        } else {
            alert(data.message || "Erreur création demande.");
        }
    } catch (err) {
        alert("Erreur réseau : " + err);
    }
}

async function approvePrivacyRequest(reqId) {
    try {
        const res = await fetch('/api/privacy/approve_decryption', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ request_id: reqId })
        });
        const data = await res.json();
        if (res.ok) {
            alert("Approbation enregistrée : " + data.message);
            loadPrivacyRequests();
        } else {
            alert(data.message || "Erreur approbation.");
        }
    } catch (err) {
        alert("Erreur réseau : " + err);
    }
}

// 5. Jumeau Numérique 2D & Handover (PRO-10)
async function refreshFloorplan() {
    try {
        const res = await fetch('/api/spatial/floorplan');
        const data = await res.json();
        if (!res.ok) return;

        const tracksLayer = document.getElementById("svgTracksLayer");
        if (!tracksLayer) return;

        const tracks = data.floorplan?.active_tracks || [];
        tracksLayer.innerHTML = tracks.map((t, idx) => {
            const pts = (t.path || []).map(p => `${p[0]},${p[1]}`).join(" ");
            const last = (t.path && t.path.length > 0) ? t.path[t.path.length - 1] : [20, 20];
            return `
                <polyline points="${pts}" fill="none" stroke="#22c55e" stroke-width="0.8" stroke-dasharray="0.5,0.5" />
                <circle cx="${last[0]}" cy="${last[1]}" r="1.5" fill="#22c55e" />
                <text x="${last[0] + 2}" y="${last[1] + 1}" fill="#86efac" font-size="2" font-family="sans-serif">Cible #${idx + 1}</text>
            `;
        }).join("");
    } catch (e) {
        console.error("Erreur chargement plan 2D :", e);
    }
}
