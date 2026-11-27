# 🛡️ SSM PRO-13-A.3.1 — TEST EVIDENCE REGISTER & TAXONOMY
## COMPREHENSIVE FORENSIC CATALOG OF TEST SUITES, EVIDENCE CLASSIFICATION, AND EXECUTION METRICS

**Mission ID :** `SSM-PRO13-A3.1-INDEPENDENT-FFMPEG-RTSP-AND-PROCESS-SECURITY-AUDIT-01`  
**Environnement de test :** Windows 11 AMD64 · Python 3.11.8 · pytest 9.1.1 · SQLite 3.45.1 · OpenCV 4.10.0  
**Volume global audité :** 272 tests automatisés  
**Classification :** READ-ONLY AUDIT · FORENSIC EVIDENCE · METHODOLOGICAL TAXONOMY

---

## 1. TAXONOMIE OFFICIELLE DES PREUVES D'AUDIT

Pour garantir une rigueur forensique absolue et interdire toute confusion entre simulations logicielles et intégrations physiques réelles, chaque élément de preuve est classé selon la taxonomie stricte suivante :

1. **`SOURCE_INSPECTION` :** Examen visuel et statique du code source, des typages et des structures de données.
2. **`STATIC_ANALYSIS` :** Analyse syntaxique, compilation bytecode (`compileall`) et conformité du formatage (`git diff --check`).
3. **`UNIT_TEST` :** Test unitaire automatisé portant sur des fonctions pures ou isolées sans composant externe (ex: parsing, masquage de secrets).
4. **`MOCK_TEST` :** Test d'intégration logique utilisant des bouchons (`unittest.mock`, `patch`) pour simuler le système d'exploitation, les sockets réseau ou les sous-processus.
5. **`LOCAL_INTEGRATION_TEST` :** Test d'intégration physique locale impliquant de véritables processus OS locaux, des tubes IPC réels ou la base de données SQLite.
6. **`REAL_FFMPEG_TEST` :** Test d'exécution réelle du binaire `ffmpeg.exe` compilé.
7. **`HARDWARE_INTEGRATION_TEST` :** Test physique raccordant une caméra réseau ONVIF/RTSP matérielle réelle.
8. **`NETWORK_EGRESS_TEST` :** Test d'interception et de mesure des flux réseau sortants vers des passerelles ou hôtes distants.
9. **`NOT_TESTED` :** Fonctionnalité formellement non couverte par un test automatisé.
10. **`NOT_AVAILABLE` :** Prérequis matériel ou binaire tiers non présent sur l'environnement hôte.

---

## 2. REGISTRE DÉTAILLÉ DU LOT A NVR (35 TESTS — `tests/test_pro13_lot_a_nvr.py`)

| # | Nom du test | Catégorie de risque | Taxonomie de preuve | Résultat | Durée |
|---|---|---|:---:|:---:|:---:|
| 1 | `test_uri_sanitization_masks_credentials` | Fuite de secrets / logs | `UNIT_TEST` | `PASSED` | 0.01s |
| 2 | `test_extract_uri_credentials` | Robustesse parsing URI | `UNIT_TEST` | `PASSED` | 0.01s |
| 3 | `test_anti_ssrf_blocks_cloud_metadata` | SSRF Cloud 169.254/16 | `UNIT_TEST` | `PASSED` | 0.01s |
| 4 | `test_anti_ssrf_blocks_loopback_in_production` | SSRF Loopback en Prod | `UNIT_TEST` | `PASSED` | 0.01s |
| 5 | `test_anti_ssrf_blocks_prohibited_ports` | Scan de ports internes | `UNIT_TEST` | `PASSED` | 0.01s |
| 6 | `test_anti_ssrf_blocks_ipv4_mapped_ipv6` | Contournement IPv6 | `UNIT_TEST` | `PASSED` | 0.01s |
| 7 | `test_anti_ssrf_dns_rebinding_simulation` | DNS Rebinding TOCTOU | `MOCK_TEST` | `PASSED` | 0.02s |
| 8 | `test_ffmpeg_adapter_command_construction_safe` | Injection de commandes | `UNIT_TEST` | `PASSED` | 0.01s |
| 9 | `test_ffmpeg_adapter_blocks_ssrf_at_connect` | Blocage SSRF adaptateur | `MOCK_TEST` | `PASSED` | 0.02s |
| 10 | `test_ffmpeg_adapter_simulated_read_and_health` | Télémétrie et métriques | `MOCK_TEST` | `PASSED` | 0.15s |
| 11 | `test_ffmpeg_adapter_detects_stream_stalls_without_serving_stale_as_live` | Perte de flux / Fraîcheur | `MOCK_TEST` | `PASSED` | 0.22s |
| 12 | `test_ffmpeg_process_cleanup_no_orphans` | Processus orphelins | `MOCK_TEST` | `PASSED` | 0.05s |
| 13 | `test_ws_discovery_probe_match_parsing` | Découverte SOAP XML | `UNIT_TEST` | `PASSED` | 0.01s |
| 14 | `test_ws_discovery_malformed_xml_resilience` | Robustesse XML malformé | `UNIT_TEST` | `PASSED` | 0.01s |
| 15 | `test_ssdp_discovery_response_parsing` | Découverte SSDP | `UNIT_TEST` | `PASSED` | 0.01s |
| 16 | `test_unified_discovery_requires_explicit_operator_approval` | Zéro auto-enrôlement | `LOCAL_INTEGRATION_TEST` | `PASSED` | 0.05s |
| 17 | `test_api_discovery_scan_and_candidates_list` | API Flask découverte | `LOCAL_INTEGRATION_TEST` | `PASSED` | 0.08s |
| 18 | `test_api_discovery_approval_enrolls_device_with_rbac` | Enrôlement avec RBAC | `LOCAL_INTEGRATION_TEST` | `PASSED` | 0.12s |
| 19 | `test_api_discovery_unauthorized_user_blocked` | Contrôle d'accès RBAC | `LOCAL_INTEGRATION_TEST` | `PASSED` | 0.06s |
| 20 | `test_api_add_rtsp_device_explicit` | Création explicite caméra | `LOCAL_INTEGRATION_TEST` | `PASSED` | 0.09s |
| 21 | `test_nvr_multi_stream_concurrency_and_performance` | Concurrence multi-flux | `LOCAL_INTEGRATION_TEST` | `PASSED` | 2.15s |
| 22 | `test_remediation_a1_001_valid_private_targets_accepted` | Cibles privées valides | `UNIT_TEST` | `PASSED` | 0.01s |
| 23 | `test_remediation_a1_001_multi_ip_dns_fail_closed` | Résolution multi-IP | `MOCK_TEST` | `PASSED` | 0.02s |
| 24 | `test_remediation_a1_002_dns_pinning_and_uri_rewrite` | Écriture URI pinée | `UNIT_TEST` | `PASSED` | 0.01s |
| 25 | `test_remediation_a1_002_ffmpeg_adapter_uses_pinned_uri` | Usage URI pinée | `MOCK_TEST` | `PASSED` | 0.02s |
| 26 | `test_remediation_a1_003_opencv_fallback_disabled_in_production` | Interdiction OpenCV Prod | `MOCK_TEST` | `PASSED` | 0.02s |
| 27 | `test_remediation_a1_004_onvif_capabilities_explicit` | Profils ONVIF déclarés | `UNIT_TEST` | `PASSED` | 0.01s |
| 28 | `test_remediation_a1_005_discovery_mdns_marked_not_implemented` | Statut mDNS | `UNIT_TEST` | `PASSED` | 0.01s |
| 29 | `test_remediation_a1_006_frame_buffer_deque_concurrency` | Concurrence buffer deque | `LOCAL_INTEGRATION_TEST` | `PASSED` | 0.18s |
| 30 | `test_a3_command_construction_protocol_whitelist_and_transport` | Paramètres FFmpeg A.3 | `UNIT_TEST` | `PASSED` | 0.01s |
| 31 | `test_a3_ipc_stderr_drain_and_credential_sanitization` | Drain stderr + masquage | `MOCK_TEST` | `PASSED` | 0.02s |
| 32 | `test_a3_ipc_stderr_bounded_memory_under_heavy_logging` | Débordement mémoire stderr | `MOCK_TEST` | `PASSED` | 0.04s |
| 33 | `test_a3_ipc_stderr_saturation_synthetic_subprocess_no_deadlock` | Saturation physique tube OS | `LOCAL_INTEGRATION_TEST` | `PASSED` | 0.78s |
| 34 | `test_a3_process_generation_isolation_on_reconnect` | Génération de processus | `MOCK_TEST` | `PASSED` | 0.02s |
| 35 | `test_a3_concurrent_cleanup_and_close_idempotent` | Fermeture concurrente | `LOCAL_INTEGRATION_TEST` | `PASSED` | 0.15s |

---

## 3. BILAN GLOBAL DES 272 TESTS DE LA BASE DE CODE

L'exécution complète de pytest sur le répertoire racine `tests/` produit le bilan suivant :
- **Total collecté :** 272 tests.
- **Réussites (PASSED) :** **272** (100.0%).
- **Échecs (FAILED) :** **0**.
- **Erreurs (ERRORS) :** **0**.
- **Avertissements (WARNINGS) :** **1** (SQLAlchemy identité persistante dans test PRO-12.3).
- **Temps total d'exécution :** 105.03s (~1 minute et 45 secondes).

### Ventilation par grands blocs fonctionnels
1. **Périmètre NVR Lot A (`test_pro13_lot_a_nvr.py`) :** 35 tests (12.92s).
2. **Périmètre Durcissement PRO-12 (`test_pro12*.py`) :** 127 tests (48.90s).
3. **Périmètre Historique Socle V1-PRO11 :** 110 tests (43.21s) :
   - API & Détection : `test_api.py`, `test_detection.py`, `test_sensors.py`.
   - Authentification, TOTP & RBAC : `test_auth_rbac.py`, `test_totp_siem.py`.
   - IA Edge & Vision : `test_edge_ai.py`, `test_presence.py`, `test_qwen_vision.py`.
   - Intégrité & Privacy : `test_integrity.py`, `test_pro09_forensic_privacy_integrity.py`.
   - P2P & Intercom : `test_p2p_mesh.py`, `test_pro11_p2p_intercom.py`, `test_webrtc.py`.
   - Fonctionnalités avancées : `test_pro03_features.py`, `test_pro07_tamper_audio.py`, `test_pro08_semantic_search.py`, `test_pro10_spatial_behavior.py`.

---

## 4. DÉCLARATION FORMELLE DES LIMITATIONS MATÉRIELLES ET LOGICIELLES

En application des règles déontologiques d'audit forensique, les limitations d'environnement suivantes sont explicitement actées :

| Domaine de vérification | État constaté | Impact sur l'accréditation |
|---|---|---|
| **Exécution de binaire réel FFmpeg** | `NOT_AVAILABLE` | `where.exe ffmpeg` échoue (code 1). Le binaire n'est pas installé sur l'hôte. Les tests reposent sur l'inspection statique de construction de commande et des tests d'intégration avec un sous-processus Python synthétique. |
| **Test matériel avec caméra physique** | `NOT_AVAILABLE` | Aucune caméra IP physique n'est branchée sur le banc de test. L'intégration matérielle finale devra faire l'objet d'un jalon de recette sur site (Hardware In the Loop - HIL). |
| **Confinement réseau des redirections SDP C** | `NOT_PROVEN` | Le DNS Pinning et la whitelist libavformat sont prouvés au niveau applicatif, mais l'absence de fuite IP secondaire en cas de redirection C requiert un pare-feu système (Egress Firewalling). |
