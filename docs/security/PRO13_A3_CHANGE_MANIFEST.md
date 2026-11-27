# SSM PRO-13-A.3 — MANIFESTE EXHAUSTIF DES MODIFICATIONS
## REGISTRE FORENSIQUE DES FICHIERS ET MODIFICATIONS APPORTÉES

**Mission ID :** `SSM-PRO13-A3-RTSP-FFMPEG-SECURITY-AND-IPC-DEADLOCK-ELIMINATION-01`  
**Dépôt canonique :** `C:\Users\USER\Documents\alarme-sys`  
**Date :** 23 novembre 2026  
**Auditeur :** Principal Application Security & Systems Engineer  

---

## 1. Tableau Synthétique des Modifications de Code

| Fichier | Modification Réalisée | Justification Technique | Risque Associé | Tests de Validation Associés |
| :--- | :--- | :--- | :--- | :--- |
| **`monitoring/acquisition/ffmpeg_adapter.py`** | 1. Définition des constantes de sécurité : `DEFAULT_RTSP_TRANSPORT = "tcp"`, `ALLOWED_RTSP_PROTOCOLS = "tcp,rtp,rtsp"`, `ALLOWED_RTSPS_PROTOCOLS = "tcp,rtp,rtsp,tls,crypto"`, plafonds de diagnostic (100 lignes / 64 Ko).<br>2. Ajout de `_diagnostic_lines`, `_diagnostic_bytes`, `_diag_lock`, `_stderr_thread` et `_process_generation` dans `__init__`.<br>3. Propriété `allowed_protocols`.<br>4. Injection de `-protocol_whitelist`, `-rtsp_transport tcp` et `-rtsp_flags +prefer_tcp` dans `_build_ffmpeg_cmd()`.<br>5. Implémentation du worker asynchrone `_stderr_drain_worker()` et `get_recent_diagnostics()`.<br>6. Implémentation du helper anti-troncature `_read_exact()`.<br>7. Mise à jour de `_run_ffmpeg_subprocess_loop()` : lancement immédiat du thread lecteur de stderr, lecture exacte de stdout.<br>8. Mise à jour de `_cleanup_process()` : fermeture ordonnée des tubes, arrêt terminate/kill et attente bornée (`join(timeout=1.0)`). | Correction des constats **A21-001** (restriction stricte du transport et des protocoles d'entrée) et **A21-003** (éradication définitive des deadlocks IPC par saturation du tube `stderr`). | **Très faible** : architecture thread-safe, déterministe, bornée en mémoire et sans injection shell (`shell=False`). | - `test_a3_command_construction_protocol_whitelist_and_transport`<br>- `test_a3_ipc_stderr_drain_and_credential_sanitization`<br>- `test_a3_ipc_stderr_bounded_memory_under_heavy_logging`<br>- `test_a3_ipc_stderr_saturation_synthetic_subprocess_no_deadlock`<br>- `test_a3_process_generation_isolation_on_reconnect`<br>- `test_a3_concurrent_cleanup_and_close_idempotent`<br>- Suite complète Lot A (35 tests) |
| **`tests/test_pro13_lot_a_nvr.py`** | 1. Ajout de la section de tests adversariaux de Niveau 5 (6 nouveaux tests automatisés couvrant la construction de commande, le drain continu, le masquage des secrets, la saturation physique de pipe, l'isolation des générations et la fermeture concurrente idempotente).<br>2. Ajustement de la temporisation de boucle `time.sleep(0.005)` dans `test_nvr_multi_stream_concurrency_and_performance` pour absorber la granularité de l'horloge système Windows (15,6 ms). | Établissement des preuves empiriques et reproductibles pour les remédiations A21-001 et A21-003 sans dépendre de ressources externes. | **Nul** : fichier de test uniquement. Aucune modification de logique de production. | - `pytest tests/test_pro13_lot_a_nvr.py -v` (35/35 passés)<br>- `pytest tests/ -q` (272/272 passés) |
| **`monitoring/acquisition/__init__.py`** *(Préexistant PRO-13-A.2)* | Exportation unifiée des interfaces, adaptateurs et services de sécurité NVR. | Centralisation des points d'entrée d'acquisition. | Nul | Suite Lot A |
| **`monitoring/acquisition/discovery.py`** *(Préexistant PRO-13-A.2)* | Documentation explicite de mDNS comme `NOT_IMPLEMENTED` (A1-005) et gestion de l'état `DISCOVERED_PENDING_APPROVAL`. | Prévention des déclarations non démontrées et du contournement de l'approbation opérateur. | Nul | Tests de découverte (5 tests) |
| **`monitoring/acquisition/onvif_adapter.py`** *(Préexistant PRO-13-A.2)* | Déclaration formelle des capacités ONVIF (`WS_DISCOVERY_SUPPORTED`, `SOAP_MEDIA_NOT_IMPLEMENTED`). | Clarté contractuelle du périmètre supporté. | Nul | Tests ONVIF (4 tests) |
| **`monitoring/acquisition/security.py`** *(Préexistant PRO-13-A.2)* | 1. Extraction d'autorité `authority.rsplit('@', 1)`.<br>2. Déballage correct du tuple `sockaddr` `item[4][0]` de `getaddrinfo`.<br>3. Validation exhaustive multi-IP fail-closed.<br>4. Suppression des identifiants de zone IPv6.<br>5. Conversion IPv4-mappée en IPv6.<br>6. Implémentation du DNS Pinning `pin_uri_to_ip()`. | Résolution des constats A1-001 (anti-SSRF, multi-IP bypass) et A1-002 (anti-DNS rebinding TOCTOU). | Nul | Tests anti-SSRF et DNS (12 tests) |

---

## 2. Dossier Documentaire Produit dans `docs/security/`

Les 7 rapports formels requis ont été générés sans altération des rapports antérieurs :
1. `docs/security/PRO13_A3_IMPLEMENTATION_REPORT.md` : Rapport d'implémentation et de durcissement.
2. `docs/security/PRO13_A3_RTSP_SECURITY_REPORT.md` : Rapport sur la sécurité du transport RTSP et les flux secondaires.
3. `docs/security/PRO13_A3_PROCESS_SUPERVISION_REPORT.md` : Rapport sur la supervision IPC et l'élimination des deadlocks.
4. `docs/security/PRO13_A3_ADVERSARIAL_TEST_REPORT.md` : Rapport des tests adversariaux et cas limites.
5. `docs/security/PRO13_A3_REGRESSION_REPORT.md` : Rapport complet de non-régression et de stabilité globale.
6. `docs/security/PRO13_A3_LOT_B_GATE_DECISION.md` : Décision officielle de jalon maintenant le Lot B bloqué.
7. `docs/security/PRO13_A3_CHANGE_MANIFEST.md` : Le présent registre forensique des modifications.

---

## 3. Attestation de Conformité aux Interdictions Absolues

L'ingénieur principal atteste sur l'honneur que :
- Aucun commit n'a été créé (`git commit`).
- Aucun push n'a été exécuté (`git push`).
- Aucun déploiement n'a été effectué.
- Aucun fichier de configuration ni mécanisme de sécurité PRO-12 n'a été affaibli.
- Aucun mot de passe ni secret n'a été exposé dans les logs ou le code source.
- Aucune caméra physique n'a été contactée et aucun scan réseau n'a été lancé.
- Le Lot B demeure strictement verrouillé (`LOT_B_GATE = BLOCKED_PENDING_INDEPENDENT_AUDIT`).
