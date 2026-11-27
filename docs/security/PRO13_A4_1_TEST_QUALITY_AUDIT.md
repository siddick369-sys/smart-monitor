# 🛡️ SSM PRO-13-A.4.1 — TEST QUALITY & EVIDENCE AUDIT
## CRITICAL EVALUATION OF THE 20 ADVERSARIAL TESTS, MOCK ISOLATION, AND REALITY DISCREPANCIES

**Mission ID :** `SSM-PRO13-A4.1-INDEPENDENT-EGRESS-ENFORCEMENT-AUDIT-01`  
**Fichiers audités :** `tests/test_pro13_lot_a_nvr.py` (Lignes 935 à 1246)  
**HEAD audité :** `b339a9c82d5b410e78d1ea6d43cae556049ba2c0`  
**Date d'audit :** 2026-11-24

---

## 1. PRINCIPE DÉONTOLOGIQUE D'AUDIT SUR LA QUALITÉ DES TESTS

Un test automatisé ne prouve que ce qu'il observe réellement.  
Dans un audit forensique indépendant, il est proscrit de confondre un test unitaire vérifiant une expression rationnelle ou un mock avec la preuve physique qu'un pare-feu de système d'exploitation bloque un paquet réseau sur une interface réseau matérielle.

---

## 2. EXAMEN INDIVIDUEL DES 20 TESTS ADVERSARIAUX A.4

| Test Name | Code Under Test | Mocks Used | Interaction OS Réelle | Propriété Prouvée | Propriété NON Prouvée |
|---|---|---|:---:|---|---|
| `test_a4_01_authorized_camera_ip` | `EgressPolicy.is_destination_allowed` | Aucun | Aucune | L'allowlist logicielle accepte l'IP configurée | Ne prouve pas que la socket OS réussit |
| `test_a4_02_unauthorized_private_ip` | `EgressPolicy.is_destination_allowed` | Aucun | Aucune | L'allowlist rejette les IP privées hors liste | Ne prouve pas que l'OS bloque un paquet |
| `test_a4_03_loopback_secondary_uri` | `EgressPolicy.is_destination_allowed` | Aucun | Aucune | `127.0.0.1` et `::1` sont rejetés en Python | Ne prouve pas que le sous-processus ne peut pas l'ouvrir |
| `test_a4_04_metadata_destination` | `EgressPolicy.is_destination_allowed` | Aucun | Aucune | `169.254.169.254` est rejeté en Python | Ne prouve pas le blocage au niveau réseau |
| `test_a4_05_link_local_destination` | `EgressPolicy.is_destination_allowed` | Aucun | Aucune | `fe80::1` et `169.254.1.1` rejetés en Python | Ne prouve pas le blocage au niveau réseau |
| `test_a4_06_unauthorized_public_ip` | `EgressPolicy.is_destination_allowed` | Aucun | Aucune | IP publique non approuvée rejetée en Python | Ne prouve pas le blocage de paquets sortants |
| `test_a4_07_ipv6_loopback` | `EgressPolicy.is_destination_allowed` | Aucun | Aucune | `::1` rejeté par la politique | Ne prouve pas le blocage de socket IPv6 |
| `test_a4_08_ipv4_mapped_ipv6` | `EgressPolicy.is_destination_allowed` | Aucun | Aucune | Normalisation syntaxique de `::ffff:` | Ne prouve pas le filtrage dans la pile IP du noyau |
| `test_a4_09_rtsp_302_redirect` | `validate_video_target` | Aucun | Aucune | L'URI de redirection est rejetée si Python la lit | **Ne teste PAS libavformat suivant un 302 en C** |
| `test_a4_10_sdp_absolute_secondary_uri` | `validate_video_target` | Aucun | Aucune | L'URI extrait du SDP est rejetée si Python la lit | **Ne teste PAS libavformat parsant un SDP en C** |
| `test_a4_11_reconnect_after_dns_change` | `validate_video_target` | `mock_dns` | Aucune | Python rejette si le DNS retourne une nouvelle IP | Ne teste pas libavformat avec cache DNS interne |
| `test_a4_12_unauthorized_udp_attempt` | `_build_ffmpeg_cmd` | Aucun | Aucune | La liste d'arguments contient `-rtsp_transport tcp` | Ne teste pas l'émission de paquets UDP |
| `test_a4_13_malformed_sdp` | `_read_exact` | `MagicMock` | Aucune | Une fermeture de tube renvoie None sans crash | Ne teste pas le comportement mémoire C de libavformat |
| `test_a4_14_excessive_reconnect_attempts` | `_current_backoff` | Aucun | Aucune | L'algorithme de backoff plafonne à 15s | Ne teste pas la charge CPU sous assaut réseau |
| `test_a4_15_worker_termination` | `_cleanup_process` | `MagicMock` | Aucune | `terminate()` ou `kill()` est invoqué sur l'objet mock | Ne teste pas la terminaison d'un processus système réel |
| `test_a4_16_isolation_unavailable` | `connect()` | `patch.dict(os.environ)` | Aucune | Refuse de connecter si les variables sont vides | **Ne vérifie pas l'état réel de Windows Firewall** |
| `test_a4_17_firewall_policy_absent` | `check_egress_enforcement` | `patch.dict(os.environ)` | Aucune | Retourne `APPLICATION_PINNING` si variables vides | Ne teste pas l'API NetSecurity de Windows |
| `test_a4_18_policy_allowlist_empty` | `EgressPolicy.__init__` | Aucun | Aucune | Lève `PolicyConfigurationError` si liste vide | Test purement unitaire |
| `test_a4_19_policy_allowlist_overly_broad` | `EgressPolicy.__init__` | Aucun | Aucune | Lève `PolicyConfigurationError` pour /8 et /0 | Test purement unitaire |
| `test_a4_20_policy_rollback` | `check_egress_enforcement` | `patch.dict(os.environ)` | Aucune | La fonction réagit à la présence de la variable env | **Ne teste pas le rollback réel du pare-feu** |

---

## 3. VENTILATION PAR MODALITÉ FORENSIQUE

- **`UNIT_TEST` (Tests unitaires purs) :** **11 tests** (A4-01, A4-02, A4-03, A4-04, A4-05, A4-06, A4-07, A4-08, A4-12, A4-14, A4-18, A4-19).
- **`MOCKED_INTEGRATION` (Intégration mockée en mémoire) :** **9 tests** (A4-09, A4-10, A4-11, A4-13, A4-15, A4-16, A4-17, A4-20).
- **`LOCAL_SOCKET_INTEGRATION` :** **0 test dans A.4** (1 test dans A.3 avec sous-processus synthétique).
- **`REAL_OS_FIREWALL` :** **0 test (`NOT_AVAILABLE`)**.
- **`REAL_FFMPEG` :** **0 test (`NOT_AVAILABLE`)**.
- **`PHYSICAL_CAMERA` :** **0 test (`NOT_AVAILABLE`)**.

---

## 4. CONSTATS FORENSIQUES CRITIQUES

1. **Illusion de confinement par inspection de chaînes :**  
   Les tests `test_a4_09_rtsp_302_redirect` et `test_a4_10_sdp_absolute_secondary_uri` passent avec succès parce qu'ils soumettent une chaîne de caractères à `validate_video_target()`. Cependant, dans la réalité opérationnelle, **FFmpeg ne renvoie pas les redirections 302 ni les attributs SDP à Python**. Ces tests valident le parseur Python, mais ne démontrent en rien que FFmpeg ne s'échappera pas sur le réseau.
2. **Dépendance totale aux variables d'environnement dans les tests :**  
   Les tests `test_a4_16`, `test_a4_17` et `test_a4_20` utilisent `patch.dict(os.environ)`. Ils vérifient que le code lit correctement un dictionnaire de chaînes en mémoire vive, mais ne vérifient à aucun moment si le pare-feu de Microsoft Windows contient ou non des règles valides.

---

## 5. MÉTRIQUES D'EXÉCUTION RÉELLES

- **Lot A (`tests/test_pro13_lot_a_nvr.py`) :** 55 passés en 20.15s.
- **PRO-12 (`tests/test_pro12*.py`) :** 127 passés, 1 warning en 76.14s.
- **Ensemble du dépôt (`tests/`) :** 292 passés, 1 warning en 113.92s.
- **Intégrité Git :** `git diff --check` -> 0 avertissement.
- **Compilation bytecode :** `python -m compileall -q .` -> 0 erreur.
