# 🛡️ SMART SECURITY MONITOR — RAPPORT FORMEL DE REMÉDIATION ET DE VÉRIFICATION
## REMÉDIATION FORENSIQUE CIBLÉE — SSRF, DNS PINNING, ISOLATION VIDÉO ET FIABILITÉ RTSP

**Identifiant Unique :** `SSM-PRO13-A2-CRITICAL-NVR-REMEDIATION-AND-VERIFICATION-01`  
**Mission Racine :** `SSM-PRO13-A2-CRITICAL-NVR-REMEDIATION-AND-VERIFICATION-01`  
**Référence d'Audit :** `SSM-PRO13-A1-INDEPENDENT-NVR-SECURITY-AND-REGRESSION-AUDIT-01`  
**Commit HEAD de Référence :** `b339a9c82d5b410e78d1ea6d43cae556049ba2c0`  
**Périmètre Exclusif :** Remédiation ciblée des constatations A1-001 à A1-006  
**Environnement Constaté :** Windows 11 · Python 3.11.8 · OpenCV 4.10.0 · SQLite 3 / SQLAlchemy · pytest 9.1.1  
**Statut Global :** **`PRO13_A2_REMEDIATION_VERIFIED_WITH_LIMITATIONS`**  
**Statut Gate Lot B :** **`BLOQUÉ (EN ATTENTE DE DÉCISION EXPLICITE DE L'OPÉRATEUR)`**  
**Date d'Émission :** 22 Novembre 2026  

---

## 1. RÉSUMÉ EXÉCUTIF

Conformément au mandat de remédiation contradictoire `SSM-PRO13-A2-CRITICAL-NVR-REMEDIATION-AND-VERIFICATION-01`, l'ensemble des six constats relevés lors de l'audit indépendant PRO-13-A.1 a été reproduit, corrigé, instrumenté et vérifié par une suite exhaustive de tests unitaires, d'intégration locale et adversariaux.

### Résultats Clés de la Remédiation :
1. **Élimination du Crash A1-001 (P1) :** Réécriture complète de l'inspection des enregistrements `socket.getaddrinfo()` dans [monitoring/acquisition/security.py](file:///C:/Users/USER/Documents/alarme-sys/monitoring/acquisition/security.py#L125-L185). L'accès direct erroné au type de socket (`[0][1][0]`) a été remplacé par une extraction robuste et typée du tuple réseau (`sockaddr = item[4]`), prenant en charge les adresses IPv4, IPv6, IPv4-mappées, zones IPv6 et réponses multi-IP avec politique stricte *fail-closed*.
2. **Neutralisation de la Fenêtre TOCTOU et DNS Pinning A1-002 (P2) :** Implémentation de la fonction `pin_uri_to_ip()` liant la destination effective transmise au décodeur à l'adresse IP validée, neutralisant le DNS rebinding. Ré-exécution obligatoire de la validation de sécurité à chaque itération de reconnexion dans `_supervision_loop()`.
3. **Suppression du Fallback OpenCV Implicite A1-003 (P2) :** En environnement de production, l'adaptateur refuse catégoriquement d'activer le décodeur in-process OpenCV lorsque `ffmpeg.exe` est manquant (`status = ERROR`, politique *fail-closed* stricte). En mode développement/test, le fallback exige une activation explicite (`allow_opencv_fallback=True`) avec timeout strict configuré.
4. **Clarification Honnête des Capacités ONVIF A1-004 (P2) :** Suppression des mentions trompeuses de compatibilité Profile S/T. Exposition explicite des états : `WS_DISCOVERY_SUPPORTED`, `SOAP_MEDIA_NOT_IMPLEMENTED`, `PROFILE_S_NOT_VERIFIED`, `PROFILE_T_NOT_VERIFIED`.
5. **Correction Documentaire mDNS A1-005 (P3) :** Clarification dans le code et les structures de données que mDNS/Zeroconf est `NOT_IMPLEMENTED`.
6. **Cohérence du Buffer Circulaire A1-006 (P3) :** Instanciation effective et utilisation thread-safe de `self._frame_buffer = deque(maxlen=2)` sous verrou réentrant `RLock`.
7. **Zéro Régression Globale :** La suite complète s'exécute avec succès : **266 tests réussis sur 266 (100% de réussite)** en 111.57s. Compilation globale : Code retour `0`.

---

## 2. BASELINE FORENSIQUE ET REPRODUCTION DES DÉFAUTS

Avant toute altération du code, les six constatations ont été reproduites et attestées :

| Constatation | Composant / Emplacement Initial | Manifestation Reproduite | Statut Initial |
| :--- | :--- | :--- | :---: |
| **A1-001** | `security.py:170` | `TypeError: 'SocketKind' object is not subscriptable` dès qu'une IP privée valide (`192.168.1.50`) était soumise. | **CONFIRMÉ** |
| **A1-002** | `ffmpeg_adapter.py:116-178` | Nom d'hôte brut transmis à FFmpeg/OpenCV sans liaison d'IP ; reconnexion sans re-validation DNS. | **CONFIRMÉ** |
| **A1-003** | `ffmpeg_adapter.py:161-270` | Basculement silencieux et inconditionnel vers OpenCV in-process sans isolation mémoire ni timeout. | **CONFIRMÉ** |
| **A1-004** | `onvif_adapter.py:167` | Prétention infondée de `profiles=["Profile S (Simulated/Candidate)"]` sans aucun client SOAP Media. | **CONFIRMÉ** |
| **A1-005** | `discovery.py:1-4` | Docstring revendiquant mDNS alors qu'aucune ligne de code mDNS n'était présente. | **CONFIRMÉ** |
| **A1-006** | `ffmpeg_adapter.py:15` | `collections.deque` importé mais jamais instancié ; utilisation d'une variable scalaire. | **CONFIRMÉ** |

---

## 3. MODIFICATIONS EFFECTUÉES PAR COMPOSANT

### 3.1 Remédiation A1-001 : Extraction Robuste `getaddrinfo` et Politique Fail-Closed
Dans [monitoring/acquisition/security.py](file:///C:/Users/USER/Documents/alarme-sys/monitoring/acquisition/security.py) :
- **Extraction typée du sockaddr :** Chaque tuple retourné par `socket.getaddrinfo()` est validé (`sockaddr = item[4]`, `ip_str = sockaddr[0]`).
- **Gestion des zones IPv6 :** Découpage de l'identifiant d'interface (`clean_ip = ip_str.split('%')[0]`).
- **Inspection exhaustive (Fail-Closed) :** Si la résolution DNS renvoie plusieurs adresses IP, **chacune d'entre elles** doit être conforme aux règles d'accès. Si un nom de domaine renvoie une combinaison d'IP privée et d'IP interdite (métadonnées cloud ou loopback), la requête est **intégralement rejetée** avec motif explicite.
- **Support des caractères spéciaux dans l'autorité :** L'extraction de l'hôte et du port utilise désormais un découpage sur le dernier délimiteur `@` de l'autorité (`authority.rsplit('@', 1)`), empêchant qu'un mot de passe contenant `@` ne corrompe la détermination du nom d'hôte.

### 3.2 Remédiation A1-002 : DNS Pinning et Reconnexion Supervisée
Dans [monitoring/acquisition/security.py](file:///C:/Users/USER/Documents/alarme-sys/monitoring/acquisition/security.py) et [monitoring/acquisition/ffmpeg_adapter.py](file:///C:/Users/USER/Documents/alarme-sys/monitoring/acquisition/ffmpeg_adapter.py) :
- **Fonction `pin_uri_to_ip(uri, ip)` :** Réécrit l'URI en remplaçant le nom d'hôte par l'adresse IP validée (en gérant les crochets `[ip]` pour IPv6), tout en préservant le port, les chemins, les paramètres et les identifiants.
- **Transmission de l'IP épinglée :** `_build_ffmpeg_cmd()` utilise `self._effective_uri` pour l'option `-i`. FFmpeg contacte directement l'IP validée via TCP, neutralisant toute possibilité de DNS rebinding lors de l'ouverture du flux.
- **Re-validation systématique au reconnect :** Dans `_supervision_loop()`, chaque cycle de reconnexion invoque `validate_video_target()` et met à jour `_effective_uri`. Si le domaine a basculé vers une adresse interdite, la boucle s'interrompt immédiatement avec `VideoSourceStatus.BLOCKED_SSRF`.

### 3.3 Remédiation A1-003 : Encadrement Strict du Fallback OpenCV
Dans [monitoring/acquisition/ffmpeg_adapter.py](file:///C:/Users/USER/Documents/alarme-sys/monitoring/acquisition/ffmpeg_adapter.py) :
- **Interdiction en Production :** L'indicateur `self._allow_opencv_fallback` est forcé à `False` dès que `config.IS_PRODUCTION=True`. Si le binaire `ffmpeg` est absent en production, `connect()` renvoie immédiatement `False` avec le statut `VideoSourceStatus.ERROR`.
- **Mode Dev/Test Contrôlé :** En développement, le fallback n'est activé que si `custom_params={"allow_opencv_fallback": True}` est explicitement passé. Un timeout strict est injecté via la variable d'environnement `OPENCV_FFMPEG_CAPTURE_OPTIONS = "timeout;5000000"`.

### 3.4 Remédiation A1-004 : Exposition Transparente des Capacités ONVIF
Dans [monitoring/acquisition/onvif_adapter.py](file:///C:/Users/USER/Documents/alarme-sys/monitoring/acquisition/onvif_adapter.py) :
- Mise à jour de `ONVIFCandidate` pour exposer le dictionnaire `capabilities` :
  ```python
  capabilities = {
      "ws_discovery": "WS_DISCOVERY_SUPPORTED",
      "soap_media": "SOAP_MEDIA_NOT_IMPLEMENTED",
      "profile_s": "PROFILE_S_NOT_VERIFIED",
      "profile_t": "PROFILE_T_NOT_VERIFIED"
  }
  ```
- Remplacement des profils simulés par `profiles = ["WS_DISCOVERY_SUPPORTED"]`.
- Documentations ajustées pour qualifier le module de "WS-Discovery Réseau" sans prétention de conformité Profile S/T.

### 3.5 Remédiation A1-005 : Documentation mDNS Conforme
Dans [monitoring/acquisition/discovery.py](file:///C:/Users/USER/Documents/alarme-sys/monitoring/acquisition/discovery.py) :
- Suppression des revendications de prise en charge mDNS.
- Indication explicite dans les docstrings et annotations que mDNS est `NOT_IMPLEMENTED`.

### 3.6 Remédiation A1-006 : Buffer Circulaire Opérationnel
Dans [monitoring/acquisition/ffmpeg_adapter.py](file:///C:/Users/USER/Documents/alarme-sys/monitoring/acquisition/ffmpeg_adapter.py) :
- Déclaration et initialisation : `self._frame_buffer = deque(maxlen=2)`.
- Alimentation atomique sous verrou réentrant `self._lock` lors de la réception de chaque trame.
- Consultation de la trame la plus récente via `self._frame_buffer[-1]`.
- Purge propre lors de `_cleanup_process()` et `close()`.

---

## 4. TESTS DE REMÉDIATION ET VÉRIFICATION DÉFENSIVE

Huit nouveaux tests automatisés ont été ajoutés dans [tests/test_pro13_lot_a_nvr.py](file:///C:/Users/USER/Documents/alarme-sys/tests/test_pro13_lot_a_nvr.py#L550-L730) :

| Identifiant de Test | Constat Couvert | Scénario Évalué | Résultat Réel |
| :--- | :---: | :--- | :---: |
| `test_remediation_a1_001_valid_private_targets_accepted` | A1-001 | Validation sans exception des IP privées (192.168.1.50, 10.0.0.10, 172.16.5.20) avec mots de passe complexes. | **PASSED** |
| `test_remediation_a1_001_multi_ip_dns_fail_closed` | A1-001 | Évaluation DNS multi-IP : succès si toutes valides, rejet fail-closed si une IP est interdite, rejet si DNS vide. | **PASSED** |
| `test_remediation_a1_002_dns_pinning_and_uri_rewrite` | A1-002 | Réécriture DNS pinning avec conservation des credentials (@, #), du port et des schémas IPv4/IPv6. | **PASSED** |
| `test_remediation_a1_002_ffmpeg_adapter_uses_pinned_uri` | A1-002 | Vérification que la commande structurée FFmpeg injecte l'IP épinglée dans `-i` au lieu du nom de domaine. | **PASSED** |
| `test_remediation_a1_003_opencv_fallback_disabled_in_production` | A1-003 | Blocage strict et mise en erreur de l'adaptateur en production lorsque FFmpeg est manquant. | **PASSED** |
| `test_remediation_a1_004_onvif_capabilities_explicit` | A1-004 | Présence des états explicites `WS_DISCOVERY_SUPPORTED` et `SOAP_MEDIA_NOT_IMPLEMENTED`. | **PASSED** |
| `test_remediation_a1_005_discovery_mdns_marked_not_implemented` | A1-005 | Vérification des métadonnées de découverte déclarant mDNS comme non implémenté. | **PASSED** |
| `test_remediation_a1_006_frame_buffer_deque_concurrency` | A1-006 | Bounded ring buffer `deque(maxlen=2)` : rétention de 2 trames max et restitution de la plus récente. | **PASSED** |

---

## 5. RÉSULTATS DES EXÉCUTIONS TERMINALES RÉELLES

### 5.1 Suite Lot A (`tests/test_pro13_lot_a_nvr.py`)
```
Command: python -m pytest tests/test_pro13_lot_a_nvr.py -v
Output: 29 passed in 17.09s
Exit Code: 0
```

### 5.2 Suite Historique PRO-12
```
Command: python -m pytest tests/test_pro12_1_adversarial.py tests/test_pro12_2_production_readiness.py tests/test_pro12_3_production_security_closure.py tests/test_pro12_4_critical_remediation.py tests/test_pro12_5_p2p_downgrade_and_bootstrap.py tests/test_pro12_security_hardening.py -q
Output: 127 passed, 1 warning in 82.63s
Exit Code: 0
```

### 5.3 Suite Globale SSM Intégrale
```
Command: python -m pytest tests/ -q
Output: 266 passed, 1 warning in 111.57s
Exit Code: 0
```

### 5.4 Compilation Bytecode
```
Command: python -m compileall -q .
Exit Code: 0 (Zéro erreur de syntaxe)
```

---

## 6. LIMITES MATÉRIELLES ET RISQUES RÉSIDUELS DOCUMENTÉS

Conformément à la déontologie d'audit et à l'interdiction d'affirmation fictive :

1. **Binaire FFmpeg Système :**  
   L'environnement Windows actuel ne comporte pas `ffmpeg.exe` dans son `PATH`. En conséquence, les tests de processus FFmpeg s'exécutent avec succès grâce aux mocks de sous-processus et à la validation des arguments structurés, tandis que les tests sans fallback OpenCV démontrent correctement le comportement *fail-closed* attendu. Le binaire FFmpeg statique devra être déployé lors de la mise en service industrielle.
2. **Caméras Physiques Locales :**  
   `HARDWARE_INTEGRATION_TEST = NOT_AVAILABLE`.  
   Aucun équipement physique n'a été raccordé au réseau local. Les tests certifient la conformité protocolaire sous simulation réseau et injection de paquets conformes.
3. **Périmètre ONVIF Résiduel :**  
   Le client SOAP Media (récupération dynamique des profils, PTZ, métadonnées analytics ONVIF) n'est pas implémenté et fera l'objet d'un lot d'extension ultérieur.

---

## 7. VERDICT FORMEL DE REMÉDIATION

Attendu que :
- Les défauts confirmés A1-001 et A1-002 ont été corrigés et vérifiés par des tests adversariaux dédiés ;
- L'isolation des processus a été durcie en interdisant le fallback OpenCV in-process en production (A1-003) ;
- Les déclarations architecturales relatives à ONVIF, mDNS et aux buffers ont été clarifiées et alignées (A1-004, A1-005, A1-006) ;
- La suite globale compte 266 tests réussis (100% de succès) sans aucune régression PRO-12 ;

Le verdict formel d'homologation de la remédiation est :

# ✅ `PRO13_A2_REMEDIATION_VERIFIED_WITH_LIMITATIONS`

*(Validation intégrale du code et de la sécurité logique, sous réserve du déploiement physique du binaire FFmpeg et d'essais sur caméras réelles lors du déploiement sur site).*

---

## 8. STATUT DE LA GATE LOT B

En application des règles du Master Prompt :
> **LA GATE DU LOT B DEMEURE STRICTEMENT BLOQUÉE.**  
> Aucun développement du Lot B (IA Multimodale et Détection Comportementale) ne débutera sans une décision formelle et explicite de l'opérateur après examen du présent rapport de remédiation.
