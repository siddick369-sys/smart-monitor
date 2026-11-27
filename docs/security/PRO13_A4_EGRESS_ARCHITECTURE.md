# 🛡️ SSM PRO-13-A.4 — EGRESS ARCHITECTURE & THREAT MODEL
## SYSTEMATIC THREAT MODELING (ATTACKS A-K), DENY-BY-DEFAULT EGRESS POLICY, AND PROCESS CONFINEMENT

**Mission ID :** `SSM-PRO13-A4-FFMPEG-EGRESS-CONFINEMENT-AND-LOT-A-FINAL-GATE-01`  
**Classification :** ARCHITECTURAL THREAT MODEL · EGRESS DEFENSE · NETWORK BOUNDARY SPECIFICATION  
**HEAD de référence :** `b339a9c82d5b410e78d1ea6d43cae556049ba2c0`  
**Date :** 2026-11-24

---

## 1. MODÈLE DE MENACE ADVERSARIAL EXHAUSTIF (ATTAQUES A À K)

Ce document établit la modélisation formelle des 11 vecteurs d'attaque réseau et d'évasion d'egress pesant sur l'acquisition vidéo NVR et le sous-processus FFmpeg.

---

### Attaque A : Redirection RTSP 302 vers une destination non autorisée
- **Entrée contrôlée par l'attaquant :** Réponse RTSP malveillante émise par la caméra avec en-tête `Location: rtsp://10.0.0.1:554/internal_admin` ou `Location: rtsp://169.254.169.254/latest/meta-data/`.
- **Composant vulnérable :** Démultiplexeur RTSP de libavformat (C) interprétant les codes HTTP/RTSP 301/302.
- **Action réseau attendue :** Ouverture d'une socket TCP vers l'adresse IP de redirection sans réinterroger le code Python.
- **Frontière de sécurité :** Double barrière : `-protocol_whitelist` (bloque les bascules de protocole vers HTTP/FILE) et pare-feu OS / Egress Policy (bloque la destination IP).
- **Prévention requise :** Le pare-feu système (ou réseau conteneur) doit bloquer toute connexion sortante dont l'IP ne figure pas dans l'allowlist des caméras.
- **Méthode de test :** Scénario `test_a4_09_rtsp_302_redirect` évaluant la conformité de l'URI redirigé face à `EgressPolicy`.
- **Risque résiduel :** Si aucun pare-feu OS ou conteneur n'est activé sur l'hôte, libavformat peut tenter d'ouvrir la socket vers une autre IP autorisée en protocole RTSP.

---

### Attaque B : Attribut SDP `a=control:` pointant vers un autre hôte
- **Entrée contrôlée par l'attaquant :** Corps de réponse RTSP `DESCRIBE` contenant un descripteur SDP avec `a=control:rtsp://192.168.1.99:554/track1`.
- **Composant vulnérable :** Parseur SDP de libavformat gérant les flux agrégés.
- **Action réseau attendue :** Établissement de la session `SETUP`/`PLAY` vers l'hôte désigné dans l'attribut SDP au lieu de l'hôte principal.
- **Frontière de sécurité :** Confinement d'egress réseau (Firewall / Network Namespace).
- **Prévention requise :** Filtrage de sortie obligatoire interdisant toute socket vers une IP non explicitement approuvée.
- **Méthode de test :** Scénario `test_a4_10_sdp_absolute_secondary_uri`.
- **Risque résiduel :** Nécessite une règle de pare-feu OS active liant le binaire à ses adresses IP de destination.

---

### Attaque C : URI absolu dans le SDP référençant Loopback, Link-Local, Métadonnées ou LAN
- **Entrée contrôlée par l'attaquant :** SDP contenant `a=control:rtsp://169.254.169.254:80/` ou `a=control:rtsp://127.0.0.1:5000/`.
- **Composant vulnérable :** Couche de transport réseau C de FFmpeg.
- **Action réseau attendue :** Attaque SSRF ciblée contre l'API de métadonnées AWS/GCP/Azure ou le port d'administration locale du Monitoring Host.
- **Frontière de sécurité :** Règles de routage du conteneur / Règles NetFirewallRule Windows / Module `EgressPolicy`.
- **Prévention requise :** Interdiction inconditionnelle des plages `169.254.0.0/16`, `fe80::/10`, `127.0.0.0/8`, `::1` et du port 5000 (`PROHIBITED_PORTS`).
- **Méthode de test :** Scénarios `test_a4_03_loopback_secondary_uri`, `test_a4_04_metadata_destination`, `test_a4_05_link_local_destination`.
- **Risque résiduel :** Éliminé dès lors que le script de pare-feu ou le conteneur est en service.

---

### Attaque D : Reconnexion RTSP après modification DNS (DNS Rebinding)
- **Entrée contrôlée par l'attaquant :** Serveur DNS externe répondant avec un TTL de 0s, retournant d'abord une IP privée légitime puis l'IP `169.254.169.254`.
- **Composant vulnérable :** Boucle de reconnexion automatique du NVR.
- **Action réseau attendue :** Reconnexion vers la nouvelle cible hostile.
- **Frontière de sécurité :** `FFmpegRTSPAdapter._supervision_loop()` réinvoquant `validate_video_target(..., egress_policy=self.egress_policy)` et `pin_uri_to_ip()` à chaque itération.
- **Prévention requise :** Re-validation systématique de la résolution DNS et pinning de l'IP avant chaque instanciation de sous-processus.
- **Méthode de test :** Scénario `test_a4_11_reconnect_after_dns_change`.
- **Risque résiduel :** Éliminé par la réévaluation obligatoire pré-connexion.

---

### Attaque E : Destination sous forme IPv4 mappée en IPv6 (`::ffff:x.x.x.x`)
- **Entrée contrôlée par l'attaquant :** Cible configurée ou injectée sous la forme `rtsp://[::ffff:169.254.169.254]:554/`.
- **Composant vulnérable :** Parseurs d'adresses réseau ne traitant que la chaîne de caractères brute.
- **Action réseau attendue :** Contournement des filtres IPv4 par encapsulation dans la syntaxe IPv6.
- **Frontière de sécurité :** Fonction `classify_ip()` et normalisation via `ip_obj.ipv4_mapped` dans `security.py` et `egress_policy.py`.
- **Prévention requise :** Dépaquetage systématique de `ipv4_mapped` avant toute décision de filtrage.
- **Méthode de test :** Scénario `test_a4_08_ipv4_mapped_ipv6`.
- **Risque résiduel :** Éliminé.

---

### Attaque F : Identifiant de zone IPv6 et adresses Scoped (`fe80::1%eth0`)
- **Entrée contrôlée par l'attaquant :** URI contenant un délimiteur de zone `%interface`.
- **Composant vulnérable :** Résolveurs de sockets et constructeurs d'URL système.
- **Action réseau attendue :** Crash du composant de validation (ValueError/Uncaught Exception) provoquant un déni de service ou un basculement non maîtrisé.
- **Frontière de sécurité :** Nettoyage automatique `ip_str.split("%")[0]` dans `validate_video_target` et `is_destination_allowed`.
- **Prévention requise :** Séparation étanche de la zone avant validation réseau.
- **Méthode de test :** Scénarios `test_remediation_a1_001` et `test_a4_05_link_local_destination`.
- **Risque résiduel :** Éliminé.

---

### Attaque G : Sous-processus FFmpeg ouvrant des connexions TCP secondaires arbitraires
- **Entrée contrôlée par l'attaquant :** Démultiplexage d'un conteneur média complexe référençant des ressources externes (ex: sous-titres distants, playlist HLS imbriquée).
- **Composant vulnérable :** Moteur libavformat ouvrant des flux auxiliaires.
- **Action réseau attendue :** Requêtes sortantes non sollicitées vers des serveurs tiers.
- **Frontière de sécurité :** `-an -sn` (suppression audio et sous-titres) combiné à `-protocol_whitelist tcp,rtp,rtsp`.
- **Prévention requise :** Désactivation de tous les flux auxiliaires et restriction stricte des protocoles.
- **Méthode de test :** Scénario `test_ffmpeg_adapter_command_construction_safe`.
- **Risque résiduel :** Éliminé par la construction minimale de la commande.

---

### Attaque H : Serveur caméra malveillant renvoyant un SDP surdimensionné ou corrompu
- **Entrée contrôlée par l'attaquant :** Réponse réseau RTSP saturée d'octets invalides (10 Mo d'en-têtes, crash mémoire libavformat).
- **Composant vulnérable :** Parseur C de FFmpeg et tubes IPC parent/enfant.
- **Action réseau attendue :** Crash du processus FFmpeg ou blocage en mémoire.
- **Frontière de sécurité :** `_read_exact` sur `stdout` et `_stderr_drain_worker` avec mémoire bornée à 64 Ko (`MAX_DIAGNOSTIC_BYTES`).
- **Prévention requise :** Détection de code de retour anormal de FFmpeg, passage en état `VideoSourceStatus.STALLED`/`ERROR`, et affichage d'une mire de substitution.
- **Méthode de test :** Scénarios `test_a3_ipc_stderr_bounded_memory_under_heavy_logging` et `test_a4_13_malformed_sdp`.
- **Risque résiduel :** Éliminé.

---

### Attaque I : Serveur RTSP hostile provoquant des reconnexions excessives (DDoS local)
- **Entrée contrôlée par l'attaquant :** Fermeture de socket immédiate après acceptation TCP, incitant le NVR à reconnecter en boucle infinie (saturation CPU / logs).
- **Composant vulnérable :** Thread de supervision du NVR.
- **Action réseau attendue :** Boucle de connexion rapide (plusieurs centaines de `Popen` par seconde).
- **Frontière de sécurité :** Algorithme de backoff exponentiel (`_current_backoff = min(_current_backoff * 1.5, config.max_backoff)`).
- **Prévention requise :** Cadencement forcé avec temps de repos croissant entre 1.0s et 30.0s.
- **Méthode de test :** Scénario `test_a4_14_excessive_reconnect_attempts`.
- **Risque résiduel :** Éliminé.

---

### Attaque J : Arrêt du processus laissant des processus orphelins ou des sockets ouvertes
- **Entrée contrôlée par l'attaquant :** Interruption brutale du flux ou blocage partiel lors d'un appel `close()`.
- **Composant vulnérable :** Gestionnaire de sous-processus de l'hôte.
- **Action réseau attendue :** Fuite de descripteurs de sockets maintenant des connexions zombie sur le réseau local.
- **Frontière de sécurité :** `_cleanup_process()` fermant explicitement `stdin`, `stdout`, `stderr`, suivie de `terminate()` puis `kill()` avec `wait(timeout=1.0)`.
- **Prévention requise :** Fermeture ordonnée garantie et enregistrement `atexit.register(self.close)`.
- **Méthode de test :** Scénarios `test_ffmpeg_process_cleanup_no_orphans` et `test_a4_15_worker_termination`.
- **Risque résiduel :** Éliminé.

---

### Attaque K : Processus exécuté en dehors de la frontière d'isolation attendue
- **Entrée contrôlée par l'attaquant :** Démarrage de l'application sur un serveur où le pare-feu ou le conteneur est désactivé.
- **Composant vulnérable :** Système de déploiement en production.
- **Action réseau attendue :** Fonctionnement en mode dégradé silencieux avec exposition aux attaques SSRF.
- **Frontière de sécurité :** Détection d'état `check_egress_enforcement_status()` et bascule **Fail-Closed** (`require_os_egress_confinement=True`).
- **Prévention requise :** Refus catégorique d'ouvrir le flux si l'environnement d'isolation revendiqué n'est pas actif.
- **Méthode de test :** Scénarios `test_a4_16_isolation_unavailable` et `test_a4_17_firewall_policy_absent`.
- **Risque résiduel :** Éliminé grâce à la politique fail-closed.

---

## 2. ARCHITECTURE DE LA POLITIQUE D'EGRESS (DENY-BY-DEFAULT)

Le module `monitoring/acquisition/egress_policy.py` applique une stratégie de sécurité à trois niveaux :

```
[Flux RTSP Demandé]
        │
        ▼
[Niveau 1 : Hygiène des Cibles (validate_video_target)]
        ├─ Parsing des identifiants et masquage (sanitize_uri)
        ├─ Vérification des ports interdits globaux (PROHIBITED_PORTS)
        └─ Résolution DNS exhaustive (IPv4 / IPv6) avec Fail-Closed
        │
        ▼
[Niveau 2 : Confinement Egress Applicatif (EgressPolicy)]
        ├─ Rejet absolu : Link-Local, Cloud Metadata, Multicast, Broadcast
        ├─ Rejet Loopback inconditionnel en Production
        ├─ Contrôle d'appartenance à l'Allowlist explicite (IP ou CIDR)
        └─ Rejet de tout RFC1918 / ULA non explicitement autorisé
        │
        ▼
[Niveau 3 : Contrôle de la Frontière Système (check_egress_enforcement_status)]
        ├─ Détection de l'état réel (Pare-feu Windows / Conteneur Docker)
        └─ Si isolation requise mais absente -> REJET FAIL-CLOSED (BLOCKED_SSRF)
```

### Règles de validation de l'Allowlist :
1. **Interdiction des listes vides :** `allowed_destinations` ne peut être ni vide ni `None` (`PolicyConfigurationError`).
2. **Interdiction des masques génériques :** Tout préfixe IPv4 $\le /8$ (ex: `0.0.0.0/0`, `10.0.0.0/8`) ou IPv6 $\le /16$ est formellement rejeté au démarrage.
3. **Interdiction des métadonnées :** L'inclusion de `169.254.0.0/16` dans la liste blanche lève une exception immédiate.
