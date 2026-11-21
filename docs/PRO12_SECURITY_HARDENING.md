# 🔐 SMART SECURITY MONITOR — GUIDE DE SÉCURITÉ & GESTION DES CLÉS CRYPTOGRAPHIQUES (PRO-12)
## Architecture Cryptographique, Gestion des Clés et Durcissement Applicatif

---

## 1. VUE D'ENSEMBLE DU DURCISSEMENT PRO-12

Le cycle de durcissement **PRO-12** traite et élimine définitivement les cinq vulnérabilités critiques (P0) mises en évidence lors de l'audit contradictoire forensique `SSM-MASTER-FORENSIC-VERIFICATION-01` :

1. **Suppression de tout secret par défaut en dur** : élimination des chaînes de secours statiques dans les modules d'intégrité de preuve et de synchronisation pair-à-pair.
2. **Cycle de vie et persistance de la clé maître AES-256-GCM** : remplacement de la clé volatile générée en mémoire par un stockage sécurisé avec contrôle d'accès sur disque (`0600` / ACL NTFS) et enveloppe versionnée `SSMENC01`.
3. **Durcissement des sessions web et politique de cookies** : application systématique des attributs `HttpOnly`, `SameSite=Lax` et `Secure` en environnement de production, avec régénération de session à l'authentification et révocation à la déconnexion.
4. **Matrice de protection contre les attaques SSRF (Server-Side Request Forgery)** : validation stricte des cibles caméras IP (adresses privées RFC 1918 et liste blanche de ports dédiés à la vidéo), blocage de la boucle locale en production, interdiction des cibles link-local (cloud metadata) et du port interne Flask (5000).
5. **Durcissement du processus d'initialisation (Bootstrap) et politique de complexité des mots de passe** : création d'un jeton d'amorçage éphémère (1h) à usage unique, verrouillage irréversible après création du premier administrateur, limitation de débit (rate limiting) et politique de mot de passe robuste.

---

## 2. MODÈLE DE GESTION DES CLÉS CRYPTOGRAPHIQUES

```
                                      +---------------------------------------------+
                                      |         SMART SECURITY MONITOR              |
                                      +---------------------------------------------+
                                                             |
            +---------------------------------+--------------+-------------------------------+
            |                                 |                                              |
            v                                 v                                              v
+-----------------------+         +-----------------------+                      +-----------------------+
|  EVIDENCE HMAC KEY    |         |   P2P CLUSTER SECRET  |                      | PRIVACY MASTER KEY    |
| (Preuves Forensiques) |         |  (Cluster Résilient)  |                      |  (Déchiffrement RGPD) |
+-----------------------+         +-----------------------+                      +-----------------------+
| - Min 16/32 octets    |         | - Min 32 octets (Prod)|                      | - 256 bits (32 octets)|
| - HMAC-SHA256         |         | - Auth mutuelle nœuds |                      | - AES-256-GCM         |
| - Fallback unsealed   |         | - File locale isolée  |                      | - storage/keys/*.key  |
|   sans crash          |         |   préservée           |                      | - AAD:SSM_V1:{kid}:{r}|
+-----------------------+         +-----------------------+                      +-----------------------+
```

### 2.1 Clé d'intégrité des preuves numériques (`EVIDENCE_HMAC_KEY`)
- **Algorithme** : HMAC-SHA256 selon FIPS 198-1.
- **Rôle** : Authentification et scellement d'intégrité de la chaîne de preuves numériques (captures JPEG, clips vidéo MP4, manifestes JSON).
- **Mode dégradé sécurisé** : Si la clé n'est pas fournie, le système calcule l'empreinte SHA-256 du fichier, marque le manifeste comme `UNSEALED_NO_HMAC_KEY` avec `signature = None`. Il ne bloque pas les opérations de surveillance locale et indique formellement l'absence de signature lors de la vérification (`INTÈGRE_SANS_SIGNATURE`).
- **Détection des falsifications** : Tout bit modifié dans le fichier physique ou dans le manifeste entraîne une erreur explicite `ALTÉRATION_DÉTECTÉE_HASH_DIFFÉRENT` ou `SIGNATURE_HMAC_INVALIDE`.

### 2.2 Secret de cluster et synchronisation pair-à-pair (`P2P_CLUSTER_SECRET`)
- **Algorithme** : HMAC-SHA256 avec horodatage anti-rejeu.
- **Rôle** : Authentification mutuelle des smartphones, nœuds edge et agents de surveillance lors de l'échange de paquets store-and-forward.
- **Entropie requise** : Minimum 32 octets en environnement de production, 16 octets minimum en environnement de test.
- **Résilience déconnectée** : Si le secret est absent, les tentatives de synchronisation réseau sont refusées (`P2P_SECRET_NON_CONFIGURE`), mais la file d'attente locale `_store_forward_queue` conserve l'intégralité des événements sans perte de données.

### 2.3 Clé maître du Privacy Shield (`storage/keys/privacy_master.key`)
- **Algorithme** : AES-256 en mode Galois/Counter Mode (GCM) avec données associées authentifiées (AEAD).
- **Format du fichier** : Fichier binaire brut de 32 octets (ou encodé en chaîne hexadécimale de 64 caractères).
- **Permissions du système de fichiers** :
  - **Linux / POSIX** : Droits stricts `0600` (`chmod 600`).
  - **Windows** : Utilisation de `icacls` pour supprimer l'héritage (`/inheritance:r`) et restreindre les droits d'accès à l'utilisateur exécutant (`%USERNAME%:(R,W)`).
- **Format d'enveloppe chiffrée (`SSMENC01`)** :
  ```
  +--------------+-------------+-------------+------------+---------------+----------+------------------+
  | Magique (8o) | kid_len(1o) | res_len(2o) | kid (str)  | res_id (str)  | IV (12o) | Ciphertext + Tag |
  |   SSMENC01   |   uint8     |   uint16    | utf-8 bytes|  utf-8 bytes  |  nonce   |   AES-256-GCM    |
  +--------------+-------------+-------------+------------+---------------+----------+------------------+
  ```
- **Données Associées Authentifiées (AAD)** : `SSM_V1:{key_id}:{resource_id}` injectées dans le tag d'authentification pour empêcher toute permutation de ciphertext entre deux fichiers distincts.
- **Rétrocompatibilité** : Détection automatique des charges utiles v0 (format `IV(12) + Ciphertext + Tag`) pour préserver les enregistrements existants.

---

## 3. PROCÉDURE DE DOUBLE CONTRÔLE JUDICIAIRE (TWO-MAN RULE)

Pour accéder aux preuves originales en clair (non floutées et non anonymisées), une procédure formelle de réquisition judiciaire à double contrôle strict est requise :

1. **Initiation** : Un opérateur ou auditeur émet une demande de déchiffrement (`create_decryption_request`) mentionnant l'identifiant de la ressource et le motif légal.
2. **Durée de validité** : La demande possède un temps de validité restreint (TTL par défaut : 1 heure). Passé ce délai, elle passe automatiquement à l'état `EXPIRED`.
3. **Double approbation** : Deux approbations distinctes provenant de comptes habilités différents (`ADMIN`, `DPO`, `AUDITOR`) sont requises.
4. **Interdiction d'auto-approbation** : Si la directive `disallow_self_approval` est activée, le demandeur ne peut pas valider sa propre demande.
5. **Interdiction de cumul d'approbations** : Un même utilisateur ne peut valider qu'une seule fois la demande (`Cet utilisateur a déjà validé cette demande`).
6. **Consommation unique** : Dès que le déchiffrement est exécuté avec succès, la demande passe irréversiblement à l'état `CONSUMED`. Toute tentative ultérieure de rejeu est systématiquement rejetée.

---

## 4. MATRICE ANTI-SSRF ET VALIDATION DES CIBLES VIDÉO

Le module `config.is_allowed_camera_target(ip_str, port, is_test_env)` protège le serveur contre les attaques par rebond réseau :

| Cible IP / Plage | Port | Environnement Production | Environnement Test/Dev | Statut & Justification |
|---|---|---|---|---|
| `127.0.0.1` | 8081 | ❌ REFUSÉ | ✅ AUTORISÉ | Boucle locale interdite en prod; autorisée en dev si `ALLOW_LOOPBACK_SIMULATOR=true`. |
| `127.0.0.1` | 5000 | ❌ REFUSÉ | ❌ REFUSÉ | Port de l'application Flask hôte strictement interdit pour éviter les boucles récursives. |
| `192.168.1.50` | 8080 | ✅ AUTORISÉ | ✅ AUTORISÉ | Réseau privé RFC 1918 / port IP Webcam standard. |
| `10.0.0.15` | 4747 | ✅ AUTORISÉ | ✅ AUTORISÉ | Réseau privé RFC 1918 / port DroidCam standard. |
| `172.16.0.22` | 554 | ✅ AUTORISÉ | ✅ AUTORISÉ | Réseau privé RFC 1918 / port RTSP standard. |
| `192.168.1.50` | 22 | ❌ REFUSÉ | ❌ REFUSÉ | Port SSH interdit (seuls les ports vidéo 8080, 8081, 4747, 8000, 8082, 554, 8554 sont admis). |
| `169.254.169.254`| 8080 | ❌ REFUSÉ | ❌ REFUSÉ | Adresse Link-Local / AWS/GCP/Azure Metadata interdite. |
| `0.0.0.0` | 8080 | ❌ REFUSÉ | ❌ REFUSÉ | Adresse non spécifiée interdite. |
| `224.0.0.1` | 8080 | ❌ REFUSÉ | ❌ REFUSÉ | Adresse Multicast interdite. |
| `8.8.8.8` | 8080 | ❌ REFUSÉ | ❌ REFUSÉ | Adresse IP publique interdite (caméras exposées sur Internet non admises). |

---

## 5. INITIALISATION (BOOTSTRAP) ET POLITIQUE DE MOT DE PASSE

### 5.1 Cycle de vie du jeton de bootstrap
- Le système ne génère un jeton de bootstrap que si **aucun administrateur actif** n'existe dans la base de données relationnelle.
- Le jeton d'amorçage comporte 24 octets aléatoires générés cryptographiquement (48 caractères hexadécimaux).
- Il est sauvegardé dans `storage/keys/bootstrap.token` avec une durée de vie limitée à **1 heure**.
- Après la création réussie du premier compte administrateur, le fichier de jeton est **immédiatement supprimé** du disque.
- Toute tentative ultérieure d'appel au point d'accès `/api/auth/bootstrap` est rejetée avec une erreur 403 (`Action refusée : le système possède déjà un compte administrateur`).

### 5.2 Protection contre les attaques par force brute (Rate Limiting)
- Toute tentative d'initialisation échouée est horodatée par adresse IP source.
- Dès que 5 tentatives consécutives échouent dans une fenêtre glissante de 5 minutes, l'adresse IP est temporairement bloquée (`Trop de tentatives d'initialisation échouées. Veuillez patienter 5 minutes`).

### 5.3 Politique de robustesse des mots de passe
Le validateur `validate_password_complexity` applique les règles suivantes :
- Longueur minimale de **8 caractères**.
- Présence obligatoire d'au moins une lettre **minuscule** (`[a-z]`).
- Présence obligatoire d'au moins une lettre **majuscule** (`[A-Z]`).
- Présence obligatoire d'au moins un **chiffre** (`[0-9]`).
- Présence obligatoire d'au moins un **caractère spécial** (`[^a-zA-Z0-9]`).
- Rejet systématique des dictionnaires de mots de passe triviaux (`password`, `admin1234`, `azerty123`, etc.).

---

## 6. SOUVERAINETÉ ET RÉSILIENCE 100% LOCALE

L'architecture PRO-12 est conçue pour fonctionner de manière autonome et souveraine, sans dépendance obligatoire envers un service cloud externe :
- **Vision par ordinateur** : Inférence locale OpenCV (Haar Cascades, seuillage de mouvement, soustraction de fond, analyse spatiale) avec bascule transparente en cas d'indisponibilité du réseau.
- **Scellement des preuves** : Horodatage certifié local (`LOCAL_CHAINED_HMAC` sous mode dégradé RFC 3161) avec chaînage SHA-256 sans nécessiter d'autorité TSA tierce sur Internet.
- **Audit de sécurité** : L'API `config.validate_security_configuration()` permet de surveiller la conformité de la configuration sans jamais exposer de clé ou de secret en clair dans les journaux ou réponses API.
