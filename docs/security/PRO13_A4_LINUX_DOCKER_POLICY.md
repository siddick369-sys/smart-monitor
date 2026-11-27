# 🛡️ SSM PRO-13-A.4 — LINUX & DOCKER CONFINEMENT POLICY
## CONTAINERIZED WORKER DESIGN, CAPABILITY MINIMIZATION, READ-ONLY ROOTFS, AND NETWORK EGRESS ISOLATION

**Mission ID :** `SSM-PRO13-A4-FFMPEG-EGRESS-CONFINEMENT-AND-LOT-A-FINAL-GATE-01`  
**Composants audités :** `docker/docker-compose.nvr-egress.yml`, `docker/Dockerfile.nvr-worker`, `monitoring/acquisition/egress_policy.py`  
**Plateforme cible :** Linux (Debian 12 Bookworm / Alpine Linux) & Docker Engine 28.x+  
**Date :** 2026-11-24

---

## 1. PRINCIPES ARCHITECTURAUX DU WORKER DOCKER DURCI

Pour les déploiements Linux et industriels, la solution de confinement de référence repose sur la conteneurisation stricte du worker d'acquisition vidéo FFmpeg.  
Le worker ne s'exécute pas dans le même conteneur ou contexte réseau que le serveur web Flask ou la base de données. Il est isolé dans un sous-système découplé :

```
┌────────────────────────────────────────────────────────┐
│  Hôte / Orchestrateur Docker                          │
│                                                        │
│  ┌───────────────────────┐   IPC /     ┌────────────┐  │
│  │ SSM Core / Web API    │◄──Shm / ───►│ NVR Worker │  │
│  │ (Flask / SQLite)      │   Socket    │ (FFmpeg)   │  │
│  └───────────────────────┘             └──────┬─────┘  │
│                                               │        │
└───────────────────────────────────────────────┼────────┘
                                                │ Réseau Isolé
                                                │ (Deny-by-Default)
                                                ▼
                                         [Caméras Approuvées]
                                         (192.168.1.50:554)
                                         (Métadonnées & LAN : BLOQUÉS)
```

---

## 2. SPÉCIFICATION DE DURCISSEMENT DU CONTENEUR (`docker-compose.nvr-egress.yml`)

Le fichier de déploiement `docker/docker-compose.nvr-egress.yml` applique les directives de durcissement suivantes :

### 2.1 Identité non-privilégiée et interdiction d'élévation
- **Utilisateur dédié :** `user: "10001:10001"` (utilisateur `ssmworker`). Le conteneur ne tourne jamais sous `root`.
- **Interdiction de privilèges :** `privileged: false`.
- **Prévention d'élévation de privilèges :** `security_opt: [no-new-privileges:true]`. Empêche l'exploitation de binaires `setuid` / `setgid`.

### 2.2 Minimisation drastique des capacités du noyau (`Capabilities`)
- **Abandon total :** `cap_drop: [ALL]`. Aucune capacité résiduelle (`CAP_NET_ADMIN`, `CAP_SYS_ADMIN`, `CAP_SYS_PTRACE`, `CAP_NET_RAW` sont révoquées). Le sous-processus FFmpeg ne peut ni modifier ses interfaces réseau, ni capturer le trafic d'autres processus, ni créer de sockets brutes (raw sockets).

### 2.3 Système de fichiers immuable en lecture seule
- **Système de fichiers racine :** `read_only: true`. Le conteneur ne peut écrire sur aucun fichier du système d'exploitation ou du code source Python.
- **Points de montage temporaires en mémoire :**
  - `/tmp:rw,noexec,nosuid,size=64m` (pour les tampons éphémères du décodage).
  - `/run:rw,noexec,nosuid,size=16m`.
  Les options `noexec` et `nosuid` empêchent l'exécution de tout binaire téléchargé ou injecté dans `/tmp`.

### 2.4 Bornage des ressources et protection anti-Fork Bomb
- `cpus: '1.0'` : Plafonnement de l'usage processeur à 1 cœur.
- `memory: 512M` : Empreinte mémoire strictement plafonnée à 512 Mo.
- `pids: 50` : Limite stricte à 50 processus/threads simultanés pour neutraliser tout risque d'attaque par déni de service de type fork-bomb.

---

## 3. CONFINEMENT RÉSEAU SORTANT (EGRESS DENY-BY-DEFAULT)

### 3.1 Proscription absolue du mode réseau hôte
L'option `network_mode: host` est **formellement interdite**. Le conteneur est rattaché à un réseau bridge dédié : `ssm-nvr-isolated-net`.

### 3.2 Contrôle du routage et des destinations
1. **Passerelle contrôlée :** Le réseau `ssm-nvr-isolated-net` n'a pas accès aux sous-réseaux internes sensibles de l'hôte (réseaux d'administration, Docker daemon socket).
2. **Filtrage des métadonnées cloud :** Les passerelles Docker et règles iptables de l'hôte interdisent tout transit du conteneur worker vers `169.254.169.254/32` et `fe80::/10`.
3. **Variables d'environnement de contrôle :**
   - `SSM_EGRESS_CONTAINER_ISOLATED=true` : Active la détection formelle de l'isolation par `check_egress_enforcement_status()`.
   - `ALLOWED_CAMERA_IPS=192.168.1.50/32` : Liste blanche stricte transmise à `EgressPolicy`.

---

## 4. CONSTAT FORENSIQUE DE L'ENVIRONNEMENT D'AUDIT

- **Présence du CLI Docker :** Docker version 28.4.0 est installé sur l'hôte.
- **État du démon Docker :** La commande `docker ps` signale que le moteur Docker Desktop Linux Engine n'est pas démarré (`The system cannot find the file specified`).
- **Qualification exacte :**
  ```
  [LINUX_DOCKER_RUNTIME] = NOT_AVAILABLE_DAEMON_NOT_STARTED
  [DOCKER_COMPOSE_SPECIFICATION] = ARTIFACT_PREPARED_AND_VERIFIED
  ```
La spécification et les fichiers de configuration sont déposés et validés statiquement dans `docker/`, prêts pour le déploiement sur les environnements cibles Linux.
