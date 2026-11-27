# 🛡️ SSM PRO-13-A.4.2 — LINUX & DOCKER EGRESS ARCHITECTURE
## ISOLATION CONTENEUR, DROPS DE CAPACITÉS ET FILTRAGE HÔTE DOCKER-USER / NFTABLES

**Mission ID :** `SSM-PRO13-A4.2-CORRECTIVE-EGRESS-ENFORCEMENT-AND-VERIFICATION-01`  
**Branche :** `main` | **HEAD initial/final :** `b339a9c82d5b410e78d1ea6d43cae556049ba2c0`  
**Timestamp :** `2026-11-26T06:40:00+01:00`  
**Environnement :** `Windows 11 AMD64 · Docker CLI 28.4.0 · Démon Docker arrêté (NOT_AVAILABLE)`

---

## 1. REMÉDIATION DES ARTEFACTS DOCKER

1. **`docker/docker-compose.nvr-egress.yml` :**
   - Suppression de `SSM_EGRESS_CONTAINER_ISOLATED=true` (interdiction de déclarer un confinement actif par variable d'environnement).
   - Maintien strict de : `user: "10001:10001"`, `privileged: false`, `cap_drop: [ALL]`, `no-new-privileges:true`, `read_only: true`, `tmpfs` bornés (`noexec,nosuid`), limites CPU (`1.0`), RAM (`512M`), PIDs (`50`).
   - Absence formelle de `network_mode: host` et de ports publiés.
   - Documentation explicite que `internal: false` nécessite le filtrage sur l'hôte Linux via `scripts/setup_docker_egress_host.sh`.
2. **`docker/Dockerfile.nvr-worker` :**
   - Suppression du paquet `iptables` du conteneur non privilégié (`10001:10001` avec `cap_drop: ALL` ne doit et ne peut pas gérer ses propres règles réseau).
3. **`scripts/setup_docker_egress_host.sh` :**
   - Détection automatique du backend pare-feu réel de l'hôte (`iptables` chaîne `DOCKER-USER` ou `nftables` hook `forward`).
   - Politique `Deny-by-Default` sur le sous-réseau `172.28.10.0/24` :
     - Blocage explicite de `169.254.0.0/16` (Cloud Metadata / Link-Local) et `fe80::/10` (IPv6).
     - Autorisation stricte uniquement vers `${ALLOWED_CAMERAS}` sur `${ALLOWED_PORTS}`.
     - Journalisation (`SSM_DOCKER_EGRESS_DROP: `) et `DROP` de tout autre trafic sortant.

---

## 2. LIMITATION ET STATUT DE QUALIFICATION

Le démon Docker n'étant pas actif sur l'environnement Windows d'audit (`Docker daemon NOT_AVAILABLE`), aucun conteneur n'a été construit ni démarré. Tous les tests nécessitant un noyau Linux / démon Docker réel sont classés **`NOT_AVAILABLE`** et devront être exécutés sur l'hôte Linux cible avec `scripts/setup_docker_egress_host.sh`.
