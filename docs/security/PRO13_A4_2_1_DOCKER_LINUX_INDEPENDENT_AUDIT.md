# 🛡️ SSM PRO-13-A.4.2.1 — DOCKER / LINUX INDEPENDENT AUDIT
## AUDIT DES MANIFESTES CONTENEUR, CAPACITÉS LINUX ET CONFINEMENT HÔTE DOCKER-USER / NFTABLES

**Mission ID :** `SSM-PRO13-A4.2.1-INDEPENDENT-AUDIT-AND-LIVE-END-TO-END-QUALIFICATION-01`  
**Composants audités :** `docker/docker-compose.nvr-egress.yml`, `docker/Dockerfile.nvr-worker`, `scripts/setup_docker_egress_host.sh`  
**Date d'audit :** 2026-11-26T16:07:00+01:00  

---

## 1. AUDIT DE L'ISOLATION DU CONTENEUR NVR

L'audit des fichiers de définition Docker confirme :
1. **Identité d'exécution :** Utilisateur non-privilégié `user: "10001:10001"`, `privileged: false`, `security_opt: [no-new-privileges:true]`.
2. **Minimisation des capacités noyau :** `cap_drop: [ALL]`. Aucune capacité `CAP_NET_ADMIN` n'est accordée au worker.
3. **Système de fichiers :** `read_only: true` avec `tmpfs` montés sous restrictions strictes (`noexec,nosuid`).
4. **Réseau :** Bridge dédié `172.28.10.0/24`. Absence formelle de `network_mode: host` et aucun port publié vers l'extérieur.
5. **Suppression de la variable falsifiable :** La variable `SSM_EGRESS_CONTAINER_ISOLATED=true` a été retirée du compose.

---

## 2. AUDIT DU FILTRAGE HÔTE (`scripts/setup_docker_egress_host.sh`)

1. **Couche de confiance :** Le filtrage est positionné sur l'hôte Docker (chaîne `DOCKER-USER` sous iptables ou hook `forward` sous nftables).
2. **Politique Deny-by-Default :**
   - Blocage inconditionnel des métadonnées cloud (`169.254.0.0/16`) et link-local IPv6 (`fe80::/10`).
   - Autorisation des paquets sortants vers les caméras approuvées `${ALLOWED_CAMERAS}` sur les ports autorisés `${ALLOWED_PORTS}`.
   - `DROP` et journalisation explicite (`SSM_DOCKER_EGRESS_DROP: `) de tout autre trafic émis depuis le sous-réseau `172.28.10.0/24`.
3. **Idempotence :** Le script remplace les règles ciblées sans dupliquer les chaînes ni affecter les conteneurs tiers.

---

## 3. STATUT SUR CET HÔTE D'AUDIT

Le démon Docker étant arrêté sous Windows (`Get-Command docker` présent, mais démon inaccessible), aucun conteneur n'a été instancié. Les tests système réels sont classés **`NOT_AVAILABLE`**.
