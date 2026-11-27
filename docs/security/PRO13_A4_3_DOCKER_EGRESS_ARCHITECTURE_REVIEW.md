# PRO13-A.4.3 — DOCKER EGRESS ARCHITECTURE REVIEW

**Mission ID :** `SSM-PRO13-A4-3-EGRESS-HARDENING-AND-CRYPTOGRAPHIC-CONTINUITY-01`  
**Date / Horodatage :** 2026-11-27T07:07:30+01:00  
**Dépôt :** `C:\Users\USER\Documents\alarme-sys` | **Branche :** `main` | **HEAD :** `b339a9c82d5b410e78d1ea6d43cae556049ba2c0`  
**Périmètre :** Audit statique de `docker/Dockerfile.nvr-worker`, `docker/docker-compose.nvr-egress.yml` et `scripts/setup_docker_egress_host.sh`.  
**État Docker sur l'hôte :** `com.docker.service = Stopped` (non démarré conformément aux interdictions).

---

## 1. ANALYSE STATIQUE DU CONTENEUR (`docker-compose.nvr-egress.yml` & `Dockerfile.nvr-worker`)

- **Privilèges et capacités :** `user: "10001:10001"`, `privileged: false`, `no-new-privileges: true`, `cap_drop: ALL`, `read_only: true`, `pids: 50`, `cpus: 1.0`, `memory: 512M`. Aucun montage du socket Docker (`/var/run/docker.sock`). **Très bon durcissement applicatif.**
- **Réseau :** Réseau bridge dédié `ssm-nvr-isolated-net` (`172.28.10.0/24`, `internal: false`). Comme indiqué en commentaire, `internal: false` laisse le trafic sortir vers la passerelle hôte : **le réseau Docker seul n'isole pas le trafic sortant**.

---

## 2. ANALYSE STATIQUE DU SCRIPT HÔTE (`scripts/setup_docker_egress_host.sh`)

- **Approche :** Utilise `DOCKER-USER` (`iptables`) ou `nftables` (`table inet ssm_nvr_egress`) sur l'hôte Linux pour filtrer `172.28.10.0/24`.
- **Points forts :** Bloque `169.254.0.0/16`, n'autorise que `${ALLOWED_CAMERAS}` sur `${ALLOWED_PORTS}` en TCP, journalise et `DROP` le reste.
- **Lacunes identifiées :**
  1. **Absence de filtrage IPv6 dans la branche `nftables` :** Les règles `nftables` ne filtrent que `ip saddr` / `ip daddr` (IPv4). Si IPv6 est actif sur le bridge Docker, il n'est pas filtré par `table inet ssm_nvr_egress`.
  2. **Non-idempotence dans `DOCKER-USER` :** Des exécutions répétées insèrent des règles en doublon (`iptables -I DOCKER-USER 1/2/3`).
  3. **Flux DNS :** Le trafic UDP/TCP 53 est bloqué par le `DROP` final (acceptable uniquement si toutes les caméras sont configurées par IP littérale).

---

## 3. TABLEAU COMPARATIF DES SOLUTIONS DE CONFINEMENT

| Solution | Niveau de confinement attendu | Dépendances | Risques | Conditions |
|---|---|---|---|---|
| **Windows Firewall (hôte standard)** | Partiel / Risqué si `DefaultBlock` global | Droits Admin + correction chevauchement RFC1918 | Contournement IP publiques ou autre `/16`, effet de bord si `DefaultBlock` | Serveur Windows dédié + règles Block complémentaires |
| **Docker bridge + filtrage hôte (`DOCKER-USER`/nftables)** | Élevé (IPv4) ; incomplet en `nftables` IPv6 | Hôte Linux + Docker + droits root | IPv6 non filtré en `nftables`, non-idempotence | Hôte Linux, règles IPv4+IPv6 idempotentes, caméra par IP |
| **Isolation dédiée (VLAN / Pare-feu matériel)** | Très élevé (indépendant de l'OS) | Infrastructure réseau dédiée | Coût d'infrastructure | Hors périmètre poste local |

---

## 4. STATUT

```text
DOCKER_EGRESS_REVIEW_GATE = PASS_WITH_LIMITATIONS  (Architecture saine en IPv4 ; Docker arrêté sur l'hôte, IPv6 nftables et idempotence à corriger)
```
