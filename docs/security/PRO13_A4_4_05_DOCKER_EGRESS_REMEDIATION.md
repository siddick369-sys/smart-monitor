# PRO13-A.4.4 — DOCKER EGRESS REMEDIATION REPORT

**Mission ID :** `SSM-PRO13-A4-4-CONTROLLED-REMEDIATION-AND-SECURITY-CLOSURE-01`  
**Date / Horodatage :** 2026-11-27T07:59:30+01:00  
**Dépôt :** `C:\Users\USER\Documents\alarme-sys` | **Branche :** `main` | **HEAD :** `b339a9c82d5b410e78d1ea6d43cae556049ba2c0`  

---

## 1. CORRECTIONS APPORTÉES À `scripts/setup_docker_egress_host.sh`

1. **Idempotence stricte sans suppression globale :**
   - Branche `iptables-docker-user` : tague toutes les règles avec `-m comment --comment "SSM_DOCKER_EGRESS"` et purge uniquement ces règles avant réinsertion, préservant les règles tierces de l'hôte.
   - Branche `nftables` : supprime uniquement `table inet ssm_nvr_egress` avant réapplication atomique.
2. **Couverture IPv6 ajoutée en branche `nftables` et `ip6tables` :**
   - Bloque `fe80::/10`, `::1/128`, et journalise/drop le trafic sortant `fc00::/7`.

---

## 2. STATUT

```text
DOCKER_EGRESS_GATE = PASS  (Idempotence et couverture IPv4/IPv6 vérifiées statiquement et par tests)
DOCKER_HOST_RUNTIME = NOT_AVAILABLE  (com.docker.service = Stopped, non démarré)
```
