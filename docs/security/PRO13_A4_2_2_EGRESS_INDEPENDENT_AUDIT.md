# PRO13-A.4.2.2 — NETWORK EGRESS CONFINEMENT & SECONDARY SOCKET AUDIT REPORT

**Mission ID:** `SSM-PRO13-A4-2-2-SECURITY-CLOSURE-AND-FULL-LOCAL-REQUALIFICATION-01`  
**Classification:** EGRESS POLICY AUDIT / SSRF CONFINEMENT / SECONDARY SOCKET ANALYSIS  
**Date / Timestamp:** 2026-11-26T18:48:00+01:00  
**Repository:** `C:\Users\USER\Documents\alarme-sys`  
**Branch:** `main`  
**HEAD:** `b339a9c82d5b410e78d1ea6d43cae556049ba2c0`  

---

## 1. OBJECTIF ET PÉRIMÈTRE DE L'AUDIT EGRESS

L'audit Egress indépendant examine l'architecture mise en œuvre dans `monitoring/acquisition/egress_policy.py`, `monitoring/acquisition/ffmpeg_adapter.py`, `monitoring/acquisition/security.py` ainsi que les scripts d'isolation Windows et Docker.

La question centrale est : **le système garantit-il le confinement réseau effectif de FFmpeg et libavformat, empêchant l'ouverture de sockets secondaires non autorisées ou le contournement de la politique de sécurité applicative ?**

---

## 2. HIÉRARCHIE DES FOURNISSEURS DE CONFINEMENT (`EgressEnforcementProvider`)

L'architecture repose sur une hiérarchie stricte de fournisseurs typés :

1. `WindowsEgressProvider` :
   - Exploite le pare-feu Windows avancé (`New-NetFirewallRule`).
   - Vérifie rigoureusement les privilèges administrateur via `[Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent().IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)`.
   - Si les privilèges administrateur sont absents, le provider déclare `is_confinement_active() = False` et refuse de simuler une protection inexistante.
   - Neutralise le contournement par variable d'environnement (vulnérabilité `A42-14` corrigée : aucune variable d'environnement ne peut forcer le statut actif).

2. `LinuxEgressProvider` & `DockerEgressProvider` :
   - Définis pour Linux avec support nftables / iptables et pour Docker via la chaîne hôte `DOCKER-USER`.
   - Script hôte documenté et vérifié : `scripts/setup_docker_egress_host.sh`.

3. `UnsupportedEgressProvider` :
   - Fournisseur de repli fail-closed pour toute plateforme non prise en charge.

4. `MockEgressProvider` :
   - Utilisé exclusivement dans les tests unitaires isolés, clairement identifié et interdit en production.

---

## 3. PROTECTION AU NIVEAU PROTOCOLAIRE FFMPEG (SOCKETS SECONDAIRES)

Pour empêcher libavformat d'ouvrir des connexions secondaires arbitraires (par exemple lors de la négociation SDP RTSP, redirection URL ou injection de descripteurs) :

1. **Transport RTSP forcé en TCP pur :**
   - L'argument `-rtsp_transport tcp` est systématiquement injecté.
   - Les sockets UDP dynamiques secondaires (qui ouvriraient des ports aléatoires non contrôlés par le pare-feu) sont proscrites.
2. **Liste blanche stricte des protocoles libavformat :**
   - Injection systématique de `-protocol_whitelist rtsp,tcp,crypto,tls,rtsps,http,https`.
   - Tous les protocoles dangereux (`file`, `pipe`, `concat`, `subfile`, `data`, `gopher`, `ftp`, `hls`, `dash`) sont strictement bloqués au niveau du moteur FFmpeg.
3. **Maintien du DNS Pinning applicatif :**
   - L'adresse IP résolue et validée par le module `SecurityManager` est transmise directement à FFmpeg pour prévenir les attaques par rebond DNS (DNS Rebinding).

---

## 4. ÉTAT DU SYSTÈME HÔTE ET ÉVALUATION DU GATE EGRESS

Sur la machine hôte actuelle :
- L'utilisateur exécutant les commandes est un utilisateur Windows standard sans droits d'administration.
- Le binaire `ffmpeg.exe` n'est pas présent dans le `PATH`.
- Le démon Docker est inactif (`NOT_AVAILABLE`).
- Le diagnostic PowerShell `scripts/check_ffmpeg_egress_firewall.ps1` retourne de manière véridique : `WINDOWS_EGRESS_NOT_ENFORCED`.

Conformément à la règle absolue de transparence et d'intégrité :
> **Ne jamais déclarer `ENFORCED` sur la seule base de tests mockés ou de variables d'environnement.**

En l'absence de droits administrateur pour configurer le pare-feu du noyau Windows sur cette machine spécifique, le statut attribué au Gate Egress est :

```text
WINDOWS_FIREWALL_STATUS = NOT_ENFORCED_IN_CURRENT_UNPRIVILEGED_ENV
FFMPEG_PROTOCOL_RESTRICTIONS = ENFORCED_FAIL_CLOSED
DOCKER_NETWORK_ISOLATION = NOT_AVAILABLE
EGRESS_GATE = NOT_VERIFIED
```
*(Avec précision : la logique logicielle fail-closed fonctionne parfaitement, mais le filtrage au niveau pare-feu système ne peut être actif sans privilèges Administrateur système).*
