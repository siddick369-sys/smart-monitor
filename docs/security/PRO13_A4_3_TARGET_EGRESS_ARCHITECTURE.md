# PRO13-A.4.3 — TARGET EGRESS ARCHITECTURE (PROPOSITION DOCUMENTAIRE)

**Mission ID :** `SSM-PRO13-A4-3-EGRESS-HARDENING-AND-CRYPTOGRAPHIC-CONTINUITY-01`  
**Date / Horodatage :** 2026-11-27T07:11:30+01:00  
**Dépôt :** `C:\Users\USER\Documents\alarme-sys` | **Branche :** `main` | **HEAD :** `b339a9c82d5b410e78d1ea6d43cae556049ba2c0`  
**Statut :** PROPOSITION ARCHITECTURALE NON APPLIQUÉE.

---

## 1. EXIGENCES DE L'ARCHITECTURE CIBLE

1. FFmpeg ne peut accéder qu'aux IP/ports explicitement autorisés (IPv4 et IPv6).
2. Toutes les autres connexions sortantes (IP publiques, RFC1918 non autorisées dans le même `/16`, ULA, metadata, loopback en prod) sont refusées.
3. Les règles sont liées au chemin absolu vérifié de `ffmpeg.exe`, persistantes après redémarrage, réversibles via préfixe `SSM_NVR_FFmpeg_Egress*` et sans impact sur les règles tierces.
4. La détection d'enforcement reste strictement séparée de la validation applicative.

---

## 2. MACHINE À ÉTATS PROPOSÉE (DOCUMENTAIRE)

```text
UNKNOWN
  |
  v  [Validation syntaxique URL/IP/port/DNS pinning]
POLICY_VALIDATED
  |
  v  [Inspection réelle OS Firewall / Host DOCKER-USER / nftables]
SYSTEM_ENFORCEMENT_CHECK
  |
  +----> ENFORCED              (Politique Deny-by-Default + règles Allow/Block IPv4+IPv6 vérifiées)
  |
  +----> NOT_ENFORCED          (Règle absente, désactivée, chevauchement non bloqué ou Default=Allow sans Block complet)
  |
  +----> VERIFICATION_FAILED   (Erreur d'inspection, privilèges insuffisants ou binaire introuvable)
```

### Règles de transition et comportement Fail-Closed :
- **Mode sécurisé (`require_os_egress_confinement=True`) :** Seul l'état `ENFORCED` autorise le lancement de `FFmpegAdapter`. Les états `NOT_ENFORCED` et `VERIFICATION_FAILED` provoquent un refus immédiat (`BLOCKED_SSRF`).
- **Récupération :** Repasser par `SYSTEM_ENFORCEMENT_CHECK` après déploiement administrateur et contrôle post-redémarrage ; aucune mise en cache permanente ni contournement par variable d'environnement.
