# PRO13-A.4.3 — WINDOWS FIREWALL POLICY REVIEW

**Mission ID :** `SSM-PRO13-A4-3-EGRESS-HARDENING-AND-CRYPTOGRAPHIC-CONTINUITY-01`  
**Date / Horodatage :** 2026-11-27T07:06:30+01:00  
**Dépôt :** `C:\Users\USER\Documents\alarme-sys` | **Branche :** `main` | **HEAD :** `b339a9c82d5b410e78d1ea6d43cae556049ba2c0`  
**Périmètre :** État observable de Windows Defender Firewall sans modification ni élévation de privilèges.  
**Méthode :** Commandes PowerShell en lecture seule (`Get-NetFirewallProfile`, `Get-NetFirewallRule -Name "*SSM*"`, `scripts/check_ffmpeg_egress_firewall.ps1`).

---

## 1. OBSERVATIONS SYSTÈME EN LECTURE SEULE

- **Profils Windows Defender Firewall :**
  - `Domain` : `Enabled = True`, `DefaultInboundAction = NotConfigured`, `DefaultOutboundAction = NotConfigured` (équivalent effectif à **Allow** en sortie).
  - `Private` : `Enabled = True`, `DefaultInboundAction = NotConfigured`, `DefaultOutboundAction = NotConfigured`.
  - `Public` : `Enabled = True`, `DefaultInboundAction = NotConfigured`, `DefaultOutboundAction = NotConfigured`.
- **Règles SSM présentes :** Aucune règle `SSM_NVR_FFmpeg_Egress*` trouvée.
- **Diagnostic script :** `scripts/check_ffmpeg_egress_firewall.ps1` retourne `WINDOWS_EGRESS_NOT_ENFORCED` (code de sortie `1` / `2` selon appel).
- **Limitation d'observabilité :** L'inventaire exhaustif de toutes les règles globales tierces n'est pas modifié ni étendu ; en session standard non-administrateur, certaines propriétés de règles système peuvent rester partiellement observables.

---

## 2. ANALYSE DE CONFORMITÉ

- **Politique sortante effective :** Permissive par défaut (`Outbound = Allow`).
- **Confinement FFmpeg au niveau OS :** **INACTIF** (`NOT_ENFORCED`).
- **Conditions requises pour un enforcement réel :**
  1. Exécution administrateur sur hôte dédié ou serveur NVR ;
  2. Correction de la logique d'exclusion de sous-réseaux privés et blocage des destinations publiques pour le programme cible (ou utilisation de `DefaultOutboundAction=Block` sur environnement serveur dédié) ;
  3. Revalidation post-redémarrage et test de connectivité TCP contrôlé.

---

## 3. STATUT

```text
WINDOWS_FIREWALL_REVIEW_GATE = PASS_WITH_LIMITATIONS  (État observé : WINDOWS_EGRESS_NOT_ENFORCED)
```
