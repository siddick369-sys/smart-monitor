# 🛡️ SSM PRO-13-A.4.2.1 — WINDOWS FIREWALL INDEPENDENT AUDIT
## AUDIT FORENSIQUE DE LA POLITIQUE SORTANTE EFFECTIVE SOUS WINDOWS ET OBSERVATIONS SYSTÈME

**Mission ID :** `SSM-PRO13-A4.2.1-INDEPENDENT-AUDIT-AND-LIVE-END-TO-END-QUALIFICATION-01`  
**Composants audités :** `scripts/setup_ffmpeg_egress_firewall.ps1`, `scripts/check_ffmpeg_egress_firewall.ps1`, `scripts/teardown_ffmpeg_egress_firewall.ps1`  
**Plateforme d'audit :** Microsoft Windows 11 AMD64  
**Date d'audit :** 2026-11-26T16:06:00+01:00  

---

## 1. POLITIQUE SORTANTE EFFECTIVE DU SYSTÈME D'EXPLOITATION

L'exécution du script de diagnostic non destructif `scripts/check_ffmpeg_egress_firewall.ps1` sur l'hôte Windows a établi les propriétés suivantes :
- Profils Windows Defender Firewall : `Domain`, `Private`, `Public` sont `Enabled=True`.
- `DefaultOutboundAction` : `NotConfigured` (hérite de la politique Windows par défaut `AllowOutbound`).
- Règles SSM : aucune règle `SSM_NVR_FFmpeg_Egress*` n'est installée.
- Verdict réel observé : `WINDOWS_EGRESS_NOT_ENFORCED`.

---

## 2. AUDIT DE LA PRÉCÉDENCE BLOCK VS ALLOW ET DENY-BY-DEFAULT

### 2.1 Faiblesse d'une simple règle Allow (Rappel A4.1)
Sur un pare-feu dont le profil sortant est `Allow`, une règle `-Action Allow` isolée n'interdit aucun paquet émis vers des destinations tierces.

### 2.2 Solution implémentée dans `setup_ffmpeg_egress_firewall.ps1`
1. Création de la règle Allow `SSM_NVR_FFmpeg_Egress_AllowCameras` restreinte aux destinations et ports déclarés.
2. Création de la règle Block `SSM_NVR_FFmpeg_Egress_BlockProhibited` ciblant :
   - Cloud Metadata : `169.254.169.254/32`, `169.254.0.0/16`, `fe80::/10` ;
   - Loopback : `127.0.0.0/8`, `::1/128` ;
   - Multicast/Broadcast : `224.0.0.0/4`, `ff00::/8`, `255.255.255.255/32` ;
   - Plages RFC1918 / ULA non utilisées par la caméra (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `fc00::/7`).
3. Prise en compte de la précédence : les sous-réseaux privés chevauchant la caméra autorisée sont exclus de la règle `Block` pour éviter que le blocage n'écrase l'autorisation (`Block overrides Allow`).
4. Option `-EnforceDefaultBlockProfile` : bascule les profils actifs en `DefaultOutboundAction = Block` sur instruction explicite.

---

## 3. LIMITES FORENSIQUES ET VERDICT WINDOWS

- **Limitation :** La session courante étant non-administrateur, aucune modification du pare-feu réel n'a été appliquée.
- **Verdict Egress Windows :**
  ```text
  WINDOWS_EGRESS_NOT_ENFORCED
  ```
  (L'architecture et les scripts sont validés en `UNIT` et `-DryRun`, mais non appliqués au niveau noyau sur cette machine).
