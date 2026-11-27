# 🛡️ SSM PRO-13-A.4.2 — WINDOWS FIREWALL ARCHITECTURE
## ÉTUDE TECHNIQUE DE PRÉCÉDENCE, CONCEPTION DENY-BY-DEFAULT ET SCRIPTS POWERSHELL

**Mission ID :** `SSM-PRO13-A4.2-CORRECTIVE-EGRESS-ENFORCEMENT-AND-VERIFICATION-01`  
**Branche :** `main` | **HEAD initial/final :** `b339a9c82d5b410e78d1ea6d43cae556049ba2c0`  
**Timestamp :** `2026-11-26T06:38:00+01:00`  
**Environnement :** `Microsoft Windows 11 AMD64 · Session non-administrateur`

---

## 1. PROBLÈME IDENTIFIÉ EN A.4.1

Sous Windows Defender Firewall (plateforme Windows Filtering Platform — WFP), la politique sortante par défaut des profils standard (`Domain`, `Private`, `Public`) est `DefaultOutboundAction = Allow` (ou `NotConfigured` héritant d'`Allow`).
Par conséquent :
- Une règle isolée `New-NetFirewallRule -Action Allow -Program ffmpeg.exe -RemoteAddress 192.168.1.50` n'interdit aucune autre destination.
- Par ailleurs, Windows applique la précédence stricte **`Block overrides Allow`** au sein d'une même couche WFP : une règle `Block -RemoteAddress Any` bloquerait également la caméra approuvée.

---

## 2. ARCHITECTURE WINDOWS RETENUE

L'architecture `PRO-13-A.4.2` implémentée dans `scripts/setup_ffmpeg_egress_firewall.ps1` combine deux mécanismes complémentaires :

1. **Règle d'autorisation ciblée (`SSM_NVR_FFmpeg_Egress_AllowCameras`) :**
   - `-Direction Outbound`
   - `-Program <chemin absolu ffmpeg.exe>`
   - `-Action Allow`
   - `-Protocol TCP`
   - `-RemoteAddress <IP/CIDR caméras validés>`
   - `-RemotePort <ports autorisés>`
2. **Règle de blocage explicite des plages proscrites (`SSM_NVR_FFmpeg_Egress_BlockProhibited`) :**
   - `-Direction Outbound`
   - `-Program <chemin absolu ffmpeg.exe>`
   - `-Action Block`
   - `-Protocol Any`
   - `-RemoteAddress` couvrant :
     - Cloud Metadata & Link-Local : `169.254.169.254/32`, `169.254.0.0/16`, `fe80::/10`
     - Loopback : `127.0.0.0/8`, `::1/128`
     - Multicast & Broadcast : `224.0.0.0/4`, `ff00::/8`, `255.255.255.255/32`
     - Plages RFC1918 / ULA ne chevauchant pas les caméras autorisées (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `fc00::/7`).
3. **Option `-EnforceDefaultBlockProfile` :**
   Pour un confinement total y compris vers l'Internet public arbitraire sans règle `Block` générique, l'opérateur peut activer `-EnforceDefaultBlockProfile` qui passe `DefaultOutboundAction` à `Block`.

---

## 3. LIMITATION INHÉRENTE AU FILTRAGE PAR CHEMIN D'EXÉCUTABLE

Conformément à la section 3.2 de la mission, il est formellement documenté qu'une règle Windows Firewall liée uniquement au chemin `-Program` ne garantit pas une identité cryptographique inviolable si un attaquant dispose de droits d'écriture sur ce chemin. En production critique, l'exécutable `ffmpeg.exe` doit être placé dans un répertoire protégé en lecture seule (`Program Files` / ACL administrateur).

---

## 4. VALIDATION NON DESTRUCTIVE EXÉCUTÉE

- **Commande :** `powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts\setup_ffmpeg_egress_firewall.ps1 -ExecutablePath "C:\Windows\System32\cmd.exe" -AllowedDestinations @("192.168.1.50/32") -DryRun`
- **Code retour :** `0`
- **Sortie observée :** planification des règles `SSM_NVR_FFmpeg_Egress_AllowCameras` et `SSM_NVR_FFmpeg_Egress_BlockProhibited` incluant `169.254.169.254/32, 169.254.0.0/16, fe80::/10, 127.0.0.0/8, ::1/128, 224.0.0.0/4, ff00::/8, 255.255.255.255/32, 10.0.0.0/8, 172.16.0.0/12, fc00::/7`.
- **Statut de qualification :** Architecture et syntaxe validées en `-DryRun` ; application noyau réelle `NOT_AVAILABLE` faute de privilèges Administrateur.
