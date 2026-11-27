# PRO13-A.4.3 — IPV4, IPV6 & BYPASS VECTOR ANALYSIS

**Mission ID :** `SSM-PRO13-A4-3-EGRESS-HARDENING-AND-CRYPTOGRAPHIC-CONTINUITY-01`  
**Date / Horodatage :** 2026-11-27T07:07:00+01:00  
**Dépôt :** `C:\Users\USER\Documents\alarme-sys` | **Branche :** `main` | **HEAD :** `b339a9c82d5b410e78d1ea6d43cae556049ba2c0`  
**Périmètre :** Couverture IPv4/IPv6 et vecteurs de contournement (DNS rebinding, redirections HTTP, proxies, sockets secondaires, processus enfants).

---

## 1. COUVERTURE IPV4 ET IPV6

| Vecteur / Plage | Contrôle applicatif (`EgressPolicy` / `security.py`) | Contrôle pare-feu Windows (`setup_ffmpeg_egress_firewall.ps1`) | Contrôle Docker (`setup_docker_egress_host.sh`) |
|---|---|---|---|
| **IPv4 Loopback (`127.0.0.0/8`)** | Bloqué en production (`classify_ip`) | Inclus dans `$prohibitedRanges` | Isolé dans bridge (hors host) |
| **IPv6 Loopback (`::1/128`)** | Bloqué en production | Inclus dans `$prohibitedRanges` | `ip6tables` uniquement (absent en branche `nftables`) |
| **Cloud Metadata (`169.254.169.254`, `fe80::/10`)** | Bloqué inconditionnellement | Inclus dans `$prohibitedRanges` | Bloqué IPv4 (`169.254.0.0/16`) ; IPv6 absent en `nftables` |
| **RFC1918 (`10/8`, `172.16/12`, `192.168/16`) & ULA (`fc00::/7`)** | Whitelist stricte par IP/CIDR | **Faille de chevauchement** : toute la plage `/8`, `/12` ou `/16` est omise du blocage si une caméra s'y trouve | `DOCKER-USER` DROP par défaut (IPv4) |
| **IPv4/IPv6 Publiques** | Bloquées si absentes de la whitelist | **Non bloquées** sans `-EnforceDefaultBlockProfile` | Bloquées en IPv4 (`DOCKER-USER`) ; **non couvertes en `nftables` IPv6** |
| **IPv4-mapped IPv6 (`::ffff:127.0.0.1`)** | Converti et bloqué (`ip_obj.ipv4_mapped`) | Dépend de la pile Windows | Non filtré explicitement en `nftables` |

---

## 2. MATRICE DE RISQUE EGRESS ET VECTEURS DE CONTOURNEMENT

| Scénario | Contrôle attendu | Contrôle existant | Preuve | Risque résiduel (état actuel) |
|---|---|---|---|---|
| **FFmpeg vers caméra autorisée** | Autorisation IP/port ciblée | `EgressPolicy` + `AllowCameras` (non déployé) | Code + tests unitaires | **Faible** (bloqué en mode fail-closed strict) |
| **FFmpeg vers IP publique** | Blocage strict | `EgressPolicy` (app) ; **absent** du script Windows sans `DefaultBlock` | Audit statique `setup_ffmpeg_egress_firewall.ps1` | **Élevé** si lancé hors fail-closed |
| **FFmpeg vers autre hôte du même `/16` privé** | Blocage de toute IP != caméra | **Contourné** par heuristique de chevauchement (lignes 149-156) | Audit statique | **Élevé** sous `DefaultOutboundAction=Allow` |
| **IPv6 non autorisé** | Blocage | `EgressPolicy` (app) ; absent en branche `nftables` | Audit statique | **Moyen-Élevé** |
| **Changement d'adresse DNS / Rebinding** | Revalidation + DNS pinning | `security.py` résout et épingle l'IP avant passage à FFmpeg | Code `security.py` | **Faible** pour FFmpeg ; à surveiller sur `requests` |
| **Redirection HTTP / RTSP** | Revalidation ou blocage | `-rtsp_transport tcp` + `-protocol_whitelist` ; `requests` à vérifier | Code `ffmpeg_adapter.py` | **Moyen** hors FFmpeg |
| **Exécutable alternatif / processus enfant** | Isolation globale du worker | Règle Windows liée au seul `$resolvedExe` | Audit statique | **Élevé** hors conteneur |
| **Proxy système / variables `HTTP_PROXY`** | Neutralisation ou contrôle | Non explicitement purgé de l'environnement enfant FFmpeg | Audit statique | **Moyen** |

---

## 3. STATUT

```text
IPV4_IPV6_REVIEW_GATE = PASS_WITH_LIMITATIONS
```
