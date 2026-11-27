# PRO13-A.4.4 — WINDOWS EGRESS REMEDIATION REPORT

**Mission ID :** `SSM-PRO13-A4-4-CONTROLLED-REMEDIATION-AND-SECURITY-CLOSURE-01`  
**Date / Horodatage :** 2026-11-27T07:59:00+01:00  
**Dépôt :** `C:\Users\USER\Documents\alarme-sys` | **Branche :** `main` | **HEAD :** `b339a9c82d5b410e78d1ea6d43cae556049ba2c0`  

---

## 1. CORRECTIONS IMPLÉMENTÉES (SANS MODIFICATION PARE-FEU RÉELLE)

1. **`monitoring/acquisition/egress_policy.py` (`compute_complementary_block_cidrs`) :**
   - Soustraction mathématique exacte (`ipaddress.address_exclude`) des destinations autorisées sur `0.0.0.0/0` et `::/0`.
   - Élimine la faille d'exclusion de tout un `/8`, `/12`, `/16` ou `fc00::/7` lors d'un chevauchement d'une caméra unique ; normalise IPv4-mapped IPv6 (`::ffff:x.x.x.x`).
2. **`scripts/setup_ffmpeg_egress_firewall.ps1` :**
   - Exploite `compute_complementary_block_cidrs` pour générer les règles Block IPv4 + IPv6 complémentaires exactes sans modifier la politique globale du poste hôte.
3. **`scripts/check_ffmpeg_egress_firewall.ps1` :**
   - Supprime le faux positif `WINDOWS_EGRESS_ENFORCED` sur simple présence de `BlockProhibited`.
   - Émet les diagnostics granulaires : `RULES_PRESENT`, `RULES_DISABLED`, `PROFILE_DISABLED`, `DEFAULT_OUTBOUND_ALLOW`, `DEFAULT_OUTBOUND_BLOCK`, `ALLOWLIST_INCOMPLETE`, `IPV4_COVERAGE_INCOMPLETE`, `IPV6_COVERAGE_INCOMPLETE`, `EXECUTABLE_SCOPE_INCOMPLETE`, `PROXY_CONFIGURATION_UNSAFE`, `WINDOWS_EGRESS_NOT_ENFORCED`, `WINDOWS_EGRESS_ENFORCED`.
4. **`monitoring/acquisition/ffmpeg_adapter.py` :**
   - `_build_sanitized_subprocess_env()` purge `HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY`, `FTP_PROXY`, `NO_PROXY` (majuscules/minuscules) de l'environnement du processus enfant FFmpeg.

---

## 2. STATUT

```text
WINDOWS_EGRESS_GATE = PASS  (Scripts corrigés et 7/7 tests unitaires/simulés réussis)
WINDOWS_OS_ENFORCEMENT = NOT_VERIFIED  (Aucune règle appliquée sans privilèges Admin)
```
