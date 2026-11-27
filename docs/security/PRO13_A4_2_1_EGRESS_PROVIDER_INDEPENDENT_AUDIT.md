# 🛡️ SSM PRO-13-A.4.2.1 — EGRESS PROVIDER INDEPENDENT AUDIT
## AUDIT INDÉPENDANT DU MODULE EGRESS_POLICY, HIÉRARCHIE DE PROVIDERS ET RÉSISTANCE AUX FAUX STATUTS

**Mission ID :** `SSM-PRO13-A4.2.1-INDEPENDENT-AUDIT-AND-LIVE-END-TO-END-QUALIFICATION-01`  
**Composant audité :** `monitoring/acquisition/egress_policy.py`  
**HEAD audité :** `b339a9c82d5b410e78d1ea6d43cae556049ba2c0`  
**Date d'audit :** 2026-11-26T16:05:00+01:00  

---

## 1. RÉPONSES AUDITÉES AUX 16 QUESTIONS CRITIQUES (SECTION 3.1)

| # | Question d'audit | Réponse forensique | Justification dans le code / Preuve |
|---|---|:---:|---|
| **1** | Le provider vérifie-t-il l'état réel du mécanisme de confinement ? | **OUI** | `WindowsEgressProvider` exécute `netsh advfirewall show allprofiles` et `netsh advfirewall firewall show rule` ; `LinuxEgressProvider` exécute `nft list ruleset` / `iptables -L`. |
| **2** | Peut-il retourner `ENFORCED` lorsque le pare-feu est désactivé ? | **NON** | `any_profile_on` contrôlé (lignes 347-360). Si aucun profil actif, retourne `NOT_ENFORCED`. |
| **3** | Peut-il retourner `ENFORCED` lorsqu'une règle manque ? | **NON** | `allow_rule_found` vérifié (lignes 374-381) ; si manquant, retourne `NOT_ENFORCED`. |
| **4** | Peut-il retourner `ENFORCED` lorsqu'une règle est désactivée ? | **NON** | `allow_enabled` vérifié (lignes 388-395) ; si `Non`/`No`, retourne `NOT_ENFORCED`. |
| **5** | Peut-il retourner `ENFORCED` si une règle contradictoire existe ? | **NON** | L'absence de blocage effectif sous profil `AllowOutbound` rétrograde en `PARTIAL`. |
| **6** | Peut-il retourner `ENFORCED` lorsque la politique sortante reste `Allow` ? | **NON** | Si `DefaultOutboundAction == Allow` sans `BlockProhibited`, retourne `PARTIAL` (lignes 446-451). |
| **7** | Peut-il retourner `ENFORCED` lorsque l'IPv6 n'est pas filtrée ? | **NON** | `BlockProhibited` exige `fe80::/10`, `::1/128`, `fc00::/7` ; sous Linux `setup_docker_egress_host.sh` inclut `ip6tables` / `nft inet`. |
| **8** | Peut-il retourner `ENFORCED` lorsque l'allowlist ne correspond pas aux règles effectives ? | **NON** | `norm_found == norm_expected` vérifié sur l'exécutable et les destinations. |
| **9** | Peut-il retourner `ENFORCED` si la vérification système échoue ? | **NON** | Tout retour différent de code 0 ou exception lève `UNKNOWN` (lignes 314-319, 370-373). |
| **10** | Peut-il retourner `ENFORCED` sur la base d'un simple nom de règle ? | **NON** | Le contenu complet (Enabled, Direction, Program, RemoteIP, Action) est analysé. |
| **11** | Peut-il retourner `ENFORCED` sur la base d'un fichier de configuration ? | **NON** | Interroge obligatoirement le sous-système de sécurité vivant via subprocess. |
| **12** | Peut-il retourner `ENFORCED` sur la base d'une variable d'environnement ? | **NON** | Présence de `SSM_EGRESS_*` ignorée pour l'octroi d'`ENFORCED` ; flag `env_spoofing_detected = True` (test `A42-14`). |
| **13** | Peut-il être trompé par une sortie subprocess incomplète ? | **NON** | Parsing défensif sur lignes canonisées et contrôles stricts de clés. |
| **14** | Peut-il être trompé par une commande indisponible ? | **NON** | `FileNotFoundError` ou exception subprocess interceptée -> retourne `UNKNOWN`. |
| **15** | Peut-il être trompé par un timeout ? | **NON** | Paramètre `timeout=5` configuré ; `TimeoutExpired` intercepté -> retourne `UNKNOWN`. |
| **16** | Peut-il confondre une politique partielle et une politique complète ? | **NON** | Statut formel `PARTIAL` expressément distinct d'`ENFORCED`, traité comme un rejet fail-closed dans `FFmpegRTSPAdapter.connect()`. |

---

## 2. AUDIT DES VARIABLES D'ENVIRONNEMENT (SECTION 3.2)

- L'ancienne détection basée sur `SSM_EGRESS_FIREWALL_ACTIVE` et `SSM_EGRESS_CONTAINER_ISOLATED` est totalement neutralisée.
- Si un utilisateur ou processus malveillant exporte `SSM_EGRESS_FIREWALL_ACTIVE="1"`, `check_egress_enforcement_status()` interroge le sous-système hôte réel et renvoie `NOT_ENFORCED`, `PARTIAL` ou `UNKNOWN`.
- Test unitaire vérifié : `test_a42_14_spoofed_env_var_never_grants_enforced` (100% réussi).

---

## 3. AUDIT DU FAIL-CLOSED DANS FFMPEGRTSPADAPTER (SECTION 3.3)

Dans `monitoring/acquisition/ffmpeg_adapter.py` :
- Méthode `connect()` : lignes 189-203.
- Le contrôle d'enforcement intervient avant toute initialisation de thread worker, de sous-processus `subprocess.Popen` ou d'ouverture de socket.
- Si `require_os_egress_confinement == True` et que le statut est différent de `ENFORCED` (`PARTIAL`, `NOT_ENFORCED`, `UNKNOWN`, `UNSUPPORTED`), la connexion est immédiatement avortée avec `VideoSourceStatus.BLOCKED_SSRF`.
- Le fallback in-process OpenCV est désactivé en production (`is_prod and self._allow_opencv_fallback == False`).
