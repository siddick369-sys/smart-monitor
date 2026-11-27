# 🛡️ SSM PRO-13-A.4.1 — EGRESS POLICY SOURCE CODE AUDIT
## LINE-BY-LINE FORENSIC ANALYSIS OF EGRESSPOLICY, RESOLUTION PATHS, AND SOCKET BINDING BOUNDARIES

**Mission ID :** `SSM-PRO13-A4.1-INDEPENDENT-EGRESS-ENFORCEMENT-AUDIT-01`  
**Composants audités :** `monitoring/acquisition/egress_policy.py`, `monitoring/acquisition/security.py`, `monitoring/acquisition/ffmpeg_adapter.py`  
**HEAD audité :** `b339a9c82d5b410e78d1ea6d43cae556049ba2c0`  
**Date d'audit :** 2026-11-24

---

## 1. EXAMEN LIGNE À LIGNE DE LA CLASSE `EGRESSPOLICY`

L'auditeur indépendant a procédé à l'analyse rigoureuse des 287 lignes du module `monitoring/acquisition/egress_policy.py`.

---

### 1.1 Configuration et compilation des destinations autorisées (`_validate_and_compile_policy`)
- **Lignes 108-112 :**
  ```python
  if self.strict_deny_all_unapproved and not self.raw_allowed_destinations:
      raise PolicyConfigurationError("Politique d'egress invalide : la liste des destinations caméras autorisées ne peut pas être vide...")
  ```
  *Verdict :* Une politique stricte sans destination autorisée est formellement rejetée au démarrage.
- **Lignes 128-141 :**
  ```python
  if isinstance(net, ipaddress.IPv4Network):
      if net.prefixlen <= 8:
          raise PolicyConfigurationError(f"Plage réseau trop large interdite dans la politique d'egress : '{dest_str}' (préfixe /{net.prefixlen} <= /8)...")
  elif isinstance(net, ipaddress.IPv6Network):
      if net.prefixlen <= 16:
          raise PolicyConfigurationError(f"Plage IPv6 trop large interdite dans la politique d'egress : '{dest_str}' (préfixe /{net.prefixlen} <= /16)...")
  ```
  *Verdict :* Les masques réseau excessifs (`0.0.0.0/0`, `10.0.0.0/8`, `::/0`) sont activement rejetés.
- **Lignes 144-153 :**
  Vérification par `net.overlaps(meta)` et `net.overlaps(lb)` interdisant formellement l'inclusion de métadonnées cloud (`169.254.0.0/16`, `fe80::/10`) et de boucles locales (`127.0.0.0/8`) en production.

---

### 1.2 Évaluation des cibles réseau (`is_destination_allowed`)
- **Lignes 174-175 (Zone Identifiers IPv6) :**
  ```python
  clean_target = str(target_ip_or_host).strip().split("%")[0]
  ```
  *Verdict :* L'identifiant de zone (ex: `fe80::1%eth0`) est tronqué de manière sécurisée avant analyse d'adresse, évitant tout crash du parseur IP.
- **Lignes 192-195 (IPv4-Mapped IPv6) :**
  ```python
  if isinstance(ip_obj, ipaddress.IPv6Address) and ip_obj.ipv4_mapped:
      ip_obj = ip_obj.ipv4_mapped
      clean_target = str(ip_obj)
  ```
  *Verdict :* Les adresses IPv4 encapsulées en IPv6 (`::ffff:169.254.169.254`) sont normalisées en adresses IPv4 pures, neutralisant l'évasion par masquage de protocole.
- **Lignes 200-217 (Rejet des cibles non autorisées) :**
  Les ports interdits (`PROHIBITED_PORTS`), les métadonnées cloud, les adresses link-local, les boucles locales en production, les cibles multicast, broadcast et non spécifiées (`0.0.0.0`, `::`) sont inconditionnellement rejetés.
- **Lignes 220-243 (Deny-by-Default sur RFC1918 et Internet) :**
  Toute adresse privée RFC1918 ou publique qui ne correspond pas exactement à une plage de `self.parsed_allowed_networks` est rejetée avec un message explicite.

---

## 2. RÉPONSES AUX 15 QUESTIONS FORENSIQUES

| # | Question d'audit | Réponse forensique | Justification dans le code |
|---|---|:---:|---|
| **1** | Configuration des destinations | **Conforme** | Parsées via `ipaddress.ip_network` en liste compilée (`parsed_allowed_networks`). |
| **2** | Rejet de liste blanche vide | **Conforme** | Ligne 108 : lève `PolicyConfigurationError` si vide en mode strict. |
| **3** | Rejet des CIDR trop larges | **Conforme** | Lignes 130 & 137 : rejette $\le /8$ pour IPv4 et $\le /16$ pour IPv6. |
| **4** | CIDRs chevauchants | **Conforme** | Évaluation itérative sans effet de bord imprévu ; rejet si chevauchement avec métadonnées/loopback. |
| **5** | Prise en charge IPv4 et IPv6 | **Conforme** | Typage exhaustif `Union[ipaddress.IPv4Network, ipaddress.IPv6Network]`. |
| **6** | IPv4-mapped IPv6 | **Conforme** | Normalisé via `ip_obj.ipv4_mapped` (lignes 59 et 193). |
| **7** | Identifiants de zone IPv6 | **Conforme** | Découpage sécurisé par `.split("%")[0]` (ligne 175). |
| **8** | Résolution DNS exhaustive | **Conforme** | `validate_video_target` utilise `socket.getaddrinfo` et itère sur tous les résultats (`addr_info`). |
| **9** | Réponses DNS mixtes rejetées | **Conforme** | Si une seule IP de la réponse DNS échoue aux critères, rejet immédiat Fail-Closed. |
| **10** | Chaque adresse résolue vérifiée | **Conforme** | Boucle explicite `for item in addr_info` (ligne 220 de `security.py`). |
| **11** | Re-validation DNS lors des reconnexions | **Conforme** | `_supervision_loop()` réinvoque `validate_video_target` avant chaque tentative de reconnexion. |
| **12** | Parsing d'URI et mots de passe avec `@` | **Conforme** | `extract_uri_credentials` et `validate_video_target` utilisent `rsplit("@", 1)`. |
| **13** | Représentations IP non-canoniques | **Conforme** | Parseur natif `ipaddress` conforme RFC 6890 ; formats octaux ambigus rejetés sous Python 3.11. |
| **14** | Possibilité de DNS Rebinding | **Neutralisé** | Réécriture systématique en adresse IP validée via `pin_uri_to_ip()`. |
| **15** | Contrôle des sockets secondaires C | **NON ASSURÉ** | `EgressPolicy` ne contrôle que les arguments Python. Les sockets secondaires libavformat s'ouvrent en C. |

---

## 3. GRAPHE D'APPEL ET FRONTIÈRE DE CONFINEMENT

Le graphe d'appel ci-dessous détaille le cheminement complet d'un flux depuis la configuration jusqu'à la couche réseau :

```
[Configuration Utilisateur]
  │ CameraConnectionConfig(uri="rtsp://cam1.corp:554/live", custom_params={...})
  ▼
[FFmpegRTSPAdapter.connect()]
  │
  ├─► [check_egress_enforcement_status()] ──► [Vérification Variables d'Environnement]
  │     └─ Si require_os_egress_confinement=True et non appliqué ──► BLOCKED_SSRF (Fail-Closed)
  │
  ├─► [validate_video_target(uri, egress_policy)]
  │     ├─► [socket.getaddrinfo()] (Résolution DNS)
  │     ├─► Contrôle des ports interdits (PROHIBITED_PORTS)
  │     ├─► Contrôle SSRF (Link-Local, Cloud Metadata, Loopback)
  │     └─► [EgressPolicy.is_destination_allowed(ip, port)]
  │           └─ Vérification appartenance stricte à l'Allowlist
  │
  ├─► [pin_uri_to_ip(uri, resolved_ip)] ──► Génération de _effective_uri (DNS Pinning)
  │
  ├─► [_build_ffmpeg_cmd()] ──► Insertion des drapeaux structurés :
  │     -protocol_whitelist tcp,rtp,rtsp
  │     -rtsp_transport tcp
  │     -rtsp_flags +prefer_tcp
  │     -i <_effective_uri>
  │
  └─► [subprocess.Popen(cmd, shell=False)]
        │
════════╡ FRONTIÈRE LOGICIELLE PYTHON / SOUS-PROCESSUS FFMPEG ════════
        │
        ▼
   [Binaire FFmpeg / libavformat (C)]
        │
        ├─► [Socket TCP Initiale] ──► Connectée à l'IP pinée (CONFORME)
        │
        ▼ (Événement réseau hostile en cours de session)
        │
        ├─► [RTSP 302 Redirect] ──► libavformat ouvre une socket C interne sans repasser par Python !
        └─► [SDP a=control:rtsp://...] ──► libavformat ouvre une socket C vers l'URI absolu en C !
        │
════════╡ FRONTIÈRE RÉSEAU KERNEL / SYSTÈME D'EXPLOITATION ════════════
        │
        ▼
   [Pare-feu OS (WFP / NetFirewallRule) ou Passerelle Conteneur]
        └─► Seul ce niveau peut intercepter et bloquer les sockets secondaires C !
```

---

## 4. CONCLUSION FORENSIQUE

L'audit de `EgressPolicy` confirme que la composante logicielle Python est **robuste, sans faille de parsing, deny-by-default et fail-closed**.  
Cependant, l'auditeur souligne avec force la distinction capitale :  
**`EgressPolicy` valide et contraint la cible initiale ; elle ne peut pas interdire les sockets secondaires ouvertes en espace mémoire C par FFmpeg.**  
Cette responsabilité incombe exclusivement à l'étanchéité du pare-feu OS ou du conteneur.
