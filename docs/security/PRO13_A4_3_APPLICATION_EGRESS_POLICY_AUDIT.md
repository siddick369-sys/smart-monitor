# PRO13-A.4.3 — APPLICATION EGRESS POLICY & OUTBOUND PATHS AUDIT

**Mission ID :** `SSM-PRO13-A4-3-EGRESS-HARDENING-AND-CRYPTOGRAPHIC-CONTINUITY-01`  
**Date / Horodatage :** 2026-11-27T07:08:00+01:00  
**Dépôt :** `C:\Users\USER\Documents\alarme-sys` | **Branche :** `main` | **HEAD :** `b339a9c82d5b410e78d1ea6d43cae556049ba2c0`  
**Périmètre :** Audit de `EgressPolicy`, `EgressEnforcementProvider`, `FFmpegAdapter` et inventaire de tous les chemins réseau sortants hors FFmpeg.

---

## 1. DISTINCTION ENTRE POLITIQUE APPLICATIVE ET ENFORCEMENT SYSTÈME

- **`POLICY_ALLOWED` :** Signifie uniquement que l'URL/IP/port cible respecte la liste blanche applicative Python (`EgressPolicy.validate_destination`).
- **`SYSTEM_EGRESS_ENFORCED` :** Signifie qu'un pare-feu noyau OS ou conteneur (`WindowsEgressProvider`, `LinuxEgressProvider`, `DockerEgressProvider`) bloque effectivement tout trafic non autorisé.
- **Comportement fail-closed :** Dans `FFmpegAdapter`, lorsque `require_os_egress_confinement=True`, le démarrage du flux échoue (`BLOCKED_SSRF`) si `EgressEnforcementProvider.check_status()` ne retourne pas `ENFORCED`. L'application ne confond plus ces deux statuts et neutralise la falsification par variable d'environnement (`env_spoofing_detected`).

---

## 2. AUDIT DE `EgressPolicy` (`monitoring/acquisition/egress_policy.py`)

- **Validation des destinations :** Rejette les listes vides en mode strict, normalise les adresses IPv4-mapped IPv6 (`::ffff:x.x.x.x`), bloque `LINK_LOCAL`, `CLOUD_METADATA` (`169.254.169.254`), `LOOPBACK` en production, `MULTICAST`, `BROADCAST`, `UNSPECIFIED` et `RESERVED`.
- **Validation des ports :** Vérifie `PROHIBITED_PORTS` puis la liste blanche `allowed_ports` (`554, 8554, 80, 443, 8080, 8081`).
- **DNS Pinning & Redirections (FFmpeg) :** `security.py` résout l'IP avant lancement et `FFmpegAdapter` force `-rtsp_transport tcp` et `-protocol_whitelist` restreint.

---

## 3. INVENTAIRE DES CHEMINS RÉSEAU SORTANTS HORS FFMPEG

| Module | Mécanisme / Ligne | Destination / Usage | Contrôle redirections / Egress | Caractère |
|---|---|---|---|---|
| `monitoring/sensor_manager.py:195` | `requests.get(self.sensors_url)` | Télémétrie HTTP caméra | `allow_redirects=False`, timeout défini | Nécessaire (caméra) |
| `monitoring/alarm_manager.py:143` | `requests.get(url)` | Activation torche caméra | `allow_redirects=False`, timeout défini | Nécessaire (pilotage) |
| `monitoring/diagnostic_manager.py:27` | `socket.socket` TCP | Test connectivité port caméra | Port/IP issus du `device_store` | Nécessaire (diagnostic) |
| `monitoring/presence_manager.py:163` | `socket.socket` TCP | Sonde présence LAN | IP locale configurée | Facultatif |
| `monitoring/acquisition/discovery.py:57`, `onvif_adapter.py:85` | `socket.socket` UDP | Découverte ONVIF / mDNS | Multicast LAN uniquement | Facultatif (découverte) |
| `monitoring/evidence_integrity.py:194-200` | `urllib.request.urlopen` | Horodatage RFC3161 optionnel | Timeout 3.0s | Facultatif (désactivé par défaut) |
| `monitoring/qwen_vision_manager.py:137, 360` | `requests.get` / `post` | API Qwen Vision | Désactivé si non configuré | Facultatif (IA cloud/locale) |
| `monitoring/telegram_notifier.py:92, 156` | `requests.post` | API Telegram Bot | Désactivé sans token | Facultatif (notification) |

---

## 4. STATUT

```text
APPLICATION_EGRESS_GATE = PASS_WITH_LIMITATIONS  (Politique applicative fail-closed solide pour FFmpeg ; appels facultatifs hors FFmpeg non soumis au pare-feu Windows tant que celui-ci est inactif)
```
