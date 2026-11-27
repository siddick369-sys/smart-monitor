# PRO13-A.4.4 — APPLICATION EGRESS REQUALIFICATION REPORT

**Mission ID :** `SSM-PRO13-A4-4-CONTROLLED-REMEDIATION-AND-SECURITY-CLOSURE-01`  
**Date / Horodatage :** 2026-11-27T08:17:30+01:00  
**Dépôt :** `C:\Users\USER\Documents\alarme-sys` | **Branche :** `main` | **HEAD :** `b339a9c82d5b410e78d1ea6d43cae556049ba2c0`  

---

## 1. INVENTAIRE ET QUALIFICATION DES CHEMINS RÉSEAU SORTANTS

| Composant | Protocole / Port | DNS / Redirections / Proxy | Contrôle SSRF / Fail-Closed | Soumis au pare-feu OS actuel ? |
|---|---|---|---|---|
| `FFmpegRTSPAdapter` | RTSP/TCP (`554, 8554`), HTTP(S) (`80, 443, 8080, 8081`) | DNS pinning (`security.py`), `-protocol_whitelist` restreint, env proxy purgé (`_build_sanitized_subprocess_env`) | `EgressPolicy` + fail-closed (`BLOCKED_SSRF`) si `require_os_egress_confinement=True` | **Non** (`WINDOWS_EGRESS_NOT_ENFORCED`) |
| `sensor_manager.py` | HTTP/HTTPS | `allow_redirects=False`, timeout `config.HTTP_TIMEOUT` | URL issue du `device_store` validé | Non |
| `alarm_manager.py` | HTTP/HTTPS | `allow_redirects=False`, timeout `config.HTTP_TIMEOUT` | URL issue du `device_store` validé | Non |
| `diagnostic_manager.py` / `presence_manager.py` | TCP Socket | IP directe issue de la config | Port/IP validés | Non |
| `discovery.py` / `onvif_adapter.py` | UDP Multicast | Multicast LAN uniquement | Optionnel | Non |
| `evidence_integrity.py` | HTTP/HTTPS (TSA optionnel) | Timeout 3.0s | Désactivé par défaut | Non |
| `qwen_vision_manager.py` / `telegram_notifier.py` | HTTPS | API externe optionnelle | Désactivés par défaut / sans clé | Non |

---

## 2. STATUT

```text
APPLICATION_EGRESS_GATE = PASS_WITH_LIMITATIONS
```
