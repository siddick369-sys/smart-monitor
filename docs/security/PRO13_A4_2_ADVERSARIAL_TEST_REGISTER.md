# 🛡️ SSM PRO-13-A.4.2 — ADVERSARIAL TEST REGISTER
## REGISTRE DES SCÉNARIOS A42-01 À A42-42 CLASSÉS PAR MÉTHODE DE PREUVE

**Mission ID :** `SSM-PRO13-A4.2-CORRECTIVE-EGRESS-ENFORCEMENT-AND-VERIFICATION-01`  
**Branche :** `main` | **HEAD initial/final :** `b339a9c82d5b410e78d1ea6d43cae556049ba2c0`  
**Timestamp :** `2026-11-26T06:41:00+01:00`  
**Suite :** `tests/test_pro13_a4_2_egress_enforcement.py` (`python -m pytest tests/test_pro13_a4_2_egress_enforcement.py -q` -> **36 passed in 4.04s**, code retour `0`)

---

## 1. TAXONOMIE STRICTE DES MÉTHODES DE PREUVE

| Taxonomie | Signification | Statut sur cet hôte |
|---|---|---|
| `UNIT` | Test pur de logique Python / manifeste | **EXÉCUTÉ & RÉUSSI** |
| `MOCKED_INTEGRATION` | Simulation déterministe `netsh` / `DockerEgressProvider` / `-DryRun` | **EXÉCUTÉ & RÉUSSI** |
| `LOCAL_SOCKET_INTEGRATION` | Socket TCP locale réelle (`127.0.0.1`) | **EXÉCUTÉ & RÉUSSI** |
| `REAL_WINDOWS_FIREWALL` | Blocage noyau WFP effectif (nécessite Admin) | **NOT_AVAILABLE** (non-admin) |
| `REAL_DOCKER` / `REAL_LINUX_FIREWALL` | Conteneur & iptables/nftables Linux | **NOT_AVAILABLE** (Docker daemon arrêté) |
| `REAL_FFMPEG` / `PHYSICAL_CAMERA` | Binaire `ffmpeg.exe` + flux RTSP matériel | **NOT_AVAILABLE** |

---

## 2. REGISTRE DÉTAILLÉ DES SCÉNARIOS (A42-01 À A42-42)

- **7.1 Unitaires (`A42-01` à `A42-14`) :** 14/14 réussis (`UNIT`). Vérifient notamment le rejet des listes vides, CIDR $\le /8$, ports/protocoles interdits, IPv4/IPv6 non approuvées, IPv4-mapped IPv6, metadata, multicast, DNS mixte/vide, statut `UNKNOWN` fail-closed et rejet de la falsification par variable d'environnement (`A42-14`).
- **7.2 Politique Windows (`A42-15` à `A42-24`) :** 10/10 réussis en `MOCKED_INTEGRATION` (inspection `netsh` mockée, `-DryRun` PowerShell et vérification statique rollback). Le blocage noyau réel sous Windows est `NOT_AVAILABLE`.
- **7.3 Docker / Linux (`A42-25` à `A42-34`) :** 10/10 réussis en `UNIT` / `MOCKED_INTEGRATION`. L'exécution sur démon Docker réel est `NOT_AVAILABLE`.
- **7.4 Sockets secondaires (`A42-35` à `A42-42`) :** 8/8 scénarios réussis en `UNIT` et `LOCAL_SOCKET_INTEGRATION` (pinning IP sur socket TCP locale, drapeaux `-rtsp_transport tcp` et `-protocol_whitelist`).
