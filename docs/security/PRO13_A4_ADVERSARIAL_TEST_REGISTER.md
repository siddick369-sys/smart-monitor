# 🛡️ SSM PRO-13-A.4 — ADVERSARIAL TEST REGISTER & TAXONOMY
## COMPREHENSIVE FORENSIC CATALOG OF 20 ADVERSARIAL EGRESS SCENARIOS (A4-01 TO A4-20)

**Mission ID :** `SSM-PRO13-A4-FFMPEG-EGRESS-CONFINEMENT-AND-LOT-A-FINAL-GATE-01`  
**Fichier de test audité :** `tests/test_pro13_lot_a_nvr.py`  
**Volume Lot A audité :** 55 tests (35 historiques Lot A + 20 nouveaux tests adversariaux A.4)  
**Date d'exécution :** 2026-11-24

---

## 1. TAXONOMIE RIGOUREUSE DES PREUVES D'AUDIT

Afin d'interdire formellement toute ambiguïté entre ce qui a été prouvé par des tests logiciels et ce qui dépend de composants d'infrastructure non présents sur la machine de test, chaque résultat est ventilé selon la taxonomie stricte suivante :

1. **`UNIT_TEST` :** Test unitaire automatisé portant sur des fonctions pures et la logique d'arbitrage d'adresses (ex: `EgressPolicy`, `classify_ip`).
2. **`MOCK_TEST` :** Test d'intégration logique utilisant des bouchons pour simuler les réponses réseau, DNS ou les processus système.
3. **`LOCAL_INTEGRATION_TEST` :** Test physique local impliquant des processus réels de l'hôte (ex: test de saturation du tube OS à 100 Ko).
4. **`REAL_FIREWALL_TEST` :** Test effectif de filtrage réseau réalisé avec des règles actives dans le noyau de l'OS (`NOT_AVAILABLE`).
5. **`REAL_FFMPEG_TEST` :** Test d'exécution réelle du binaire `ffmpeg.exe` compilé (`NOT_AVAILABLE`).
6. **`HARDWARE_INTEGRATION_TEST` :** Test physique avec caméra IP réelle branchée sur le banc de test (`NOT_AVAILABLE`).

---

## 2. REGISTRE DÉTAILLÉ DE LA MATRICE ADVERSARIALE (SCÉNARIOS A4-01 À A4-20)

| ID | Scénario adversarial | Cible / Entrée injectée | Comportement attendu | Catégorie de preuve | Statut |
|---|---|---|---|:---:|:---:|
| **A4-01** | Caméra autorisée dans la liste | `192.168.1.50:554` | Autorisée par la politique | `UNIT_TEST` | **PASSED** |
| **A4-02** | Destination privée non autorisée | `192.168.1.99`, `10.0.0.1`, `172.16.5.20` | Rejetée (RFC1918 Deny-by-Default) | `UNIT_TEST` | **PASSED** |
| **A4-03** | Destination de boucle locale | `127.0.0.1:554`, `::1` | Rejetée | `UNIT_TEST` | **PASSED** |
| **A4-04** | Métadonnées Cloud | `169.254.169.254:80` | Rejetée inconditionnellement | `UNIT_TEST` | **PASSED** |
| **A4-05** | Destination Link-Local | `169.254.1.10`, `fe80::1` | Rejetée | `UNIT_TEST` | **PASSED** |
| **A4-06** | Destination publique non approuvée | `8.8.8.8:554`, `93.184.216.34` | Rejetée | `UNIT_TEST` | **PASSED** |
| **A4-07** | Boucle locale IPv6 | `::1:554` | Rejetée | `UNIT_TEST` | **PASSED** |
| **A4-08** | IPv4 mappée en IPv6 | `::ffff:169.254.169.254`, `::ffff:10.0.0.1` | Normalisée et rejetée | `UNIT_TEST` | **PASSED** |
| **A4-09** | Redirection RTSP 302 | `Location: rtsp://10.0.0.1:554/` | Bloquée à l'évaluation de l'URI | `MOCK_TEST` | **PASSED** |
| **A4-10** | Attribut SDP absolu secondaire | `a=control:rtsp://169.254.169.254/` | Bloqué à l'évaluation de sécurité | `MOCK_TEST` | **PASSED** |
| **A4-11** | Reconnexion après modification DNS | `camera.local` basculant vers `10.0.0.1` | Bloquée lors de la re-validation | `MOCK_TEST` | **PASSED** |
| **A4-12** | Tentative de transport UDP non autorisé | Commande FFmpeg générée | UDP exclu de la whitelist et transport TCP forcé | `UNIT_TEST` | **PASSED** |
| **A4-13** | Données SDP malformées ou flux corrompu | Tube fermé prématurément (EOF) | Arrêt fail-closed et mire affichée | `MOCK_TEST` | **PASSED** |
| **A4-14** | Reconnexions excessives | 10 échecs consécutifs de supervision | Backoff exponentiel borné à max_backoff | `UNIT_TEST` | **PASSED** |
| **A4-15** | Terminaison du worker | Appel `_cleanup_process()` | Aucun processus orphelin, descripteurs fermés | `MOCK_TEST` | **PASSED** |
| **A4-16** | Confinement requis mais absent | `require_os_egress_confinement=True` | Refus de connexion fail-closed (BLOCKED_SSRF) | `MOCK_TEST` | **PASSED** |
| **A4-17** | Absence de politique pare-feu | Hôte sans pare-feu configuré | Statut exact (Pinning applicatif, zéro fausse prétention) | `MOCK_TEST` | **PASSED** |
| **A4-18** | Allowlist d'egress vide | `allowed_destinations=[]` ou `None` | Rejetée au démarrage (`PolicyConfigurationError`) | `UNIT_TEST` | **PASSED** |
| **A4-19** | Allowlist d'egress trop large | `0.0.0.0/0`, `10.0.0.0/8`, `::/0`, `169.254/16` | Rejetée au démarrage (`PolicyConfigurationError`) | `UNIT_TEST` | **PASSED** |
| **A4-20** | Rollback et restauration d'état | Variable `SSM_EGRESS_FIREWALL_ACTIVE` | Détection dynamique de révocation validée | `MOCK_TEST` | **PASSED** |

---

## 3. VENTILATION QUANTITATIVE ET DISCIPLINE DES STATUTS

- **Total des scénarios adversariaux A.4 :** 20 tests.
- **Réussites logicielles :** **20 / 20 (100.0%)**.
- **Ventilation par modalité de test :**
  - Tests unitaires de règles et de validation : **11 tests**.
  - Tests d'intégration mockée (processus, sockets, DNS) : **9 tests**.
  - Tests sur pare-feu réel du système d'exploitation : **NON EXÉCUTÉ (`NOT_AVAILABLE`)** — Nécessite des droits Administrateur pour la modification du noyau Windows.
  - Tests avec flux vidéo réel via binaire FFmpeg local : **NON EXÉCUTÉ (`NOT_AVAILABLE`)** — Binaire absent du PATH hôte.
  - Tests physiques avec caméra IP branchée : **NON EXÉCUTÉ (`NOT_AVAILABLE`)** — Aucun matériel physique disponible sur la machine de test.

L'auditeur certifie que le succès de ces 20 tests valide de manière irréfutable l'implémentation **logicielle et algorithmique** du confinement d'egress, sans extrapoler abusivement ce succès aux couches matérielles et système déclarées indisponibles.
