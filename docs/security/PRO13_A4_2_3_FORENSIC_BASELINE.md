# PRO13-A.4.2.3 — FORENSIC BASELINE & REPOSITORY INTEGRITY REPORT

**Mission ID :** `SSM-PRO13-A4-2-3-FINAL-EVIDENCE-RECONCILIATION-AND-INDEPENDENT-CLOSURE-AUDIT-01`  
**Classification :** FORENSIC BASELINE / STRICT READ-ONLY INTEGRITY REGISTER  
**Date / Horodatage local :** 2026-11-26T19:52:00+01:00  
**Dépôt canonique :** `C:\Users\USER\Documents\alarme-sys`  
**Branche constatée :** `main`  
**HEAD de référence constaté :** `b339a9c82d5b410e78d1ea6d43cae556049ba2c0`  

---

## 1. VÉRIFICATION DE L'ENVIRONNEMENT ET DES PRIVILÈGES

| Paramètre | Valeur constatée | Conforme au mandat |
|---|---|---|
| **Répertoire de travail** | `C:\Users\USER\Documents\alarme-sys` | Oui |
| **Branche Git** | `main` | Oui |
| **Commit HEAD** | `b339a9c82d5b410e78d1ea6d43cae556049ba2c0` | Oui (Exactement la baseline attendue) |
| **Système d'exploitation** | Windows 11 Professionnel (Build 10.0.26200, AMD64) | Oui |
| **Interpréteur Python** | Python 3.11.8 (64-bit) | Oui |
| **OpenCV** | 4.10.0 | Oui |
| **Privilèges processus** | Utilisateur non-administrateur (`IsInRole(Administrator) == False`) | Oui |
| **Statut réseau externe** | Aucune règle ni interface externe modifiée | Oui |

---

## 2. STATUT GIT ET FICHIERS DU DÉPÔT

### 2.1. Fichiers suivis modifiés (Unstaged) : 11 fichiers
- `app.py` (+12 / -3) : CSP durcie avec directives de restriction (`object-src 'none'`, `base-uri 'self'`, etc.)
- `monitoring/acquisition/__init__.py` (+14) : Exports du sous-système d'acquisition
- `monitoring/acquisition/discovery.py` (+11 / -2) : Découverte ONNX / ONVIF
- `monitoring/acquisition/ffmpeg_adapter.py` (+319 / -36) : Durcissement FFmpeg, protocole TCP forcé, fail-closed
- `monitoring/acquisition/onvif_adapter.py` (+26 / -5) : Adaptateur ONVIF
- `monitoring/acquisition/security.py` (+192 / -28) : Filtrage des schémas d'URL, DNS pinning
- `monitoring/notification_manager.py` (+5 / -2) : Compteur monotone anti-collision de notification
- `monitoring/recording_manager.py` (+30 / -4) : Neutralisation OWASP CSV Formula Injection
- `routes/alerts.py` (+88 / -6) : Décorateurs `@login_required`, `@roles_required`, validation des paramètres
- `static/js/dashboard.js` (+128 / -51) : Définition `escapeHtml` et échappement DOM XSS
- `tests/test_pro13_lot_a_nvr.py` (+700 / -2) : Tests NVR Lot A

### 2.2. Nouveaux fichiers de test (Untracked) :
- `tests/test_pro13_a4_2_2_alerts_endpoint_security.py`
- `tests/test_pro13_a4_2_2_csp_security.py`
- `tests/test_pro13_a4_2_2_xss_output_encoding.py`
- `tests/test_pro13_a4_2_egress_enforcement.py`

### 2.3. Empreintes SHA-256 des fichiers critiques au démarrage de l'audit :
| Fichier | Empreinte SHA-256 |
|---|---|
| `app.py` | `17d96f22c3fa3ff418ca103f833801e1e18d71338d2aa18aa7e711eec93ceb65` |
| `routes/alerts.py` | `4990e257d36513b49d109640fd754cb43cca966de317ca3fae762ddccf7db5d0` |
| `monitoring/recording_manager.py` | `d4c86e1ddb7b3ee402423cfeb1b89aa91108496174d926b6638b566695beab0c` |
| `monitoring/notification_manager.py` | `1b461bffdcd3792739dd77ffd9685c5171ce2810007080c5a1a7541a56b6a12b` |
| `monitoring/acquisition/egress_policy.py` | `c507a6379ddd46bc6a38ca27626baddcbe30f842cab1956a48ad5c8b1827640e` |
| `monitoring/acquisition/ffmpeg_adapter.py` | `7ce5ee4d27c1f49c8daf2e07b94164f7773750908b41ddd2b8a83e43d3e32a93` |
| `monitoring/acquisition/security.py` | `be5cb25a445e421be4da0535c262aa48a2da70b7fba28b1bd42edc1f1e4786c1` |
| `static/js/dashboard.js` | `6688f8c0d8f40c563c2fd268724bdfe6d4c7a107d9c202b9e158f3360bf4cc53` |
| `tests/test_pro13_a4_2_2_alerts_endpoint_security.py` | `0584c09c994080d16b25d0f58f4e8fac5ac8bc01636513682547d44e8d672493` |
| `tests/test_pro13_a4_2_2_csp_security.py` | `fa35b01489a06d27b5d8b08efe94a2368c0fae8b00e1ac13a9d6912603a931ec` |
| `tests/test_pro13_a4_2_2_xss_output_encoding.py` | `d08f0522dc2ce36fac942dbdc94b946020ea6bce4f32abca2ec180bd88320ea1` |

---

## 3. INVENTAIRE DES 16 RAPPORTS HISTORIQUES PRO-13-A.4.2.2

Les 16 rapports de la mission précédente sont tous présents sur disque dans `docs/security/` :
1. `PRO13_A4_2_2_ALERTS_ENDPOINT_SECURITY_REPORT.md` (`286fc63ba9a5ac3d933626c3cd468ec39aee31bab760a78a060a955cff339e44`)
2. `PRO13_A4_2_2_API_LIVE_QUALIFICATION.md` (`3273a57822eda5efed1300223f5b2f0f31be035b340b9f9b9d1e912489d5c07a`)
3. `PRO13_A4_2_2_AUTH_RBAC_CSRF_AUDIT.md` (`cc8d0173aba8699f08dfaf1aa4365666af3bb9e049c911f974e64095ff367e2e`)
4. `PRO13_A4_2_2_BASELINE_FORENSIC_REPORT.md` (`d6d8ec199c85684c11ee4db9c68e353800df2e216bd64198cf8945f605d75db5`)
5. `PRO13_A4_2_2_BROWSER_LIVE_QUALIFICATION.md` (`75f425467d3b3e39b6b7d2b0b96b128bb56b725f6eaf485a5e41f914e0f6d2d7`)
6. `PRO13_A4_2_2_CAMERA_PIPELINE_REPORT.md` (`85cb8f7cb037b0b9f389b7a4f466e878f6ef9dce39a296338fb3ddf01607b940`)
7. `PRO13_A4_2_2_CSP_SECURITY_REPORT.md` (`3b85cd1d9f7944a3ebcd73c8cb73fb83f809c551775b0799eb35fb224ebef2af`)
8. `PRO13_A4_2_2_DETECTION_ALERT_RECORDING_REPORT.md` (`3b4836724eefbb302a6448731be62c4ecf07fb1a57a0c38c4426468c0617b728`)
9. `PRO13_A4_2_2_EGRESS_INDEPENDENT_AUDIT.md` (`c4f7cee9291bbaf4bbf25b4414517c77b1dbe33316d8590e3740f7f4a2157b24`)
10. `PRO13_A4_2_2_END_TO_END_FINAL_QUALIFICATION.md` (`c6bdc83f95f792474b25a976a91004ab8a6599f478bb08e046134ce02bc6766b`)
11. `PRO13_A4_2_2_FINAL_GATE_DECISION.md` (`4b2160304503de2fe0c9e216c90224c3d2bc436215d015b29c0fac1b75346a6c`)
12. `PRO13_A4_2_2_FINAL_INDEPENDENT_AUDIT.md` (`c4f26a59f9c2ab72ad314af638e4dd45653c3c87426e3297c51df548e44c1285`)
13. `PRO13_A4_2_2_LOCAL_STARTUP_REPORT.md` (`7147b568f7a35df0a5e3aa8aef00f6bf6e093634cc39ab01e54876f071388090`)
14. `PRO13_A4_2_2_PERFORMANCE_STABILITY_REPORT.md` (`94413c6a7835e60429264a9a671ff19d44279ffde88f1926ab6eb017c6917593`)
15. `PRO13_A4_2_2_REGRESSION_REPORT.md` (`1ce47c513817b5356773bf62d6a14a0a311296680953de13ffb5faf826295c54`)
16. `PRO13_A4_2_2_XSS_AUDIT_REPORT.md` (`35e837eeea029ee956d0ef275772cfcf61ad6ce5cb2540b31ce056063d0123f6`)

---

## 4. DÉCISION FORENSIQUE INITIALE

```text
FORENSIC_GATE = PASS
BASELINE_VERIFIED = TRUE
PROCEED_TO_PHASE_1 = AUTHORIZED
```
