# PRO13-A.4.3 — HMAC FORENSIC ANALYSIS REPORT

**Mission ID :** `SSM-PRO13-A4-3-EGRESS-HARDENING-AND-CRYPTOGRAPHIC-CONTINUITY-01`  
**Date / Horodatage :** 2026-11-27T07:09:00+01:00  
**Dépôt :** `C:\Users\USER\Documents\alarme-sys` | **Branche :** `main` | **HEAD :** `b339a9c82d5b410e78d1ea6d43cae556049ba2c0`  
**Périmètre :** Analyse forensique en lecture seule de `integrity_log` (`storage/security_monitor.db`), `IntegrityLogEntry` (`monitoring/models.py`) et `IntegrityManager` (`monitoring/integrity_manager.py`).

---

## 1. SCHÉMA RÉEL CONSTATÉ (`IntegrityLogEntry`)

Colonnes effectivement présentes dans `monitoring/models.py` et SQLite :
- `id` (Integer, PK autoincrement)
- `proof_id` (String(64))
- `alert_id` (String(64))
- `file_path` (String(256))
- `file_hash` (String(64))
- `prev_hash` (String(64))
- `entry_hash` (String(64)) — calculé comme `SHA256(f"{proof_id}|{file_hash}|{prev_hash}|{created_at}")`
- `hmac_sig` (String(64), nullable) — calculé comme `HMAC-SHA256(secret_key, entry_hash)` si `secret_key` est non nul
- `created_at` (Float)

**Champs absents du schéma actuel :** Aucun champ `key_id`, aucun champ `algorithm`, aucun champ `format_version`.

---

## 2. CAUSE RACINE DÉMONTRÉE DE L'ÉCHEC HMAC

L'inspection directe en lecture seule des **1 031 entrées** présentes dans `storage/security_monitor.db` (après l'exécution précédente de `pytest`) révèle :

| Catégorie HMAC (par rapport à la clé active de 34 octets) | Nombre d'entrées | Origine démontrée |
|---|---|---|
| **Signature absente (`hmac_sig IS NULL`)** | **377** | Entrées créées sans clé (`IntegrityManager(secret_key=None)`, ex. `tests/test_integrity.py:96`) ou avant configuration de clé |
| **Signature discordante (`mismatch`)** | **176** | Entrées créées par les tests unitaires avec des clés de test dédiées (`tests/test_integrity.py:14, 56`) |
| **Signature concordante (`match`)** | **478** | Entrées signées avec la clé active courante (`config.INTEGRITY_SECRET_KEY`) |
| **Total** | **1 031** | **100 % des entrées ont un `entry_hash` et un `prev_hash` SHA-256 valides** |

### Preuve directe sur les entrées #1 à #5 :

| Entrée | Horodatage (UTC+1) | `entry_hash` SHA-256 | `hmac_sig` | Provenance (`file_path`) | Interprétation |
|---|---|---|---|---|---|
| **#1** | `2026-11-14T04:57:24.465445+01:00` | Valide | Absente (`None`) | `storage/screenshots/screenshot_alert_1794628644453.jpg` | Générée sans clé HMAC configurée |
| **#2** | `2026-11-14T04:57:29.637825+01:00` | Valide | Absente (`None`) | `storage/recordings/incident_alert_1794628644453.mp4` | Générée sans clé HMAC configurée |
| **#3** | `2026-11-14T04:57:36.231132+01:00` | Valide | Échec (clé différente) | `../../AppData/Local/Temp/pytest-of-USER/pytest-263/test_evidence_registration_and0/sample_proof.jpg` | **Pollution directe par `pytest` (`tests/test_integrity.py`)** avec clé de test dédiée |
| **#4** | `2026-11-14T04:57:36.426414+01:00` | Valide | Absente (`None`) | `storage/screenshots/screenshot_alert_1794628656390.jpg` | Générée sans clé HMAC configurée |
| **#5** | `2026-11-14T04:57:36.726811+01:00` | Valide | Absente (`None`) | `storage/screenshots/screenshot_alert_1794628656711.jpg` | Générée sans clé HMAC configurée |

**Conclusion forensique :**
1. L'échec de `verify_chain_integrity(check_hmac=True)` à l'entrée #3 **n'est pas une altération malveillante** des données canoniques (`entry_hash` est exact pour #1-#5 et `prev_hash` est continu sur 1 031 entrées).
2. Il résulte de la **cohabitation dans la même base SQLite** (`storage/security_monitor.db`) d'entrées applicatives et d'entrées injectées par `pytest` avec des clés différentes ou nulles (`secret_key=None`), aggravée par l'absence de `key_id` dans `IntegrityLogEntry`.

---

## 3. COMPARAISON DES OPTIONS DE PRÉSERVATION HISTORIQUE (THÉORIQUE — NON APPLIQUÉE)

| Option | Sécurité | Traçabilité | Complexité | Risque de migration | Rejeu / Faux positif |
|---|---|---|---|---|---|
| **A — Préserver l'historique tel quel** | Préserve les preuves sans falsification | Signalement explicite des entrées sans HMAC / autre clé | Nulle | Nul | `check_hmac=True` reste bloqué sur l'historique mixte |
| **B — Manifeste de continuité signé** | Élevée : fige l'état historique sans réécrire les lignes | Excellente : empreinte DB + bornes d'ID + signature clé courante | Faible | Nul (document externe) | Aucun rejeu si daté et chaîné à l'ID courant |
| **C — Versionnement du format (`key_id`, `algorithm`, `format_version`)** | Optimale pour l'avenir : distingue clé absente, clé révoquée et clé invalide | Complète par entrée | Moyenne (migration schéma) | Moyen (test requis) | Élimine toute ambiguïté sur les futures rotations |

**Rejet formel :** Toute réécriture rétroactive des signatures #1-#3 ou passage en mode permissif est **strictement rejetée**.

---

## 4. STATUT

```text
HMAC_FORENSIC_GATE = PASS_WITH_LIMITATIONS  (Cause racine 100 % démontrée : pollution pytest + multi-clés sans key_id ; aucune modification effectuée)
```
