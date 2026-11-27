# PRO13-A.4.4 — HMAC CONTINUITY & MANIFEST REPORT

**Mission ID :** `SSM-PRO13-A4-4-CONTROLLED-REMEDIATION-AND-SECURITY-CLOSURE-01`  
**Date / Horodatage :** 2026-11-27T07:55:00+01:00  
**Dépôt :** `C:\Users\USER\Documents\alarme-sys` | **Branche :** `main` | **HEAD :** `b339a9c82d5b410e78d1ea6d43cae556049ba2c0`  

---

## 1. PRÉSERVATION STRICTE DE L'HISTORIQUE

- **Base `storage/security_monitor.db` :** 1 031 entrées conservées à l'identique (`sha256 = a06e40bdd9c2369477a66c84cc3d351a220d0ef46974a7c899e4cfcc31349e02`).
- **Aucune signature HMAC historique réécrite**, aucune entrée supprimée, aucun `key_id` attribué rétroactivement.

---

## 2. FORMAT CRYPTOGRAPHIQUE VERSIONNÉ (v2)

- **`monitoring/models.py` (`IntegrityLogEntry`) & `database.py` (`init_db`) :** Ajout des colonnes `format_version` (défaut `1` pour l'héritage), `algorithm` et `key_id`.
- **`monitoring/integrity_manager.py` :**
  - Les nouvelles entrées utilisent `format_version = 2`, `algorithm = "SHA256+HMAC-SHA256"`, `key_id = self.key_id` et une sérialisation canonique `v2|proof_id|file_hash|prev_hash|created_at|algorithm|key_id`.
  - Statuts explicites implémentés : `HASH_VALID`, `HASH_INVALID`, `HMAC_VALID`, `HMAC_INVALID`, `HMAC_MISSING`, `LEGACY_UNVERIFIABLE`, `MANIFEST_VALID`, `MANIFEST_INVALID`, `KEY_UNAVAILABLE`.
  - `HMAC_MISSING` et `HMAC_INVALID` ne sont jamais convertis en succès.

---

## 3. MANIFESTE DE CONTINUITÉ & LIMITE D'ANCRE DE CONFIANCE

- `create_continuity_manifest()` lit la base en mode URI `mode=ro` et produit un manifeste signé avec une clé distincte de la clé HMAC historique (sans fallback codé en dur).
- `verify_continuity_manifest()` vérifie indépendamment la signature JSON canonique.
- **Limitation documentée :** En l'absence de HSM/KMS externe ou de tiers RFC 3161 actif, le manifeste constitue une ancre locale uniquement :
  `CRYPTOGRAPHIC_CONTINUITY_WITH_LOCAL_TRUST_ANCHOR_ONLY`.

---

## 4. STATUT

```text
HMAC_CONTINUITY_GATE = PASS_WITH_LIMITATIONS
```
