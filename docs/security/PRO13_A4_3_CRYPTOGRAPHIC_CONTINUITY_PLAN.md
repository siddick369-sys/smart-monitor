# PRO13-A.4.3 — CRYPTOGRAPHIC CONTINUITY PLAN (DOCUMENTARY PROPOSAL)

**Mission ID :** `SSM-PRO13-A4-3-EGRESS-HARDENING-AND-CRYPTOGRAPHIC-CONTINUITY-01`  
**Date / Horodatage :** 2026-11-27T07:09:30+01:00  
**Dépôt :** `C:\Users\USER\Documents\alarme-sys` | **Branche :** `main` | **HEAD :** `b339a9c82d5b410e78d1ea6d43cae556049ba2c0`  
**Statut d'application :** PROPOSITION TECHNIQUE NON APPLIQUÉE (AUCUNE MIGRATION EXÉCUTÉE).

---

## 1. PRINCIPES DIRECTEURS

1. **Aucune réécriture historique :** Les 1 031 entrées existantes ne doivent jamais être modifiées ni re-signées rétroactivement.
2. **Isolation stricte des tests :** Les tests automatisés (`pytest`) doivent impérativement utiliser une base SQLite temporaire isolée (`tmp_path`) et ne jamais écrire dans `storage/security_monitor.db`.
3. **Séparation explicite des vérifications :**
   - **Intégrité de chaînage (`SHA-256`)** : vérifie `prev_hash` et `entry_hash`.
   - **Authenticité (`HMAC-SHA256`)** : vérifie `hmac_sig` selon `key_id` et rejette explicitement `MISSING_HMAC`, `UNKNOWN_KEY_ID` ou `INVALID_HMAC` sans fallback silencieux.

---

## 2. ARCHITECTURE CIBLE PROPOSÉE

### 2.1. Manifeste de Continuité Signé (pour la transition de la base existante)
- **Contenu :** Empreinte SHA-256 du fichier `storage/security_monitor.db` au moment du gel, plage d'ID historiques (`1..N_cutoff`), résultat du chaînage SHA-256 (`1031/1031`), comptage des entrées `NULL` / `test-key`, identifiant logique de la clé active (`key_id`), horodatage UTC.
- **Format & Algorithme :** JSON canonique signé par `HMAC-SHA256` avec la clé active courante (sans exposer la clé).
- **Stockage & Permissions :** Fichier dédié `storage/continuity_manifest.json` en lecture seule pour le service applicatif.
- **Limite explicite :** Le manifeste atteste de l'état figé à la date de coupure ; il ne rend pas valides les signatures historiques absentes ou issues de clés de test.

### 2.2. Versionnement du Schéma (`IntegrityLogEntry` v2)
- Ajout des colonnes :
  - `format_version` (Integer, ex. `2`)
  - `algorithm` (String, ex. `SHA256+HMAC-SHA256`)
  - `key_id` (String, identifiant logique non secret de la clé, ex. `k_2026_11`)
- Politique de vérification stricte pour toute entrée `format_version >= 2` : `hmac_sig` obligatoire, `key_id` résolu dans le trousseau de vérification, rejet immédiat en cas de signature manquante ou invalide.
- Procédure de renouvellement / perte de clé : rotation par incrément de `key_id` ; conservation en lecture seule des anciennes empreintes de vérification ; en cas de perte de clé, émission d'un nouveau `key_id` et consignation d'un événement d'incident sans suppression de l'historique.

---

## 3. STATUT

```text
CRYPTOGRAPHIC_CONTINUITY_GATE = PASS_WITH_LIMITATIONS  (Plan documenté et fondé sur preuves ; non appliqué par mandat strict)
```
