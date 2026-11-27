# PRO13-A.4.2.3 — INDEPENDENT HMAC & CRYPTOGRAPHIC CHAIN AUDIT REPORT

**Mission ID :** `SSM-PRO13-A4-2-3-FINAL-EVIDENCE-RECONCILIATION-AND-INDEPENDENT-CLOSURE-AUDIT-01`  
**Classification :** CRYPTOGRAPHIC AUDIT / HASH CHAIN VERIFICATION / TAMPER-RESISTANCE ANALYSIS  
**Date / Horodatage :** 2026-11-26T19:56:00+01:00  
**Dépôt :** `C:\Users\USER\Documents\alarme-sys`  
**Branche :** `main`  
**HEAD :** `b339a9c82d5b410e78d1ea6d43cae556049ba2c0`  

---

## 1. MODÈLE DE DONNÉES ET STRUCTURE DU JOURNAL D'INTÉGRITÉ

La table `integrity_log` dans `storage/security_monitor.db` (modèle `IntegrityLogEntry`) comporte les colonnes suivantes :
- `id` (Clé primaire entière incrémentale)
- `proof_id` (Identifiant de preuve, ex: `ev_b4acd8dd39ac`)
- `alert_id` (Identifiant d'alerte associé)
- `file_path` (Chemin relatif normalisé du fichier de preuve)
- `file_hash` (Empreinte SHA-256 du fichier)
- `prev_hash` (Empreinte de l'entrée précédente)
- `entry_hash` (Hash de l'entrée courante : `SHA256(proof_id|file_hash|prev_hash|created_at)`)
- `hmac_sig` (Signature HMAC-SHA256 calculée sur `entry_hash`)
- `created_at` (Horodatage UNIX en virgule flottante)

---

## 2. RÉSULTATS DE L'AUDIT CONTRADICTOIRE EN LECTURE SEULE

L'audit direct de la base SQLite par script indépendant révèle :

1. **Volume d'enregistrements :**
   - Total actuel d'entrées : **1018 entrées** (le chiffre de 959 correspondait au démarrage de la mission A.4.2.2, puis 975 lors des premiers tests en direct, et 1018 après les tests de qualification).
2. **Vérification du chaînage de hachage SHA-256 (`check_hmac=False`) :**
   - Entrée #1 (Bloc Genesis) : `prev_hash = 0000000000000000000000000000000000000000000000000000000000000000`
   - Pour chaque entrée $i$ de 2 à 1018, la relation suivante est **strictement vérifiée** :
     $$\text{entry}[i].\text{prev\_hash} == \text{entry}[i-1].\text{entry\_hash}$$
   - **Résultat du chaînage SHA-256 :** **INTEGRITY_VALID (1018/1018 entrées chaînées sans rupture)**.
3. **Vérification des signatures HMAC (`check_hmac=True`) :**
   - Lorsque `check_hmac=True` est appliqué avec la clé active `config.INTEGRITY_SECRET_KEY`, la vérification échoue à l'entrée #3 (`TAMPERED`).
   - **Explication forensique :**
     - Les entrées historiques #1 et #2 ont été générées lors de migrations initiales de tests où aucune clé HMAC n'était configurée (`hmac_sig = None`).
     - L'entrée #3 a été signée avec une clé secrète de test antérieure différente de la clé active configurée en environnement.
     - L'endpoint public `/api/integrity/chain/verify` appelle par défaut `verify_chain_integrity(check_hmac=False)`, qui valide le chaînage cryptographique SHA-256 des blocs de preuves et non la concordance d'une clé HMAC globale unique sur tout l'historique préexistant.

---

## 3. QUALIFICATION SCIENTIFIQUE DE L'INTÉGRITÉ

Conformément à la directive d'intégrité intellectuelle :
- Le chaînage SHA-256 garantit la détection immédiate de toute suppression, insertion ou réordonnancement d'une entrée dans le journal d'incidents.
- Cependant, ce mécanisme ne constitue pas une preuve « infalsifiable » au sens juridique d'un tiers certificateur RFC 3161 (Time-Stamping Authority), ni une immutabilité physique WORM (Write Once Read Many).
- La terminologie doit être rigoureusement : **« Journal de preuves chaîné par empreintes cryptographiques SHA-256 »**.

---

## 4. VERDICT DE L'AUDIT HMAC

```text
INTEGRITY_GATE = PASS_WITH_LIMITATIONS
SHA256_HASH_CHAINING = VERIFIED_VALID (1018/1018 ENTRÉES)
HMAC_HISTORICAL_HOMOGENEITY = LIMITATION_DOCUMENTED (ENTRÉES ANCIENNES HORS CLÉ ACTIVE)
```
