# RAPPORT DE REMÉDIATION TECHNIQUE CRITIQUE — PRO-12.5
## ÉLIMINATION DU DOWNGRADE PROTOCOLAIRE P2P ET VALIDATION STRICTE AU DÉMARRAGE

---

## 1. EXECUTIVE SUMMARY

| Paramètre | Valeur |
| :--- | :--- |
| **Mission ID** | `SSM-PRO12.5-P2P-DOWNGRADE-ELIMINATION-AND-SECURITY-BOOTSTRAP-01` |
| **Mission Parente** | `SSM-PRO12.4.1-INDEPENDENT-ADVERSARIAL-VERIFICATION` |
| **Date** | 22 novembre 2026 |
| **Dépôt** | `C:\Users\USER\Documents\alarme-sys` |
| **Environnement Cible** | Windows 11 Professionnel / Python 3.11.8 / Flask 3.1.3 / SQLite (WAL) |
| **Priorité** | P1 — HIGH |
| **Findings Traités** | `SEC-1241-01` (P2P Downgrade & Unauthenticated Payload Injection)<br>`SEC-1241-02` (Production Configuration Validator Not Invoked at Startup) |
| **Verdict Final** | **`PRO12_5_REMEDIATION_COMPLETE_WITH_LIMITATIONS`** |

### Synthèse des Réalisations
1. **Élimination Définitive du Downgrade P2P (`SEC-1241-01`) :**  
   La branche de rétrocompatibilité descendante silencieuse vers la signature legacy `v1` (qui n'englobait pas le payload) a été intégralement supprimée de `monitoring/p2p_sync.py`. Désormais, tout message P2P reçu sans la version exacte `SSMP2P02` ou sans signature HMAC-SHA256 valide sur le payload canonique est rejeté immédiatement, sans aucun effet de bord métier ni persistance anti-rejeu.
2. **Validation Obligatoire de Sécurité au Démarrage (`SEC-1241-02`) :**  
   L'appel à `config.validate_security_configuration(strict_production=is_prod)` a été formellement intégré dans la factory `create_app()` d'`app.py`. En environnement de production (`APP_ENV=production`), l'application refuse catégoriquement de s'initialiser si `SECRET_KEY` est absente, par défaut ou de longueur inférieure à 32 caractères, si `SESSION_COOKIE_SECURE` est désactivé, si `DEBUG=True`, ou si des variables environnementales booléennes sont corrompues.
3. **Validation Adversariale Complète :**  
   Une suite de 43 tests dédiés (`tests/test_pro12_5_p2p_downgrade_and_bootstrap.py`) a été créée et validée à 100%. Elle démontre la neutralisation formelle du PoC PRO-12.4.1, la robustesse de la canonicalisation JSON (rejet de `NaN`, `Infinity`, dépassement de profondeur), et l'échec fermé au démarrage en cas de mauvaise configuration.

---

## 2. BASELINE FORENSIQUE

- **Commit HEAD Initial :** `91c1b5ee608b67bc28ddea98febe0f71ad32b165`
- **État Initial du Working Tree :** Vérifié propre avant intervention.
- **Empreintes SHA-256 Initiales des Fichiers Clés :**
  - `monitoring/p2p_sync.py` : `FDDC0FB12B238BAACDE18B9F07FA0697DD7AFFB6D344C382D2292A2084B57278`
  - `config.py` : `CC734F74AADE7ACF8BFE5E53E1C1172E7B722B32441F605E42C125471876D9A7`
  - `app.py` : `7DC0FE6858CBC69A8E7AA6A2768D16006F83321590EFEF5242DDD7B1C58E3A11`

---

## 3. TRAITEMENT DU FINDING SEC-1241-01 — P2P PROTOCOL DOWNGRADE

### 3.1 Cause Racine et Chemin d'Exploitation Initial
Dans `monitoring/p2p_sync.py`, la fonction `receive_sync_batch()` évaluait :
```python
if not is_valid_v2 and proto_version != "SSMP2P02":
    is_valid_v1 = hmac.compare_digest(expected_sig_v1, str(sig))
```
Si le champ `proto_version` était absent, vide ou égal à `"v1"`, le récepteur basculait dans le calcul legacy `expected_sig_v1 = hmac(f"{ev_id}:{device_id}:{seq}:{ev_type}:{ev_time}")`. Cette signature ne couvrait aucunement le dictionnaire `payload`. Un attaquant sur le réseau du cluster pouvait donc modifier arbitrairement les données d'alerte ou de commande sans invalider la signature.

### 3.2 Remédiation Appliquée
1. **Suppression Inconditionnelle du Fallback :** La variable `expected_sig_v1` et la branche conditionnelle permissive ont été entièrement éradiquées.
2. **Politique de Version Stricte :** Seule la chaîne littérale exacte `"SSMP2P02"` est admise :
   ```python
   proto_version = ev_data.get("proto_version")
   if not isinstance(proto_version, str) or proto_version != self.REQUIRED_PROTOCOL_VERSION:
       continue
   ```
3. **Canonicalisation Robuste et Rejet RFC 8259 :**
   - Tri déterministe des clés (`sort_keys=True`).
   - Séparateurs sans espaces (`separators=(',', ':')`).
   - Échappement ASCII déterministe (`ensure_ascii=True`).
   - Interdiction stricte de `NaN`, `Infinity` et `-Infinity` (`allow_nan=False`).
   - Limite de profondeur maximale fixée à 10 niveaux.
4. **Validation Avant Tout Effet de Bord :** La signature HMAC-SHA256 est désormais vérifiée **avant** toute écriture dans le registre mémoire `_received_event_ids`, avant toute requête SQLite et avant toute modification d'état.

---

## 4. TRAITEMENT DU FINDING SEC-1241-02 — VALIDATION AU DÉMARRAGE

### 4.1 Cause Racine Initiale
Bien que la fonction `validate_security_configuration(strict_production=True)` ait été implémentée dans `config.py`, elle n'était invoquée que ponctuellement par certains tests unitaires et n'était jamais appelée à l'initialisation de l'application Flask dans `create_app()`.

### 4.2 Remédiation Appliquée
Dans `app.py`, la factory `create_app()` débute désormais par :
```python
is_prod = getattr(config, "IS_PRODUCTION", False) or os.environ.get("APP_ENV", "").lower() in ["production", "prod"]
config.validate_security_configuration(strict_production=is_prod)
```
En production (`is_prod=True`), la validation applique les contrôles stricts suivants :
- Rejet si `SECRET_KEY` est vide, absente, de longueur < 32 caractères ou égale aux clés de test par défaut.
- Rejet si `SESSION_COOKIE_SECURE` est `False`.
- Rejet si `SESSION_COOKIE_HTTPONLY` est `False`.
- Rejet si `SESSION_COOKIE_SAMESITE` n'est pas `'Lax'` ou `'Strict'`.
- Rejet si `DEBUG=True`.
- Rejet si `ALLOW_LOOPBACK_SIMULATOR=True`.
- Rejet si `EVIDENCE_HMAC_KEY` est absent ou < 16 caractères.
- Rejet si une variable booléenne d'environnement contient une chaîne non standard.

---

## 5. SPÉCIFICATION DU PROTOCOLE P2P (SSMP2P02)

### 5.1 Format du Message Signé
Le message canonique soumis au calcul HMAC-SHA256 respecte la structure déterministe suivante :
$$\text{Message} = \text{SSMP2P02} : \text{device\_id} : \text{event\_id} : \text{sequence\_num} : \text{event\_type} : \text{timestamp} : \text{canonical\_payload}$$

- `device_id`, `event_id`, `event_type` : chaînes sans séparateur deux-points (`:`) ni saut de ligne.
- `sequence_num` : entier positif ou nul.
- `timestamp` : flottant UTC.
- `canonical_payload` : JSON compact déterministe UTF-8/ASCII sans espaces.

---

## 6. MATRICE DE TESTS ADVERSARIAUX P2P

| ID Test | Scénario Évalué | Résultat Attendu | Résultat Obtenu |
| :--- | :--- | :---: | :---: |
| **E01** | `proto_version="SSMP2P02"` valide + signature payload | Accepté (count=1) | **PASSED** |
| **E02** | `proto_version` absent | Rejeté (count=0) | **PASSED** |
| **E03** | `proto_version="null"` | Rejeté (count=0) | **PASSED** |
| **E04** | `proto_version=""` (chaîne vide) | Rejeté (count=0) | **PASSED** |
| **E05** | `proto_version="v1"` | Rejeté (count=0) | **PASSED** |
| **E06** | `proto_version="SSMP2P01"` / `"SSMP2P00"` | Rejeté (count=0) | **PASSED** |
| **E07** | `proto_version="SSMP2P99"` (inconnue) | Rejeté (count=0) | **PASSED** |
| **E08** | `proto_version=2` (numérique) | Rejeté (count=0) | **PASSED** |
| **E09** | `proto_version=True` (booléen) | Rejeté (count=0) | **PASSED** |
| **E10** | `proto_version=" SSMP2P02 "` (espaces) | Rejeté (count=0) | **PASSED** |
| **E11** | `proto_version="ssmp2p02"` (minuscules) | Rejeté (count=0) | **PASSED** |
| **E12** | Altération de champ imbriqué dans le payload | Rejeté (count=0) | **PASSED** |
| **E13** | Altération d'un booléen dans le payload | Rejeté (count=0) | **PASSED** |
| **E14** | Altération de séquence / timestamp | Rejeté (count=0) | **PASSED** |
| **E15** | Signature absente / vide / tronquée / non hex | Rejeté (count=0) | **PASSED** |
| **E16** | Injection de `NaN` ou `Infinity` | Rejeté (`ValueError`) | **PASSED** |
| **E17** | Injection de deux-points (`:`) dans `device_id` | Rejeté (`ValueError`) | **PASSED** |
| **E18** | Reproduction PoC PRO-12.4.1 (omission version) | Rejeté (count=0) | **PASSED** |
| **E19** | Reproduction PoC PRO-12.4.1 (version="v1") | Rejeté (count=0) | **PASSED** |
| **E20** | Rejeu persistant après redémarrage SQLite | Rejeté (count=0) | **PASSED** |

---

## 7. RÉSULTATS D'EXÉCUTION DES TESTS

### 7.1 Suite Dédiée PRO-12.5
```
pytest tests/test_pro12_5_p2p_downgrade_and_bootstrap.py -v
============================= 43 passed in 5.55s =============================
```

### 7.2 Suites de Sécurité et Non-Régression Consolidées
- `tests/test_master_api.py` : 6 passed / 6.
- `tests/test_pro11_p2p_intercom.py` : 5 passed / 5.
- `tests/test_pro12_security_hardening.py` : 11 passed / 11.
- `tests/test_pro12_1_adversarial.py` : 10 passed / 10.
- `tests/test_pro12_2_production_readiness.py` : 10 passed / 10.
- `tests/test_pro12_3_production_security_closure.py` : 27 passed / 27.
- `tests/test_pro12_4_critical_remediation.py` : 26 passed / 26.
- `tests/test_pro12_5_p2p_downgrade_and_bootstrap.py` : 43 passed / 43.

**Total cumulé des tests de sécurité exécutés : 138 tests passés, 0 échec.**

---

## 8. ADAPTATIONS DES TESTS HISTORIQUES (JUSTIFICATION TECHNIQUE)

En stricte application de la consigne (*"Si un test historique échoue à cause d'une incompatibilité réelle, expliquer précisément le conflit et proposer une adaptation ciblée"*), 4 tests historiques qui forgeaient manuellement des événements de test selon la formule legacy v1 sans payload ont été adaptés pour utiliser l'API officielle `compute_event_signature(..., proto_version="SSMP2P02")` :
- `test_pro12_security_hardening.py` (test nominal P2P) : signature v1 remplacée par signature SSMP2P02 avec payload dict.
- `test_pro12_1_adversarial.py` (scénarios 4 et concurrence) : événements légitimes mis à niveau vers SSMP2P02.
- `test_pro12_2_production_readiness.py` (anti-rejeu inter-redémarrage) : événements légitimes mis à niveau vers SSMP2P02.
- `test_pro12_3_production_security_closure.py` (anti-rejeu et 8 workers) : événements légitimes mis à niveau vers SSMP2P02.

Ces adaptations ne modifient aucune assertion de sécurité mais reflètent l'obsolescence programmée du format v1 non sécurisé.

---

## 9. FICHIERS MODIFIÉS

| Fichier | Nature de l'Intervention | Justification |
| :--- | :--- | :--- |
| `monitoring/p2p_sync.py` | Suppression fallback v1, validation stricte SSMP2P02, canonicalisation durcie. | Résolution `SEC-1241-01` |
| `config.py` | Durcissement `validate_security_configuration()`. | Résolution `SEC-1241-02` |
| `app.py` | Câblage de la validation au démarrage de `create_app()`. | Résolution `SEC-1241-02` |
| `.gitignore` | Ajout des motifs d'exclusion des clés et jetons. | Conformité test secrets git |
| `tests/test_pro12_5_p2p_downgrade_and_bootstrap.py` | Création de 43 tests adversariaux et de démarrage. | Validation formelle PRO-12.5 |
| `tests/test_master_api.py` | Mise à niveau test HTTP P2P vers SSMP2P02. | Non-régression master API |
| `tests/test_pro12_*.py` | Mise à niveau des 4 scénarios nominaux P2P. | Incompatibilité protocolaire v1 |

---

## 10. LIMITES DE SÉCURITÉ ET RECOMMANDATIONS FUTURES

1. **Secret Partagé Symétrique du Cluster P2P :**  
   Le protocole P2P repose sur une clé HMAC symétrique partagée entre tous les nœuds du cluster. Bien que le payload soit désormais intégralement protégé contre toute falsification en transit, la compromission d'un nœud autorise la création d'événements pour les autres nœuds. Une migration vers des paires de clés asymétriques Ed25519 par nœud est recommandée pour les versions futures.
2. **Gestion de Concurrence SQLite :**  
   La déduplication persistante s'appuie sur le mode WAL et la contrainte de clé primaire de `p2p_received_events`. Sur des clusters de très grande taille (> 100 nœuds), un broker distribué (Redis ou PostgreSQL) sera requis.

---

## 11. VERDICT FINAL D'AUDIT

Les deux vulnérabilités `SEC-1241-01` (P1) et `SEC-1241-02` (P3) sont intégralement corrigées dans le code source, validées de manière contradictoire et certifiées par 138 tests automatisés sans régression.

$$\text{VERDICT FORMEL} = \mathbf{PRO12\_5\_REMEDIATION\_COMPLETE\_WITH\_LIMITATIONS}$$
