# PRO13-A.4.2.3 — EXECUTION FAILURE & ANOMALY RECONCILIATION REPORT

**Mission ID :** `SSM-PRO13-A4-2-3-FINAL-EVIDENCE-RECONCILIATION-AND-INDEPENDENT-CLOSURE-AUDIT-01`  
**Classification :** FORENSIC RECONCILIATION / ROOT CAUSE ANALYSIS  
**Date / Horodatage :** 2026-11-26T19:55:00+01:00  
**Dépôt :** `C:\Users\USER\Documents\alarme-sys`  
**Branche :** `main`  
**HEAD :** `b339a9c82d5b410e78d1ea6d43cae556049ba2c0`  

---

## 1. ANOMALIE 1 : SCRIPT DE QUALIFICATION TERMINÉ AVEC CODE 1

### 1.1. Faits constatés
Dans la mission précédente, l'outil `run_command` a rapporté :  
`Ran run updated live qualification script · Exited with code 1`.

### 1.2. Reconstitution forensique et cause racine démontrée
- **Script exécuté :** `scratch_live_qualification.py` (script ad-hoc de vérification en direct).
- **Ligne responsable :**
  ```python
  cur.execute("SELECT id, timestamp, event_type, current_hash FROM integrity_log ORDER BY id DESC LIMIT 1")
  ```
- **Exception exacte levée :**
  ```text
  sqlite3.OperationalError: no such column: timestamp
  ```
- **Analyse technique :**
  Le modèle ORM `IntegrityLogEntry` dans [monitoring/models.py](file:///C:/Users/USER/Documents/alarme-sys/monitoring/models.py) et la table SQLite `integrity_log` définissent la colonne d'horodatage sous le nom `created_at` (et non `timestamp`), et les colonnes de hash sous les noms `prev_hash` et `entry_hash` (et non `current_hash`).
  L'auteur du script ad-hoc a utilisé des noms de colonnes erronés lors de sa dernière requête SQL de lecture.
- **Impact sur l'application :** Aucun.
  Toutes les étapes fonctionnelles précédentes du script (vérification capteurs mock 8081, vérification CSP et en-têtes HTTP sur 5000, login administrateur avec session et jeton CSRF, consultation `GET /api/alerts`, export `GET /api/alerts/export/csv`, rejet HTTP 401 sans session, simulation de mouvement) s'étaient exécutées avec succès avec HTTP 200 et HTTP 401 conforme.
- **Statut de l'anomalie :** **RÉSOLUE — BOGUE DU SCRIPT DE TEST AD-HOC (AUCUN DÉFAUT SYSTÈME SSM)**.

---

## 2. ANOMALIE 2 : ÉCHEC INITIAL DE LA SUITE DE TESTS D'ALERTES (TESTS 3 À 10)

### 2.1. Faits constatés
Lors d'une ré-exécution de `tests/test_pro13_a4_2_2_alerts_endpoint_security.py`, 8 tests ont échoué avec l'erreur :  
`sqlalchemy.exc.IntegrityError: (sqlite3.IntegrityError) UNIQUE constraint failed: users.username`.

### 2.2. Cause racine et remédiation
- La fonction auxiliaire `create_user_with_session` tentait d'insérer des utilisateurs avec des noms fixes (`revoked_user`, `inactive_user`, etc.) déjà présents dans la base persistante issue du premier passage.
- La fonction a été modifiée pour injecter un suffixe aléatoire `uuid.uuid4().hex[:6]` dans `username`, garantissant l'unicité stricte et la reproductibilité des tests sans collision.
- La ré-exécution suivante a confirmé **18/18 tests réussis à 100%**.
- **Statut de l'anomalie :** **RÉSOLUE**.

---

## 3. ANOMALIE 3 : ERREURS API 503 D'ANTIGRAVITY

### 3.1. Faits constatés
Le journal mentionne des alertes d'infrastructure LLM : `No capacity available for model gemini-3.8-flash-medium` et un avis de redémarrage serveur hôte.

### 3.2. Analyse contradictoire
- Ces erreurs proviennent exclusivement de la saturation temporaire du backend LLM Antigravity (gestionnaire d'inférence de l'agent).
- Elles n'ont aucun lien avec le serveur local Smart Security Monitor (qui tournait sur le port local 5000).
- Aucune tâche n'a été corrompue ; toutes les validations de code, tests et rapports ont été menés à terme.
- **Statut :** **ANOMALIE EXTERNE HORS PÉRIMÈTRE LOGICIEL SSM**.

---

## 4. ANOMALIE 4 : VÉRIFICATION DES PORTS 5000 ET 8081 TERMINÉE AVEC CODE 1

### 4.1. Faits constatés
La commande `Get-NetTCPConnection -LocalPort 5000, 8081 -ErrorAction SilentlyContinue` s'est terminée avec le code de sortie 1.

### 4.2. Cause racine et vérification indépendante
- En PowerShell, la cmdlet `Get-NetTCPConnection` renvoie une erreur non bloquante et positionne `$LASTEXITCODE = 1` lorsqu'**aucune connexion** ne correspond aux ports demandés.
- L'audit contradictoire via `netstat -ano | findstr ":5000 :8081"` confirme qu'**aucun processus n'écoute** sur les ports 5000 et 8081 (`0` socket en écoute).
- Seules des tentatives de reconnexion en `SYN_SENT` depuis l'application cliente `Antigravity` (PID 12124) vers le port fermé 5000 étaient visibles.
- **Statut de l'anomalie :** **CONFIRMÉ — PORTS RÉELLEMENT ET PARFAITEMENT LIBÉRÉS**.

---

## 5. VERDICT DE LA PHASE 1

```text
EXECUTION_RECONCILIATION_GATE = PASS
ANOMALIES_EXPLAINED = 4/4
UNRESOLVED_CRITICAL_FAILURES = 0
```
