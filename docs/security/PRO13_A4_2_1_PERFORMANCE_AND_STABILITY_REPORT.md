# 🛡️ SSM PRO-13-A.4.2.1 — PERFORMANCE AND STABILITY REPORT
## MESURES DE LATENCE LOCALE, CHARGE HTTP ET STABILITÉ SQLITE

**Mission ID :** `SSM-PRO13-A4.2.1-INDEPENDENT-AUDIT-AND-LIVE-END-TO-END-QUALIFICATION-01`  
**Branche :** `main` | **HEAD :** `b339a9c82d5b410e78d1ea6d43cae556049ba2c0`  
**Timestamp :** `2026-11-26T17:32:00+01:00`  

---

## 1. BENCHMARK HTTP LOCAL (50 REQUÊTES RAPIDES)

- **Cible :** `http://127.0.0.1:5000/api/auth/csrf_token`
- **Volume :** `50` requêtes séquentielles rapides pendant que le simulateur MJPEG (port `8081`) et `SystemCoordinator` étaient actifs.
- **Durée totale :** `0.50s`
- **Latence minimale :** `2.87 ms`
- **Latence moyenne :** `10.04 ms`
- **Latence maximale :** `75.36 ms`
- **Erreurs HTTP / timeouts :** `0`

---

## 2. STABILITÉ MULTI-FLUX ET SQLITE

- **Flux vidéo simulé :** Stable à ~10-12 FPS, `last_communication_age: 0.1s`, `0` déconnexion intempestive.
- **Base SQLite (`storage/security_monitor.db`) :** `17` -> `18+` alertes, `640+` preuves, `777+` notifications persistées sans verrouillage (`database is locked`).
- **Remarque :** Ce benchmark local synthétique mesure la réactivité de Flask/SQLite sur le poste de développement ; il ne constitue pas un benchmark matériel de production multi-caméras HD.
