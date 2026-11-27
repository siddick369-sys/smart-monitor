# PRO13-A.4.3 — CSP & XSS DEEP AUDIT REPORT

**Mission ID :** `SSM-PRO13-A4-3-EGRESS-HARDENING-AND-CRYPTOGRAPHIC-CONTINUITY-01`  
**Date / Horodatage :** 2026-11-27T07:10:00+01:00  
**Dépôt :** `C:\Users\USER\Documents\alarme-sys` | **Branche :** `main` | **HEAD :** `b339a9c82d5b410e78d1ea6d43cae556049ba2c0`  
**Périmètre :** `app.py` (en-têtes CSP), `templates/login.html`, `templates/dashboard.html`, `templates/offline.html`, `static/js/dashboard.js`.

---

## 1. INVENTAIRE DES SCRIPTS ET USAGES `unsafe-inline`

- **Sinks JavaScript dangereux recherchés (`eval`, `new Function`, `document.write`, `insertAdjacentHTML`, `outerHTML`, `javascript:`, `srcdoc`) :** **0 occurrence** trouvée dans `templates/` et `static/js/`.
- **Raisons techniques du maintien actuel de `'unsafe-inline'` :**
  1. `script-src` : `templates/dashboard.html:16` (`tailwind.config`) et `templates/login.html:134` (logique de connexion/bootstrap) utilisent des blocs `<script>` inline, et les templates / `dashboard.js` utilisent des attributs événementiels inline (`onclick="..."`, `onchange="..."`).
  2. `style-src` : `https://cdn.tailwindcss.com` (Tailwind Play CDN) injecte dynamiquement des balises `<style>` dans le DOM à l'exécution ; des attributs `style="..."` sont également utilisés pour les sparklines.

---

## 2. ANALYSE CONTEXTUELLE DE `escapeHtml()` ET MATRICE DES SINKS

`escapeHtml(str)` dans `static/js/dashboard.js` (lignes 3-11) convertit `&`, `<`, `>`, `"`, `'` en entités HTML (`&amp;`, `&lt;`, `&gt;`, `&quot;`, `&#039;`).

| Sink | Source des données | Contexte | Protection actuelle | Risque résiduel |
|---|---|---|---|---|
| `renderAlertsTable` | API `/api/alerts` | Contenu HTML + attribut `onclick` | `escapeHtml` (HTML) + `encodeURIComponent`/`encodeURI` | **Faible en HTML** ; **Moyen dans `onclick="openImageModal(..., '${safeType} — ${safeDatetime}')"`** (décodage d'entités HTML `&#039;` avant exécution JS si `a.type` était contrôlé) |
| `renderNotifications` | API `/api/notifications` | Contenu HTML + `onclick` | `escapeHtml` + `encodeURIComponent(n.id)` | **Faible** |
| `renderZones` | API `/api/devices/<id>/zones` | Contenu HTML + `onchange`/`onclick` | `escapeHtml(z.name)` + `encodeURIComponent(z.id)` | **Faible** |
| `renderCameraCards` | API `/api/status` | Contenu HTML + `onclick` | `escapeHtml(dev.name)` + `encodeURIComponent` + `decodeURIComponent` | **Faible** (l'encodage URL neutralise les guillemets dans `onclick`) |
| `loadPrivacyRequests` | API `/api/privacy/status` | Contenu HTML + `onclick` | `escapeHtml` + `encodeURIComponent(r.id)` | **Faible** |
| `searchSemantic` | API `/api/search/semantic` | Contenu HTML | `escapeHtml` sur `event_id`, `device_id`, `labels` | **Faible** |
| `renderSiemLogs` / `renderPresenceDevices` | API audit / présence | Contenu HTML | `escapeHtml` | **Faible** |
| Blocs `catch (err)` & `renderDiagnostic` | Exceptions JS / API diagnostics | Contenu HTML (`innerHTML`) | Non échappé (`${err.message}`, `${diag...}`) | **P3 (Faible)** — préférer `textContent` |

---

## 3. STRATÉGIE RECOMMANDÉE POUR SUPPRIMER `'unsafe-inline'`

1. **Étape 1 (Frontend) :** Externaliser les scripts inline de `login.html` et `dashboard.html` vers `static/js/` ; remplacer les attributs `onclick="..."` par `addEventListener` / délégation d'événements (`data-*`) et utiliser `textContent` / `createElement` au lieu d'`innerHTML`.
2. **Étape 2 (Dépendance Tailwind) :** Compiler et servir la feuille CSS Tailwind localement (`static/css/tailwind.min.css`) au lieu de `https://cdn.tailwindcss.com` (ce qui supprime aussi l'injection dynamique de `<style>`).
3. **Étape 3 (Déploiement CSP) :** Activer `Content-Security-Policy-Report-Only` sans `'unsafe-inline'`, vérifier `0` violation, puis basculer en mode `Content-Security-Policy` strict avec nonces par requête si un inline résiduel subsiste.

---

## 4. STATUT

```text
CSP_XSS_GATE = PASS_WITH_LIMITATIONS  (Sinks principaux protégés ; 'unsafe-inline' et contexte onclick openImageModal documentés)
```
