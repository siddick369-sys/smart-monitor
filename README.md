# SMART SECURITY MONITOR — CONSOLE PROFESSIONNELLE DE SURVEILLANCE DISTRIBUÉE
### Évolution Majeure PRO-06 → PRO-11 : Suite Sécurité Entreprise & Edge AI

---

## 1. Présentation Générale

**SMART SECURITY MONITOR (PRO-11 Master Edition)** est une plateforme professionnelle souveraine de vidéosurveillance distribuée, de gestion forensique d'incidents, de cybersécurité applicative et de dissuasion active. Conçue pour transformer un poste central sous Windows 11 en un **Monitoring Host** résilient et autonome, elle orchestre des smartphones Android utilisés comme caméras IP et stations télémétriques multiparamétriques.

L'évolution **PRO-06 → PRO-11** apporte 15 innovations stratégiques surpassant les systèmes NVR propriétaires du marché (comme Agent DVR / iSpy) en matière d'intégrité de preuve numérique, de souveraineté locale, de respect strict du RGPD et de résilience réseau.

---

## 2. Les 15 Piliers Technologiques Majeurs (PRO-06 → PRO-11)

### Groupe A : Fondations Intelligentes (PRO-06)
1. **Edge AI Local (YOLOv8-Nano / ONNX Runtime CPU)** : Inférence d'objets sur processeur sans GPU dédié, avec politiques commutables (`OPENCV_ONLY`, `EDGE_AI_ASSISTED`, `EDGE_AI_REQUIRED`).
2. **Géofencing Wi-Fi & Armement Intelligent** : Détection non-intrusive (ARP/ICMP) avec période de grâce anti-flapping (60s) et sécurité anti-désarmement silencieux.
3. **Double Facteur TOTP (RFC 6238) & SIEM** : Codes 2FA à usage unique avec jetons de secours et exportation d'audit au format **ArcSight CEF** et **Syslog RFC 5424**.
4. **Streaming Vidéo Hybride WebRTC & Fallback MJPEG** : Signalisation SDP/ICE ultra-basse latence avec repli automatique sur flux MJPEG multi-clients.
5. **Progressive Web App (PWA) & Notifications Web Push** : Console installable, Service Worker hors-ligne et notifications natives sur smartphone et poste client.

### Groupe B : Détection Avancée & Anti-Sabotage (PRO-07)
6. **Anti-Sabotage Multi-Vecteurs (Tamper Detection)** : Analyse temps réel de 7 anomalies critiques : obstruction optique, bascule accélérométrique, déplacement physique, flou sévère, surexposition lumineuse, coupure de flux et dérive télémétrique.
7. **Classificateur Acoustique d'Urgence** : Détection d'événements sonores critiques (cris humains de détresse, bris de verre, sirène d'alarme, chocs) avec fusion multi-vectorielle audio/vidéo.

### Groupe C : Recherche Vidéo Intelligente (PRO-08)
8. **Recherche Vidéo Sémantique Multimodale** : Indexation vectorielle automatique dans SQLite, calcul de descripteurs perceptuels et recherche en langage naturel (ex: *"personne en rouge"*, *"véhicule"*) par similarité cosinus avec pagination.

### Groupe D : Forensique, Confidentialité & Intégrité (PRO-09)
9. **Moteur Forensique Certifié PDF** : Rapports judiciaires ReportLab séparant formellement faits physiques bruts vérifiables et interprétations probabilistes IA.
10. **Bouclier de Confidentialité (Two-Man Rule)** : Floutage protecteur des visages, chiffrement des originaux en AES-256-GCM et déchiffrement assujetti au protocole obligatoire de double approbation.
11. **Intégrité Cryptographique, Horodatage TSA & Tatouage** : Hachage SHA-256 par blocs de 64 Ko, sceau HMAC-SHA256, horodatage RFC 3161 (avec repli local) et tatouage visible et stéganographique LSB.

### Groupe E : Compréhension Spatiale & Comportementale (PRO-10)
12. **Jumeau Numérique 2D & Handover Inter-Caméras** : Plan vectoriel interactif SVG, calcul d'angles et projection de coordonnées cibles, suivi continu de trajectoire et alerte sur zones interdites.
13. **Détection Posturale & Prévention de Chute** : Repérage de posture allongée/chute et de maraudage prolongé (>20s), avec qualification déontologique systématique `NEEDS_REVIEW` (présomption d'innocence).

### Groupe F : Communication & Résilience Réseau (PRO-11)
14. **Synchronisation P2P Store-and-Forward** : File d'attente d'incidents hors-ligne persistée sur les nœuds distants, authentification HMAC et déduplication automatique lors du retour réseau.
15. **Interphonie Bidirectionnelle & Sommation Défensive** : Communication audio WebRTC, diffusion de messages vocaux déclaratifs neutres et stroboscope optique sécurisé (plafond 8s et cooldown 15s).

---

## 3. Cartographie des Ports et Services

| Composant | Port | Protocole | Fonction |
|---|---|---|---|
| **Monitoring Host** | `5000` | HTTP / WS | Console de supervision, API REST, WebRTC & PWA (`http://127.0.0.1:5000`) |
| **Simulateur Android Mock** | `8081` | HTTP | Émulateur Android IP Webcam avec flux 640x480 et capteurs physiques |
| **Smartphones Réels** | `8080` (défaut) | HTTP | Application Android IP Webcam (`http://IP_PHONE:8080`) |

---

## 4. Démarrage Rapide

### Prérequis
- Windows 10/11 64-bit
- Python 3.11.x (recommandé 3.11.8)
- Dépendances installées via `pip install -r requirements.txt`

### Lancement Automatisé (1 Clic)
Double-cliquez sur `run.bat` à la racine du projet ou exécutez dans PowerShell :
```powershell
python run.py
```
Accédez à la console dans votre navigateur : **`http://127.0.0.1:5000`**

---

## 5. Campagne de Tests et Certification

L'ensemble des tests est exécuté sous Python 3.11 sur l'environnement Windows 11 cible :

### 1. Suite de Tests Automatisés (110 tests)
```powershell
python -m pytest tests/ -v
```
**Résultat : 110 tests réussis sur 110 (100% de succès en ~52 secondes).**

### 2. Smoke Test End-to-End (12 points validés)
```powershell
python tests/smoke_test.py
```
**Résultat : 12/12 points validés à 100% avec simulateur intégré et persistance SQLite certifiée.**

---

## 6. Structure de la Documentation (`docs/`)

| Document | Objet |
|---|---|
| 📋 [docs/SSM_MASTER_EVOLUTION_FINAL_REPORT.md](file:///c:/Users/USER/Documents/alarme-sys/docs/SSM_MASTER_EVOLUTION_FINAL_REPORT.md) | Rapport maître exhaustif de synthèse, certification et audit complet PRO-06 → PRO-11. |
| 📖 [docs/ARCHITECTURE.md](file:///c:/Users/USER/Documents/alarme-sys/docs/ARCHITECTURE.md) | Architecture technique détaillée, diagrammes Mermaid, flux de données Edge AI & SIEM. |
| 📘 [docs/USER_GUIDE.md](file:///c:/Users/USER/Documents/alarme-sys/docs/USER_GUIDE.md) | Guide d'utilisation complet (2FA, présence, Edge AI, PWA, rapports, recherche sémantique). |
| ⚠️ [docs/LIMITATIONS.md](file:///c:/Users/USER/Documents/alarme-sys/docs/LIMITATIONS.md) | Analyse critique des limites réelles (CPU, randomisation MAC Wi-Fi, WebRTC). |
| 🎓 [docs/FINAL_PRESENTATION.md](file:///c:/Users/USER/Documents/alarme-sys/docs/FINAL_PRESENTATION.md) | Scénario de soutenance universitaire minuté pour le jury. |
| 📋 [docs/PRO06_FINAL_REPORT.md](file:///c:/Users/USER/Documents/alarme-sys/docs/PRO06_FINAL_REPORT.md) | Rapport de clôture technique et certification formelle PRO-06. |
