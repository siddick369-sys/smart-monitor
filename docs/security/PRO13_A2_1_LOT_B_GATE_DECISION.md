# SSM PRO-13-A.2.1 — DÉCISION FORENSIQUE DE FRANCHISSEMENT DE JALON (GATE DECISION : LOT B)

**Mission ID :** `SSM-PRO13-A2.1-INDEPENDENT-RTSP-SECURITY-AND-REGRESSION-AUDIT-01`  
**Dépôt :** `C:\Users\USER\Documents\alarme-sys`  
**Date d'évaluation :** 22 novembre 2026  
**Auditeur :** Principal Defensive Architect & Independent Security Auditor  
**Décision du Jalon Lot B :** **`LOT_B_GATE = BLOCKED`**

---

## 1. Cadre Réglementaire et Mandat de Contrôle

Conformément aux directives fondamentales du programme **SSM PRO-13**, le passage d'un lot fonctionnel à un autre ne peut s'effectuer sans l'approbation formelle d'un jalon d'assurance de sécurité (Quality & Security Gate).

Le **Lot B (IA Multimodale & Vision Périphérique)** prévoit l'intégration de pipelines d'inférence neuronale lourds (YOLOv8, modèles audio multimodaux, détection de silhouettes, zones d'exclusion). Ces pipelines consomment des ressources CPU/GPU significatives et s'alimentent directement depuis le buffer circulaire de trames vidéo produit par le **Lot A (NVR Universel & Acquisition)**.

Si le socle d'acquisition vidéo du Lot A présente des faiblesses d'isolation réseau ou des risques de blocage de processus (deadlock IPC), l'injection de charges d'inférence IA amplifierait exponentiellement l'instabilité du système et exposerait SSM à des dénis de service critiques.

---

## 2. Grille d'Évaluation Contradictoire des Prérequis d'Entrée

| N° | Condition Préalable à l'Ouverture du Lot B | Statut de Contrôle | Commentaire Forensique |
| :---: | :--- | :---: | :--- |
| **1** | Résolution complète et vérifiée des anomalies A1-001 à A1-006 | **VALIDÉ** | Déballage `sockaddr`, multi-IP fail-closed, DNS pinning, buffer `maxlen=2`, non-enrôlement et mDNS documenté. |
| **2** | Absence totale de régression sur le socle de sécurité PRO-12 | **VALIDÉ** | 127/127 tests historiques réussis (Two-Man Rule, Merkle trees, P2P strict). |
| **3** | Stabilité globale de la suite de tests et compilation sans erreur | **VALIDÉ** | 266/266 tests réussis, `compileall` code 0. |
| **4** | Étanchéité absolue de la frontière réseau post-handshake RTSP | **NON ATTEINT** | **A21-001 (P2)** : Absence de `-max_redirects 0` et `-protocol_whitelist` sur la commande FFmpeg. Risque de suivi de redirection 301/302 vers une cible interne. |
| **5** | Résilience de la supervision IPC et absence de risque de blocage | **NON ATTEINT** | **A21-003 (P3)** : Risque de saturation du tube `stderr` de FFmpeg (pipe deadlock) en cas de flux corrompu. |
| **6** | Qualification sur flux RTSP matériel physique | **NON ATTEINT** | `HARDWARE_INTEGRATION_TEST = NOT_AVAILABLE`. Tests validés sur simulation/synthèse uniquement. |
| **7** | Approbation formelle et décharge explicite de la gouvernance humaine | **NON ATTEINT** | En attente de revue et décision de l'opérateur. |

---

## 3. Analyse Justificative de la Décision : Pourquoi le Lot B est Maintenu BLOQUÉ

La décision de maintenir **`LOT_B_GATE = BLOCKED`** est motivée par les impératifs d'ingénierie défensive suivants :

1. **Priorité de l'Étanchéité Réseau sur les Fonctionnalités d'IA :**
   Le constat **A21-001** démontre que le DNS Pinning applicatif protège l'établissement de la socket initiale, mais qu'un flux RTSP renvoyant une redirection 302 ou un descripteur SDP avec des cibles absolues peut amener FFmpeg à contacter des hôtes arbitraires. Intégrer de l'IA sur un canal d'acquisition dont les flux secondaires ne sont pas formellement verrouillés par `-max_redirects 0` et `-protocol_whitelist` constitue une entorse au principe de défense en profondeur.

2. **Résilience de la Boucle de Streaming (Anti-Deadlock) :**
   Le constat **A21-003** met en évidence qu'une saturation du tampon `stderr` de 4 Ko sous Windows peut figer la lecture de `stdout`. Si un pipeline d'inférence IA attend des trames qui ne viennent jamais à cause d'un pipe bloqué, l'ensemble du système de détection d'intrusion sera paralysé sans alerte explicite.

3. **Démarcation Honnête de la Qualification Matérielle :**
   L'application est 100% fonctionnelle au niveau logiciel et algorithmique sous simulation. Cependant, aucune caméra physique n'a encore été connectée. Le programmeur et l'architecte ne doivent pas présumer du comportement matériel sans preuve empirique.

---

## 4. Feuille de Route pour le Déblocage du Jalon (Mission PRO-13-A.3)

Le déblocage du Lot B ne nécessite pas de refonte majeure. Il s'articule autour d'une micro-remédiation de durcissement (PRO-13-A.3) d'une durée estimée très courte :

### Étape 4.1 : Application des Correctifs Défensifs Ciblés
1. **Durcissement FFmpeg (`monitoring/acquisition/ffmpeg_adapter.py`) :**
   - Injecter `-max_redirects 0` dans `_build_ffmpeg_cmd()` pour refuser les redirections non auditées.
   - Injecter `-protocol_whitelist tcp,rtp,rtsp` pour confiner FFmpeg à ses seuls protocoles d'acquisition.
   - Vider `stderr` de manière asynchrone ou le rediriger vers `subprocess.DEVNULL` pour éliminer définitivement tout risque de deadlock IPC (A21-003).

### Étape 4.2 : Re-validation Automatisée
- Exécuter la suite complète (266 tests) pour confirmer le maintien du 100% vert.

### Étape 4.3 : Décision de l'Opérateur Humain
- L'opérateur humain examine le présent dossier d'audit.
- S'il valide la micro-remédiation PRO-13-A.3 et accepte l'état de qualification matérielle simulée, il formule l'autorisation formelle :
  `LOT_B_GATE = AUTHORIZED`.

---

## 5. Formalisation du Verdict

```
╔══════════════════════════════════════════════════════════════════════════════╗
║                    SMART SECURITY MONITOR — PRO-13-A.2.1                     ║
║                       VERDICT OFFICIEL DE JALON (GATE)                       ║
╠══════════════════════════════════════════════════════════════════════════════╣
║                                                                              ║
║   LOT ACTUEL (LOT A - NVR UNIVERSEL) :         VALIDÉ AVEC RÉSERVES          ║
║   REMÉDIATIONS A1-001 À A1-006 :               CONFORMES ET CONFIRMÉES       ║
║   NON-RÉGRESSION PRO-12 (127 TESTS) :          100% SUCCÈS (0 RÉGRESSION)    ║
║   SUITE GLOBALE (266 TESTS) :                  100% SUCCÈS (0 ÉCHEC)         ║
║   NOUVEAUX CONSTATS RÉSIDUELS :                A21-001 (P2), A21-003 (P3)    ║
║   QUALIFICATION MATÉRIELLE PHYSIQUE :          NON DISPONIBLE (SIMULÉE)      ║
║                                                                              ║
║   STATUT DU JALON LOT B :                      >>> BLOQUÉ (BLOCKED) <<<      ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
```
