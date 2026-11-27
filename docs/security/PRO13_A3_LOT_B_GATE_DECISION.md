# SSM PRO-13-A.3 — DÉCISION DE JALON (GATE DECISION : LOT B)
## STATUT DU JALON : BLOQUÉ EN ATTENTE D'AUDIT INDÉPENDANT ET D'AUTORISATION HUMAINE

**Mission ID :** `SSM-PRO13-A3-RTSP-FFMPEG-SECURITY-AND-IPC-DEADLOCK-ELIMINATION-01`  
**Dépôt canonique :** `C:\Users\USER\Documents\alarme-sys`  
**Date d'évaluation :** 23 novembre 2026  
**Auditeur :** Principal Systems Architect & Defensive Security Lead  
**Décision Officielle :** **`LOT_B_GATE = BLOCKED_PENDING_INDEPENDENT_AUDIT`**

---

## 1. Cadre Réglementaire du Programme SSM PRO-13

Le programme d'évolution architecturale **SSM PRO-13** applique un modèle d'assurance de sécurité strict :
> **Règle Fondamentale :** Aucune nouvelle capacité fonctionnelle lourde (Lot B : Intelligence Artificielle, Détection YOLOv8, Ré-identification, Analyse Multimodale audio/vidéo) ne peut être initiée tant que le socle d'acquisition sous-jacent (Lot A : NVR Universel, flux RTSP, protocoles réseau et tuyauterie IPC) n'a pas été formellement durci, testé contradictoirement et audité de manière indépendante.

Bien que la présente mission PRO-13-A.3 ait achevé avec succès l'ensemble des corrections techniques exigées pour A21-001 et A21-003, l'ouverture du Lot B **ne peut pas être auto-proclamée par l'équipe d'implémentation**.

---

## 2. Bilan de Réalisation des Remédiations PRO-13-A.3

| Référence Constat | Intitulé de la Vulnérabilité / Risque | Statut Technique | Niveau de Preuve Obtenu |
| :---: | :--- | :---: | :--- |
| **A21-001** | Risque protocolaire RTSP secondaire et SSRF post-handshake | **RÉSOLU** | `-protocol_whitelist` actif (`tcp,rtp,rtsp`), transport TCP forcé (`-rtsp_transport tcp`), pas d'évasion UDP, DNS Pinning préservé. |
| **A21-003** | Risque de blocage IPC (Deadlock) sur saturation du tube `stderr` | **RÉSOLU** | Thread lecteur continu (`_stderr_drain_worker`), tampon borné (64 Ko / 100 lignes), masquage des secrets, test de saturation physique 100 Ko réussi. |
| **PRO-12 Non-Régression** | Préservation des 127 contrôles de sécurité historiques | **VALIDÉ** | 127 / 127 tests passés (Two-Man Rule, scellement Merkle, P2P SSMP2P02, AES-256-GCM). |
| **Stabilité Globale** | Intégrité de la suite complète de tests du dépôt | **VALIDÉ** | 272 / 272 tests passés, 1 warning (100% succès). |
| **Compilation Statique** | Absence d'erreur de syntaxe ou de symbole manquant | **VALIDÉ** | `compileall` code retour 0, `git diff --check` code retour 0. |

---

## 3. Matrice des Risques Résiduels Ouverts

Trois risques résiduels demeurent consignés dans le registre de sécurité :

| Réf. Risque | Priorité | Description du Risque Résiduel | Justification du Maintien |
| :---: | :---: | :--- | :--- |
| **A3-R01** | **P2** | **Frontière Moteur C (`libavformat`) vs Egress Réseau :** Bien que la whitelist bloque les protocoles non RTSP, les flux secondaires RTSP 301/302 ou SDP absolus s'exécutent en code natif C. | Une étanchéité egress totale nécessitera un cloisonnement réseau système (conteneur ou pare-feu OS) lors de la phase industrielle. |
| **A3-R02** | **P2** | **Absence de Banc de Test Matériel Réel :** Les tests ont été validés sur mocks déterministes et sous-processus synthétiques, sans caméra IP physique connectée. | `HARDWARE_VALIDATION = NOT_AVAILABLE`. Aucune caméra physique n'a été raccordée sur le réseau local. |
| **A3-R03** | **P3** | **Absence du Binaire FFmpeg sur le PATH :** L'environnement Windows hôte ne dispose pas de `ffmpeg.exe` dans le PATH système. | `REAL_FFMPEG_VALIDATION = NOT_AVAILABLE`. L'adaptateur utilise le fallback OpenCV en Dev/Test et fail-close en Production. |

---

## 4. Prérequis pour le Déverrouillage Formel du Lot B

L'autorisation d'entrée dans le Lot B exige la validation des deux étapes suivantes :

### Étape 1 : Audit Forensique Indépendant Contradictoire (Mission PRO-13-A.3.1)
Un auditeur indépendant en mode strictement READ-ONLY devra examiner le code final issu de PRO-13-A.3 pour :
1. Vérifier de manière contradictoire l'absence de régression.
2. Évaluer la robustesse de l'implémentation de `_stderr_drain_worker` face à des flux asynchrones extrêmes.
3. Confirmer l'absence de tout contournement de sécurité.
4. Émettre son rapport d'audit et formuler sa recommandation de jalon.

### Étape 2 : Décision Explicite de la Gouvernance Humaine
L'opérateur humain ou l'autorité technique du projet doit :
1. Prendre acte des limitations matérielles (`HARDWARE_VALIDATION = NOT_AVAILABLE`).
2. Valider formellement la conformité du socle d'acquisition Lot A.
3. Signer la décision autorisant le passage au Lot B :
   `LOT_B_GATE = AUTHORIZED`.

---

## 5. Formalisation du Verdict de Jalon

```
╔══════════════════════════════════════════════════════════════════════════════╗
║                     VERDICT OFFICIEL DU JALON LOT B                          ║
╠══════════════════════════════════════════════════════════════════════════════╣
║                                                                              ║
║   SOCLE LOT A (NVR UNIVERSEL) :         DURCI, TESTÉ ET VALIDÉ (35 TESTS)    ║
║   REMÉDIATION A21-001 (RTSP/PROTO) :    COMPLÈTE (-protocol_whitelist, TCP)  ║
║   REMÉDIATION A21-003 (IPC/DEADLOCK) :  COMPLÈTE (Drain continu, 64 Ko max)  ║
║   SUITE GLOBALE (272 TESTS) :           100% SUCCÈS (0 ÉCHEC)                ║
║   STABILITÉ GIT :                       AUCUN COMMIT, AUCUN PUSH             ║
║                                                                              ║
║   STATUT DU JALON LOT B :               >>> BLOQUÉ (BLOCKED) <<<             ║
║   MOTIF :                               En attente d'audit indépendant       ║
║                                         PRO-13-A.3.1 et d'accord humain      ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
```
