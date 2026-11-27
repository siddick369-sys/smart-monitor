# 🛡️ SSM PRO-13-A.3.1 — LOT B GATE DECISION & GOVERNANCE ROADMAP
## FORMAL GOVERNANCE RULING, ACCEPTANCE MATRIX, AND PRECONDITIONS FOR AI EVOLUTION

**Mission ID :** `SSM-PRO13-A3.1-INDEPENDENT-FFMPEG-RTSP-AND-PROCESS-SECURITY-AUDIT-01`  
**Autorité :** Senior Independent Forensic Security Auditor  
**Date d'émission :** 2026-11-23  
**Classification :** GOVERNANCE GATE · FORMAL DECISION · RISK ACCEPTANCE FRAMEWORK  
**Statut initial :** `LOT_B_GATE = BLOCKED_PENDING_INDEPENDENT_AUDIT`  
**Statut final arrêté :** `LOT_B_GATE = BLOCKED_PENDING_HUMAN_APPROVAL`

---

## 1. HISTORIQUE ET RÈGLES DE GOUVERNANCE

Le programme PRO-13 a instauré des points de contrôle stricts (Security Gates) séparant les phases d'infrastructure d'acquisition vidéo (Lot A — NVR Universel) des phases d'analyse avancée et d'intelligence artificielle (Lot B — IA Multimodale, Re-ID, YOLOv8, YAMNet) :
- **Directive racine :** Aucun développement du Lot B ne peut être initié tant que le Lot A n'a pas fait l'objet d'un audit forensique indépendant complet et contradictoire.
- **Règle absolue :** L'agent auditeur indépendant ne possède pas l'autorité d'autoriser unilatéralement le déverrouillage du Lot B ; sa mission consiste à certifier le niveau de conformité du Lot A et à soumettre la décision de franchissement à l'arbitrage humain explicite.

---

## 2. MATRICE D'ACCEPTATION DU LOT A (NVR UNIVERSEL)

| Critère d'évaluation Lot A | Exigence de la mission racine | Constat forensique d'audit | Décision |
|---|---|---|:---:|
| **Architecture FFmpeg** | Sous-processus supervisés indépendants | `subprocess.Popen` structuré, `shell=False`, arguments en liste | **ACCEPTÉ** |
| **Abstraction VideoSource** | Interface abstraite découplée du moteur | Héritage strict de `VideoSource`, polymorphisme respecté | **ACCEPTÉ** |
| **Protocole P2P Mesh** | Protocole strict `SSMP2P02` maintenu | Anti-downgrade vérifié, zéro compatibilité avec signatures faibles | **ACCEPTÉ** |
| **Isolation SQLite** | Élimination des conflits concurrents | Base de données de test isolée, transactions propres | **ACCEPTÉ** |
| **Profil par défaut** | 10 FPS, 640x480 paramétrable | Valeurs par défaut configurables sans prétention d'universalité | **ACCEPTÉ** |
| **Découverte réseau** | Zéro auto-enrôlement, approbation opérateur | Statut `DISCOVERED_PENDING_APPROVAL` imposé sous contrôle RBAC | **ACCEPTÉ** |
| **Anti-SSRF & DNS** | Neutralisation cloud metadata & TOCTOU | `validate_video_target` + `pin_uri_to_ip` actifs et vérifiés | **ACCEPTÉ** |
| **Résilience IPC** | Élimination des blocages stderr/stdout | Drain worker asynchrone, mémoire $\le 64$ Ko, tests 100 Ko passés | **ACCEPTÉ** |
| **Régression PRO-12** | Zéro régression sur le socle historique | 127/127 tests passés (100%), 0 régression | **ACCEPTÉ** |
| **Validation binaire réel** | Exécution de `ffmpeg.exe` local | Binaire absent du PATH hôte (`REAL_FFMPEG_VALIDATION = NOT_AVAILABLE`) | **LIMITATION ACTÉE** |
| **Validation matérielle** | Caméras physiques IP branchées | Banc de test virtuel (`HARDWARE_INTEGRATION_TEST = NOT_AVAILABLE`) | **LIMITATION ACTÉE** |
| **Confinement réseau C** | Blocage redirections SDP libavformat | Filtrage protocoles OK, isolation IP requiert pare-feu externe | **LIMITATION ACTÉE** |

---

## 3. DÉCISION OFFICIELLE POUR LE LOT A

### **VERDICT LOT A : `PASS_WITH_LIMITATIONS`**

**Motifs de la décision :**
1. L'ensemble des exigences logicielles, architecturales et de durcissement de sécurité du Lot A est pleinement satisfait.
2. Les 35 tests NVR dédiés et les 127 tests historiques PRO-12 sont au vert (272 tests au total sur le dépôt).
3. Les limitations relevées (absence de binaire FFmpeg local, banc de test virtuel et nécessité d'un pare-feu pour le confinement réseau complet des sockets C) sont des contraintes environnementales et d'infrastructure qui ne remettent pas en cause la qualité et la conformité du code Python développé.

---

## 4. DÉCISION OFFICIELLE POUR LE LOT B

### **VERDICT LOT B : `BLOCKED_PENDING_HUMAN_APPROVAL`**

**Statut :** **STRICTEMENT VERROUILLÉ.**  
Le passage au Lot B (IA multimodale, YOLOv8, suivi multi-caméra Re-ID, détection audio YAMNet) est **INTERDIT** à ce stade.

---

## 5. CONDITIONS PRÉALABLES POUR LE DÉVERROUILLAGE HUMAIN DU LOT B

Pour autoriser l'ouverture du Lot B, l'autorité humaine de gouvernance devra :

1. **Revue formelle du dossier d'audit PRO-13-A.3.1 :** Prendre acte des 7 rapports d'audit forensique déposés dans `docs/security/`.
2. **Acceptation des limitations opérationnelles :** Acter que la validation physique avec le binaire FFmpeg et des caméras réelles interviendra lors de l'intégration dans l'image de conteneur Docker finale.
3. **Approbation de l'architecture réseau de déploiement :** Valider la mise en place d'un cloisonnement réseau conteneurisé (Egress Filtering) pour neutraliser le risque de redirection RTSP vers des adresses IP sensibles.
4. **Ordre de mission explicite :** Émettre une consigne humaine explicite stipulant l'autorisation formelle d'entamer les spécifications et développements du Lot B.
