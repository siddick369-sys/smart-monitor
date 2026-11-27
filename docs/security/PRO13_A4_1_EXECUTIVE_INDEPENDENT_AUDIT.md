# 🛡️ SSM PRO-13-A.4.1 — INDEPENDENT FORENSIC AUDIT EXECUTIVE REPORT
## INDEPENDENT ADVERSARIAL AUDIT OF EGRESS CONFINEMENT, WINDOWS FIREWALL SCRIPTING & DOCKER NETWORK ISOLATION

**Mission ID :** `SSM-PRO13-A4.1-INDEPENDENT-EGRESS-ENFORCEMENT-AUDIT-01`  
**Classification :** CRITICAL SECURITY AUDIT / NETWORK EGRESS / SSRF / FIREWALL POLICY VERIFICATION  
**Auditeur :** Senior Independent Forensic Security Auditor  
**Dépôt canonique :** `C:\Users\USER\Documents\alarme-sys`  
**Branche :** `main`  
**HEAD audité :** `b339a9c82d5b410e78d1ea6d43cae556049ba2c0`  
**Date d'audit :** 2026-11-24  
**Statut initial :** `A4_EGRESS_CONFINEMENT_VERIFIED_WITH_LIMITATIONS`  
**Verdict d'audit A4.1 :** `A4_1_EGRESS_ARCHITECTURE_VERIFIED_WITH_LIMITATIONS`  
**Statut Gate Lot B :** `LOT_B_GATE = BLOCKED_PENDING_EXPLICIT_HUMAN_APPROVAL`

---

## 1. MANDAT ET POSTURE D'AUDIT INDÉPENDANTE

Le présent audit forensique a été mandaté pour évaluer de manière strictement contradictoire, objective et en mode **STRICT READ-ONLY** la réalité des garanties apportées par la mission PRO-13-A.4.

La question centrale posée par cet audit est la suivante :  
**L'architecture implémentée empêche-t-elle effectivement FFmpeg/libavformat d'ouvrir des connexions réseau non autorisées, y compris des connexions RTSP secondaires qui contournent la validation Python ?**

### Posture déontologique :
- Aucune modification de code de production ni de test n'a été effectuée.
- Les scripts de pare-feu n'ont pas été exécutés de manière destructive sur la machine hôte.
- Le moteur Docker n'a pas été démarré.
- Toutes les affirmations du rapport PRO-13-A.4 ont été réévaluées sans complaisance.

---

## 2. TABLEAU DE CONFRONTATION INDÉPENDANT : AFFIRMATIONS VS RÉALITÉ FORENSIQUE

| # | Affirmation du rapport A.4 | Examen forensique indépendant | Verdict de l'audit A.4.1 |
|---|---|---|:---:|
| **1** | La politique `EgressPolicy` empêche les connexions vers les IP non approuvées | `EgressPolicy` valide l'URI initiale et filtre les IP dans Python, mais **n'intercepte pas** les sockets ouvertes directement en C par libavformat. | **PARTIELLEMENT VRAI (Couche applicative uniquement)** |
| **2** | Le DNS Pinning neutralise l'évasion réseau | `pin_uri_to_ip` réécrit l'hôte sur la ligne de commande initiale de FFmpeg. Il ne contrôle pas les redirections RTSP 3xx ou les URI absolus dans les SDP analysés en C. | **LIMITÉ AU SOCKET INITIAL** |
| **3** | Le script Windows établit une liste blanche stricte | `setup_ffmpeg_egress_firewall.ps1` crée une règle `Action Allow`. Sur Windows standard où le profil sortant par défaut est `Allow`, **le trafic vers les autres destinations reste autorisé** ! | **DÉFAUT D'EFFICACITÉ CONSTATÉ** |
| **4** | Le conteneur Docker est totalement isolé | Le réseau est configuré en `internal: false` sans règles iptables hôte documentées. Le conteneur peut router vers toute destination accessible par la passerelle hôte. | **CONFINEMENT CONDITIONNEL À L'HÔTE** |
| **5** | La détection d'isolation vérifie le pare-feu OS | `check_egress_enforcement_status()` vérifie uniquement des variables d'environnement (`SSM_EGRESS_FIREWALL_ACTIVE`), sans requêter le pare-feu OS réel. | **VÉRIFICATION PAR VARIABLE D'ENVIRONNEMENT** |
| **6** | 20 scénarios adversariaux prouvent le confinement | Les 20 tests sont tous des tests `UNIT` ou `MOCKED_INTEGRATION`. Aucun test n'a validé un blocage de paquet sur une interface réseau OS réelle. | **PREUVE LOGICIELLE EXCLUSIVE** |
| **7** | Aucune régression sur le socle PRO-12 | 127 tests PRO-12 passés (100%), 292 tests au total sur le dépôt passés (100%). | **PLEINEMENT CONFIRMÉ** |

---

## 3. CONCLUSIONS ADVERSARIALES MAJEURES (SYNTHÈSE DES FINDINGS)

### Finding 1 (Majeur) — Limite intrinsèque de libavformat face aux sockets secondaires
La bibliothèque C libavformat de FFmpeg possède sa propre boucle d'événements réseau. Lorsqu'un serveur RTSP hostile renvoie un code de redirection 302 ou un descripteur SDP contenant `a=control:rtsp://10.0.0.1:554/track1`, libavformat ouvre une nouvelle socket TCP directement depuis le code C (`libavformat/rtsp.c`).  
**Conséquence :** Aucun code Python (`validate_video_target`, `EgressPolicy`, `pin_uri_to_ip`) n'est réinvoqué. Seul un filtrage externe de niveau noyau (pare-feu OS ou conteneur) peut interdire cette socket.

### Finding 2 (Majeur) — Incomplétude du script de pare-feu Windows
Dans `scripts/setup_ffmpeg_egress_firewall.ps1`, la règle créée est :
```powershell
New-NetFirewallRule ... -Program $resolvedExe -Action Allow -RemoteAddress $validDestinations
```
Sous Windows, le profil par défaut de Windows Defender Firewall autorise tout le trafic sortant non explicitement bloqué (`DefaultOutboundAction: Allow`). Par conséquent, créer une règle `-Action Allow` sans définir le comportement par défaut de l'exécutable à `Block` ou sans règle de blocage complémentaire n'empêche pas FFmpeg de se connecter à d'autres adresses IP !

### Finding 3 (Moyen) — Détection d'enforcement basée sur des variables d'environnement
La fonction `check_egress_enforcement_status()` détermine l'état d'application de l'isolation en lisant `os.environ.get("SSM_EGRESS_FIREWALL_ACTIVE")` ou `SSM_EGRESS_CONTAINER_ISOLATED`. Une variable d'environnement ne constitue pas une preuve cryptographique ou matérielle qu'une règle de filtrage est effectivement active dans la pile réseau du système d'exploitation.

### Finding 4 (Moyen) — Confinement conteneur Docker dépendant de l'hôte
Le manifeste `docker/docker-compose.nvr-egress.yml` utilise `internal: false` pour permettre au conteneur de joindre les caméras sur le réseau local. Dans ce mode, Docker active le NAT via la passerelle hôte. Le conteneur exécutant `user: "10001:10001"` et `cap_drop: [ALL]` ne peut pas exécuter `iptables` en interne ; le filtrage d'egress dépend donc impérativement de règles iptables configurées sur l'hôte Docker externe.

---

## 4. DÉCISIONS FORMELLES DE GATE

```
================================================================================
LOT A AUDIT VERDICT :
A4_1_EGRESS_ARCHITECTURE_VERIFIED_WITH_LIMITATIONS

LOT B GATE DECISION :
LOT_B_GATE = BLOCKED_PENDING_EXPLICIT_HUMAN_APPROVAL
================================================================================
```

1. **Lot A : `A4_1_EGRESS_ARCHITECTURE_VERIFIED_WITH_LIMITATIONS`**  
   L'architecture logicielle, la modularité et les défenses applicatives contre le SSRF sont remarquables et couvertes par 292 tests au vert. Les limitations relevées (nécessité d'une règle de blocage par défaut dans le script Windows, filtrage iptables sur l'hôte Docker et absence d'interception Python sur les sockets C internes de FFmpeg) sont des réalités architecturales objectives qui doivent être prises en compte lors du déploiement industriel sans pour autant invalider la conformité du code Python développé.
2. **Lot B : `BLOCKED_PENDING_EXPLICIT_HUMAN_APPROVAL`**  
   Le passage aux développements d'intelligence artificielle demeure **STRICTEMENT VERROUILLÉ**.
