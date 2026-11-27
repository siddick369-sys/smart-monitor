# 🛡️ SMART SECURITY MONITOR — RAPPORT FORENSIQUE EXÉCUTIF D'AUDIT INDÉPENDANT
## AUDIT ADVERSARIAL DU PINNING DNS, DE L'ISOLATION VIDÉO ET DES CONNEXIONS SECONDAIRES RTSP (PRO-13-A.2.1)

**Identifiant Unique :** `SSM-PRO13-A2.1-INDEPENDENT-RTSP-SECURITY-AND-REGRESSION-AUDIT-01`  
**Mission :** Audit de sécurité contradictoire, adversarial et strictement READ-ONLY post-remédiation PRO-13-A.2  
**Projet :** Smart Security Monitor (SSM)  
**Dépôt :** `C:\Users\USER\Documents\alarme-sys`  
**HEAD de Référence :** `b339a9c82d5b410e78d1ea6d43cae556049ba2c0`  
**Mode :** Strictement READ-ONLY (aucun fichier modifié en production)  
**Environnement Constaté :** Windows 11 · Python 3.11.8 · OpenCV 4.10.0 · SQLite 3 / SQLAlchemy · pytest 9.1.1  
**Verdict Global :** **`PRO13_A2_1_VERIFIED_WITH_LIMITATIONS`**  
**Statut de la Gate Lot B :** **`LOT_B_GATE = BLOCKED`**  
**Date d'Audit :** 22 Novembre 2026  

---

## 1. RÉSUMÉ EXÉCUTIF

Cet audit forensique a été exécuté dans le respect rigoureux de la directive READ-ONLY pour vérifier de manière contradictoire la réalité et la robustesse des remédiations annoncées dans PRO-13-A.2 (`A1-001` à `A1-006`).

L'analyse s'est focalisée sur la question centrale posée par le mandat :
> *La validation DNS et le remplacement du nom d'hôte par une adresse IP préviennent-ils réellement toutes les connexions non maîtrisées vers des cibles interdites lors de l'ingestion RTSP ?*

### Conclusions Principales de l'Audit :

1. **Validation DNS et Pinning Initial Robustes (A1-001 & A1-002) — VALIDÉS :**  
   L'extraction des enregistrements dans `validate_video_target()` a été corrigée avec succès (`sockaddr = item[4]`). L'inspection est exhaustive : en cas de résolution DNS multi-IP, la présence d'une seule IP non autorisée entraîne un rejet *fail-closed* immédiat. La fonction `pin_uri_to_ip()` lie l'URI de connexion à l'adresse IP validée, neutralisant la fenêtre TOCTOU pour la connexion TCP initiale. De plus, la boucle de reconnexion ré-exécute la validation complète à chaque cycle.
2. **Vecteurs SSRF Secondaires RTSP / SDP Identifiés (P2 — Risque Résiduel Non Mitigé) :**  
   Le pinning de l'URI d'entrée ne contraint que la requête RTSP initiale (`OPTIONS` / `DESCRIBE`). Si un serveur RTSP hostile répond avec une redirection RTSP (`301 Moved Permanently` / `302 Moved Temporarily`) ou renvoie un descriptif SDP contenant des URLs de contrôle absolues (`a=control:rtsp://169.254.169.254/` ou `a=control:rtsp://127.0.0.1:3306/`), le client FFmpeg sous-jacent émettra des requêtes vers ces destinations secondaires sans repasser par `validate_video_target()`. L'absence d'options FFmpeg restrictives (ex: `-protocol_whitelist`, filtrage des redirections) et l'absence de pare-feu réseau de sortie laissent ce risque ouvert.
3. **Désactivation du Fallback OpenCV en Production (A1-003) — VALIDÉE :**  
   L'indicateur `_allow_opencv_fallback` est forcé à `False` dès que `IS_PRODUCTION=True`. En l'absence de `ffmpeg.exe`, l'adaptateur se met formellement en état `VideoSourceStatus.ERROR` et refuse la capture. En environnement de développement, l'injection de `OPENCV_FFMPEG_CAPTURE_OPTIONS` configure le timeout `stimeout`, mais ne constitue en aucun cas une isolation de processus (une panne native libavcodec fait chuter l'ensemble du processus Python).
4. **Clarification ONVIF & mDNS (A1-004 & A1-005) — VALIDÉE :**  
   Les capacités ONVIF exposent fidèlement `WS_DISCOVERY_SUPPORTED` et `SOAP_MEDIA_NOT_IMPLEMENTED`. Toute mention de conformité Profile S/T a été purgée. Le protocole mDNS est formellement documenté comme `NOT_IMPLEMENTED`.
5. **Buffer Circulaire `deque(maxlen=2)` (A1-006) — VALIDÉ :**  
   Le buffer circulaire est effectivement instancié, thread-safe sous `RLock`, et garantit la fraîcheur de la trame restituée.
6. **Reproduction Intégrale des Résultats de Tests :**  
   - Lot A : **29 / 29 réussis (100%)** en 13.70s.
   - PRO-12 historique : **127 / 127 réussis (100%)** en 86.51s.
   - Suite complète : **266 / 266 réussis (100%)** en 131.55s.
   - Compilation `compileall` : Code retour `0`.

---

## 2. BASELINE FORENSIQUE ET IDENTITÉ DU DÉPÔT

| Paramètre | Valeur Constatée |
| :--- | :--- |
| **Chemin du dépôt** | `C:\Users\USER\Documents\alarme-sys` |
| **Branche courante** | `main` |
| **HEAD complet** | `b339a9c82d5b410e78d1ea6d43cae556049ba2c0` |
| **Date du dernier commit** | `2026-11-22 08:32:50 +0100` |
| **Message du commit** | `docs(pro13): add Lot A NVR report and git push automation scripts` |
| **État Git Working Tree** | 6 fichiers modifiés suivis, 2 rapports non suivis, aucun commit local créé |
| **Diff suivi** | +448 lignes / -68 lignes (strictement circonscrit à A1-001..A1-006) |
| **Binaire FFmpeg système** | **ABSENT** (`where.exe ffmpeg` -> Code 1) |
| **Version Python** | 3.11.8 (64-bit AMD64) |
| **Version OpenCV** | 4.10.0 (AVFormat 58.76.100, AVCodec 58.134.100) |

---

## 3. MATRICE SYNTHÉTIQUE DES CONSTATATIONS D'AUDIT

| ID | Domaine | Sévérité | Statut d'Audit | Description & Impact |
| :--- | :--- | :---: | :---: | :--- |
| **A21-001** | Protocole RTSP | **P2** | `UNVERIFIED_RISK` | **SSRF Secondaire via Redirection RTSP (301/302) et SDP `a=control` absolu :** `pin_uri_to_ip()` n'agit que sur l'URI initiale. Une caméra compromise peut renvoyer une redirection ou une URL de contrôle absolue vers une IP interne sensible non validée. |
| **A21-002** | FFmpeg Options | **P2** | `PARTIALLY_VERIFIED` | **Absence de `-protocol_whitelist` dans FFmpeg :** La ligne de commande FFmpeg n'impose pas de liste blanche de protocoles (`-protocol_whitelist "rtsp,tcp,crypto,tls"`), autorisant potentiellement des protocoles imbriqués (concat, subfile, data). |
| **A21-003** | Concurrence Pipe | **P3** | `UNVERIFIED_RISK` | **Risque de Deadlock sur `stderr=subprocess.PIPE` :** FFmpeg écrit sur `stderr` qui n'est vidé qu'après la fin du processus. Un volume élevé d'erreurs vidéo pourrait saturer le tampon OS (4-64 Ko) et bloquer l'écriture `stdout`. |
| **A21-004** | OpenCV Fallback | **P3** | `VERIFIED_WITH_LIMITATIONS` | **Timeout OpenCV in-process vs Isolation :** Le timeout `stimeout` est configuré via variable d'environnement, mais ne protège pas contre un gel dans `cap.read()` natif et n'offre aucune isolation de processus. |
| **A21-005** | Infrastructure | **INFO** | `NOT_AVAILABLE` | **Validation Matérielle Réelle :** `HARDWARE_INTEGRATION_TEST = NOT_AVAILABLE`. Aucune caméra physique n'a été raccordée. |

---

## 4. DÉCISION RELATIVE À LA GATE DU LOT B

En application des critères stricts de la section 13 du mandat :
- Les remédiations logiques A1-001 à A1-006 sont vérifiées dans le cadre du code Python.
- Cependant, la frontière réseau RTSP comporte un risque résiduel de redirection secondaire (A21-001) et FFmpeg n'est pas encore déployé sous forme binaire isolée sur l'hôte.

Par conséquent :
> **STATUT DE LA GATE LOT B :** **`LOT_B_GATE = BLOCKED`**  
> *L'ouverture du Lot B (IA Multimodale) demeure formellement bloquée. Elle ne pourra être envisagée qu'après approbation humaine explicite et, idéalement, après ajout des options FFmpeg de restriction de protocole (`-protocol_whitelist`).*
