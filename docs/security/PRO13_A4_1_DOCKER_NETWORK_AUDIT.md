# 🛡️ SSM PRO-13-A.4.1 — DOCKER NETWORK ISOLATION AUDIT
## ARCHITECTURAL AUDIT OF THE CONTAINERIZED NVR WORKER, BRIDGE ROUTING, AND HOST-LEVEL EGRESS FILTERING

**Mission ID :** `SSM-PRO13-A4.1-INDEPENDENT-EGRESS-ENFORCEMENT-AUDIT-01`  
**Composants audités :** `docker/docker-compose.nvr-egress.yml`, `docker/Dockerfile.nvr-worker`  
**HEAD audité :** `b339a9c82d5b410e78d1ea6d43cae556049ba2c0`  
**Date d'audit :** 2026-11-24

---

## 1. ANALYSE DU RÉSEAU DOCKER ET ROUTAGE SORTANT

Le fichier `docker/docker-compose.nvr-egress.yml` définit l'architecture réseau du conteneur `ssm_nvr_worker_isolated` :

```yaml
networks:
  ssm-nvr-isolated-net:
    driver: bridge
    internal: false
    ipam:
      config:
        - subnet: 172.28.10.0/24
          gateway: 172.28.10.1
```

### 1.1 Examen critique de `internal: false`
- **Pourquoi `internal: false` ?**  
  Dans Docker, un réseau avec `internal: true` supprime la passerelle de sortie par défaut (`gateway`). Si `internal: true` était activé, le conteneur worker serait dans l'incapacité absolue de se connecter à toute caméra IP physique située sur le réseau local de l'entreprise (ex: `192.168.1.50`). L'activation de la passerelle est donc requise pour joindre les caméras.
- **Le revers de sécurité :**  
  Puisque `internal: false` est configuré, le démon Docker applique par défaut une règle de masquage NAT (`MASQUERADE`) sur l'interface réseau de l'hôte. En l'absence de règles de filtrage complémentaires, **le conteneur peut émettre des paquets vers n'importe quelle adresse routable par l'hôte**, y compris les métadonnées cloud (`169.254.169.254`) ou d'autres machines du réseau interne.

---

### 1.2 Impossibilité d'exécuter `iptables` à l'intérieur du conteneur
L'image `docker/Dockerfile.nvr-worker` installe le paquet `iptables` (ligne 21). Cependant :
- Le conteneur s'exécute sous `user: "10001:10001"` (non-root).
- Le conteneur abandonne toutes ses capacités : `cap_drop: [ALL]`.
- Par conséquent, le binaire `iptables` **ne peut pas être exécuté dans le conteneur** car la capacité `CAP_NET_ADMIN` est absente et le compte n'est pas `root`.

### 1.3 Exigence de filtrage au niveau de l'Hôte Docker (Chaîne DOCKER-USER)
Pour que le confinement réseau sortant du conteneur soit réel et étanche en environnement Linux de production, l'administrateur de l'hôte Docker doit impérativement configurer les règles iptables **sur la machine hôte**, dans la chaîne standard `DOCKER-USER` :
```bash
# Exemple de règle hôte requise pour rendre l'isolation effective :
iptables -I DOCKER-USER -s 172.28.10.0/24 -d 192.168.1.50 -p tcp --dport 554 -j ACCEPT
iptables -A DOCKER-USER -s 172.28.10.0/24 -j DROP
```
Sans cette configuration sur l'hôte, le conteneur n'est **pas confiné au niveau réseau**.

---

## 2. AUDIT DE DURCISSEMENT DU CONTENEUR (SYSTÈME ET RESSOURCES)

L'audit des couches système du conteneur relève des garanties de très haut niveau :

| Paramètre audité | Valeur configurée | Évaluation de sécurité |
|---|---|:---:|
| Utilisateur d'exécution | `10001:10001` (`ssmworker`) | **Excellent** : Aucun privilège root. |
| Privileged mode | `privileged: false` | **Conforme** : Interdiction du mode privilégié. |
| No-new-privileges | `no-new-privileges: true` | **Conforme** : Empêche toute élévation via setuid. |
| Linux Capabilities | `cap_drop: [ALL]` | **Excellent** : Suppression totale des capacités noyau. |
| Système de fichiers | `read_only: true` | **Excellent** : FS racine immuable. |
| Répertoires temporaires | `/tmp:rw,noexec,nosuid,size=64m` | **Conforme** : Mémoire vive, pas d'exécution de code injecté. |
| Plafonnement CPU | `cpus: '1.0'` | **Conforme** : Anti-DDoS CPU. |
| Plafonnement Mémoire | `memory: 512M` | **Conforme** : Évite les fuites mémoire. |
| Plafonnement Processus | `pids: 50` | **Conforme** : Anti-Fork Bomb. |

---

## 3. COMPORTEMENT DU DNS DOCKER

Le conteneur utilise le serveur DNS interne de Docker (`127.0.0.11`). Celui-ci relaye les résolutions DNS vers les serveurs DNS de l'hôte.  
Dans notre architecture, la résolution DNS est de toute façon effectuée par Python avant l'appel à FFmpeg, et l'URI transmise à FFmpeg est réécrite avec l'adresse IP (`_effective_uri`), ce qui limite le recours au DNS par FFmpeg au démarrage.

---

## 4. CONCLUSION FORENSIQUE

L'architecture du worker Docker est **remarquablement durcie sur les plans système, privilèges et ressources**.  
Cependant, l'isolation réseau ne peut être considérée comme active que si les règles de filtrage de la chaîne `DOCKER-USER` sont déployées sur le système d'exploitation hôte.
