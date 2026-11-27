#!/usr/bin/env bash
# =============================================================================
# SMART SECURITY MONITOR — CONFINEMENT EGRESS HÔTE POUR DOCKER NVR
# Programme PRO-13 — Lot A.4.2 (Remédiation DOCKER-USER / nftables)
# =============================================================================
# Ce script s'exécute sur l'HÔTE LINUX DOCKER (privilèges root requis).
# Il applique une politique Deny-by-Default sur le trafic sortant du sous-réseau
# Docker ssm-nvr-isolated-net (172.28.10.0/24) en filtrant dans la couche de
# confiance appropriée (hôte).
# =============================================================================

set -euo pipefail

DOCKER_SUBNET="${DOCKER_SUBNET:-172.28.10.0/24}"
ALLOWED_CAMERAS="${ALLOWED_CAMERAS:-192.168.1.50/32,192.168.1.51/32}"
ALLOWED_PORTS="${ALLOWED_PORTS:-554,8554,80,443,8080,8081}"
DRY_RUN=false

if [[ "${1:-}" == "--dry-run" ]]; then
    DRY_RUN=true
fi

echo "================================================================================"
echo "SSM PRO-13 A.4.2 — CONFIGURATION CONFINEMENT EGRESS HÔTE DOCKER"
echo "================================================================================"
echo "Sous-réseau Docker   : ${DOCKER_SUBNET}"
echo "Caméras autorisées   : ${ALLOWED_CAMERAS}"
echo "Ports TCP autorisés  : ${ALLOWED_PORTS}"
echo "Mode Dry-Run         : ${DRY_RUN}"

if [[ "$DRY_RUN" == "false" && "$(id -u)" -ne 0 ]]; then
    echo "[ERREUR] Ce script doit être exécuté en tant que root sur l'hôte Docker." >&2
    exit 1
fi

# Détection du backend pare-feu réel sur l'hôte
BACKEND="unknown"
if command -v iptables >/dev/null 2>&1 && iptables -L DOCKER-USER -n >/dev/null 2>&1; then
    BACKEND="iptables-docker-user"
elif command -v nft >/dev/null 2>&1; then
    BACKEND="nftables"
fi

echo "Backend détecté      : ${BACKEND}"

if [[ "$BACKEND" == "unknown" ]]; then
    echo "[ERREUR] Ni chaîne DOCKER-USER (iptables) ni nftables détecté." >&2
    exit 1
fi

if [[ "$BACKEND" == "iptables-docker-user" ]]; then
    run_cmd() {
        if [[ "$DRY_RUN" == "true" ]]; then
            echo "[DRY-RUN] $*"
        else
            "$@"
        fi
    }

    # 0. Purge idempotente des seules règles SSM existantes (préserve les règles tierces)
    if [[ "$DRY_RUN" == "true" ]]; then
        echo "[DRY-RUN] Purge idempotente des règles commentées SSM_DOCKER_EGRESS dans DOCKER-USER (IPv4/IPv6)"
    else
        while iptables -S DOCKER-USER 2>/dev/null | grep -q "SSM_DOCKER_EGRESS"; do
            RULE_NUM=$(iptables -L DOCKER-USER --line-numbers -n | awk '/SSM_DOCKER_EGRESS/{print $1; exit}')
            [[ -n "${RULE_NUM}" ]] && iptables -D DOCKER-USER "${RULE_NUM}" || break
        done
    fi

    # 1. Autoriser les retours de connexions établies
    run_cmd iptables -I DOCKER-USER 1 -d "${DOCKER_SUBNET}" -m conntrack --ctstate ESTABLISHED,RELATED -m comment --comment "SSM_DOCKER_EGRESS" -j RETURN

    # 2. Bloquer explicitement Cloud Metadata et Link-Local
    run_cmd iptables -I DOCKER-USER 2 -s "${DOCKER_SUBNET}" -d 169.254.0.0/16 -m comment --comment "SSM_DOCKER_EGRESS" -j DROP

    # 3. Autoriser uniquement les caméras et ports approuvés
    IFS=',' read -ra CAM_ARRAY <<< "${ALLOWED_CAMERAS}"
    for cam in "${CAM_ARRAY[@]}"; do
        run_cmd iptables -I DOCKER-USER 3 -s "${DOCKER_SUBNET}" -d "${cam}" -p tcp -m multiport --dports "${ALLOWED_PORTS}" -m comment --comment "SSM_DOCKER_EGRESS" -j RETURN
    done

    # 4. Journaliser et bloquer tout autre trafic sortant depuis le conteneur (Deny-by-Default)
    run_cmd iptables -A DOCKER-USER -s "${DOCKER_SUBNET}" -m comment --comment "SSM_DOCKER_EGRESS" -j LOG --log-prefix "SSM_DOCKER_EGRESS_DROP: "
    run_cmd iptables -A DOCKER-USER -s "${DOCKER_SUBNET}" -m comment --comment "SSM_DOCKER_EGRESS" -j DROP

    # 5. Contrôle IPv6 idempotent (ip6tables si disponible)
    if command -v ip6tables >/dev/null 2>&1 && ip6tables -L DOCKER-USER -n >/dev/null 2>&1; then
        if [[ "$DRY_RUN" != "true" ]]; then
            while ip6tables -S DOCKER-USER 2>/dev/null | grep -q "SSM_DOCKER_EGRESS"; do
                RULE6_NUM=$(ip6tables -L DOCKER-USER --line-numbers -n | awk '/SSM_DOCKER_EGRESS/{print $1; exit}')
                [[ -n "${RULE6_NUM}" ]] && ip6tables -D DOCKER-USER "${RULE6_NUM}" || break
            done
        fi
        run_cmd ip6tables -I DOCKER-USER 1 -m conntrack --ctstate ESTABLISHED,RELATED -m comment --comment "SSM_DOCKER_EGRESS" -j RETURN
        run_cmd ip6tables -I DOCKER-USER 2 -d fe80::/10 -m comment --comment "SSM_DOCKER_EGRESS" -j DROP
        run_cmd ip6tables -A DOCKER-USER -m comment --comment "SSM_DOCKER_EGRESS" -j DROP
    fi
elif [[ "$BACKEND" == "nftables" ]]; then
    NFT_RULES=$(cat <<EOF
table inet ssm_nvr_egress {
    chain forward {
        type filter hook forward priority -10; policy accept;
        ct state established,related accept
        ip saddr ${DOCKER_SUBNET} ip daddr 169.254.0.0/16 drop
        ip saddr ${DOCKER_SUBNET} ip daddr { ${ALLOWED_CAMERAS} } tcp dport { ${ALLOWED_PORTS} } accept
        ip saddr ${DOCKER_SUBNET} log prefix "SSM_DOCKER_EGRESS_DROP: " drop
        ip6 daddr fe80::/10 drop
        ip6 daddr ::1/128 drop
        ip6 saddr fc00::/7 log prefix "SSM_DOCKER_EGRESS_V6_DROP: " drop
    }
}
EOF
)
    if [[ "$DRY_RUN" == "true" ]]; then
        echo "[DRY-RUN] Suppression idempotente de table inet ssm_nvr_egress + application :"
        echo "${NFT_RULES}"
    else
        nft delete table inet ssm_nvr_egress 2>/dev/null || true
        echo "${NFT_RULES}" | nft -f -
    fi
fi

echo "Configuration Docker Egress terminée avec succès."
