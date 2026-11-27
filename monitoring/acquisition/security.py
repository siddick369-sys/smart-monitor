"""
Module de sécurité défensive pour l'acquisition vidéo NVR universelle.
Garantit la protection anti-SSRF, le DNS pinning, la neutralisation du rebinding et l'hygiène des secrets dans les logs.
Architecture NVR universelle PRO-13.
"""

import socket
import ipaddress
import re
from urllib.parse import urlparse
from typing import Tuple, Optional, Dict, Any, Set, List
import config
from monitoring.acquisition.egress_policy import (
    EgressPolicy, EgressEnforcementStatus, PolicyConfigurationError,
    check_egress_enforcement_status, classify_ip
)


# Ports strictement interdits pour les flux vidéo (services internes sensibles)
PROHIBITED_PORTS: Set[int] = {
    21,    # FTP
    22,    # SSH
    23,    # Telnet
    25,    # SMTP
    53,    # DNS
    110,   # POP3
    143,   # IMAP
    389,   # LDAP
    445,   # SMB
    636,   # LDAPS
    2049,  # NFS
    2375,  # Docker non-TLS
    2376,  # Docker TLS
    3306,  # MySQL
    5000,  # SSM Monitoring Host lui-même (anti-boucle)
    5432,  # PostgreSQL
    6379,  # Redis
    9200,  # Elasticsearch
    11211, # Memcached
    27017, # MongoDB
}


def sanitize_uri(uri: str) -> str:
    """Masque tout mot de passe ou jeton présent dans une URI pour empêcher les fuites dans les logs.
    Exemple : 'rtsp://admin:P@ssw0rd!#2026@192.168.1.50:554/ch0' -> 'rtsp://admin:***@192.168.1.50:554/ch0'
    """
    if not isinstance(uri, str) or "://" not in uri:
        return str(uri or "")

    scheme, rest = uri.split("://", 1)
    if "@" in rest:
        path_idx = rest.find("/")
        authority = rest[:path_idx] if path_idx != -1 else rest
        suffix = rest[path_idx:] if path_idx != -1 else ""
        if "@" in authority:
            userinfo, hostport = authority.rsplit("@", 1)
            if ":" in userinfo:
                username, _ = userinfo.split(":", 1)
                return f"{scheme}://{username}:***@{hostport}{suffix}"
            else:
                return f"{scheme}://***@{hostport}{suffix}"
    return uri


def extract_uri_credentials(uri: str) -> Tuple[str, Optional[str], Optional[str]]:
    """Extrait en toute sécurité les identifiants d'une URI et renvoie l'URI nettoyée sans credentials.
    Gère correctement les mots de passe contenant des caractères spéciaux (@, #, !).
    Retourne : (clean_uri, username, password)
    """
    if not isinstance(uri, str) or "://" not in uri:
        return uri, None, None

    scheme, rest = uri.split("://", 1)
    path_idx = rest.find("/")
    query_idx = rest.find("?")
    split_idx = -1
    if path_idx != -1 and query_idx != -1:
        split_idx = min(path_idx, query_idx)
    elif path_idx != -1:
        split_idx = path_idx
    elif query_idx != -1:
        split_idx = query_idx

    authority = rest[:split_idx] if split_idx != -1 else rest
    suffix = rest[split_idx:] if split_idx != -1 else ""

    username: Optional[str] = None
    password: Optional[str] = None
    hostport = authority

    if "@" in authority:
        userinfo, hostport = authority.rsplit("@", 1)
        if ":" in userinfo:
            username, password = userinfo.split(":", 1)
        else:
            username = userinfo

    clean_uri = f"{scheme}://{hostport}{suffix}"
    return clean_uri, username, password


def pin_uri_to_ip(uri: str, ip: str) -> str:
    """Réécrit une URI de flux vidéo en remplaçant son nom d'hôte par l'adresse IP validée (DNS Pinning).
    Élimine la fenêtre TOCTOU de DNS rebinding entre la validation de sécurité et la connexion effective.
    Préserve intégralement les identifiants, le port, le chemin et la query string.
    """
    if not isinstance(uri, str) or "://" not in uri:
        return uri

    scheme, rest = uri.split("://", 1)
    path_idx = rest.find("/")
    query_idx = rest.find("?")
    split_idx = -1
    if path_idx != -1 and query_idx != -1:
        split_idx = min(path_idx, query_idx)
    elif path_idx != -1:
        split_idx = path_idx
    elif query_idx != -1:
        split_idx = query_idx

    authority = rest[:split_idx] if split_idx != -1 else rest
    suffix = rest[split_idx:] if split_idx != -1 else ""

    userinfo_prefix = ""
    hostport = authority
    if "@" in authority:
        userinfo, hostport = authority.rsplit("@", 1)
        userinfo_prefix = userinfo + "@"

    # Extraction du port existant
    port_str = ""
    if hostport.startswith("["):
        rb = hostport.rfind("]")
        if rb != -1 and ":" in hostport[rb:]:
            port_str = hostport[rb:]
    elif ":" in hostport:
        _, p_part = hostport.rsplit(":", 1)
        port_str = ":" + p_part

    # Formatage de l'adresse IP (crochets pour IPv6)
    formatted_ip = f"[{ip}]" if ":" in ip else ip
    return f"{scheme}://{userinfo_prefix}{formatted_ip}{port_str}{suffix}"


def validate_video_target(
    target_str: str,
    port: Optional[int] = None,
    allow_loopback: bool = False,
    is_production: Optional[bool] = None,
    egress_policy: Optional[EgressPolicy] = None
) -> Tuple[bool, str, Optional[str]]:
    """Valide rigoureusement une cible vidéo avant toute ouverture de socket ou appel de sous-processus.
    
    Vérifications effectuées :
    1. Parsing robuste de l'URI ou du nom d'hôte (même avec mot de passe contenant @).
    2. Contrôle des ports interdits (anti-scan interne).
    3. Résolution DNS stricte (IPv4 et IPv6).
    4. Inspection de TOUS les résultats de résolution (politique fail-closed : si une seule IP est invalide, rejet total).
    5. Neutralisation des IPv4 mappées en IPv6 et zones IPv6.
    6. Interdiction des métadonnées cloud (169.254.0.0/16, fe80::/10), loopback en production, adresses publiques non autorisées.
    
    Retourne : (est_valide, raison, ip_resolue_primaire)
    """
    if not target_str or not isinstance(target_str, str):
        return False, "Cible vidéo vide ou non spécifiée.", None

    # Extraction robuste du hostname et port
    if "://" in target_str:
        scheme, rest = target_str.split("://", 1)
        if scheme.lower() not in ("rtsp", "rtsps", "http", "https"):
            return False, f"Protocole vidéo non autorisé : '{scheme}://'.", None
        path_idx = rest.find("/")
        query_idx = rest.find("?")
        split_idx = -1
        if path_idx != -1 and query_idx != -1:
            split_idx = min(path_idx, query_idx)
        elif path_idx != -1:
            split_idx = path_idx
        elif query_idx != -1:
            split_idx = query_idx

        authority = rest[:split_idx] if split_idx != -1 else rest
        hostport = authority.rsplit("@", 1)[-1] if "@" in authority else authority

        if hostport.startswith("["):
            rb = hostport.rfind("]")
            hostname = hostport[1:rb]
            port_part = hostport[rb + 1:]
            target_port = int(port_part[1:]) if port_part.startswith(":") else (554 if scheme.lower() == "rtsp" else 80)
        elif ":" in hostport:
            hostname, p_str = hostport.rsplit(":", 1)
            try:
                target_port = int(p_str)
            except ValueError:
                target_port = 554 if scheme.lower() == "rtsp" else 80
        else:
            hostname = hostport
            target_port = port or (554 if scheme.lower() == "rtsp" else 80)
    else:
        hostname = target_str
        target_port = port or 554

    if not hostname:
        return False, "Nom d'hôte ou adresse IP introuvable dans la cible.", None

    # 1. Vérification des ports interdits
    if target_port in PROHIBITED_PORTS:
        return False, f"Port destination interdit ({target_port}) pour prévenir les attaques SSRF.", None

    # 2. Détermination de la politique de production
    is_prod = config.IS_PRODUCTION if is_production is None else bool(is_production)

    # 3. Résolution DNS stricte pour IPv4 et IPv6
    try:
        addr_info = socket.getaddrinfo(hostname, target_port, socket.AF_UNSPEC, socket.SOCK_STREAM)
        if not addr_info:
            return False, f"Impossible de résoudre le nom d'hôte '{hostname}'.", None
    except socket.gaierror as e:
        return False, f"Échec de résolution DNS pour '{hostname}' : {e}", None
    except Exception as e:
        return False, f"Erreur lors de la résolution de '{hostname}' : {e}", None

    validated_ips: List[str] = []

    # 4. Examen rigoureux de CHAQUE IP résolue (Politique fail-closed intégrale)
    for item in addr_info:
        if len(item) < 5 or not isinstance(item[4], tuple) or len(item[4]) < 1:
            return False, f"Format d'adresse réseau invalide retourné pour '{hostname}'.", None

        sockaddr = item[4]
        ip_str = sockaddr[0]

        # Nettoyage de l'identifiant de zone IPv6 éventuel (ex: fe80::1%eth0)
        clean_ip = ip_str.split("%")[0]

        try:
            ip_obj = ipaddress.ip_address(clean_ip)
        except ValueError:
            return False, f"Format d'adresse IP résolue invalide : '{clean_ip}'.", None

        # Gestion des adresses IPv4 mappées en IPv6 (ex: ::ffff:127.0.0.1 ou ::ffff:169.254.169.254)
        if isinstance(ip_obj, ipaddress.IPv6Address) and ip_obj.ipv4_mapped:
            ip_obj = ip_obj.ipv4_mapped
            clean_ip = str(ip_obj)

        # A. Métadonnées Cloud (AWS, GCP, Azure, OpenStack : 169.254.0.0/16, fe80::/10 link-local)
        if ip_obj.is_link_local:
            return False, f"Adresse link-local/métadonnées cloud interdite : '{clean_ip}'.", clean_ip

        # B. Boucle locale (127.0.0.0/8, ::1)
        if ip_obj.is_loopback:
            if is_prod:
                return False, f"Accès loopback interdit en environnement de production : '{clean_ip}'.", clean_ip
            if not allow_loopback:
                return False, f"Accès loopback non autorisé pour cette caméra : '{clean_ip}'.", clean_ip

        # C. Cibles interdites multicast / broadcast / réservées / non spécifiées (0.0.0.0, ::)
        if ip_obj.is_multicast or ip_obj.is_reserved or ip_obj.is_unspecified:
            return False, f"Adresse multicast, réservée ou non spécifiée interdite : '{clean_ip}'.", clean_ip

        # D. Vérification réseau privé / public
        if not ip_obj.is_private and not ip_obj.is_loopback:
            if not getattr(config, "ALLOW_PUBLIC_CAMERAS", False):
                return False, f"Adresse IP publique non autorisée pour une caméra locale : '{clean_ip}'.", clean_ip

        # E. Vérification de la politique d'egress stricte (Lot A.4)
        if egress_policy is not None:
            allowed, egress_reason, _ = egress_policy.is_destination_allowed(clean_ip, target_port)
            if not allowed:
                return False, f"Rejet par la politique de confinement d'egress : {egress_reason}", clean_ip

        validated_ips.append(clean_ip)

    if not validated_ips:
        return False, f"Aucune adresse IP valide n'a pu être vérifiée pour '{hostname}'.", None

    primary_ip = validated_ips[0]
    return True, "Cible validée et conforme aux règles de sécurité.", primary_ip
