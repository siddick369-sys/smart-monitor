"""
Module de sécurité défensive pour l'acquisition vidéo NVR universelle.
Garantit la protection anti-SSRF, la neutralisation du DNS rebinding et l'hygiène des secrets dans les logs.
"""

import socket
import ipaddress
import re
from urllib.parse import urlparse
from typing import Tuple, Optional, Dict, Any, Set
import config


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
    Retourne : (clean_uri, username, password)
    """
    if not isinstance(uri, str) or "://" not in uri:
        return uri, None, None

    parsed = urlparse(uri)
    username = parsed.username
    password = parsed.password

    # Reconstruire l'URI sans user:pass@
    netloc = parsed.hostname or ""
    if parsed.port:
        netloc = f"{netloc}:{parsed.port}"

    clean_uri = f"{parsed.scheme}://{netloc}{parsed.path}"
    if parsed.query:
        clean_uri += f"?{parsed.query}"

    return clean_uri, username, password


def validate_video_target(
    target_str: str,
    port: Optional[int] = None,
    allow_loopback: bool = False,
    is_production: Optional[bool] = None
) -> Tuple[bool, str, Optional[str]]:
    """Valide rigoureusement une cible vidéo avant toute ouverture de socket ou appel de sous-processus.
    
    Vérifications effectuées :
    1. Parsing de l'URI ou du nom d'hôte.
    2. Contrôle des ports interdits (anti-scan interne).
    3. Résolution DNS stricte de l'hôte.
    4. Validation de l'adresse IP résolue (interdiction loopback, link-local metadata cloud, adresses publiques).
    5. Neutralisation des IPv4 mappées en IPv6.
    
    Retourne : (est_valide, raison, ip_resolue)
    """
    if not target_str or not isinstance(target_str, str):
        return False, "Cible vidéo vide ou non spécifiée.", None

    # Extraction du hostname et port depuis une URI si présente
    if "://" in target_str:
        parsed = urlparse(target_str)
        hostname = parsed.hostname
        target_port = parsed.port or (554 if parsed.scheme.lower() == "rtsp" else (80 if parsed.scheme.lower() == "http" else 443))
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

    # 3. Résolution DNS et vérification anti-rebinding
    try:
        # Résolution pour IPv4 et IPv6
        addr_info = socket.getaddrinfo(hostname, target_port, socket.AF_UNSPEC, socket.SOCK_STREAM)
        if not addr_info:
            return False, f"Impossible de résoudre le nom d'hôte '{hostname}'.", None
    except socket.gaierror as e:
        return False, f"Échec de résolution DNS pour '{hostname}' : {e}", None
    except Exception as e:
        return False, f"Erreur lors de la résolution de '{hostname}' : {e}", None

    # 4. Examen de chaque IP résolue
    for family, socktype, proto, canonname, sockaddr in addr_info:
        ip_str = sockaddr[0]

        try:
            ip_obj = ipaddress.ip_address(ip_str)
        except ValueError:
            return False, f"Format d'adresse IP résolue invalide : '{ip_str}'.", None

        # Gestion des adresses IPv4 mappées en IPv6 (ex: ::ffff:127.0.0.1 ou ::ffff:169.254.169.254)
        if isinstance(ip_obj, ipaddress.IPv6Address) and ip_obj.ipv4_mapped:
            ip_obj = ip_obj.ipv4_mapped
            ip_str = str(ip_obj)

        # A. Métadonnées Cloud (AWS, GCP, Azure, OpenStack : 169.254.169.254 et 169.254.0.0/16)
        if ip_obj.is_link_local:
            return False, f"Adresse link-local/métadonnées cloud interdite : '{ip_str}'.", ip_str

        # B. Boucle locale (127.0.0.0/8, ::1)
        if ip_obj.is_loopback:
            if is_prod:
                return False, f"Accès loopback interdit en environnement de production : '{ip_str}'.", ip_str
            if not allow_loopback:
                return False, f"Accès loopback non autorisé pour cette caméra : '{ip_str}'.", ip_str

        # C. Cibles interdites multicast / broadcast / réservées
        if ip_obj.is_multicast or ip_obj.is_reserved:
            return False, f"Adresse multicast ou réservée interdite pour un flux direct : '{ip_str}'.", ip_str

        # D. Vérification réseau privé / public
        # En mode standard, les caméras de sécurité résident sur le réseau local privé
        if not ip_obj.is_private and not ip_obj.is_loopback:
            # Rejet des adresses publiques pour prévenir les SSRF vers internet
            if not getattr(config, "ALLOW_PUBLIC_CAMERAS", False):
                return False, f"Adresse IP publique non autorisée pour une caméra locale : '{ip_str}'.", ip_str

    # Première IP valide retenue
    resolved_ip = addr_info[0][1][0]
    return True, "Cible validée et conforme aux règles de sécurité.", resolved_ip
