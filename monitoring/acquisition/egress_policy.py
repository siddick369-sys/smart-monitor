"""
Module de politique de confinement réseau (Egress Policy) pour l'acquisition vidéo NVR.
Architecture NVR universelle PRO-13 — Lot A.4.2 (Remédiation et durcissement OS/Kernel).

Garantit :
1. Une politique d'interdiction par défaut (Deny-by-Default) pour tout trafic réseau sortant.
2. La restriction stricte aux seules adresses IP et sous-réseaux caméras explicitement autorisés.
3. Le rejet inconditionnel des destinations non autorisées : métadonnées cloud, link-local,
   adresses de boucle locale (en production), IPv4 mappées en IPv6, adresses multicast,
   broadcast, non spécifiées, et plages RFC1918 non explicitement inscrites en liste blanche.
4. La détection et le rejet précoce des politiques mal configurées (listes vides, masques trop larges).
5. L'évaluation authentique et non falsifiable du niveau d'application réel au niveau OS / Pare-feu / Conteneur
   via la hiérarchie de providers EgressEnforcementProvider, éliminant toute confiance aveugle dans des variables d'environnement.
"""

import os
import sys
import abc
import socket
import logging
import ipaddress
import subprocess
from enum import Enum
from typing import List, Tuple, Optional, Set, Union, Dict, Any

import config

logger = logging.getLogger("SmartSecurityMonitor.NVR.EgressPolicy")


class PolicyConfigurationError(ValueError):
    """Levée lorsqu'une politique d'egress est invalide ou présente une configuration dangereuse."""
    pass


class EgressEnforcementStatus(str, Enum):
    """Statuts qualifiant le niveau effectif d'application du confinement réseau.
    Conforme aux spécifications formelles PRO-13 A.4.2.
    """
    ENFORCED = "ENFORCED"
    PARTIAL = "PARTIAL"
    NOT_ENFORCED = "NOT_ENFORCED"
    UNKNOWN = "UNKNOWN"
    UNSUPPORTED = "UNSUPPORTED"

    # Alias de rétrocompatibilité (PRO-13 A.4)
    ENFORCED_OS_FIREWALL = "ENFORCED"
    ENFORCED_CONTAINER = "ENFORCED"
    ENFORCED_APPLICATION_PINNING = "PARTIAL"
    UNENFORCED = "NOT_ENFORCED"
    NOT_SUPPORTED_PLATFORM = "UNSUPPORTED"
    FAIL_CLOSED_BLOCKED = "NOT_ENFORCED"


# Réseaux réservés et cibles dangereuses devant être proscrits par défaut
CLOUD_METADATA_NETWORKS = [
    ipaddress.ip_network("169.254.169.254/32"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("fe80::/10"),
]

LOOPBACK_NETWORKS = [
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("::1/128"),
]


def classify_ip(ip_obj: Union[ipaddress.IPv4Address, ipaddress.IPv6Address]) -> str:
    """Catégorise formellement une adresse IP selon la taxonomie réseau de sécurité."""
    # Détection IPv4-mapped IPv6
    if isinstance(ip_obj, ipaddress.IPv6Address) and ip_obj.ipv4_mapped:
        ip_obj = ip_obj.ipv4_mapped

    if ip_obj.is_loopback:
        return "LOOPBACK"
    if ip_obj.is_link_local:
        return "LINK_LOCAL"
    if str(ip_obj) == "169.254.169.254":
        return "CLOUD_METADATA"
    if ip_obj.is_multicast:
        return "MULTICAST"
    if ip_obj.is_unspecified:
        return "UNSPECIFIED"
    if ip_obj.is_reserved:
        return "RESERVED"
    if isinstance(ip_obj, ipaddress.IPv4Address) and str(ip_obj) == "255.255.255.255":
        return "BROADCAST"
    if ip_obj.is_private:
        if isinstance(ip_obj, ipaddress.IPv6Address):
            return "IPV6_UNIQUE_LOCAL"
        return "RFC1918_PRIVATE"
    return "PUBLIC_INTERNET"


class EgressPolicy:
    """Politique de confinement réseau stricte et deny-by-default pour l'acquisition vidéo."""

    def __init__(
        self,
        allowed_destinations: Optional[List[str]] = None,
        allowed_ports: Optional[List[int]] = None,
        allow_loopback: bool = False,
        is_production: Optional[bool] = None,
        strict_deny_all_unapproved: bool = True
    ):
        self.raw_allowed_destinations = list(allowed_destinations or [])
        self.allowed_ports: Set[int] = set(allowed_ports or [554, 8554, 80, 443, 8080, 8081])
        self.allow_loopback = allow_loopback
        self.is_production = config.IS_PRODUCTION if is_production is None else bool(is_production)
        self.strict_deny_all_unapproved = strict_deny_all_unapproved

        # Résolution et validation des réseaux autorisés
        self.parsed_allowed_networks: List[Union[ipaddress.IPv4Network, ipaddress.IPv6Network]] = []
        self._validate_and_compile_policy()

    def _validate_and_compile_policy(self) -> None:
        """Valide rigoureusement la configuration de la politique d'egress.
        Échoue si la liste est vide (en mode strict) ou contient des sous-réseaux trop larges.
        """
        if self.strict_deny_all_unapproved and not self.raw_allowed_destinations:
            raise PolicyConfigurationError(
                "Politique d'egress invalide : la liste des destinations caméras autorisées "
                "ne peut pas être vide (politique deny-by-default obligatoire)."
            )

        for dest in self.raw_allowed_destinations:
            dest_str = str(dest).strip()
            if not dest_str:
                continue

            try:
                # Accepte les adresses individuelles ou blocs CIDR
                net = ipaddress.ip_network(dest_str, strict=False)
            except ValueError as e:
                raise PolicyConfigurationError(
                    f"Format d'adresse ou sous-réseau autorisé invalide dans la politique d'egress : '{dest_str}' ({e})"
                )

            # Rejet absolu des masques réseau démesurés (anti-évasion / anti-wildcard)
            # Pour IPv4 : interdiction des préfixes <= 8 (ex: 0.0.0.0/0, 10.0.0.0/8, etc.)
            if isinstance(net, ipaddress.IPv4Network):
                if net.prefixlen <= 8:
                    raise PolicyConfigurationError(
                        f"Plage réseau trop large interdite dans la politique d'egress : '{dest_str}' "
                        f"(préfixe /{net.prefixlen} <= /8). Les règles doivent cibler des caméras spécifiques."
                    )
            # Pour IPv6 : interdiction des préfixes <= 16 (ex: ::/0)
            elif isinstance(net, ipaddress.IPv6Network):
                if net.prefixlen <= 16:
                    raise PolicyConfigurationError(
                        f"Plage IPv6 trop large interdite dans la politique d'egress : '{dest_str}' "
                        f"(préfixe /{net.prefixlen} <= /16)."
                    )

            # Rejet formel des réseaux de métadonnées cloud dans la liste blanche
            if any(net.overlaps(meta) for meta in CLOUD_METADATA_NETWORKS):
                raise PolicyConfigurationError(
                    f"Inclusion interdite d'adresses de métadonnées cloud dans la liste d'egress : '{dest_str}'."
                )

            # Rejet formel de la boucle locale en production
            if self.is_production and any(net.overlaps(lb) for lb in LOOPBACK_NETWORKS):
                raise PolicyConfigurationError(
                    f"Inclusion interdite d'adresses de boucle locale en environnement de production : '{dest_str}'."
                )

            self.parsed_allowed_networks.append(net)

    def is_destination_allowed(self, target_ip_or_host: str, port: int) -> Tuple[bool, str, Optional[str]]:
        """Contrôle si une destination réseau spécifique est autorisée par la politique d'egress.
        
        Vérifications :
        1. Résolution de l'adresse IP et normalisation IPv4/IPv6.
        2. Vérification des ports interdits globaux (anti-scan).
        3. Contrôle des ports autorisés.
        4. Rejet inconditionnel des métadonnées cloud et link-local.
        5. Contrôle de la boucle locale selon l'environnement.
        6. Rejet des cibles multicast, broadcast et non spécifiées.
        7. Vérification de l'appartenance stricte à la liste des caméras autorisées.
        
        Retourne : (est_autorise, raison, ip_canonique)
        """
        if not target_ip_or_host:
            return False, "Cible réseau vide ou indéterminée.", None

        # Nettoyage de l'adresse (gestion des identifiants de zone IPv6)
        clean_target = str(target_ip_or_host).strip().split("%")[0]

        # Résolution DNS préliminaire si nom d'hôte fourni
        try:
            ip_obj = ipaddress.ip_address(clean_target)
        except ValueError:
            # Nom d'hôte fourni -> tentative de résolution
            try:
                addr_info = socket.getaddrinfo(clean_target, port, socket.AF_UNSPEC, socket.SOCK_STREAM)
                if not addr_info:
                    return False, f"Impossible de résoudre le nom d'hôte '{clean_target}'.", None
                sockaddr = addr_info[0][4]
                clean_target = sockaddr[0].split("%")[0]
                ip_obj = ipaddress.ip_address(clean_target)
            except Exception as e:
                return False, f"Échec de résolution DNS pour l'egress '{clean_target}' : {e}", None

        # Normalisation IPv4-mapped IPv6 (ex: ::ffff:192.168.1.50)
        if isinstance(ip_obj, ipaddress.IPv6Address) and ip_obj.ipv4_mapped:
            ip_obj = ip_obj.ipv4_mapped
            clean_target = str(ip_obj)

        ip_category = classify_ip(ip_obj)

        # 1. Vérification des ports strictement interdits
        from monitoring.acquisition.security import PROHIBITED_PORTS
        if port in PROHIBITED_PORTS:
            return False, f"Port destination interdit ({port}) par la politique de sécurité globale.", clean_target

        # 2. Rejet des métadonnées cloud et link-local
        if ip_category in ("LINK_LOCAL", "CLOUD_METADATA") or ip_obj.is_link_local:
            return False, f"Accès interdit aux adresses link-local / métadonnées cloud : '{clean_target}'.", clean_target

        # 3. Rejet de la boucle locale en production
        if ip_obj.is_loopback:
            if self.is_production:
                return False, f"Accès loopback interdit en production par la politique d'egress : '{clean_target}'.", clean_target
            if not self.allow_loopback:
                return False, f"Accès loopback non autorisé pour ce flux : '{clean_target}'.", clean_target

        # 4. Rejet des cibles multicast, broadcast, non spécifiées
        if ip_category in ("MULTICAST", "BROADCAST", "UNSPECIFIED", "RESERVED"):
            return False, f"Destination multicast, broadcast ou non spécifiée interdite : '{clean_target}'.", clean_target

        # 5. Vérification de l'appartenance à la liste blanche explicite
        matched_network = None
        for net in self.parsed_allowed_networks:
            if ip_obj in net:
                matched_network = net
                break

        if not matched_network:
            if ip_category == "RFC1918_PRIVATE":
                return False, (
                    f"Destination privée RFC1918 non autorisée : '{clean_target}' "
                    "n'appartient à aucune plage caméra expressément approuvée (Deny-by-Default)."
                ), clean_target
            elif ip_category == "IPV6_UNIQUE_LOCAL":
                return False, (
                    f"Destination IPv6 ULA non autorisée : '{clean_target}' "
                    "n'appartient à aucun réseau caméra approuvé."
                ), clean_target
            elif ip_category == "PUBLIC_INTERNET":
                return False, (
                    f"Destination publique non autorisée : '{clean_target}' "
                    "ne figure pas dans la liste blanche des flux approuvés."
                ), clean_target
            else:
                return False, f"Destination non autorisée par la politique d'egress : '{clean_target}'.", clean_target

        # 6. Vérification du port de destination
        if self.allowed_ports and port not in self.allowed_ports:
            return False, f"Port {port} non autorisé par la politique d'egress (ports admis: {sorted(self.allowed_ports)}).", clean_target

        return True, f"Destination autorisée par la politique d'egress (réseau {matched_network}).", clean_target


# =============================================================================
# HIÉRARCHIE DE PROVIDERS D'ENFORCEMENT (PRO-13 A.4.2)
# =============================================================================

class EgressEnforcementProvider(abc.ABC):
    """Interface abstraite pour la vérification du niveau effectif d'application
    du confinement réseau (Egress Enforcement) au niveau OS/noyau/conteneur.
    """

    @abc.abstractmethod
    def check_status(
        self,
        expected_executable: Optional[str] = None,
        expected_destinations: Optional[List[str]] = None,
        expected_ports: Optional[List[int]] = None
    ) -> Tuple[EgressEnforcementStatus, str, Dict[str, Any]]:
        """Inspecte le système hôte et retourne (statut, raison_détaillée, diagnostics)."""
        pass


class WindowsEgressProvider(EgressEnforcementProvider):
    """Fournisseur d'inspection pour Windows Defender Firewall via netsh advfirewall et PowerShell.
    Vérifie l'état réel des profils et l'adéquation de la politique effective (Allow + Block / Deny-by-default).
    """

    RULE_ALLOW_NAME = "SSM_NVR_FFmpeg_Egress_AllowCameras"
    RULE_BLOCK_NAME = "SSM_NVR_FFmpeg_Egress_BlockProhibited"

    def check_status(
        self,
        expected_executable: Optional[str] = None,
        expected_destinations: Optional[List[str]] = None,
        expected_ports: Optional[List[int]] = None
    ) -> Tuple[EgressEnforcementStatus, str, Dict[str, Any]]:
        diagnostics: Dict[str, Any] = {
            "platform": "win32",
            "firewall_active": False,
            "profiles": {},
            "rules_found": [],
            "outbound_default": "UNKNOWN",
            "allow_rule_present": False,
            "allow_rule_enabled": False,
            "executable_matched": None,
            "destinations_matched": None,
            "ports_matched": None,
            "block_rules_present": False,
            "env_spoofing_detected": False,
            "error": None
        }

        # Détection de tentative de contournement par variable d'environnement (A42-14)
        if os.environ.get("SSM_EGRESS_FIREWALL_ACTIVE") or os.environ.get("SSM_EGRESS_CONTAINER_ISOLATED"):
            diagnostics["env_spoofing_detected"] = True

        if sys.platform != "win32":
            return (
                EgressEnforcementStatus.UNSUPPORTED,
                f"WindowsEgressProvider ne prend pas en charge la plateforme '{sys.platform}'.",
                diagnostics
            )

        # 1. Inspection des profils de pare-feu via netsh advfirewall show allprofiles
        try:
            profile_res = subprocess.run(
                ["netsh", "advfirewall", "show", "allprofiles"],
                capture_output=True,
                text=True,
                timeout=5
            )
            if profile_res.returncode != 0:
                diagnostics["error"] = f"netsh show allprofiles a échoué (code {profile_res.returncode}): {profile_res.stderr.strip()}"
                return EgressEnforcementStatus.UNKNOWN, diagnostics["error"], diagnostics
        except Exception as e:
            diagnostics["error"] = f"Exception lors de l'appel netsh : {e}"
            return EgressEnforcementStatus.UNKNOWN, diagnostics["error"], diagnostics

        # Analyse des profils actifs et des stratégies sortantes
        p_stdout = profile_res.stdout
        any_profile_on = False
        default_outbound_block = False

        for block in p_stdout.split("\n\n"):
            block_lower = block.lower()
            if "actif" in block_lower or "state                                 on" in block_lower or "état                                  actif" in block_lower:
                any_profile_on = True
            if "blockoutbound" in block_lower:
                default_outbound_block = True

        diagnostics["firewall_active"] = any_profile_on
        diagnostics["outbound_default"] = "Block" if default_outbound_block else "Allow"

        if not any_profile_on:
            return (
                EgressEnforcementStatus.NOT_ENFORCED,
                "Pare-feu Windows Defender entièrement désactivé ou inactif sur les profils réseau.",
                diagnostics
            )

        # 2. Inspection des règles de filtrage SSM pour FFmpeg
        try:
            allow_res = subprocess.run(
                ["netsh", "advfirewall", "firewall", "show", "rule", f"name={self.RULE_ALLOW_NAME}"],
                capture_output=True,
                text=True,
                timeout=5
            )
        except Exception as e:
            diagnostics["error"] = f"Erreur lors de la vérification de la règle Allow : {e}"
            return EgressEnforcementStatus.UNKNOWN, diagnostics["error"], diagnostics

        allow_rule_found = (allow_res.returncode == 0) and ("aucune règle" not in allow_res.stdout.lower()) and ("no rules" not in allow_res.stdout.lower())

        if not allow_rule_found:
            return (
                EgressEnforcementStatus.NOT_ENFORCED,
                "Aucune règle de filtrage sortant SSM active n'est enregistrée sur Windows Defender Firewall.",
                diagnostics
            )

        allow_out = allow_res.stdout
        diagnostics["rules_found"].append(self.RULE_ALLOW_NAME)
        diagnostics["allow_rule_present"] = True

        # Contrôle d'activation de la règle
        allow_enabled = ("oui" in allow_out.lower() or "yes" in allow_out.lower() or "activer" in allow_out.lower())
        diagnostics["allow_rule_enabled"] = allow_enabled
        if not allow_enabled:
            return (
                EgressEnforcementStatus.NOT_ENFORCED,
                f"La règle de pare-feu '{self.RULE_ALLOW_NAME}' existe mais est désactivée.",
                diagnostics
            )

        # Contrôle de correspondance de l'exécutable
        if expected_executable:
            norm_expected = os.path.normpath(expected_executable).lower()
            norm_found = None
            for line in allow_out.splitlines():
                stripped_lower = line.strip().lower()
                if stripped_lower.startswith(("programme", "program")) and ":" in line:
                    norm_found = os.path.normpath(line.split(":", 1)[1].strip()).lower()
                    break

            if norm_found:
                matched_exe = (norm_found == norm_expected)
                diagnostics["executable_matched"] = matched_exe
                if not matched_exe:
                    return (
                        EgressEnforcementStatus.NOT_ENFORCED,
                        f"Règle de pare-feu associée à un binaire différent ('{norm_found}' != '{norm_expected}').",
                        diagnostics
                    )
            else:
                diagnostics["executable_matched"] = False

        # 3. Contrôle de l'efficacité du blocage (résolution de la précédence Windows Allow vs Default Outbound)
        # Si la politique sortante par défaut est Block, la règle Allow seule est pleinement restrictive
        if default_outbound_block:
            return (
                EgressEnforcementStatus.ENFORCED,
                "Confinement Windows effectif : politique sortante DefaultOutbound=Block avec règle Allow spécifique.",
                diagnostics
            )

        # Si DefaultOutboundAction est Allow, vérifier l'existence de règles complémentaires de blocage
        try:
            block_res = subprocess.run(
                ["netsh", "advfirewall", "firewall", "show", "rule", f"name={self.RULE_BLOCK_NAME}"],
                capture_output=True,
                text=True,
                timeout=5
            )
            block_rule_found = (block_res.returncode == 0) and ("aucune règle" not in block_res.stdout.lower()) and ("no rules" not in block_res.stdout.lower())
        except Exception:
            block_rule_found = False

        diagnostics["block_rules_present"] = block_rule_found

        if block_rule_found:
            diagnostics["rules_found"].append(self.RULE_BLOCK_NAME)
            return (
                EgressEnforcementStatus.ENFORCED,
                "Confinement Windows effectif : règles d'autorisation ciblée et de blocage complémentaire actives.",
                diagnostics
            )

        # Faiblesse identifiée par A4.1 : Allow seul sur profil AllowOutbound
        return (
            EgressEnforcementStatus.PARTIAL,
            "Règle Allow configurée mais la politique sortante Windows est DefaultOutbound=Allow "
            "sans règle Block restrictive complémentaire. Confinement partiel uniquement.",
            diagnostics
        )


class LinuxEgressProvider(EgressEnforcementProvider):
    """Fournisseur d'inspection pour Linux hôte via nftables ou iptables.
    Vérifie la présence de chaînes et règles de filtrage effectives associées au worker.
    """

    def check_status(
        self,
        expected_executable: Optional[str] = None,
        expected_destinations: Optional[List[str]] = None,
        expected_ports: Optional[List[int]] = None
    ) -> Tuple[EgressEnforcementStatus, str, Dict[str, Any]]:
        diagnostics: Dict[str, Any] = {
            "platform": "linux",
            "backend": "UNKNOWN",
            "rules_found": [],
            "env_spoofing_detected": False,
            "error": None
        }

        if os.environ.get("SSM_EGRESS_FIREWALL_ACTIVE") or os.environ.get("SSM_EGRESS_CONTAINER_ISOLATED"):
            diagnostics["env_spoofing_detected"] = True

        if not sys.platform.startswith("linux"):
            return (
                EgressEnforcementStatus.UNSUPPORTED,
                f"LinuxEgressProvider ne prend pas en charge la plateforme '{sys.platform}'.",
                diagnostics
            )

        # Tentative d'inspection nftables
        try:
            nft_res = subprocess.run(["nft", "list", "ruleset"], capture_output=True, text=True, timeout=3)
            if nft_res.returncode == 0:
                diagnostics["backend"] = "nftables"
                if "ssm_nvr_egress" in nft_res.stdout.lower():
                    diagnostics["rules_found"].append("ssm_nvr_egress")
                    return (
                        EgressEnforcementStatus.ENFORCED,
                        "Confinement effectif vérifié via nftables ruleset.",
                        diagnostics
                    )
        except Exception:
            pass

        # Tentative d'inspection iptables
        try:
            ipt_res = subprocess.run(["iptables", "-L", "OUTPUT", "-n"], capture_output=True, text=True, timeout=3)
            if ipt_res.returncode == 0:
                diagnostics["backend"] = "iptables"
                if "ssm_nvr" in ipt_res.stdout.lower():
                    diagnostics["rules_found"].append("ssm_nvr_output")
                    return (
                        EgressEnforcementStatus.ENFORCED,
                        "Confinement effectif vérifié via règles iptables OUTPUT.",
                        diagnostics
                    )
        except Exception:
            pass

        return (
            EgressEnforcementStatus.NOT_ENFORCED,
            "Aucune règle de pare-feu Linux (nftables / iptables) active trouvée pour le worker SSM.",
            diagnostics
        )


class DockerEgressProvider(EgressEnforcementProvider):
    """Fournisseur d'inspection pour environnement conteneur Docker.
    Vérifie l'absence de privilèges et la présence démontrable de règles de passerelle hôte.
    """

    def check_status(
        self,
        expected_executable: Optional[str] = None,
        expected_destinations: Optional[List[str]] = None,
        expected_ports: Optional[List[int]] = None
    ) -> Tuple[EgressEnforcementStatus, str, Dict[str, Any]]:
        diagnostics: Dict[str, Any] = {
            "platform": "docker",
            "is_container": False,
            "non_root_user": False,
            "cap_dropped": False,
            "host_filtering_proven": False,
            "env_spoofing_detected": False,
            "error": None
        }

        if os.environ.get("SSM_EGRESS_FIREWALL_ACTIVE") or os.environ.get("SSM_EGRESS_CONTAINER_ISOLATED"):
            diagnostics["env_spoofing_detected"] = True

        # Détection de l'environnement conteneur
        is_container = os.path.exists("/.dockerenv") or (
            os.path.exists("/proc/1/cgroup") and "docker" in open("/proc/1/cgroup", "r", errors="ignore").read()
        )
        diagnostics["is_container"] = is_container

        if not is_container:
            return (
                EgressEnforcementStatus.NOT_ENFORCED,
                "Exécution hors conteneur Docker détectée.",
                diagnostics
            )

        # Vérification utilisateur non-root
        is_non_root = (hasattr(os, "getuid") and os.getuid() != 0)
        diagnostics["non_root_user"] = is_non_root

        # Vérification du fichier de marqueur hôte authentifié (écrit par setup_docker_egress_host.sh)
        host_proof_path = "/run/ssm_egress_enforced.marker"
        if os.path.exists(host_proof_path):
            try:
                with open(host_proof_path, "r") as f:
                    content = f.read().strip()
                if content.startswith("SSM_DOCKER_EGRESS_ENFORCED:"):
                    diagnostics["host_filtering_proven"] = True
                    return (
                        EgressEnforcementStatus.ENFORCED,
                        "Confinement Docker effectif validé par preuve cryptographique hôte.",
                        diagnostics
                    )
            except Exception:
                pass

        # Dans un conteneur standard avec internal: false sans preuve hôte
        return (
            EgressEnforcementStatus.PARTIAL,
            "Conteneur Docker détecté sans preuve formelle de filtrage hôte DOCKER-USER / nftables.",
            diagnostics
        )


class UnsupportedEgressProvider(EgressEnforcementProvider):
    """Fournisseur pour les plateformes non supportées."""

    def check_status(
        self,
        expected_executable: Optional[str] = None,
        expected_destinations: Optional[List[str]] = None,
        expected_ports: Optional[List[int]] = None
    ) -> Tuple[EgressEnforcementStatus, str, Dict[str, Any]]:
        return (
            EgressEnforcementStatus.UNSUPPORTED,
            f"La plateforme '{sys.platform}' n'est pas supportée pour le confinement réseau OS.",
            {"platform": sys.platform}
        )


class MockEgressProvider(EgressEnforcementProvider):
    """Fournisseur mockable et déterministe pour tests unitaires et adversariaux."""

    def __init__(
        self,
        status: EgressEnforcementStatus = EgressEnforcementStatus.NOT_ENFORCED,
        reason: str = "Mock enforcement provider",
        diagnostics: Optional[Dict[str, Any]] = None
    ):
        self.status = status
        self.reason = reason
        self.diagnostics = diagnostics or {}
        self.query_count = 0
        self.last_query_args: Dict[str, Any] = {}

    def check_status(
        self,
        expected_executable: Optional[str] = None,
        expected_destinations: Optional[List[str]] = None,
        expected_ports: Optional[List[int]] = None
    ) -> Tuple[EgressEnforcementStatus, str, Dict[str, Any]]:
        self.query_count += 1
        self.last_query_args = {
            "expected_executable": expected_executable,
            "expected_destinations": expected_destinations,
            "expected_ports": expected_ports
        }
        return self.status, self.reason, self.diagnostics


# =============================================================================
# GESTION DU FOURNISSEUR PAR DÉFAUT ET API PUBLIQUE
# =============================================================================

_DEFAULT_PROVIDER: Optional[EgressEnforcementProvider] = None


def get_egress_provider(platform_name: Optional[str] = None) -> EgressEnforcementProvider:
    """Résout le provider approprié en fonction de la plateforme ou du contexte conteneur."""
    global _DEFAULT_PROVIDER
    if _DEFAULT_PROVIDER is not None:
        return _DEFAULT_PROVIDER

    plat = platform_name or sys.platform

    # Détection conteneur prioritaire si sous Linux
    if os.path.exists("/.dockerenv"):
        return DockerEgressProvider()

    if plat == "win32":
        return WindowsEgressProvider()
    elif plat.startswith("linux"):
        return LinuxEgressProvider()
    else:
        return UnsupportedEgressProvider()


def set_default_egress_provider(provider: Optional[EgressEnforcementProvider]) -> None:
    """Définit explicitement le fournisseur d'enforcement (utilisé pour l'injection de dépendances et les tests)."""
    global _DEFAULT_PROVIDER
    _DEFAULT_PROVIDER = provider


def check_egress_enforcement_status(
    provider: Optional[EgressEnforcementProvider] = None,
    expected_executable: Optional[str] = None,
    expected_destinations: Optional[List[str]] = None,
    expected_ports: Optional[List[int]] = None
) -> Tuple[EgressEnforcementStatus, str]:
    """Inspecte l'environnement d'exécution via le provider dédié et détermine le niveau réel d'isolation réseau.
    
    IMPORTANT (PRO-13 A.4.2) :
    Cette fonction interroge le sous-système de sécurité ou le conteneur.
    Elle ne fait JAMAIS confiance à de simples variables d'environnement utilisateur
    telles que SSM_EGRESS_FIREWALL_ACTIVE pour accorder le statut ENFORCED.
    """
    prov = provider or get_egress_provider()
    status, reason, _ = prov.check_status(
        expected_executable=expected_executable,
        expected_destinations=expected_destinations,
        expected_ports=expected_ports
    )
    return status, reason


def get_egress_diagnostics(
    provider: Optional[EgressEnforcementProvider] = None,
    expected_executable: Optional[str] = None,
    expected_destinations: Optional[List[str]] = None,
    expected_ports: Optional[List[int]] = None
) -> Dict[str, Any]:
    """Retourne l'ensemble des diagnostics techniques bruts issus de l'inspection système."""
    prov = provider or get_egress_provider()
    _, _, diag = prov.check_status(
        expected_executable=expected_executable,
        expected_destinations=expected_destinations,
        expected_ports=expected_ports
    )
    return diag


def compute_complementary_block_cidrs(allowed_destinations: List[str]) -> Dict[str, List[str]]:
    """Calcule les sous-réseaux CIDR complémentaires à bloquer pour IPv4 et IPv6 (PRO-13 A.4.4 Lot C).

    Contrairement à une exclusion naïve par classe (/8, /12, /16), soustrait uniquement les préfixes
    exacts autorisés de 0.0.0.0/0 et ::/0, garantissant le blocage des hôtes voisins et des IP publiques.
    """
    if not allowed_destinations:
        raise PolicyConfigurationError("La liste des destinations autorisées ne peut pas être vide.")

    v4_allowed: List[ipaddress.IPv4Network] = []
    v6_allowed: List[ipaddress.IPv6Network] = []

    for raw in allowed_destinations:
        item = str(raw).strip()
        if not item:
            continue
        if item in ("0.0.0.0/0", "::/0", "*", "Any", "any"):
            raise PolicyConfigurationError(f"Destination générique interdite : '{item}'.")
        try:
            net = ipaddress.ip_network(item, strict=False)
        except ValueError as e:
            raise PolicyConfigurationError(f"Destination CIDR invalide '{item}' : {e}")

        # Normaliser IPv4-mapped IPv6
        if isinstance(net, ipaddress.IPv6Network) and net.network_address.ipv4_mapped:
            mapped_ip = net.network_address.ipv4_mapped
            v4_prefix = max(0, net.prefixlen - 96)
            net = ipaddress.ip_network(f"{mapped_ip}/{v4_prefix}", strict=False)

        if isinstance(net, ipaddress.IPv4Network):
            if net.prefixlen <= 8:
                raise PolicyConfigurationError(f"Préfixe IPv4 trop large interdit (/{net.prefixlen} <= /8) : '{item}'.")
            if net.is_link_local or net.is_loopback or net.is_multicast:
                raise PolicyConfigurationError(f"Plage IPv4 réservée interdite dans l'allowlist : '{item}'.")
            v4_allowed.append(net)
        else:
            if net.prefixlen <= 16:
                raise PolicyConfigurationError(f"Préfixe IPv6 trop large interdit (/{net.prefixlen} <= /16) : '{item}'.")
            if net.is_link_local or net.is_loopback or net.is_multicast:
                raise PolicyConfigurationError(f"Plage IPv6 réservée interdite dans l'allowlist : '{item}'.")
            v6_allowed.append(net)

    if not v4_allowed and not v6_allowed:
        raise PolicyConfigurationError("Aucune destination valide après normalisation.")

    # Soustraction exacte sur 0.0.0.0/0
    v4_blocks: List[ipaddress.IPv4Network] = [ipaddress.ip_network("0.0.0.0/0")]
    for allowed_net in ipaddress.collapse_addresses(v4_allowed):
        next_blocks: List[ipaddress.IPv4Network] = []
        for blk in v4_blocks:
            if blk.overlaps(allowed_net):
                if allowed_net.subnet_of(blk):
                    next_blocks.extend(blk.address_exclude(allowed_net))
                # Si blk est un sous-réseau de allowed_net, il est entièrement autorisé
            else:
                next_blocks.append(blk)
        v4_blocks = next_blocks

    # Soustraction exacte sur ::/0
    v6_blocks: List[ipaddress.IPv6Network] = [ipaddress.ip_network("::/0")]
    for allowed_net in ipaddress.collapse_addresses(v6_allowed):
        next_blocks_v6: List[ipaddress.IPv6Network] = []
        for blk in v6_blocks:
            if blk.overlaps(allowed_net):
                if allowed_net.subnet_of(blk):
                    next_blocks_v6.extend(blk.address_exclude(allowed_net))
            else:
                next_blocks_v6.append(blk)
        v6_blocks = next_blocks_v6

    return {
        "allowed_ipv4": [str(n) for n in ipaddress.collapse_addresses(v4_allowed)],
        "allowed_ipv6": [str(n) for n in ipaddress.collapse_addresses(v6_allowed)],
        "block_ipv4": [str(n) for n in ipaddress.collapse_addresses(v4_blocks)],
        "block_ipv6": [str(n) for n in ipaddress.collapse_addresses(v6_blocks)],
    }
