"""
Tests des remédiations Egress Windows, CIDR IPv4/IPv6, proxy et Docker (PRO-13-A.4.4 Lots C & D).
Aucune règle pare-feu système réelle n'est modifiée ni Docker démarré.
"""

import os
import ipaddress
import subprocess
import pytest

from monitoring.acquisition.egress_policy import (
    compute_complementary_block_cidrs,
    PolicyConfigurationError,
)
from monitoring.acquisition.ffmpeg_adapter import FFmpegRTSPAdapter


def _is_ip_blocked(ip_str: str, block_cidrs: list) -> bool:
    ip_obj = ipaddress.ip_address(ip_str)
    for cidr in block_cidrs:
        if ip_obj in ipaddress.ip_network(cidr):
            return True
    return False


def test_a44_egress_01_single_ipv4_blocks_neighbors_and_public():
    """Une caméra 192.168.1.50/32 autorisée bloque tout le reste de 192.168.0.0/16 et Internet public."""
    res = compute_complementary_block_cidrs(["192.168.1.50/32"])
    assert res["allowed_ipv4"] == ["192.168.1.50/32"]
    blk4 = res["block_ipv4"]
    blk6 = res["block_ipv6"]

    # Caméra autorisée non bloquée
    assert not _is_ip_blocked("192.168.1.50", blk4)
    # Hôte voisin dans le MÊME /16 et même /24 bloqué !
    assert _is_ip_blocked("192.168.1.51", blk4)
    assert _is_ip_blocked("192.168.1.1", blk4)
    assert _is_ip_blocked("192.168.2.10", blk4)
    # Autres RFC1918, metadata, loopback, public IPv4 bloqués
    assert _is_ip_blocked("10.0.0.5", blk4)
    assert _is_ip_blocked("172.16.0.10", blk4)
    assert _is_ip_blocked("169.254.169.254", blk4)
    assert _is_ip_blocked("127.0.0.1", blk4)
    assert _is_ip_blocked("8.8.8.8", blk4)
    # IPv6 non autorisé entièrement bloqué
    assert _is_ip_blocked("::1", blk6)
    assert _is_ip_blocked("2001:4860:4860::8888", blk6)


def test_a44_egress_02_multiple_subnets_and_ipv6_ula():
    """Plusieurs caméras IPv4 dans des sous-réseaux distincts + caméra IPv6 ULA."""
    res = compute_complementary_block_cidrs(["192.168.1.50/32", "10.20.30.40/32", "fd00:10::50/128"])
    assert not _is_ip_blocked("192.168.1.50", res["block_ipv4"])
    assert not _is_ip_blocked("10.20.30.40", res["block_ipv4"])
    assert _is_ip_blocked("10.20.30.41", res["block_ipv4"])
    assert not _is_ip_blocked("fd00:10::50", res["block_ipv6"])
    assert _is_ip_blocked("fd00:10::51", res["block_ipv6"])


def test_a44_egress_03_reject_wide_and_reserved_prefixes():
    """Refuse les /8, /16 IPv6, 0.0.0.0/0, link-local, loopback et multicast."""
    for bad in ("10.0.0.0/8", "0.0.0.0/0", "::/0", "169.254.169.254/32", "fe80::1/128", "127.0.0.1/32", "224.0.0.1/32"):
        with pytest.raises(PolicyConfigurationError):
            compute_complementary_block_cidrs([bad])


def test_a44_egress_04_ipv4_mapped_ipv6_normalized():
    """Normalise ::ffff:192.168.1.50 en 192.168.1.50/32."""
    res = compute_complementary_block_cidrs(["::ffff:192.168.1.50/128"])
    assert res["allowed_ipv4"] == ["192.168.1.50/32"]
    assert not _is_ip_blocked("192.168.1.50", res["block_ipv4"])
    assert _is_ip_blocked("192.168.1.51", res["block_ipv4"])


def test_a44_egress_05_ffmpeg_sanitized_env_strips_proxies(monkeypatch):
    """Vérifie que l'environnement enfant FFmpeg supprime toutes les variables proxy."""
    for k in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"):
        monkeypatch.setenv(k, "http://proxy.evil.local:8080")
    clean_env = FFmpegRTSPAdapter._build_sanitized_subprocess_env()
    for k in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"):
        assert k not in clean_env


def test_a44_egress_06_check_script_tokens_and_readonly_execution():
    """Vérifie les jetons diagnostiques dans check_ffmpeg_egress_firewall.ps1 et son exécution non destructive."""
    base = os.path.dirname(os.path.dirname(__file__))
    check_ps = open(os.path.join(base, "scripts", "check_ffmpeg_egress_firewall.ps1"), encoding="utf-8").read()
    for token in (
        "RULES_PRESENT", "RULES_DISABLED", "PROFILE_DISABLED",
        "DEFAULT_OUTBOUND_ALLOW", "DEFAULT_OUTBOUND_BLOCK",
        "ALLOWLIST_INCOMPLETE", "IPV4_COVERAGE_INCOMPLETE", "IPV6_COVERAGE_INCOMPLETE",
        "EXECUTABLE_SCOPE_INCOMPLETE", "PROXY_CONFIGURATION_UNSAFE",
        "WINDOWS_EGRESS_NOT_ENFORCED", "WINDOWS_EGRESS_ENFORCED"
    ):
        assert token in check_ps

    # Exécution non destructive sur l'hôte
    proc = subprocess.run(
        ["powershell", "-ExecutionPolicy", "Bypass", "-File", os.path.join(base, "scripts", "check_ffmpeg_egress_firewall.ps1")],
        capture_output=True, text=True, timeout=15
    )
    assert "WINDOWS_EGRESS_NOT_ENFORCED" in proc.stdout
    assert "WINDOWS_EGRESS_ENFORCED" not in proc.stdout


def test_a44_egress_07_docker_script_ipv6_and_idempotence():
    """Vérifie que setup_docker_egress_host.sh inclut IPv6 nftables et une purge idempotente."""
    base = os.path.dirname(os.path.dirname(__file__))
    sh = open(os.path.join(base, "scripts", "setup_docker_egress_host.sh"), encoding="utf-8").read()
    assert "SSM_DOCKER_EGRESS" in sh
    assert "ip6 daddr fe80::/10 drop" in sh
    assert "ip6 daddr ::1/128 drop" in sh
    assert "ip6 saddr fc00::/7" in sh
    assert "nft delete table inet ssm_nvr_egress" in sh
