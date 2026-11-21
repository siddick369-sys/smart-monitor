"""
Module d'Authentification TOTP à Deux Facteurs (RFC 6238).
Compatible avec Google Authenticator, Aegis, 1Password, Microsoft Authenticator.
Ne requiert aucune bibliothèque externe (implémentation pure Python standard + QR code optionnel).
"""

import hmac
import hashlib
import struct
import time
import base64
import os
import io
import re
from typing import Tuple, List, Optional, Dict, Any

try:
    import qrcode
    HAS_QRCODE = True
except ImportError:
    qrcode = None
    HAS_QRCODE = False

import config

class TOTPManager:
    """Gestionnaire TOTP RFC 6238 avec fenêtrage temporel et protection anti-rejeu."""

    def __init__(self, issuer: str = config.TOTP_ISSUER, time_step: int = 30, digits: int = 6):
        self.issuer = issuer
        self.time_step = max(10, time_step)
        self.digits = digits

    @staticmethod
    def generate_secret(byte_length: int = 20) -> str:
        """Génère un secret aléatoire cryptographiquement sûr encodé en Base32 (160 bits recommandé)."""
        random_bytes = os.urandom(byte_length)
        return base64.b32encode(random_bytes).decode('ascii').rstrip('=')

    def get_time_counter(self, timestamp: Optional[float] = None) -> int:
        """Calcule le compteur de pas de temps actuel."""
        t = timestamp if timestamp is not None else time.time()
        return int(t // self.time_step)

    def generate_token(self, secret_b32: str, counter: Optional[int] = None) -> str:
        """Calcule le code TOTP à 6 chiffres pour un pas de temps donné (RFC 6238 / RFC 4226)."""
        if counter is None:
            counter = self.get_time_counter()

        # Normaliser le Base32 avec padding nécessaire
        secret_clean = secret_b32.strip().replace(" ", "").upper()
        padding_needed = (8 - len(secret_clean) % 8) % 8
        secret_padded = secret_clean + ("=" * padding_needed)

        try:
            key = base64.b32decode(secret_padded, casefold=True)
        except Exception as e:
            raise ValueError(f"Secret Base32 invalide : {e}")

        # Encodage du compteur sur 8 octets gros-boutiste (Big Endian)
        msg = struct.pack(">Q", counter)

        # HMAC-SHA1
        h = hmac.new(key, msg, hashlib.sha1).digest()

        # Tronquage dynamique (Dynamic Truncation)
        offset = h[-1] & 0x0F
        binary_code = struct.unpack(">I", h[offset:offset+4])[0] & 0x7FFFFFFF

        # Réduction au nombre de chiffres souhaité
        token_int = binary_code % (10 ** self.digits)
        return f"{token_int:0{self.digits}d}"

    def verify_token(self,
                     secret_b32: str,
                     token_candidate: str,
                     last_counter: Optional[int] = None,
                     window: int = 1) -> Tuple[bool, Optional[int]]:
        """
        Vérifie la validité d'un code TOTP avec tolérance d'horloge (+/- 1 pas)
        et protection stricte contre le rejeu (interdiction d'utiliser le même pas de temps).
        """
        if not token_candidate or not secret_b32:
            return False, None

        # Nettoyage du code saisi (suppression des espaces ou tirets)
        token_clean = re.sub(r"\D", "", token_candidate)
        if len(token_clean) != self.digits:
            return False, None

        current_counter = self.get_time_counter()

        # Fenêtre temporelle d'acceptation [current - window, current + window]
        for offset in range(-window, window + 1):
            check_counter = current_counter + offset

            # Règle anti-rejeu : le code ne peut pas provenir d'un pas déjà consommé
            if last_counter is not None and check_counter <= last_counter:
                continue

            try:
                expected_token = self.generate_token(secret_b32, check_counter)
                if hmac.compare_digest(expected_token, token_clean):
                    return True, check_counter
            except Exception:
                continue

        return False, None

    def get_provisioning_uri(self, secret_b32: str, username: str) -> str:
        """Génère l'URI standard otpauth:// pour enrôlement dans les apps mobiles."""
        from urllib.parse import quote
        safe_issuer = quote(self.issuer)
        safe_user = quote(username)
        return f"otpauth://totp/{safe_issuer}:{safe_user}?secret={secret_b32}&issuer={safe_issuer}&algorithm=SHA1&digits={self.digits}&period={self.time_step}"

    def generate_qr_code_data_uri(self, provisioning_uri: str) -> Optional[str]:
        """Génère un data URI base64 PNG du QR Code d'enrôlement."""
        if not HAS_QRCODE:
            return None

        try:
            qr = qrcode.QRCode(box_size=4, border=2)
            qr.add_data(provisioning_uri)
            qr.make(fit=True)
            img = qr.make_image(fill_color="black", back_color="white")
            buf = io.BytesIO()
            img.save(buf, format="PNG")
            b64_img = base64.b64encode(buf.getvalue()).decode("ascii")
            return f"data:image/png;base64,{b64_img}"
        except Exception:
            return None

    @staticmethod
    def generate_recovery_codes(count: int = 8) -> Tuple[List[str], List[str]]:
        """
        Génère un lot de codes de récupération d'urgence à usage unique.
        Retourne : (codes_en_clair_pour_l_utilisateur, codes_haches_pour_le_stockage)
        """
        plain_codes = []
        hashed_codes = []

        for _ in range(count):
            # Format lisible : xxxx-xxxx (8 caractères hexadécimaux avec tiret)
            token = os.urandom(4).hex()
            formatted = f"{token[:4]}-{token[4:]}".upper()
            plain_codes.append(formatted)

            # Hachage sécurisé pour stockage au repos
            h = hashlib.sha256(formatted.encode("utf-8")).hexdigest()
            hashed_codes.append(h)

        return plain_codes, hashed_codes

    @staticmethod
    def verify_recovery_code(candidate_code: str, hashed_codes: List[str]) -> Tuple[bool, List[str]]:
        """
        Vérifie et consomme un code de secours à usage unique.
        Retourne (succès, liste_mise_a_jour_sans_le_code_utilise).
        """
        if not candidate_code or not hashed_codes:
            return False, hashed_codes

        norm_code = candidate_code.strip().upper()
        cand_hash = hashlib.sha256(norm_code.encode("utf-8")).hexdigest()

        for idx, stored_hash in enumerate(hashed_codes):
            if hmac.compare_digest(cand_hash, stored_hash):
                # Code valide consommé : retrait de la liste
                remaining = [h for i, h in enumerate(hashed_codes) if i != idx]
                return True, remaining

        return False, hashed_codes
