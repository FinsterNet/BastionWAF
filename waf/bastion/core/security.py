"""
Bastion WAF Cryptographic Security & Authentication Core.
Provides Argon2 / scrypt password hashing, constant-time verification,
dummy timing equalization, RFC 6238 TOTP 2FA, and session token hashing.
"""

import base64
import hashlib
import hmac
import os
from pathlib import Path
import re
import secrets
import struct
import time
from typing import List, Optional, Tuple

# Master secret key for encrypting secrets (TOTP keys, etc.)
# Loaded from environment variable or persisted in a local secure keyfile
KEY_FILE = Path(__file__).resolve().parent.parent.parent / "config" / ".secret_key"


def get_master_key() -> bytes:
    """Retrieve or generate persistent 32-byte master key."""
    env_key = os.environ.get("BASTION_SECRET_KEY")
    if env_key:
        return hashlib.sha256(env_key.encode("utf-8")).digest()

    if KEY_FILE.exists():
        try:
            return bytes.fromhex(KEY_FILE.read_text().strip())
        except Exception:
            pass

    KEY_FILE.parent.mkdir(parents=True, exist_ok=True)
    new_key = secrets.token_bytes(32)
    try:
        KEY_FILE.write_text(new_key.hex())
        os.chmod(str(KEY_FILE), 0o600)
    except Exception:
        pass
    return new_key


# Check for optional argon2-cffi
HAS_ARGON2 = False
_argon2_hasher = None
try:
    from argon2 import PasswordHasher
    from argon2.exceptions import VerifyMismatchError

    # OWASP baseline: ~19 MiB memory, 2 iterations, 1 parallelism
    _argon2_hasher = PasswordHasher(time_cost=2, memory_cost=19456, parallelism=1)
    HAS_ARGON2 = True
except ImportError:
    HAS_ARGON2 = False


# Common breached and trivial passwords to reject
COMMON_PASSWORDS = {
    "password", "password123", "password1234", "123456789012",
    "admin123456", "admin12345678", "administrator", "bastion123456",
    "qwertyuiop12", "welcome12345", "letmein12345", "changeme12345",
}


def validate_password_strength(password: str) -> Tuple[bool, Optional[str]]:
    """Enforce NIST/OWASP password baseline: 12-128 chars, non-trivial."""
    if len(password) < 12:
        return False, "Password must be at least 12 characters long"
    if len(password) > 128:
        return False, "Password must not exceed 128 characters"
    if password.lower() in COMMON_PASSWORDS or password.lower().startswith("password"):
        return False, "Password is too common or easily guessable"
    return True, None


def hash_password(password: str) -> str:
    """Hash password using Argon2id if installed, otherwise memory-hard scrypt."""
    if HAS_ARGON2 and _argon2_hasher:
        return _argon2_hasher.hash(password)

    # Scrypt baseline: 32-byte salt, N=131072 (2^17), r=8, p=1 (~128MB memory-hard)
    salt = secrets.token_bytes(32)
    derived = hashlib.scrypt(
        password.encode("utf-8"),
        salt=salt,
        n=131072,
        r=8,
        p=1,
        maxmem=512 * 1024 * 1024,
    )
    return f"scrypt$131072$8$1${salt.hex()}${derived.hex()}"


# Pre-computed dummy hash to equalize timing on non-existent accounts
DUMMY_HASH = hash_password("bastion_dummy_timing_stabilizer_password_987654321")


def verify_password(password: str, stored_hash: str) -> bool:
    """Verify password against stored hash with constant-time protection."""
    if not stored_hash:
        return False

    if stored_hash.startswith("$argon2"):
        if HAS_ARGON2 and _argon2_hasher:
            try:
                return _argon2_hasher.verify(stored_hash, password)
            except Exception:
                return False
        return False

    if stored_hash.startswith("scrypt$"):
        try:
            parts = stored_hash.split("$")
            if len(parts) != 6:
                return False
            _, n_str, r_str, p_str, salt_hex, hash_hex = parts
            n = int(n_str)
            r = int(r_str)
            p = int(p_str)
            salt = bytes.fromhex(salt_hex)
            expected = bytes.fromhex(hash_hex)

            computed = hashlib.scrypt(
                password.encode("utf-8"),
                salt=salt,
                n=n,
                r=r,
                p=p,
                maxmem=512 * 1024 * 1024,
            )
            return secrets.compare_digest(computed, expected)
        except Exception:
            return False

    return False


def dummy_verify_password(password: str):
    """Execute constant-time dummy verification when user is not found."""
    verify_password(password, DUMMY_HASH)


# ============================================================
# Token Management (Sessions, Password Resets, CSRF)
# ============================================================

def generate_secure_token(num_bytes: int = 32) -> str:
    """Generate high-entropy random URL-safe token."""
    return secrets.token_urlsafe(num_bytes)


def hash_token(raw_token: str) -> str:
    """Hash random token with SHA-256 for secure storage."""
    return hashlib.sha256(raw_token.encode("utf-8")).hexdigest()


def generate_csrf_token(user_id: int, session_id: int) -> str:
    """Generate cryptographic session-bound CSRF synchronizer token."""
    key = get_master_key()
    message = f"csrf:{user_id}:{session_id}".encode("utf-8")
    sig = hmac.new(key, message, hashlib.sha256).hexdigest()
    return f"{user_id}:{session_id}:{sig[:32]}"


def verify_csrf_token(token: str, user_id: int, session_id: int) -> bool:
    """Verify synchronizer CSRF token matches current session."""
    if not token:
        return False
    expected = generate_csrf_token(user_id, session_id)
    return secrets.compare_digest(token, expected)


# ============================================================
# TOTP 2FA (RFC 6238 Pure Python Implementation)
# ============================================================

def generate_totp_secret() -> str:
    """Generate RFC 6238 compatible 160-bit Base32 secret."""
    random_bytes = secrets.token_bytes(20)
    return base64.b32encode(random_bytes).decode("utf-8").replace("=", "")


def encrypt_totp_secret(secret: str) -> str:
    """Encrypt TOTP secret using Master Key with HMAC verification."""
    key = get_master_key()
    iv = secrets.token_bytes(16)
    # Simple XOR-stream with SHA-256 KDF for portability
    derived_enc_key = hashlib.sha256(key + b":enc:" + iv).digest()
    derived_mac_key = hashlib.sha256(key + b":mac:" + iv).digest()

    raw_data = secret.encode("utf-8")
    encrypted_bytes = bytes(b ^ derived_enc_key[i % len(derived_enc_key)] for i, b in enumerate(raw_data))

    mac = hmac.new(derived_mac_key, iv + encrypted_bytes, hashlib.sha256).digest()
    combined = iv + mac + encrypted_bytes
    return base64.b64encode(combined).decode("utf-8")


def decrypt_totp_secret(encrypted_b64: str) -> Optional[str]:
    """Decrypt TOTP secret and verify integrity."""
    try:
        combined = base64.b64decode(encrypted_b64)
        if len(combined) < 48:
            return None
        iv = combined[:16]
        mac = combined[16:48]
        encrypted_bytes = combined[48:]

        key = get_master_key()
        derived_enc_key = hashlib.sha256(key + b":enc:" + iv).digest()
        derived_mac_key = hashlib.sha256(key + b":mac:" + iv).digest()

        expected_mac = hmac.new(derived_mac_key, iv + encrypted_bytes, hashlib.sha256).digest()
        if not secrets.compare_digest(mac, expected_mac):
            return None

        decrypted = bytes(b ^ derived_enc_key[i % len(derived_enc_key)] for i, b in enumerate(encrypted_bytes))
        return decrypted.decode("utf-8")
    except Exception:
        return None


def compute_totp_code(secret: str, time_step: Optional[int] = None) -> str:
    """Compute 6-digit TOTP code for secret at given time step (default current)."""
    if time_step is None:
        time_step = int(time.time() // 30)

    # Decode base32 secret with proper padding
    cleaned = secret.strip().replace(" ", "").upper()
    padding = "=" * ((8 - len(cleaned) % 8) % 8)
    key_bytes = base64.b32decode(cleaned + padding, casefold=True)

    # 8-byte big-endian time counter
    msg = struct.pack(">Q", time_step)
    h = hmac.new(key_bytes, msg, hashlib.sha1).digest()

    offset = h[-1] & 0x0F
    code_int = struct.unpack(">I", h[offset:offset + 4])[0] & 0x7FFFFFFF
    code = code_int % 1000000
    return f"{code:06d}"


def verify_totp_code(secret: str, user_code: str, window: int = 1) -> bool:
    """Verify 6-digit TOTP code within ±window time steps (covers ±30s clock drift)."""
    if not user_code or len(user_code.strip()) != 6:
        return False
    clean_code = user_code.strip()
    current_step = int(time.time() // 30)

    for step_offset in range(-window, window + 1):
        target_step = current_step + step_offset
        expected = compute_totp_code(secret, target_step)
        if secrets.compare_digest(clean_code, expected):
            return True
    return False


def get_totp_uri(email: str, secret: str, issuer: str = "BastionWAF") -> str:
    """Generate standard otpauth URI for authenticator apps."""
    clean_email = email.strip()
    return f"otpauth://totp/{issuer}:{clean_email}?secret={secret}&issuer={issuer}&algorithm=SHA1&digits=6&period=30"


# ============================================================
# Recovery Codes
# ============================================================

def generate_recovery_codes(count: int = 10) -> List[str]:
    """Generate human-readable 8-character recovery codes (e.g., 'a1b2-c3d4')."""
    codes = []
    for _ in range(count):
        part1 = secrets.token_hex(2)
        part2 = secrets.token_hex(2)
        codes.append(f"{part1}-{part2}")
    return codes
