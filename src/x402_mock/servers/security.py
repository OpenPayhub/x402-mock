import base64
import json
import hmac
import hashlib
import secrets
import time
from typing import Dict, Optional
import string
import os

from fastapi import Header, HTTPException, status

from ..engine.exceptions import InvalidTokenError, TokenExpiredError


def _b64encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("utf-8")


def _b64decode(data: str) -> bytes:
    padding = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + padding)


def create_private_key(
    *,
    prefix: str = "",
    length: int = 32,
    use_special_chars: bool = False
) -> str:
    """
    Generate a private key with optional prefix and randomization rules.

    Args:
        prefix: A custom string to prepend to the random key (semi-automatic rule).
        length: The number of random characters to generate.
        use_special_chars: Whether to include special characters in the random part.

    Returns:
        A secure private key string.
    """
    alphabet = string.ascii_letters + string.digits
    if use_special_chars:
        alphabet += "!@#$%^&*()_+-="

    random_part = ''.join(secrets.choice(alphabet) for _ in range(length))
    return f"{prefix}{random_part}"


def save_key_to_env(key_name: str, key_value: str, env_file: str = ".env"):
    """
    Save or update a key-value pair in a .env file.

    Args:
        key_name: The environment variable name (e.g., "PRIVATE_KEY").
        key_value: The actual key string to save.
        env_file: Path to the .env file. Defaults to ".env".
    """
    lines = []
    found = False
    new_line = f"{key_name}={key_value}\n"

    # Read existing content if file exists
    if os.path.exists(env_file):
        with open(env_file, "r", encoding="utf-8") as f:
            lines = f.readlines()

    # Update the line if key_name already exists
    for i, line in enumerate(lines):
        if line.startswith(f"{key_name}="):
            lines[i] = new_line
            found = True
            break

    # If key_name not found, append it
    if not found:
        # Ensure the file ends with a newline before appending
        if lines and not lines[-1].endswith("\n"):
            lines[-1] += "\n"
        lines.append(new_line)

    # Write back to the file
    with open(env_file, "w", encoding="utf-8") as f:
        f.writelines(lines)


def generate_token(
    *,
    private_key: str,
    expires_in: int = 3600,
    nonce_length: int = 16,
) -> str:
    """
    Generate a signed token.

    Args:
        private_key: Secret key used to sign the token.
        expires_in: Token lifetime in seconds.
        nonce_length: Length of random nonce.

    Returns:
        Signed token string.
    """
    now = int(time.time())

    payload: Dict[str, object] = {
        "iat": now,
        "exp": now + expires_in,
        "nonce": secrets.token_urlsafe(nonce_length),
    }

    payload_json = json.dumps(payload, separators=(",", ":"), sort_keys=True)
    payload_b64 = _b64encode(payload_json.encode())

    signature = hmac.new(
        key=private_key.encode(),
        msg=payload_b64.encode(),
        digestmod=hashlib.sha256,
    ).digest()

    signature_b64 = _b64encode(signature)

    return f"{payload_b64}.{signature_b64}"


def verify_token(
    *,
    token: str,
    private_key: str,
    leeway: int = 0,
) -> Dict[str, object]:
    """
    Verify token signature and expiration.

    Args:
        token: Token string.
        private_key: Secret key used to verify the token.
        leeway: Allowed clock skew in seconds.

    Returns:
        Decoded payload if valid.

    Raises:
        TokenExpired: If token is expired.
        TokenInvalid: If token is malformed or signature mismatch.
    """
    try:
        payload_b64, signature_b64 = token.split(".")
    except ValueError:
        raise InvalidTokenError("Invalid token format")

    expected_sig = hmac.new(
        key=private_key.encode(),
        msg=payload_b64.encode(),
        digestmod=hashlib.sha256,
    ).digest()

    actual_sig = _b64decode(signature_b64)

    if not hmac.compare_digest(expected_sig, actual_sig):
        raise InvalidTokenError("Signature verification failed")

    payload_json = _b64decode(payload_b64)
    payload = json.loads(payload_json)

    now = int(time.time())

    if now > payload["exp"] + leeway:
        raise TokenExpiredError("Token has expired")

    return payload


