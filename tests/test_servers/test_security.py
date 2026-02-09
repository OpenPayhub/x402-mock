import pytest
from x402_mock.servers import security
import time
from x402_mock.engine.exceptions import InvalidTokenError, TokenExpiredError

def test_create_private_key():
    """Test private key generation with different parameters."""
    # Test default key
    key = security.create_private_key()
    assert len(key) == 32
    assert all(c in security.string.ascii_letters + security.string.digits for c in key)

    # Test custom length
    key = security.create_private_key(length=16)
    assert len(key) == 16

    # Test prefix
    key = security.create_private_key(prefix="test_")
    assert key.startswith("test_")
    assert len(key) == len("test_") + 32

    # Test special characters
    key = security.create_private_key(use_special_chars=True)
    special_chars = "!@#$%^&*()_+-="
    assert any(c in special_chars for c in key)


def test_generate_token():
    """Test token generation."""
    private_key = security.create_private_key()
    token = security.generate_token(private_key=private_key)
    
    # Basic token structure
    assert len(token.split(".")) == 2  # payload.signature
    
    # Test expiration
    token = security.generate_token(private_key=private_key, expires_in=1)
    security.verify_token(token=token, private_key=private_key)
    time.sleep(2)  # Wait for token to expire
    with pytest.raises(TokenExpiredError):
        security.verify_token(token=token, private_key=private_key)


def test_verify_token():
    """Test token verification."""
    private_key = security.create_private_key()
    token = security.generate_token(private_key=private_key)
    
    # Valid token
    payload = security.verify_token(token=token, private_key=private_key)
    assert "iat" in payload
    assert "exp" in payload
    assert "nonce" in payload
    
    # Invalid signature
    payload_b64, _ = token.split(".")
    bad_token = f"{payload_b64}.YmFkX3NpZ25hdHVyZQ=="
    with pytest.raises(InvalidTokenError):
        security.verify_token(token=bad_token, private_key=private_key)
    
    # Invalid format
    with pytest.raises(InvalidTokenError):
        security.verify_token(token="invalid_token", private_key=private_key)


def test_token_expiration():
    """Test token expiration with leeway."""
    private_key = security.create_private_key()
    
    # Generate token with 1s expiration
    token = security.generate_token(private_key=private_key, expires_in=1)
    
    # Test immediate verification
    security.verify_token(token=token, private_key=private_key)
    
    # Wait longer than expiration
    time.sleep(2)
    with pytest.raises(TokenExpiredError):
        security.verify_token(token=token, private_key=private_key)
    
    # Test with leeway
    time.sleep(1)
    with pytest.raises(TokenExpiredError):
        security.verify_token(token=token, private_key=private_key, leeway=1)


def test_hmac_comparison():
    """Test constant-time comparison."""
    private_key = security.create_private_key()
    token1 = security.generate_token(private_key=private_key)
    token2 = security.generate_token(private_key=private_key)
    
    # Split tokens
    payload_b64_1, signature_b64_1 = token1.split(".")
    payload_b64_2, signature_b64_2 = token2.split(".")
    
    # Valid comparison
    expected_sig = security.hmac.new(
        key=private_key.encode(),
        msg=payload_b64_1.encode(),
        digestmod=security.hashlib.sha256
    ).digest()
    assert security.hmac.compare_digest(expected_sig, security._b64decode(signature_b64_1))
    
    # Invalid comparison
    assert not security.hmac.compare_digest(expected_sig, security._b64decode(signature_b64_2))


def test_b64_encode_decode():
    """Test base64 encoding/decoding."""
    data = b"test_data"
    encoded = security._b64encode(data)
    decoded = security._b64decode(encoded)
    assert decoded == data
    
    # Test padding handling
    padded = security._b64encode(data) + "=="  # Add padding
    decoded_padded = security._b64decode(padded)
    assert decoded_padded == data


def test_token_nonce():
    """Test token nonce uniqueness."""
    private_key = security.create_private_key()
    token1 = security.generate_token(private_key=private_key)
    token2 = security.generate_token(private_key=private_key)
    
    payload1 = security.verify_token(token=token1, private_key=private_key)
    payload2 = security.verify_token(token=token2, private_key=private_key)
    
    assert payload1["nonce"] != payload2["nonce"]
    