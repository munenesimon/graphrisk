"""
Unit tests for app/auth/security.py: password hashing and JWT
create/decode -- the primitives every authenticated endpoint's
get_current_user dependency relies on.
"""
from datetime import datetime, timedelta, timezone

import pytest
from jose import JWTError, jwt

from app.auth.security import (
    create_access_token,
    decode_access_token,
    hash_password,
    verify_password,
)
from app.config import settings


class TestPasswordHashing:
    def test_correct_password_verifies(self):
        hashed = hash_password("correct horse battery staple")
        assert verify_password("correct horse battery staple", hashed) is True

    def test_wrong_password_does_not_verify(self):
        hashed = hash_password("correct horse battery staple")
        assert verify_password("wrong password", hashed) is False

    def test_hash_is_not_the_plaintext(self):
        hashed = hash_password("correct horse battery staple")
        assert hashed != "correct horse battery staple"

    def test_same_password_hashes_differently_each_time(self):
        """bcrypt salts automatically -- two hashes of the same password
        must differ, even though both verify correctly."""
        h1 = hash_password("same-password")
        h2 = hash_password("same-password")
        assert h1 != h2
        assert verify_password("same-password", h1) is True
        assert verify_password("same-password", h2) is True


class TestAccessToken:
    def test_roundtrip_carries_the_right_claims(self):
        token = create_access_token(user_id="u1", tenant_id="t1", graph_tenant_id="demo", role="owner")
        payload = decode_access_token(token)
        assert payload["sub"] == "u1"
        assert payload["tenant_id"] == "t1"
        assert payload["graph_tenant_id"] == "demo"
        assert payload["role"] == "owner"

    def test_tampered_token_is_rejected(self):
        token = create_access_token(user_id="u1", tenant_id="t1", graph_tenant_id="demo", role="member")
        # Flip the last character of the signature -- still well-formed JWT shape, wrong signature.
        tampered = token[:-1] + ("A" if token[-1] != "A" else "B")
        with pytest.raises(JWTError):
            decode_access_token(tampered)

    def test_expired_token_is_rejected(self):
        expired_payload = {
            "sub": "u1", "tenant_id": "t1", "graph_tenant_id": "demo", "role": "owner",
            "exp": datetime.now(timezone.utc) - timedelta(minutes=1),
        }
        expired_token = jwt.encode(expired_payload, settings.secret_key, algorithm=settings.algorithm)
        with pytest.raises(JWTError):
            decode_access_token(expired_token)

    def test_token_signed_with_a_different_key_is_rejected(self):
        forged_payload = {
            "sub": "attacker", "tenant_id": "victim-tenant", "graph_tenant_id": "victim",
            "role": "owner", "exp": datetime.now(timezone.utc) + timedelta(hours=1),
        }
        forged_token = jwt.encode(forged_payload, "some-other-key-the-attacker-guessed", algorithm=settings.algorithm)
        with pytest.raises(JWTError):
            decode_access_token(forged_token)
