"""
Unit tests for app/connectors/crypto.py -- the Fernet-based encryption used
to store connector credentials (see PUT /{connector_id}/config).

Not testing a new fix here: the SECRET_KEY-derived-key tradeoff is already
self-documented in crypto.py as a deliberate simplification. These tests
just pin down the actual behavior (roundtrip correctness, and what happens
when the key changes) so a future change can't silently break either.
"""
import pytest

from app.config import settings
from app.connectors.crypto import ConfigDecryptionError, decrypt_config, encrypt_config


class TestRoundTrip:
    def test_simple_config_roundtrips(self):
        original = {"client_id": "abc-123", "client_secret": "s3cr3t"}
        assert decrypt_config(encrypt_config(original)) == original

    def test_nested_and_unicode_values_roundtrip(self):
        original = {"api_url": "https://例え.example.com", "meta": {"region": "eu", "tags": ["a", "b"]}}
        assert decrypt_config(encrypt_config(original)) == original

    def test_empty_config_roundtrips(self):
        assert decrypt_config(encrypt_config({})) == {}

    def test_ciphertext_does_not_contain_the_plaintext_secret(self):
        token = encrypt_config({"client_secret": "extremely-sensitive-value"})
        assert "extremely-sensitive-value" not in token


class TestKeyMismatch:
    def test_decrypting_with_a_different_secret_key_fails_cleanly(self, monkeypatch):
        token = encrypt_config({"client_secret": "s3cr3t"})
        monkeypatch.setattr(settings, "secret_key", "a-completely-different-secret-key")
        with pytest.raises(ConfigDecryptionError):
            decrypt_config(token)

    def test_garbage_input_fails_cleanly_not_with_a_raw_crypto_exception(self):
        with pytest.raises(ConfigDecryptionError):
            decrypt_config("not-a-valid-fernet-token")
