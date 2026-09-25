"""
Symmetric encryption for connector credentials saved via
PUT /api/v1/connectors/{connector_id}/config.

Config is only ever stored encrypted (see the ConnectorConfig node
queries in connectors.py) and only ever decrypted in-process, immediately
before being merged into a connector run -- never returned to a client
in plaintext (GET /config reports which keys are set, never their values).

The Fernet key is derived from SECRET_KEY (SHA-256 -> urlsafe-base64)
rather than a dedicated env var, so this works in every environment that
already has SECRET_KEY set (local .env, Render) with no new required
config value and no deploy-time risk of the app failing to start over a
missing setting. A real multi-purpose production system should use a key
dedicated to this one job (ideally from a KMS), so that rotating the JWT
signing secret doesn't also silently re-key every stored connector
credential. Documented here as a deliberate portfolio-project
simplification, not a security recommendation -- see the "Kenyan
regulatory crosswalk"-style honesty the rest of this codebase aims for.
"""
import base64
import hashlib
import json

from cryptography.fernet import Fernet, InvalidToken

from app.config import settings


class ConfigDecryptionError(Exception):
    """
    Stored config could not be decrypted -- most likely SECRET_KEY has
    changed since it was saved (e.g. rotated, or a different environment's
    .env). The caller should treat this the same as "no config saved" and
    surface a clear error rather than crash, since to the connector adapter
    a bad decrypt and a missing key look the same: nothing usable.
    """


def _fernet() -> Fernet:
    key_bytes = hashlib.sha256(settings.secret_key.encode("utf-8")).digest()
    return Fernet(base64.urlsafe_b64encode(key_bytes))


def encrypt_config(config: dict) -> str:
    payload = json.dumps(config).encode("utf-8")
    return _fernet().encrypt(payload).decode("utf-8")


def decrypt_config(token: str) -> dict:
    try:
        payload = _fernet().decrypt(token.encode("utf-8"))
    except InvalidToken as e:
        raise ConfigDecryptionError(
            "Stored connector config could not be decrypted -- SECRET_KEY "
            "may have changed since it was saved."
        ) from e
    return json.loads(payload.decode("utf-8"))
