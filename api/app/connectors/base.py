"""
Layer 1 of the universal connector architecture: BaseConnector.

Handles everything identical across every vendor: OAuth 2.0 token management,
HTTP requests with retry/backoff, rate-limit handling, and pagination.
Every per-vendor adapter inherits from this and only implements vendor-specific logic.
"""
import time
import logging
import requests
from abc import ABC, abstractmethod
from typing import Generator, Optional

from .models import CheckResult

logger = logging.getLogger(__name__)


class CheckError:
    """A single failed check, carrying enough detail for the caller to act on it."""
    def __init__(self, check_id: str, error_type: str, message: str):
        self.check_id   = check_id
        self.error_type = error_type
        self.message    = message

    def to_dict(self) -> dict:
        return {
            "check_id":   self.check_id,
            "error_type": self.error_type,
            "message":    self.message,
        }

    def __repr__(self) -> str:
        return f"CheckError({self.check_id}: {self.error_type} - {self.message})"


class BaseConnector(ABC):
    """
    Abstract base for all GraphRisk connectors.

    Subclasses MUST implement:
      - authenticate()      : acquire and store an access token
      - supported_checks()  : list of check_ids this adapter can run
      - run_check(check_id) : execute one check, return a CheckResult

    Everything else (HTTP, retries, pagination, OAuth) is handled here.
    """

    CONNECTOR_ID:   str = "base"    # Override in subclass, e.g. "entra_id"
    CONNECTOR_NAME: str = "Base"    # Override in subclass, e.g. "Microsoft Entra ID"

    # Config keys this connector requires -- override in subclass so
    # missing-config errors can be reported clearly before any request is made.
    REQUIRED_CONFIG_KEYS: list[str] = []

    def __init__(self, tenant_id: str, config: dict):
        self.tenant_id = tenant_id
        self.config    = config
        self._token         = None
        self._token_expiry  = 0.0
        self._session        = requests.Session()

    # ── Abstract interface — every adapter implements these three ──────────
    @abstractmethod
    def authenticate(self) -> None:
        """Acquire and store an access token. Called automatically before requests."""
        raise NotImplementedError

    @abstractmethod
    def supported_checks(self) -> list[str]:
        """Return the list of check_ids this adapter can run."""
        raise NotImplementedError

    @abstractmethod
    def run_check(self, check_id: str) -> CheckResult:
        """Run a specific check and return a CheckResult."""
        raise NotImplementedError

    # ── Config validation ────────────────────────────────────────────────────
    def validate_config(self) -> Optional[CheckError]:
        """
        Check that all REQUIRED_CONFIG_KEYS are present before attempting
        authentication. Returns a CheckError describing what is missing,
        or None if config looks complete.
        """
        missing = [k for k in self.REQUIRED_CONFIG_KEYS if k not in self.config or not self.config[k]]
        if missing:
            return CheckError(
                check_id="config_validation",
                error_type="MissingConfig",
                message=f"Missing required config key(s): {', '.join(missing)}",
            )
        return None

    # ── Token management ────────────────────────────────────────────────────
    def _ensure_token(self) -> None:
        if time.time() >= self._token_expiry - 60:
            self.authenticate()

    def _set_token(self, token: str, expires_in: int = 3600) -> None:
        self._token        = token
        self._token_expiry = time.time() + expires_in

    # ── HTTP methods with retry + rate-limit handling ───────────────────────
    def _get(self, url: str, params: Optional[dict] = None, retries: int = 3) -> dict:
        self._ensure_token()
        headers = {"Authorization": f"Bearer {self._token}"}
        for attempt in range(retries):
            try:
                r = self._session.get(url, headers=headers, params=params, timeout=30)
                if r.status_code == 429:
                    wait = int(r.headers.get("Retry-After", 2 ** attempt))
                    logger.warning(f"Rate limited by {url}. Waiting {wait}s...")
                    time.sleep(wait)
                    continue
                if r.status_code == 401:
                    self.authenticate()   # Force a token refresh and retry
                    headers = {"Authorization": f"Bearer {self._token}"}
                    continue
                r.raise_for_status()
                return r.json()
            except requests.RequestException as e:
                if attempt == retries - 1:
                    raise
                logger.warning(f"Request failed (attempt {attempt+1}/{retries}): {e}")
                time.sleep(2 ** attempt)
        raise RuntimeError(f"Request failed after {retries} attempts: {url}")

    def _post(self, url: str, json_body: Optional[dict] = None, retries: int = 3) -> dict:
        self._ensure_token()
        headers = {"Authorization": f"Bearer {self._token}"}
        for attempt in range(retries):
            try:
                r = self._session.post(url, headers=headers, json=json_body, timeout=30)
                if r.status_code == 429:
                    wait = int(r.headers.get("Retry-After", 2 ** attempt))
                    time.sleep(wait)
                    continue
                r.raise_for_status()
                return r.json()
            except requests.RequestException as e:
                if attempt == retries - 1:
                    raise
                time.sleep(2 ** attempt)
        raise RuntimeError(f"Request failed after {retries} attempts: {url}")

    # ── Pagination helper — works for cursor-based and offset-based APIs ────
    def _paginate(
        self,
        url: str,
        params: Optional[dict] = None,
        items_key: str = "value",
        next_key: str = "@odata.nextLink",
    ) -> Generator[dict, None, None]:
        """
        Yield every item from a paginated API endpoint.
        Defaults match Microsoft Graph's shape (@odata.nextLink); override
        items_key/next_key for other vendors' pagination conventions.
        """
        data = self._get(url, params)
        yield from data.get(items_key, [])
        next_url = data.get(next_key)
        while next_url:
            data = self._get(next_url)
            yield from data.get(items_key, [])
            next_url = data.get(next_key)

    # ── OAuth 2.0 client credentials — the dominant auth pattern ────────────
    def _oauth_client_credentials(
        self, token_url: str, client_id: str, client_secret: str, scope: str
    ) -> None:
        """Standard OAuth 2.0 client credentials flow, shared by most vendors."""
        r = self._session.post(token_url, data={
            "grant_type":    "client_credentials",
            "client_id":     client_id,
            "client_secret": client_secret,
            "scope":         scope,
        })
        r.raise_for_status()
        data = r.json()
        self._set_token(data["access_token"], data.get("expires_in", 3600))

    # ── Run every supported check, surfacing both results and errors ────────
    def run_all_checks(self) -> tuple[list[CheckResult], list[CheckError]]:
        """
        Run every check this adapter supports.
        Returns (results, errors) -- callers get full visibility into what
        succeeded and what failed, rather than silently losing failures.
        Config is validated once up front so a single missing credential
        does not need to fail N times, once per check.
        """
        config_error = self.validate_config()
        if config_error:
            return [], [config_error]

        results: list[CheckResult] = []
        errors:  list[CheckError]  = []

        for check_id in self.supported_checks():
            try:
                result = self.run_check(check_id)
                results.append(result)
                logger.info(f"{self.CONNECTOR_ID}/{check_id}: {result.status.value}")
            except Exception as e:
                error = CheckError(
                    check_id=check_id,
                    error_type=type(e).__name__,
                    message=str(e),
                )
                errors.append(error)
                logger.error(f"{self.CONNECTOR_ID}/{check_id} failed: {error}")

        return results, errors
