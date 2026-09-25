"""
Registers every adapter with the CheckRegistry singleton.
Import this module once at application startup (see app/main.py) so all
connectors are available before any request tries to use them.
"""
from .registry import registry
from .adapters.entra_id import EntraIDAdapter, SUPPORTED_CHECKS as ENTRA_CHECKS
from .adapters.aws import AWSAdapter, SUPPORTED_CHECKS as AWS_CHECKS
from .adapters.okta import OktaAdapter, SUPPORTED_CHECKS as OKTA_CHECKS
from .adapters.wazuh import WazuhAdapter, SUPPORTED_CHECKS as WAZUH_CHECKS
from .adapters.crowdstrike import CrowdStrikeAdapter, SUPPORTED_CHECKS as CROWDSTRIKE_CHECKS
from .adapters.qualys import QualysAdapter, SUPPORTED_CHECKS as QUALYS_CHECKS

registry.register(EntraIDAdapter, ENTRA_CHECKS)
registry.register(AWSAdapter, AWS_CHECKS)
registry.register(OktaAdapter, OKTA_CHECKS)
registry.register(WazuhAdapter, WAZUH_CHECKS)
registry.register(CrowdStrikeAdapter, CROWDSTRIKE_CHECKS)
registry.register(QualysAdapter, QUALYS_CHECKS)
