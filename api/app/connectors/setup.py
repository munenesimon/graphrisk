"""
Registers every adapter with the CheckRegistry singleton.
Import this module once at application startup (see app/main.py) so all
connectors are available before any request tries to use them.
"""
from .registry import registry
from .adapters.entra_id import EntraIDAdapter, SUPPORTED_CHECKS as ENTRA_CHECKS

registry.register(EntraIDAdapter, ENTRA_CHECKS)

# Future connectors register the same way:
# from .adapters.aws import AWSAdapter, SUPPORTED_CHECKS as AWS_CHECKS
# registry.register(AWSAdapter, AWS_CHECKS)
