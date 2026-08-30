"""Compatibility import surface for credential contracts."""

from .lease import SecretLease, SecretLeaseClosed, SecretLeaseError, SecretLeaseExpired
from .models import (
    CREDENTIAL_BINDING_SCHEMA_VERSION,
    SECRET_REF_SCHEMA_VERSION,
    CredentialBinding,
    ResolveContext,
    SecretRef,
    SecretResolutionContext,
)
from .providers import SecretProvider, SecretProviderError

__all__ = [
    "CREDENTIAL_BINDING_SCHEMA_VERSION",
    "SECRET_REF_SCHEMA_VERSION",
    "CredentialBinding",
    "ResolveContext",
    "SecretLease",
    "SecretLeaseClosed",
    "SecretLeaseError",
    "SecretLeaseExpired",
    "SecretProvider",
    "SecretProviderError",
    "SecretRef",
    "SecretResolutionContext",
]
