"""Opaque credential bindings and ephemeral secret-provider contracts."""

from .lease import SecretLease, SecretLeaseClosed, SecretLeaseError, SecretLeaseExpired
from .models import (
    CREDENTIAL_BINDING_SCHEMA_VERSION,
    SECRET_REF_SCHEMA_VERSION,
    CredentialBinding,
    ResolveContext,
    SecretRef,
    SecretResolutionContext,
)
from .providers import (
    EnvironmentSecretProvider,
    InMemorySecretProvider,
    SecretProvider,
    SecretProviderError,
)
from .store import (
    BindingConflict,
    BindingNotFound,
    CredentialBindingConflict,
    CredentialBindingNotFound,
    CredentialBindingStore,
    CredentialBindingStoreError,
    SQLiteCredentialBindingStore,
)

__all__ = [
    "CREDENTIAL_BINDING_SCHEMA_VERSION",
    "SECRET_REF_SCHEMA_VERSION",
    "BindingConflict",
    "BindingNotFound",
    "CredentialBinding",
    "CredentialBindingConflict",
    "CredentialBindingNotFound",
    "CredentialBindingStore",
    "CredentialBindingStoreError",
    "EnvironmentSecretProvider",
    "InMemorySecretProvider",
    "ResolveContext",
    "SQLiteCredentialBindingStore",
    "SecretLease",
    "SecretLeaseClosed",
    "SecretLeaseError",
    "SecretLeaseExpired",
    "SecretProvider",
    "SecretProviderError",
    "SecretRef",
    "SecretResolutionContext",
]
