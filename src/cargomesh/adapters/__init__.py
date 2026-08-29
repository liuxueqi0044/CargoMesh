"""Versioned adapter package contracts and deterministic executors."""

from .contracts import (
    ADAPTER_MANIFEST_SCHEMA_VERSION,
    BROWSER_RECIPE_SCHEMA_VERSION,
    AdapterManifest,
    BrowserRecipe,
    LoadedAdapterPackage,
)

__all__ = [
    "ADAPTER_MANIFEST_SCHEMA_VERSION",
    "BROWSER_RECIPE_SCHEMA_VERSION",
    "AdapterManifest",
    "BrowserRecipe",
    "LoadedAdapterPackage",
]
