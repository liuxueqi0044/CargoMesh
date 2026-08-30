"""Deterministic adapter-factory contracts."""

from .capture import (
    AssertAction,
    ClickAction,
    DemonstrationCapture,
    FillAction,
    SelectAction,
    SemanticLocator,
)
from .package_builder import (
    AdapterCertificationRecord,
    AdapterPackageBuildError,
    GeneratedAdapterPackage,
    GeneratedRecipe,
    PackageBuildOptions,
    build_adapter_package,
)
from .spec import (
    AdapterFactoryCompiler,
    Ambiguity,
    BindingSpecification,
    ParameterBinding,
    ParameterEvidence,
    Resolution,
    ReviewedSOP,
)

__all__ = [
    "AdapterCertificationRecord",
    "AdapterFactoryCompiler",
    "AdapterPackageBuildError",
    "Ambiguity",
    "AssertAction",
    "BindingSpecification",
    "ClickAction",
    "DemonstrationCapture",
    "FillAction",
    "GeneratedAdapterPackage",
    "GeneratedRecipe",
    "PackageBuildOptions",
    "ParameterBinding",
    "ParameterEvidence",
    "Resolution",
    "ReviewedSOP",
    "SelectAction",
    "SemanticLocator",
    "build_adapter_package",
]
