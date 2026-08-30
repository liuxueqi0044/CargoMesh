"""Deterministic, restricted adapter-package construction from reviewed bindings."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from enum import Enum
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, model_validator

from cargomesh.adapters.contracts import (
    AdapterManifest,
    BrowserRecipe,
    ExtractTextAction,
    InputBinding,
    LocatorSpec,
    NavigateAction,
    RecipeReference,
    RoleLocator,
    SignatureProbe,
    ValueLocator,
)
from cargomesh.adapters.contracts import FillAction as BrowserFillAction
from cargomesh.factory.capture import SemanticLocator

from .spec import BindingSpecification, FactoryName, ParameterBinding, Sha256Digest
from .tck import TCKReport

PACKAGE_BUILD_OPTIONS_SCHEMA_VERSION: Literal["cargomesh.factory-package-options/v1"] = (
    "cargomesh.factory-package-options/v1"
)
GENERATED_PACKAGE_SCHEMA_VERSION: Literal["cargomesh.generated-adapter-package/v1"] = (
    "cargomesh.generated-adapter-package/v1"
)
CERTIFICATION_RECORD_SCHEMA_VERSION: Literal["cargomesh.adapter-certification-record/v1"] = (
    "cargomesh.adapter-certification-record/v1"
)

_SAFE_INPUT_SEGMENT = "transaction/subject/"
_OUTPUT_NAME = Annotated[
    str,
    StringConstraints(
        strip_whitespace=True,
        min_length=1,
        max_length=128,
        pattern=r"^[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*$",
    ),
]
_SEMVER = Annotated[
    str,
    StringConstraints(
        pattern=r"^(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)$"
    ),
]
_PORTAL_VERSION = Annotated[
    str,
    StringConstraints(strip_whitespace=True, min_length=1, max_length=512),
]
_CERTIFIER = Annotated[
    str,
    StringConstraints(strip_whitespace=True, min_length=1, max_length=512),
]


class PackageBuilderModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)


class AdapterPackageBuildError(ValueError):
    """Bounded build/certification error without captured values or generated source."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


class PackageBuildOptions(PackageBuilderModel):
    """Non-executable adapter metadata needed by the restricted recipe contract."""

    schema_version: Literal["cargomesh.factory-package-options/v1"] = (
        PACKAGE_BUILD_OPTIONS_SCHEMA_VERSION
    )
    adapter_name: FactoryName
    source_system: FactoryName
    version: _SEMVER
    portal_version: _PORTAL_VERSION
    minimum_cargomesh_version: _SEMVER
    operation: FactoryName
    capability: FactoryName
    navigation_path: Annotated[
        str,
        StringConstraints(strip_whitespace=True, min_length=1, max_length=1024),
    ]
    portal_signature: SignatureProbe
    result_locator: LocatorSpec
    output_key: _OUTPUT_NAME


class GeneratedRecipe(PackageBuilderModel):
    """A canonical BrowserRecipe document and its exact file bytes."""

    operation: FactoryName
    file_name: Annotated[
        str,
        StringConstraints(pattern=r"^[a-z][a-z0-9_-]{0,63}\.recipe\.json$", max_length=80),
    ]
    recipe: BrowserRecipe
    recipe_bytes: bytes = Field(min_length=1, max_length=1_048_576)
    recipe_digest: Sha256Digest

    @model_validator(mode="after")
    def validate_recipe_document(self) -> GeneratedRecipe:
        if self.recipe.operation != self.operation:
            raise ValueError("generated recipe operation does not match file metadata")
        if self.recipe_bytes != _canonical_json_bytes(self.recipe):
            raise ValueError("generated recipe bytes are not canonical")
        if self.recipe_digest != _sha256(self.recipe_bytes):
            raise ValueError("generated recipe digest does not match")
        return self


class GeneratedAdapterPackage(PackageBuilderModel):
    """Immutable in-memory package; this builder deliberately has no write method."""

    schema_version: Literal["cargomesh.generated-adapter-package/v1"] = (
        GENERATED_PACKAGE_SCHEMA_VERSION
    )
    binding_spec_digest: Sha256Digest
    manifest: AdapterManifest
    manifest_bytes: bytes = Field(min_length=1, max_length=1_048_576)
    manifest_digest: Sha256Digest
    recipes: tuple[GeneratedRecipe, ...] = Field(min_length=1, max_length=16)
    package_digest: Sha256Digest

    @model_validator(mode="after")
    def validate_package(self) -> GeneratedAdapterPackage:
        if self.manifest_bytes != _canonical_json_bytes(self.manifest):
            raise ValueError("generated manifest bytes are not canonical")
        if self.manifest_digest != _sha256(self.manifest_bytes):
            raise ValueError("generated manifest digest does not match")
        if len({recipe.file_name for recipe in self.recipes}) != len(self.recipes):
            raise ValueError("generated recipe file names must be unique")
        recipe_by_operation = {recipe.operation: recipe for recipe in self.recipes}
        if set(recipe_by_operation) != set(self.manifest.operations):
            raise ValueError("generated recipes must match manifest operations")
        for operation, reference in self.manifest.operations.items():
            recipe = recipe_by_operation[operation]
            if reference.file != recipe.file_name or reference.sha256 != recipe.recipe_digest:
                raise ValueError("manifest recipe reference does not match generated recipe")
        if self.package_digest != _package_digest(
            self.binding_spec_digest,
            self.manifest_digest,
            self.recipes,
        ):
            raise ValueError("generated package digest does not match")
        return self

    def files(self) -> Mapping[str, bytes]:
        """Return a read-only mapping for a caller that controls persistence."""

        return {
            "manifest.json": self.manifest_bytes,
            **{recipe.file_name: recipe.recipe_bytes for recipe in self.recipes},
        }


class AdapterCertificationRecord(PackageBuilderModel):
    """A package certificate requiring a compatible, security-clean TCK report."""

    schema_version: Literal["cargomesh.adapter-certification-record/v1"] = (
        CERTIFICATION_RECORD_SCHEMA_VERSION
    )
    binding_spec_digest: Sha256Digest
    adapter_package_digest: Sha256Digest
    tck_suite_digest: Sha256Digest
    tck_report_digest: Sha256Digest
    certified_by: _CERTIFIER
    certified_at: datetime
    certification_digest: Sha256Digest

    @model_validator(mode="after")
    def validate_record(self) -> AdapterCertificationRecord:
        _aware_time(self.certified_at)
        if self.certification_digest != _model_digest(
            self,
            exclude={"certification_digest"},
        ):
            raise ValueError("adapter certification record digest does not match")
        return self

    @classmethod
    def issue(
        cls,
        package: GeneratedAdapterPackage,
        specification: BindingSpecification,
        report: TCKReport,
        *,
        certified_by: str,
        certified_at: datetime,
    ) -> AdapterCertificationRecord:
        _validate_certification_inputs(package, specification, report)
        values: dict[str, object] = {
            "schema_version": CERTIFICATION_RECORD_SCHEMA_VERSION,
            "binding_spec_digest": specification.checksum,
            "adapter_package_digest": package.package_digest,
            "tck_suite_digest": report.suite_digest,
            "tck_report_digest": report.report_digest,
            "certified_by": certified_by,
            "certified_at": certified_at,
        }
        values["certification_digest"] = _digest(values)
        return cls.model_validate(values)


def build_adapter_package(
    specification: BindingSpecification,
    options: PackageBuildOptions,
) -> GeneratedAdapterPackage:
    """Build one canonical read-only BrowserRecipe from a ready reviewed specification."""

    _validate_specification(specification)
    recipe = _build_recipe(specification, options)
    recipe_bytes = _canonical_json_bytes(recipe)
    recipe_digest = _sha256(recipe_bytes)
    generated_recipe = GeneratedRecipe(
        operation=options.operation,
        file_name=_recipe_file_name(options.operation),
        recipe=recipe,
        recipe_bytes=recipe_bytes,
        recipe_digest=recipe_digest,
    )
    manifest = AdapterManifest(
        name=options.adapter_name,
        source_system=options.source_system,
        version=options.version,
        portal_version=options.portal_version,
        minimum_cargomesh_version=options.minimum_cargomesh_version,
        capabilities=(options.capability,),
        operations={
            options.operation: RecipeReference(
                file=generated_recipe.file_name,
                sha256=generated_recipe.recipe_digest,
            )
        },
    )
    manifest_bytes = _canonical_json_bytes(manifest)
    manifest_digest = _sha256(manifest_bytes)
    return GeneratedAdapterPackage(
        binding_spec_digest=specification.checksum,
        manifest=manifest,
        manifest_bytes=manifest_bytes,
        manifest_digest=manifest_digest,
        recipes=(generated_recipe,),
        package_digest=_package_digest(
            specification.checksum,
            manifest_digest,
            (generated_recipe,),
        ),
    )


def _validate_specification(specification: BindingSpecification) -> None:
    if not specification.ready:
        raise AdapterPackageBuildError(
            "factory_spec_not_ready",
            "Binding specification is not ready for package generation",
        )
    ambiguity_ids = {item.ambiguity_id for item in specification.ambiguities}
    resolution_ids = {item.ambiguity_id for item in specification.resolutions}
    if not ambiguity_ids.issubset(resolution_ids):
        raise AdapterPackageBuildError(
            "factory_ambiguity_unresolved",
            "Binding specification has unresolved ambiguities",
        )
    if not specification.parameters:
        raise AdapterPackageBuildError(
            "factory_binding_missing",
            "Binding specification has no executable parameter bindings",
        )


def _build_recipe(
    specification: BindingSpecification,
    options: PackageBuildOptions,
) -> BrowserRecipe:
    actions: list[NavigateAction | BrowserFillAction | ExtractTextAction] = [
        NavigateAction(path=options.navigation_path)
    ]
    for binding in sorted(specification.parameters, key=lambda item: item.parameter):
        actions.append(_binding_to_fill_action(binding))
    actions.append(
        ExtractTextAction(
            locator=options.result_locator,
            output_key=options.output_key,
        )
    )
    return BrowserRecipe(
        operation=options.operation,
        capability=options.capability,
        portal_signatures=(options.portal_signature,),
        actions=tuple(actions),
    )


def _binding_to_fill_action(binding: ParameterBinding) -> BrowserFillAction:
    if binding.action != "fill":
        raise AdapterPackageBuildError(
            "factory_unsupported_action",
            "Binding action is not supported by the browser recipe contract",
        )
    return BrowserFillAction(
        locator=_to_browser_locator(binding.locator),
        value=InputBinding(pointer=f"/{_SAFE_INPUT_SEGMENT}{binding.parameter}"),
    )


def _to_browser_locator(locator: SemanticLocator) -> LocatorSpec:
    if locator.kind == "role":
        return RoleLocator(role="textbox", name=locator.value, exact=locator.exact)
    return ValueLocator(kind=locator.kind, value=locator.value, exact=locator.exact)


def _recipe_file_name(operation: str) -> str:
    return f"recipe-{hashlib.sha256(operation.encode('utf-8')).hexdigest()[:16]}.recipe.json"


def _validate_certification_inputs(
    package: GeneratedAdapterPackage,
    specification: BindingSpecification,
    report: TCKReport,
) -> None:
    if package.binding_spec_digest != specification.checksum:
        raise AdapterPackageBuildError(
            "factory_certification_binding_mismatch",
            "Certification package does not match binding specification",
        )
    if report.adapter_package_digest != package.package_digest:
        raise AdapterPackageBuildError(
            "factory_certification_package_mismatch",
            "Certification report does not match generated package",
        )
    if not report.compatible:
        raise AdapterPackageBuildError(
            "factory_certification_tck_incompatible",
            "Certification requires a compatible TCK report",
        )
    if not any(result.security_critical for result in report.results):
        raise AdapterPackageBuildError(
            "factory_certification_security_missing",
            "Certification requires at least one security-critical TCK case",
        )
    if any(not result.passed for result in report.results if result.security_critical):
        raise AdapterPackageBuildError(
            "factory_certification_security_failed",
            "Certification requires passing security-critical TCK cases",
        )


def _package_digest(
    binding_spec_digest: str,
    manifest_digest: str,
    recipes: Sequence[GeneratedRecipe],
) -> str:
    return _digest(
        {
            "binding_spec_digest": binding_spec_digest,
            "manifest_digest": manifest_digest,
            "recipes": {
                recipe.file_name: recipe.recipe_digest
                for recipe in sorted(recipes, key=lambda value: value.file_name)
            },
        }
    )


def _canonical_json_bytes(model: BaseModel) -> bytes:
    return json.dumps(
        _canonical(model),
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
        allow_nan=False,
    ).encode("utf-8")


def _model_digest(model: BaseModel, *, exclude: set[str]) -> str:
    return _digest(model.model_dump(mode="python", exclude=exclude, warnings=False))


def _digest(value: object) -> str:
    return _sha256(
        json.dumps(
            _canonical(value),
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
            allow_nan=False,
        ).encode("utf-8")
    )


def _sha256(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _canonical(value: object) -> object:
    if isinstance(value, BaseModel):
        return _canonical(value.model_dump(mode="python"))
    if isinstance(value, datetime):
        return _aware_time(value).isoformat(timespec="microseconds")
    if isinstance(value, Enum):
        return _canonical(value.value)
    if isinstance(value, Mapping):
        return {str(key): _canonical(item) for key, item in value.items()}
    if isinstance(value, Sequence) and not isinstance(value, str | bytes | bytearray):
        return [_canonical(item) for item in value]
    return value


def _aware_time(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("certification time must include a timezone")
    return value.astimezone(UTC)


__all__ = [
    "CERTIFICATION_RECORD_SCHEMA_VERSION",
    "GENERATED_PACKAGE_SCHEMA_VERSION",
    "PACKAGE_BUILD_OPTIONS_SCHEMA_VERSION",
    "AdapterCertificationRecord",
    "AdapterPackageBuildError",
    "GeneratedAdapterPackage",
    "GeneratedRecipe",
    "PackageBuildOptions",
    "build_adapter_package",
]
