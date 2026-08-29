"""Strict, browser-independent contracts for versioned CargoMesh adapters."""

from __future__ import annotations

from typing import Annotated, Final, Literal
from urllib.parse import unquote, urlsplit

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, model_validator

from cargomesh.ir.enums import RiskClass
from cargomesh.runtime.models import RuntimeName

ADAPTER_MANIFEST_SCHEMA_VERSION: Final[Literal["cargomesh.adapter-manifest/v1"]] = (
    "cargomesh.adapter-manifest/v1"
)
BROWSER_RECIPE_SCHEMA_VERSION: Final[Literal["cargomesh.browser-recipe/v1"]] = (
    "cargomesh.browser-recipe/v1"
)

BoundedText = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=512)]
JsonPointer = Annotated[
    str,
    StringConstraints(
        strip_whitespace=True,
        min_length=1,
        max_length=512,
        pattern=r"^(?:/(?:[^~/]|~[01])*)+$",
    ),
]
RelativePath = Annotated[
    str,
    StringConstraints(
        strip_whitespace=True,
        min_length=1,
        max_length=1024,
        pattern=r"^/[^\x00-\x20]*$",
    ),
]
Sha256Digest = Annotated[str, StringConstraints(pattern=r"^sha256:[0-9a-f]{64}$")]
SemVer = Annotated[
    str,
    StringConstraints(
        pattern=r"^(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)$"
    ),
]
SupportedRole = Literal["button", "heading", "link", "main", "status", "textbox"]
RecipeFilename = Annotated[
    str,
    StringConstraints(
        pattern=r"^[a-z][a-z0-9_-]{0,63}\.recipe\.json$", max_length=80
    ),
]


class AdapterContractModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)


class RoleLocator(AdapterContractModel):
    kind: Literal["role"] = "role"
    role: SupportedRole
    name: BoundedText
    exact: bool = True


class ValueLocator(AdapterContractModel):
    kind: Literal["label", "test_id", "text", "placeholder"]
    value: BoundedText
    exact: bool = True


LocatorSpec = Annotated[RoleLocator | ValueLocator, Field(discriminator="kind")]


class LiteralBinding(AdapterContractModel):
    source: Literal["literal"] = "literal"
    value: BoundedText


class InputBinding(AdapterContractModel):
    source: Literal["input"] = "input"
    pointer: JsonPointer


ValueBinding = Annotated[LiteralBinding | InputBinding, Field(discriminator="source")]


class NavigateAction(AdapterContractModel):
    kind: Literal["navigate"] = "navigate"
    path: RelativePath
    wait_until: Literal["domcontentloaded", "load"] = "domcontentloaded"
    timeout_ms: int | None = Field(default=None, ge=100, le=120_000)

    @model_validator(mode="after")
    def require_safe_relative_path(self) -> NavigateAction:
        parsed = urlsplit(self.path)
        decoded_segments = unquote(parsed.path).replace("\\", "/").split("/")
        if (
            self.path.startswith("//")
            or parsed.scheme
            or parsed.netloc
            or parsed.fragment
            or ".." in decoded_segments
            or "\\" in self.path
        ):
            raise ValueError("navigation path must remain on the configured origin")
        return self


class FillAction(AdapterContractModel):
    kind: Literal["fill"] = "fill"
    locator: LocatorSpec
    value: ValueBinding
    timeout_ms: int | None = Field(default=None, ge=100, le=120_000)


class ClickAction(AdapterContractModel):
    kind: Literal["click"] = "click"
    locator: LocatorSpec
    timeout_ms: int | None = Field(default=None, ge=100, le=120_000)


class WaitVisibleAction(AdapterContractModel):
    kind: Literal["wait_visible"] = "wait_visible"
    locator: LocatorSpec
    timeout_ms: int | None = Field(default=None, ge=100, le=120_000)


class TextExpectation(AdapterContractModel):
    mode: Literal["equals", "contains"]
    value: BoundedText
    case_sensitive: bool = True


class AssertTextAction(AdapterContractModel):
    kind: Literal["assert_text"] = "assert_text"
    locator: LocatorSpec
    expectation: TextExpectation
    timeout_ms: int | None = Field(default=None, ge=100, le=120_000)


class ExtractTextAction(AdapterContractModel):
    kind: Literal["extract_text"] = "extract_text"
    locator: LocatorSpec
    output_key: RuntimeName
    max_length: int = Field(default=4096, ge=1, le=65_536)
    timeout_ms: int | None = Field(default=None, ge=100, le=120_000)


BrowserAction = Annotated[
    NavigateAction
    | FillAction
    | ClickAction
    | WaitVisibleAction
    | AssertTextAction
    | ExtractTextAction,
    Field(discriminator="kind"),
]


class SignatureProbe(AdapterContractModel):
    key: RuntimeName
    locator: LocatorSpec
    expectation: TextExpectation | None = None


class BrowserRecipe(AdapterContractModel):
    schema_version: Literal["cargomesh.browser-recipe/v1"] = BROWSER_RECIPE_SCHEMA_VERSION
    operation: RuntimeName
    capability: RuntimeName
    risk_class: Literal[RiskClass.READ_ONLY] = RiskClass.READ_ONLY
    portal_signatures: tuple[SignatureProbe, ...]
    actions: tuple[BrowserAction, ...] = Field(min_length=1, max_length=100)

    @model_validator(mode="after")
    def validate_recipe(self) -> BrowserRecipe:
        if not isinstance(self.actions[0], NavigateAction):
            raise ValueError("the first browser action must be navigate")
        if not self.portal_signatures:
            raise ValueError("browser recipe requires at least one portal signature")
        signature_keys = [probe.key for probe in self.portal_signatures]
        if len(signature_keys) != len(set(signature_keys)):
            raise ValueError("portal signature keys must be unique")
        output_keys = [
            action.output_key for action in self.actions if isinstance(action, ExtractTextAction)
        ]
        if len(output_keys) != len(set(output_keys)):
            raise ValueError("browser recipe output keys must be unique")
        if not output_keys:
            raise ValueError("browser recipe must extract at least one output")
        return self


class RecipeReference(AdapterContractModel):
    file: RecipeFilename
    sha256: Sha256Digest


class AdapterManifest(AdapterContractModel):
    schema_version: Literal["cargomesh.adapter-manifest/v1"] = ADAPTER_MANIFEST_SCHEMA_VERSION
    name: RuntimeName
    version: SemVer
    portal_version: BoundedText
    minimum_cargomesh_version: SemVer
    capabilities: tuple[RuntimeName, ...]
    operations: dict[RuntimeName, RecipeReference]

    @model_validator(mode="after")
    def validate_manifest(self) -> AdapterManifest:
        if not self.capabilities:
            raise ValueError("adapter manifest must declare at least one capability")
        if len(self.capabilities) != len(set(self.capabilities)):
            raise ValueError("adapter capabilities must be unique")
        if not self.operations:
            raise ValueError("adapter manifest must declare at least one operation")
        recipe_files = [reference.file for reference in self.operations.values()]
        if len(recipe_files) != len(set(recipe_files)):
            raise ValueError("each operation must reference a distinct recipe file")
        return self


class LoadedAdapterPackage(AdapterContractModel):
    manifest: AdapterManifest
    recipes: dict[RuntimeName, BrowserRecipe]

    @model_validator(mode="after")
    def validate_lockstep(self) -> LoadedAdapterPackage:
        if set(self.recipes) != set(self.manifest.operations):
            raise ValueError("loaded recipes must match manifest operations")
        for operation, recipe in self.recipes.items():
            if recipe.operation != operation:
                raise ValueError("recipe operation must match its manifest key")
            if recipe.capability not in self.manifest.capabilities:
                raise ValueError("recipe capability is not declared by the manifest")
        return self


def text_matches(actual: str, expectation: TextExpectation) -> bool:
    """Evaluate the bounded non-regex text predicate shared by runtime and tests."""

    expected = expectation.value
    if not expectation.case_sensitive:
        actual = actual.casefold()
        expected = expected.casefold()
    if expectation.mode == "equals":
        return actual == expected
    return expected in actual
