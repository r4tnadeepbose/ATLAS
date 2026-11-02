"""SBOM parsers for CycloneDX (JSON/XML) and SPDX (JSON/tag-value).

Parsing never executes uploaded content. XML is parsed with defusedxml to
prevent entity-expansion attacks, and every parser enforces structural
validation before returning normalized components.
"""

from __future__ import annotations

import json
import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field

from defusedxml import ElementTree as DefusedET

from app.core.exceptions import ValidationError

PURL_ECOSYSTEMS = {
    "npm": "npm",
    "pypi": "PyPI",
    "gem": "RubyGems",
    "golang": "Go",
    "cargo": "crates.io",
    "maven": "Maven",
    "nuget": "NuGet",
    "deb": "Debian",
    "rpm": "RPM",
    "apk": "Alpine",
    "docker": "Docker",
    "oci": "Docker",
    "composer": "Packagist",
    "swift": "SwiftURL",
}


@dataclass
class ParsedComponent:
    uid: str
    name: str
    version: str | None
    purl: str | None = None
    cpe: str | None = None
    ecosystem: str | None = None
    supplier: str | None = None
    license: str | None = None
    component_type: str = "library"
    is_direct: bool = False
    depends_on: list[str] = field(default_factory=list)


@dataclass
class ParsedSbom:
    format: str
    spec_version: str | None
    name: str
    components: list[ParsedComponent]
    metadata: dict = field(default_factory=dict)


def ecosystem_from_purl(purl: str | None) -> str | None:
    if not purl or not purl.startswith("pkg:"):
        return None
    match = re.match(r"pkg:([^/]+)/", purl)
    return PURL_ECOSYSTEMS.get(match.group(1)) if match else None


def _license_string(value) -> str | None:
    if not value:
        return None
    if isinstance(value, str):
        return value[:250]
    if isinstance(value, list):
        parts = []
        for item in value:
            if isinstance(item, dict):
                license_def = item.get("license") or {}
                parts.append(license_def.get("id") or license_def.get("name") or "")
            elif isinstance(item, str):
                parts.append(item)
        joined = ", ".join(part for part in parts if part)
        return joined[:250] or None
    if isinstance(value, dict):
        license_def = value.get("license") or {}
        return (license_def.get("id") or license_def.get("name") or value.get("expression") or None)
    return None


def detect_format(content: bytes, filename: str | None = None) -> str:
    text = content.lstrip()[:4000]
    lowered = text[:400].lower()
    if text.startswith(b"{") or text.startswith(b"["):
        try:
            document = json.loads(content.decode("utf-8", errors="strict"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValidationError("Uploaded SBOM is not valid JSON") from exc
        if isinstance(document, dict) and "bomFormat" in document:
            return "cyclonedx-json"
        if isinstance(document, dict) and "spdxVersion" in document:
            return "spdx-json"
        raise ValidationError("Unrecognised JSON SBOM: expected CycloneDX or SPDX")
    if text.startswith(b"<"):
        return "cyclonedx-xml"
    if b"SPDXVersion:" in content[:4000]:
        return "spdx-tag-value"
    raise ValidationError("Unrecognised SBOM format. Supported: CycloneDX JSON/XML, SPDX JSON/tag-value")


def parse_sbom(content: bytes, filename: str | None = None) -> ParsedSbom:
    fmt = detect_format(content, filename)
    if fmt == "cyclonedx-json":
        return _parse_cyclonedx_json(json.loads(content.decode("utf-8")))
    if fmt == "cyclonedx-xml":
        return _parse_cyclonedx_xml(content)
    if fmt == "spdx-json":
        return _parse_spdx_json(json.loads(content.decode("utf-8")))
    return _parse_spdx_tag_value(content.decode("utf-8", errors="replace"))


def _parse_cyclonedx_json(document: dict) -> ParsedSbom:
    components: list[ParsedComponent] = []
    by_ref: dict[str, ParsedComponent] = {}

    def add_component(raw: dict, is_direct: bool = False) -> None:
        ref = raw.get("bom-ref") or raw.get("purl") or raw.get("name")
        if not ref:
            return
        purl = raw.get("purl")
        component = ParsedComponent(
            uid=str(ref),
            name=raw.get("name") or str(ref),
            version=raw.get("version"),
            purl=purl,
            cpe=(raw.get("cpe") or "").strip() or None,
            ecosystem=ecosystem_from_purl(purl),
            supplier=(raw.get("supplier") or {}).get("name") if isinstance(raw.get("supplier"), dict) else None,
            license=_license_string(raw.get("licenses")),
            component_type=raw.get("type") or "library",
            is_direct=is_direct,
        )
        components.append(component)
        by_ref[component.uid] = component

    metadata = document.get("metadata") or {}
    root = metadata.get("component")
    if isinstance(root, dict):
        add_component(root, is_direct=True)

    for raw in document.get("components") or []:
        if isinstance(raw, dict):
            add_component(raw)

    for dependency in document.get("dependencies") or []:
        parent = by_ref.get(str(dependency.get("ref")))
        if parent is None:
            continue
        for child_ref in dependency.get("dependsOn") or []:
            if child_ref in by_ref:
                parent.depends_on.append(child_ref)

    if not components:
        raise ValidationError("CycloneDX document contains no components")
    return ParsedSbom(
        format="cyclonedx-json",
        spec_version=document.get("specVersion"),
        name=metadata.get("component", {}).get("name") if isinstance(metadata.get("component"), dict) else "CycloneDX SBOM",
        components=components,
        metadata={"tool": metadata.get("tools"), "timestamp": metadata.get("timestamp")},
    )


def _local(tag: str) -> str:
    return tag.split("}", 1)[-1]


def _parse_cyclonedx_xml(content: bytes) -> ParsedSbom:
    try:
        root = DefusedET.fromstring(content)
    except ET.ParseError as exc:
        raise ValidationError("Invalid CycloneDX XML") from exc
    except Exception as exc:  # noqa: BLE001 - defusedxml raises its own errors
        raise ValidationError("CycloneDX XML rejected by secure parser") from exc

    components: list[ParsedComponent] = []
    by_ref: dict[str, ParsedComponent] = {}

    def walk(element, is_direct=False):
        for child in list(element):
            if _local(child.tag) == "component":
                ref = child.get("bom-ref") or _child_text(child, "purl") or _child_text(child, "name")
                purl = _child_text(child, "purl")
                if ref:
                    component = ParsedComponent(
                        uid=str(ref),
                        name=_child_text(child, "name") or str(ref),
                        version=_child_text(child, "version"),
                        purl=purl,
                        ecosystem=ecosystem_from_purl(purl),
                        supplier=_child_text(child, "supplier") or None,
                        license=_child_text(child, "license") or None,
                        component_type=child.get("type") or "library",
                        is_direct=is_direct,
                    )
                    components.append(component)
                    by_ref[component.uid] = component
                walk(child, False)
            else:
                walk(child, is_direct)

    walk(root)
    for dependency in root.iter():
        if _local(dependency.tag) != "dependency":
            continue
        parent = by_ref.get(dependency.get("ref") or "")
        if parent is None:
            continue
        for child in dependency:
            if _local(child.tag) == "dependency" and child.get("ref") in by_ref:
                parent.depends_on.append(child.get("ref"))
    if not components:
        raise ValidationError("CycloneDX XML contains no components")
    return ParsedSbom(
        format="cyclonedx-xml",
        spec_version=root.get("version"),
        name="CycloneDX SBOM",
        components=components,
    )


def _child_text(element, name: str) -> str | None:
    for child in list(element):
        if _local(child.tag) == name:
            return (child.text or "").strip() or None
    return None


def _parse_spdx_json(document: dict) -> ParsedSbom:
    packages = document.get("packages") or []
    by_id: dict[str, ParsedComponent] = {}
    components: list[ParsedComponent] = []
    for raw in packages:
        spdx_id = raw.get("SPDXID") or raw.get("name")
        purl = None
        for ref in raw.get("externalRefs") or []:
            if ref.get("referenceType") == "purl":
                purl = ref.get("referenceLocator")
                break
        component = ParsedComponent(
            uid=str(spdx_id),
            name=raw.get("name") or str(spdx_id),
            version=raw.get("versionInfo"),
            purl=purl,
            ecosystem=ecosystem_from_purl(purl),
            supplier=raw.get("supplier"),
            license=raw.get("licenseConcluded") or raw.get("licenseDeclared"),
            component_type=raw.get("primaryPackagePurpose", "library").lower(),
        )
        components.append(component)
        by_id[str(spdx_id)] = component
    for relationship in document.get("relationships") or []:
        if str(relationship.get("relationshipType", "")).upper() not in {"DEPENDS_ON", "CONTAINS", "RUNTIME_DEPENDENCY_OF", "BUILD_DEPENDENCY_OF"}:
            continue
        parent = by_id.get(str(relationship.get("spdxElementId")))
        child = by_id.get(str(relationship.get("relatedSpdxElement")))
        if parent and child and relationship.get("relationshipType", "").upper() in {"DEPENDS_ON", "CONTAINS"}:
            parent.depends_on.append(child.uid)
    if not components:
        raise ValidationError("SPDX document contains no packages")
    return ParsedSbom(
        format="spdx-json",
        spec_version=document.get("spdxVersion"),
        name=document.get("name") or "SPDX SBOM",
        components=components,
        metadata={"documentNamespace": document.get("documentNamespace")},
    )


def _parse_spdx_tag_value(text: str) -> ParsedSbom:
    components: dict[str, ParsedComponent] = {}
    current: ParsedComponent | None = None
    relationships: list[tuple[str, str, str]] = []
    for line in text.splitlines():
        if not line.strip() or line.startswith("#"):
            continue
        key, _, value = line.partition(":")
        value = value.strip()
        if key == "PackageName":
            current = ParsedComponent(uid="", name=value, version=None)
        elif key == "SPDXID":
            spdx_id = value
            if current is not None and current.uid == "":
                current.uid = spdx_id
                components[spdx_id] = current
        elif key == "PackageVersion" and current is not None:
            current.version = value
        elif key == "PackageSupplier" and current is not None:
            current.supplier = value
        elif key == "PackageLicenseConcluded" and current is not None:
            current.license = value
        elif key == "ExternalRef" and current is not None:
            parts = value.split()
            if len(parts) >= 3 and parts[0] == "PACKAGE-MANAGER" and parts[1].lower() == "purl":
                current.purl = parts[2]
                current.ecosystem = ecosystem_from_purl(parts[2])
        elif key == "Relationship":
            parts = value.split()
            if len(parts) >= 3:
                relationships.append((parts[0], parts[1], parts[2]))
    for parent_id, rel_type, child_id in relationships:
        if rel_type.upper() not in {"DEPENDS_ON", "CONTAINS"}:
            continue
        parent = components.get(parent_id)
        if parent and child_id in components:
            parent.depends_on.append(child_id)
    if not components:
        raise ValidationError("SPDX tag-value document contains no packages")
    return ParsedSbom(
        format="spdx-tag-value",
        spec_version=None,
        name="SPDX SBOM",
        components=list(components.values()),
    )
