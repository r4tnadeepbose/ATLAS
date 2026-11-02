import json

import pytest

from app.core.exceptions import ValidationError
from app.modules.sbom.parsers import parse_sbom


CYCLONEDX_JSON = {
    "bomFormat": "CycloneDX",
    "specVersion": "1.5",
    "metadata": {"component": {"bom-ref": "app", "type": "application", "name": "demo-app", "version": "1.0"}},
    "components": [
        {
            "bom-ref": "pkg:npm/lodash@4.17.20",
            "type": "library",
            "name": "lodash",
            "version": "4.17.20",
            "purl": "pkg:npm/lodash@4.17.20",
            "supplier": {"name": "OpenJS"},
            "licenses": [{"license": {"id": "MIT"}}],
        }
    ],
    "dependencies": [{"ref": "app", "dependsOn": ["pkg:npm/lodash@4.17.20"]}],
}


def test_parse_cyclonedx_json():
    parsed = parse_sbom(json.dumps(CYCLONEDX_JSON).encode(), "bom.json")
    assert parsed.format == "cyclonedx-json"
    assert parsed.spec_version == "1.5"
    assert len(parsed.components) == 2
    lodash = next(component for component in parsed.components if component.name == "lodash")
    assert lodash.ecosystem == "npm"
    assert lodash.license == "MIT"
    app_component = next(component for component in parsed.components if component.uid == "app")
    assert "pkg:npm/lodash@4.17.20" in app_component.depends_on


def test_parse_cyclonedx_xml():
    xml = b"""<?xml version="1.0" encoding="UTF-8"?>
    <bom xmlns="http://cyclonedx.org/schema/bom/1.5" version="1">
      <metadata><component type="application" bom-ref="app"><name>demo</name><version>1.0</version></component></metadata>
      <components>
        <component type="library" bom-ref="pkg:pypi/requests@2.25.0">
          <name>requests</name><version>2.25.0</version><purl>pkg:pypi/requests@2.25.0</purl>
        </component>
      </components>
    </bom>"""
    parsed = parse_sbom(xml, "bom.xml")
    assert parsed.format == "cyclonedx-xml"
    requests = next(component for component in parsed.components if component.name == "requests")
    assert requests.ecosystem == "PyPI"


def test_parse_spdx_json():
    document = {
        "spdxVersion": "SPDX-2.3",
        "name": "demo",
        "packages": [
            {
                "SPDXID": "SPDXRef-Package-1",
                "name": "lodash",
                "versionInfo": "4.17.20",
                "licenseConcluded": "MIT",
                "externalRefs": [{"referenceType": "purl", "referenceLocator": "pkg:npm/lodash@4.17.20"}],
            }
        ],
        "relationships": [],
    }
    parsed = parse_sbom(json.dumps(document).encode(), "bom.spdx.json")
    assert parsed.format == "spdx-json"
    assert parsed.components[0].purl == "pkg:npm/lodash@4.17.20"


def test_parse_spdx_tag_value():
    text = """SPDXVersion: SPDX-2.3
DocumentName: demo
PackageName: requests
SPDXID: SPDXRef-requests
PackageVersion: 2.25.0
ExternalRef: PACKAGE-MANAGER purl pkg:pypi/requests@2.25.0
"""
    parsed = parse_sbom(text.encode(), "bom.spdx")
    assert parsed.format == "spdx-tag-value"
    assert parsed.components[0].version == "2.25.0"
    assert parsed.components[0].ecosystem == "PyPI"


def test_invalid_document_is_rejected():
    with pytest.raises(ValidationError):
        parse_sbom(b"not an sbom", "bom.txt")
    with pytest.raises(ValidationError):
        parse_sbom(b'{"hello": "world"}', "bom.json")
