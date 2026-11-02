import json

from app.integrations.base import AdapterError, ToolAdapter, validate_target


class GrypeAdapter(ToolAdapter):
    def __init__(self) -> None:
        super().__init__(key="grype", binary="grype", category="vulnerability", capabilities=["scan_image", "scan_sbom", "scan_directory"])

    def scan(self, target: str) -> dict:
        validate_target(target)
        result = self.run([target, "-o", "json", "-q"], timeout=600)
        if result.returncode != 0:
            raise AdapterError((result.stderr or "grype failed")[:1000])
        try:
            return json.loads(result.stdout or "{}")
        except json.JSONDecodeError as exc:
            raise AdapterError("grype returned malformed JSON") from exc
