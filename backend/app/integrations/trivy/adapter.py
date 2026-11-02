import json

from app.integrations.base import AdapterError, ToolAdapter, validate_target


class TrivyAdapter(ToolAdapter):
    def __init__(self) -> None:
        super().__init__(key="trivy", binary="trivy", category="container", capabilities=["image_scan", "sbom_scan", "filesystem_scan"])

    def scan_image(self, image: str, timeout: int = 900) -> dict:
        validate_target(image)
        result = self.run(["image", "--format", "json", "--quiet", "--scanners", "vuln,secret", image], timeout=timeout)
        if result.returncode != 0:
            raise AdapterError((result.stderr or "trivy failed")[:1000])
        try:
            return json.loads(result.stdout or "{}")
        except json.JSONDecodeError as exc:
            raise AdapterError("trivy returned malformed JSON") from exc
