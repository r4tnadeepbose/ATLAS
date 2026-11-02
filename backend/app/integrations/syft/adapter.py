import json

from app.integrations.base import AdapterError, ToolAdapter, validate_target


class SyftAdapter(ToolAdapter):
    def __init__(self) -> None:
        super().__init__(
            key="syft",
            binary="syft",
            category="sbom",
            capabilities=["sbom_generation", "container_images", "source_directories"],
        )

    def generate(self, target: str, output_format: str = "cyclonedx-json") -> dict:
        validate_target(target)
        try:
            result = self.run([target, "-o", output_format, "-q"], timeout=300)
        except Exception as exc:  # noqa: BLE001
            return {"ok": False, "error": str(exc)}
        if result.returncode != 0:
            return {"ok": False, "error": (result.stderr or "syft failed")[:1000]}
        if not result.stdout.strip():
            return {"ok": False, "error": "syft produced no output"}
        return {"ok": True, "content": result.stdout.encode("utf-8"), "format": output_format}

    def scan(self, target: str) -> dict:
        generate = self.generate(target)
        if not generate["ok"]:
            raise AdapterError(generate["error"])
        return json.loads(generate["content"])
