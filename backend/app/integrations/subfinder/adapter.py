import json
from urllib.parse import urlparse

from app.integrations.base import AdapterError, ToolAdapter, validate_target


class SubfinderAdapter(ToolAdapter):
    def __init__(self) -> None:
        super().__init__(key="subfinder", binary="subfinder", category="attack_surface", capabilities=["subdomain_enumeration"])

    def enumerate(self, domain: str) -> list[str]:
        validate_target(domain)
        result = self.run(["-d", domain, "-silent"], timeout=300)
        if result.returncode != 0:
            raise AdapterError((result.stderr or "subfinder failed")[:1000])
        return sorted({line.strip() for line in result.stdout.splitlines() if line.strip()})


class HttpxAdapter(ToolAdapter):
    def __init__(self) -> None:
        super().__init__(key="httpx", binary="httpx", category="attack_surface", capabilities=["http_probe", "technology_detection"])

    def probe(self, targets: list[str]) -> list[dict]:
        if not targets:
            return []
        for target in targets:
            validate_target(target)
        result = self.run(
            ["-silent", "-json", "-status-code", "-title", "-tech-detect", "-server"],
            timeout=300,
            stdin_data="\n".join(targets) + "\n",
        )
        if result.returncode != 0:
            raise AdapterError((result.stderr or "httpx failed")[:1000])
        entries = []
        for line in result.stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                entries.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        return entries


class NmapAdapter(ToolAdapter):
    def __init__(self) -> None:
        super().__init__(key="nmap", binary="nmap", category="attack_surface", capabilities=["service_discovery", "port_scan"])

    def top_ports(self, target: str) -> dict:
        validate_target(target)
        result = self.run(["-Pn", "-sV", "--top-ports", "100", "-oX", "-", target], timeout=600)
        if result.returncode != 0:
            raise AdapterError((result.stderr or "nmap failed")[:1000])
        return {"xml": result.stdout}


class NucleiAdapter(ToolAdapter):
    def __init__(self) -> None:
        super().__init__(key="nuclei", binary="nuclei", category="attack_surface", capabilities=["template_scan"])

    def scan(self, target: str, severity: str = "critical,high,medium") -> list[dict]:
        validate_target(target)
        if not target.startswith(("http://", "https://")):
            raise AdapterError("Nuclei requires an HTTP(S) target")
        result = self.run(
            ["-u", target, "-jsonl", "-silent", "-severity", severity, "-timeout", "10", "-retries", "1"],
            timeout=600,
        )
        if result.returncode != 0:
            raise AdapterError((result.stderr or "nuclei failed")[:1000])
        findings = []
        for line in result.stdout.splitlines():
            try:
                findings.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        return findings


class ZapAdapter(ToolAdapter):
    def __init__(self) -> None:
        super().__init__(key="zap", binary="zap-cli", category="api_security", capabilities=["baseline_scan"])

    def baseline(self, target: str) -> dict:
        validate_target(target)
        parsed = urlparse(target)
        if parsed.scheme not in {"http", "https"}:
            raise AdapterError("ZAP requires an HTTP(S) target")
        result = self.run(["--api-key", "", "baseline", target], timeout=900)
        if result.returncode != 0:
            raise AdapterError((result.stderr or "zap-cli failed")[:1000])
        return {"stdout": result.stdout}


class GitleaksAdapter(ToolAdapter):
    def __init__(self) -> None:
        super().__init__(key="gitleaks", binary="gitleaks", category="secrets", capabilities=["secret_detection"])

    def detect(self, path: str) -> list[dict]:
        validate_target(path)
        result = self.run(["detect", "--source", path, "--report-format", "json", "--report-path", "/dev/stdout", "--no-banner"], timeout=300)
        if result.returncode not in (0, 1):
            raise AdapterError((result.stderr or "gitleaks failed")[:1000])
        try:
            return json.loads(result.stdout or "[]")
        except json.JSONDecodeError:
            return []
