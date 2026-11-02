import ipaddress
from urllib.parse import urlparse

from app.core.exceptions import ScopeViolationError


def _hostname(target: str) -> str:
    if "://" in target:
        parsed = urlparse(target)
        return (parsed.hostname or "").lower()
    return target.split("/")[0].split(":")[0].lower()


def authorize_target(target: str, scope: dict) -> str:
    """Return the normalized host if the target is inside the authorized scope.

    Scanning without an explicit scope is rejected: ATLAS never touches an
    asset that has not been authorized for assessment.
    """
    host = _hostname(target)
    if not host:
        raise ScopeViolationError("Target has no resolvable host")

    domains = [d.lower().lstrip(".") for d in scope.get("domains", []) if d]
    cidrs = [c for c in scope.get("cidrs", []) if c]
    explicit_ips = {ip for ip in scope.get("ips", []) if ip}

    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        address = None

    if address is not None:
        if str(address) in explicit_ips:
            return host
        for cidr in cidrs:
            try:
                if address in ipaddress.ip_network(cidr, strict=False):
                    return host
            except ValueError:
                continue
        raise ScopeViolationError(f"{host} is outside the authorized CIDR scope")

    for domain in domains:
        if host == domain or host.endswith(f".{domain}"):
            return host
    raise ScopeViolationError(f"{host} is not covered by an authorized domain")


def validate_scope(scope: dict) -> dict:
    if not scope or not any(scope.get(key) for key in ("domains", "cidrs", "ips")):
        raise ScopeViolationError("An explicit authorized scope is required before scanning")
    normalized = {
        "domains": sorted({str(item).lower().lstrip(".") for item in scope.get("domains", []) if item}),
        "cidrs": [],
        "ips": sorted({str(item) for item in scope.get("ips", []) if item}),
    }
    for cidr in scope.get("cidrs", []):
        try:
            normalized["cidrs"].append(str(ipaddress.ip_network(str(cidr), strict=False)))
        except ValueError as exc:
            raise ScopeViolationError(f"Invalid CIDR in scope: {cidr}") from exc
    return normalized
