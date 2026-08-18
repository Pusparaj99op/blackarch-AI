"""Single source of truth for authorization scope.

Every red-team tool (and the `check_scope` MCP tool that Skills use to
pre-flight) calls `is_authorized()` here. Nothing else in this project
is allowed to decide independently whether a target may be scanned.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from datetime import date, datetime
from pathlib import Path

import yaml

PROJECT_ROOT = Path(__file__).resolve().parents[2]
SCOPE_PATH = PROJECT_ROOT / "scope.yaml"
EXAMPLE_SCOPE_PATH = PROJECT_ROOT / "scope.example.yaml"


@dataclass(frozen=True)
class ScopeTarget:
    host: str | None
    cidr: str | None
    authorized_by: str | None
    authorization_ref: str | None
    expires: str | None


@dataclass(frozen=True)
class ScopeConfig:
    targets: tuple[ScopeTarget, ...]


def _parse_target(raw: dict) -> ScopeTarget:
    return ScopeTarget(
        host=raw.get("host"),
        cidr=raw.get("cidr"),
        authorized_by=raw.get("authorized_by"),
        authorization_ref=raw.get("authorization_ref"),
        expires=raw.get("expires"),
    )


def load_scope(path: Path = SCOPE_PATH) -> ScopeConfig:
    if not path.exists():
        return ScopeConfig(targets=())
    with path.open() as f:
        raw = yaml.safe_load(f) or {}
    targets = tuple(_parse_target(t) for t in (raw.get("targets") or []))
    return ScopeConfig(targets=targets)


def _is_expired(expires: str | None) -> bool:
    if not expires:
        return False
    try:
        expiry = datetime.strptime(expires, "%Y-%m-%d").date()
    except ValueError:
        # Unparseable expiry is treated as expired (fail closed).
        return True
    return date.today() > expiry


def _host_matches(target: str, scope_target: ScopeTarget) -> bool:
    if scope_target.host is not None and scope_target.host == target:
        return True
    if scope_target.cidr is not None:
        try:
            network = ipaddress.ip_network(scope_target.cidr, strict=False)
            addr = ipaddress.ip_address(target)
        except ValueError:
            return False
        return addr in network
    return False


def is_authorized(target: str, config: ScopeConfig | None = None) -> tuple[bool, str]:
    """Return (authorized, reason). Fails closed: no match => not authorized."""
    config = config if config is not None else load_scope()

    if not config.targets:
        return False, (
            f"'{target}' is not in scope.yaml (scope.yaml has no targets defined). "
            "Add an entry under `targets:` with host/cidr, authorized_by, "
            "authorization_ref, and expires before scanning. See scope.example.yaml."
        )

    for scope_target in config.targets:
        if _host_matches(target, scope_target):
            if _is_expired(scope_target.expires):
                return False, (
                    f"'{target}' matches a scope.yaml entry but its authorization "
                    f"expired on {scope_target.expires}. Renew authorization before scanning."
                )
            return True, f"'{target}' is authorized (matched scope.yaml entry)."

    return False, (
        f"'{target}' does not match any entry in scope.yaml. "
        "Add it under `targets:` with authorization details before scanning."
    )
