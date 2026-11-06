"""Offline cloud-IAM policy analysis.

IAMosaic never contacts a cloud API. It only inspects policy JSON that the
operator exported, and reports over-permission grants for human review.

Rule catalogue
--------------
CG001  wildcard action or wildcard resource in an Allow statement
CG002  wildcard (public) principal in an Allow statement
CG003  Allow statement that grants by exclusion (NotAction / NotResource)
"""
from __future__ import annotations

from typing import Any

__all__ = [
    "RULE_CG001",
    "RULE_CG002",
    "RULE_CG003",
    "analyze_policy",
    "policy_edges",
    "policy_version",
]

RULE_CG001 = "CG001"
RULE_CG002 = "CG002"
RULE_CG003 = "CG003"

PUBLIC_PRINCIPAL = "*"
_PRINCIPAL_KEYS = ("AWS", "Service", "Federated", "CanonicalUser")


def _statement_entries(policy: Any) -> list[tuple[int, dict]]:
    """Return ``(original_index, statement)`` pairs, skipping malformed entries.

    The original index is preserved so every finding points at the statement the
    analyst sees in the exported file, even when earlier entries were malformed
    and therefore skipped.
    """
    if not isinstance(policy, dict):
        return []
    statements = policy.get("Statement")
    if statements is None:
        return []
    if isinstance(statements, dict):
        statements = [statements]
    if not isinstance(statements, list):
        return []
    return [(index, item) for index, item in enumerate(statements) if isinstance(item, dict)]


def _as_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return [item for item in value if isinstance(item, str)]
    return []


def _is_broad_action(action: str) -> bool:
    return action.strip() == "*"


def _is_wildcard_action(action: str) -> bool:
    return "*" in action


def _is_broad_resource(resource: str) -> bool:
    return resource.strip() == "*"


def _principal_values(value: Any) -> list[str]:
    """Flatten a policy ``Principal`` into a list of principal strings.

    AWS accepts a bare string, a list of strings, or a map such as
    ``{"AWS": "*"}``. Consumers of the edge list need one stable shape, so the
    map form is flattened here.
    """
    if value is None:
        return []
    if isinstance(value, str):
        return [value] if value.strip() else []
    if isinstance(value, list):
        return [item.strip() for item in value if isinstance(item, str) and item.strip()]
    if isinstance(value, dict):
        flattened: list[str] = []
        for key in _PRINCIPAL_KEYS:
            entry = value.get(key)
            if isinstance(entry, str):
                if entry.strip():
                    flattened.append(entry.strip())
            elif isinstance(entry, list):
                flattened.extend(
                    item.strip() for item in entry if isinstance(item, str) and item.strip()
                )
        if flattened:
            return flattened
        for entry in value.values():
            if isinstance(entry, str) and entry.strip():
                flattened.append(entry.strip())
            elif isinstance(entry, list):
                flattened.extend(
                    item.strip() for item in entry if isinstance(item, str) and item.strip()
                )
        return flattened
    return []


def _is_public_principal(principals: list[str]) -> bool:
    """True when any principal is the wildcard, i.e. access is public."""
    return any(principal.strip() == PUBLIC_PRINCIPAL for principal in principals)


def _effect(statement: dict) -> str:
    return str(statement.get("Effect") or "Allow").strip().lower()


def analyze_policy(policy: dict) -> list[dict]:
    """Report over-permission grants found in an exported IAM policy."""
    findings: list[dict] = []
    for index, statement in _statement_entries(policy):
        # A Deny statement removes permissions, so it is never an over-permission grant.
        if _effect(statement) == "deny":
            continue
        actions = _as_list(statement.get("Action"))
        resources = _as_list(statement.get("Resource"))
        not_actions = _as_list(statement.get("NotAction"))
        not_resources = _as_list(statement.get("NotResource"))
        principals = _principal_values(statement.get("Principal"))
        broad_action = any(_is_broad_action(action) for action in actions)
        wildcard_action = any(_is_wildcard_action(action) for action in actions)
        broad_resource = any(_is_broad_resource(resource) for resource in resources)
        public_principal = _is_public_principal(principals)
        base = {
            "statement_index": index,
            "sid": statement.get("Sid"),
            "actions": actions,
            "resources": resources,
            "principals": principals,
        }
        if wildcard_action or broad_resource:
            findings.append(
                {
                    **base,
                    "rule_id": RULE_CG001,
                    "severity": "high" if broad_action and broad_resource else "medium",
                    "recommendation": (
                        "Replace wildcard permissions with the smallest required "
                        "action and resource set."
                    ),
                }
            )
        if public_principal:
            findings.append(
                {
                    **base,
                    "rule_id": RULE_CG002,
                    "severity": "high" if (wildcard_action or broad_resource) else "medium",
                    "recommendation": (
                        "Replace the wildcard principal with the specific identities "
                        "or service principals that need access."
                    ),
                }
            )
        if not_actions or not_resources:
            findings.append(
                {
                    **base,
                    "rule_id": RULE_CG003,
                    "severity": "high",
                    "not_action": not_actions,
                    "not_resource": not_resources,
                    "recommendation": (
                        "List the allowed actions and resources explicitly instead of "
                        "granting everything except an exclusion."
                    ),
                }
            )
    return findings


def policy_edges(policy: dict) -> list[dict]:
    """Return the permission-relationship edges of an exported IAM policy.

    ``principal`` keeps the raw policy value for backwards compatibility;
    ``principals`` holds the same information normalised to a list of strings.
    """
    edges: list[dict] = []
    for index, statement in _statement_entries(policy):
        edges.append(
            {
                "statement_index": index,
                "sid": statement.get("Sid"),
                "principal": statement.get("Principal") or "unspecified",
                "principals": _principal_values(statement.get("Principal")),
                "action": _as_list(statement.get("Action")),
                "not_action": _as_list(statement.get("NotAction")),
                "resource": _as_list(statement.get("Resource")),
                "not_resource": _as_list(statement.get("NotResource")),
                "effect": statement.get("Effect") or "unspecified",
            }
        )
    return edges


def policy_version(policy: dict) -> str | None:
    """Return the ``Version`` declared by the policy, when present."""
    if not isinstance(policy, dict):
        return None
    version = policy.get("Version")
    if isinstance(version, str) and version.strip():
        return version.strip()
    return None
