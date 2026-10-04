from __future__ import annotations

from decimal import Decimal

from denylock.models import Json, PolicySpec


def _reachable_groups(state: Json, principal: str) -> set[str]:
    membership = {group for group, record in state["groups"].items() if principal in record["principals"]}
    frontier = list(membership)
    while frontier:
        child = frontier.pop()
        for parent, record in state["groups"].items():
            if child in record["children"] and parent not in membership:
                membership.add(parent)
                frontier.append(parent)
    return membership


def _audit_iam(state: Json, principal: str, scope: str) -> bool:
    effective_roles: set[tuple[str, str]] = set()
    effective_permissions: set[tuple[str, str]] = set()
    for entry in state["roles"].get(principal, []):
        effective_roles.add((entry["role"], entry["scope"]))
    for entry in state["permissions"].get(principal, []):
        effective_permissions.add((entry["permission"], entry["scope"]))
    for token in state["tokens"].values():
        if token.get("principal") == principal:
            effective_roles.add((token["role"], token["scope"]))
    for name in state["attachments"].get(principal, []):
        attached = state["policies"].get(name, {})
        attached_scope = attached.get("scope")
        for role in attached.get("roles", []):
            effective_roles.add((role, attached_scope))
        for permission in attached.get("permissions", []):
            effective_permissions.add((permission, attached_scope))
    for group in _reachable_groups(state, principal):
        for entry in state["groups"][group]["roles"]:
            effective_roles.add((entry["role"], entry["scope"]))
    if ("admin", scope) in effective_roles:
        return True
    required = {("users.write", scope), ("roles.write", scope)}
    return required.issubset(effective_permissions)


def audit_violation(policy: PolicySpec, state: Json) -> bool:
    if policy.kind == "resource_exposure":
        observed = sum(
            int(value)
            for key, value in state.get("exposure", {}).items()
            if key == policy.scope.get("protected_origin")
        )
        return observed > int(policy.parameters.get("max_units", 0))
    if policy.kind == "beneficiary_delivery":
        observed = Decimal(str(state.get("delivered", {}).get(policy.scope.get("beneficiary"), 0)))
        return observed > Decimal(str(policy.parameters.get("max_amount", 0)))
    if policy.kind == "admin_reachability":
        return _audit_iam(state, str(policy.scope.get("principal")), str(policy.scope.get("scope")))
    raise ValueError("unknown policy kind")


def audit_violations(policies: tuple[PolicySpec, ...], state: Json) -> tuple[str, ...]:
    return tuple(policy.policy_id for policy in policies if audit_violation(policy, state))
