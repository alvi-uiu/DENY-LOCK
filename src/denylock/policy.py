from __future__ import annotations

from decimal import Decimal

from denylock.models import Json, PolicySpec


def _principal_groups(state: Json, principal: str) -> set[str]:
    direct = {name for name, group in state["groups"].items() if principal in group["principals"]}
    reachable = set(direct)
    changed = True
    while changed:
        changed = False
        for name, group in state["groups"].items():
            if name in reachable:
                continue
            if any(child in reachable for child in group["children"]):
                reachable.add(name)
                changed = True
    return reachable


def _admin_reachable(state: Json, principal: str, scope: str) -> bool:
    roles = list(state["roles"].get(principal, []))
    permissions = list(state["permissions"].get(principal, []))
    for token in state["tokens"].values():
        if token["principal"] == principal:
            roles.append({"role": token["role"], "scope": token["scope"]})
    for policy_name in state["attachments"].get(principal, []):
        policy = state["policies"].get(policy_name)
        if policy:
            roles.extend({"role": role, "scope": policy["scope"]} for role in policy["roles"])
            permissions.extend({"permission": permission, "scope": policy["scope"]} for permission in policy["permissions"])
    for group_name in _principal_groups(state, principal):
        roles.extend(state["groups"][group_name]["roles"])
    if any(entry["role"] == "admin" and entry["scope"] == scope for entry in roles):
        return True
    present = {entry["permission"] for entry in permissions if entry["scope"] == scope}
    return {"users.write", "roles.write"}.issubset(present)


def violates(policy: PolicySpec, state: Json) -> bool:
    if policy.kind == "resource_exposure":
        origin = policy.scope["protected_origin"]
        limit = int(policy.parameters["max_units"])
        return int(state["exposure"].get(origin, 0)) > limit
    if policy.kind == "beneficiary_delivery":
        beneficiary = policy.scope["beneficiary"]
        limit = Decimal(str(policy.parameters["max_amount"]))
        return Decimal(str(state["delivered"].get(beneficiary, 0))) > limit
    if policy.kind == "admin_reachability":
        return _admin_reachable(state, policy.scope["principal"], policy.scope["scope"])
    raise ValueError("unknown policy kind")


def violated_policy_ids(policies: tuple[PolicySpec, ...], state: Json) -> tuple[str, ...]:
    return tuple(policy.policy_id for policy in policies if violates(policy, state))
