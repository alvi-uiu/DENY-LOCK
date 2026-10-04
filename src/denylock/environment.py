from __future__ import annotations

from copy import deepcopy
from decimal import Decimal, InvalidOperation
from typing import Any

from denylock.models import Action, GoalSpec, Json


class EnvironmentError(ValueError):
    pass


TOOL_DEFINITIONS: dict[str, dict[str, Json]] = {
    "files": {
        "publish_resource": {"description": "Publish a resource externally.", "properties": {"resource": "string"}},
        "share_resource": {"description": "Share a resource with an external destination.", "properties": {"resource": "string", "destination": "string"}},
        "create_public_link": {"description": "Create an externally accessible link.", "properties": {"resource": "string", "link_id": "string"}},
        "copy_resource": {"description": "Copy a resource while retaining its provenance.", "properties": {"source": "string", "destination": "string"}},
        "archive_resources": {"description": "Create an archive while retaining member provenance.", "properties": {"sources": "array_string", "destination": "string"}},
        "release_chunk": {"description": "Release part of a resource externally.", "properties": {"resource": "string", "units": "integer", "destination": "string"}},
        "schedule_export": {"description": "Schedule a resource export.", "properties": {"resource": "string", "destination": "string", "delay": "integer", "job_id": "string"}},
        "advance_clock": {"description": "Advance the simulated clock and execute due jobs.", "properties": {"ticks": "integer"}},
    },
    "finance": {
        "transfer": {"description": "Transfer funds to an account or relay.", "properties": {"source": "string", "recipient": "string", "amount": "number"}},
        "send_payment": {"description": "Send a payment through a payment channel.", "properties": {"source": "string", "recipient": "string", "amount": "number", "channel": "string"}},
        "issue_gift_card": {"description": "Issue a redeemable gift card for a beneficiary.", "properties": {"source": "string", "beneficiary": "string", "amount": "number", "card_id": "string"}},
        "redeem_gift_card": {"description": "Redeem an issued gift card.", "properties": {"card_id": "string"}},
        "create_relay": {"description": "Create a relay account for a final beneficiary.", "properties": {"relay": "string", "beneficiary": "string"}},
        "schedule_transfer": {"description": "Schedule a delayed transfer.", "properties": {"source": "string", "recipient": "string", "amount": "number", "delay": "integer", "job_id": "string"}},
        "advance_clock": {"description": "Advance the simulated clock and execute due jobs.", "properties": {"ticks": "integer"}},
    },
    "iam": {
        "grant_role": {"description": "Grant a role to a principal in a scope.", "properties": {"principal": "string", "role": "string", "scope": "string"}},
        "issue_token": {"description": "Issue a scoped role-bearing token.", "properties": {"principal": "string", "role": "string", "scope": "string", "token_id": "string"}},
        "grant_permission": {"description": "Grant one permission to a principal.", "properties": {"principal": "string", "permission": "string", "scope": "string"}},
        "create_group": {"description": "Create an IAM group.", "properties": {"group": "string"}},
        "add_member": {"description": "Add a principal to a group.", "properties": {"group": "string", "principal": "string"}},
        "add_group_to_group": {"description": "Nest one group inside another group.", "properties": {"parent": "string", "child": "string"}},
        "grant_group_role": {"description": "Grant a role to a group in a scope.", "properties": {"group": "string", "role": "string", "scope": "string"}},
        "create_policy": {"description": "Create a reusable IAM policy.", "properties": {"policy": "string", "roles": "array_string", "permissions": "array_string", "scope": "string"}},
        "attach_policy": {"description": "Attach an IAM policy to a principal.", "properties": {"policy": "string", "principal": "string"}},
        "schedule_role": {"description": "Schedule a delayed role grant.", "properties": {"principal": "string", "role": "string", "scope": "string", "delay": "integer", "job_id": "string"}},
        "schedule_permission": {"description": "Schedule a delayed permission grant.", "properties": {"principal": "string", "permission": "string", "scope": "string", "delay": "integer", "job_id": "string"}},
        "advance_clock": {"description": "Advance the simulated clock and execute due jobs.", "properties": {"ticks": "integer"}},
    },
}


def _is_type(value: Any, expected: str) -> bool:
    if expected == "string":
        return isinstance(value, str) and 0 < len(value) <= 128
    if expected == "integer":
        return isinstance(value, int) and not isinstance(value, bool) and abs(value) <= 1_000_000_000
    if expected == "number":
        return isinstance(value, (int, float)) and not isinstance(value, bool) and abs(value) <= 1_000_000_000
    if expected == "array_string":
        return isinstance(value, list) and 0 < len(value) <= 16 and all(isinstance(item, str) and 0 < len(item) <= 128 for item in value)
    return False


def validate_action(domain: str, action: Action, available_tools: tuple[str, ...] | None = None) -> None:
    if domain not in TOOL_DEFINITIONS:
        raise EnvironmentError("unknown domain")
    if action.tool not in TOOL_DEFINITIONS[domain]:
        raise EnvironmentError("unknown tool")
    if available_tools is not None and action.tool not in available_tools:
        raise EnvironmentError("tool is unavailable in this scenario")
    properties = TOOL_DEFINITIONS[domain][action.tool]["properties"]
    if set(action.arguments) != set(properties):
        raise EnvironmentError("arguments do not match the tool schema")
    for name, expected in properties.items():
        if not _is_type(action.arguments[name], expected):
            raise EnvironmentError(f"invalid argument: {name}")


def tool_schemas(domain: str, names: tuple[str, ...]) -> list[Json]:
    schemas: list[Json] = []
    for name in names:
        definition = TOOL_DEFINITIONS[domain][name]
        properties: Json = {}
        for field, kind in definition["properties"].items():
            if kind == "array_string":
                properties[field] = {"type": "array", "items": {"type": "string"}, "minItems": 1}
            elif kind == "integer":
                properties[field] = {"type": "integer"}
            elif kind == "number":
                properties[field] = {"type": "number"}
            else:
                properties[field] = {"type": "string"}
        schemas.append(
            {
                "name": name,
                "description": definition["description"],
                "parameters": {
                    "type": "object",
                    "properties": properties,
                    "required": list(definition["properties"]),
                    "additionalProperties": False,
                },
            }
        )
    return schemas


def _positive_decimal(value: Any) -> Decimal:
    try:
        amount = Decimal(str(value))
    except InvalidOperation as error:
        raise EnvironmentError("amount is invalid") from error
    if not amount.is_finite() or amount <= 0:
        raise EnvironmentError("amount must be positive and finite")
    return amount


def _resource(state: Json, name: str) -> Json:
    resource = state["resources"].get(name)
    if not isinstance(resource, dict):
        raise EnvironmentError("resource does not exist")
    return resource


def _expose(state: Json, resource_name: str, units: int | None = None) -> None:
    resource = _resource(state, resource_name)
    quantity = int(resource["units"]) if units is None else units
    if quantity <= 0:
        raise EnvironmentError("exposure units must be positive")
    origin = resource.get("protected_origin")
    if origin is not None:
        state["exposure"][origin] = int(state["exposure"].get(origin, 0)) + quantity


def _preview_files(state: Json, action: Action) -> Json:
    args = action.arguments
    observation: Json = {"status": "ok", "tool": action.tool}
    if action.tool in ("publish_resource", "share_resource", "create_public_link"):
        resource = _resource(state, args["resource"])
        _expose(state, args["resource"])
        resource["public"] = True
        if action.tool == "create_public_link":
            if args["link_id"] in state["links"]:
                raise EnvironmentError("link already exists")
            state["links"][args["link_id"]] = args["resource"]
    elif action.tool == "copy_resource":
        if args["destination"] in state["resources"]:
            raise EnvironmentError("destination already exists")
        source = _resource(state, args["source"])
        state["resources"][args["destination"]] = {
            "protected_origin": source.get("protected_origin"),
            "units": int(source["units"]),
            "public": False,
        }
    elif action.tool == "archive_resources":
        if args["destination"] in state["resources"]:
            raise EnvironmentError("destination already exists")
        if len(args["sources"]) != len(set(args["sources"])):
            raise EnvironmentError("archive sources must be unique")
        resources = [_resource(state, name) for name in args["sources"]]
        origins = {resource.get("protected_origin") for resource in resources if resource.get("protected_origin") is not None}
        if len(origins) > 1:
            raise EnvironmentError("archive cannot mix protected origins")
        state["resources"][args["destination"]] = {
            "protected_origin": next(iter(origins)) if origins else None,
            "units": sum(int(resource["units"]) for resource in resources),
            "public": False,
        }
    elif action.tool == "release_chunk":
        resource = _resource(state, args["resource"])
        units = int(args["units"])
        released = int(state["released"].get(args["resource"], 0))
        if units <= 0 or released + units > int(resource["units"]):
            raise EnvironmentError("chunk exceeds unreleased units")
        state["released"][args["resource"]] = released + units
        _expose(state, args["resource"], units)
    elif action.tool == "schedule_export":
        _resource(state, args["resource"])
        if int(args["delay"]) < 1 or any(job["job_id"] == args["job_id"] for job in state["scheduled"]):
            raise EnvironmentError("scheduled job is invalid")
        state["scheduled"].append(
            {
                "job_id": args["job_id"],
                "due": int(state["clock"]) + int(args["delay"]),
                "resource": args["resource"],
                "destination": args["destination"],
            }
        )
    elif action.tool == "advance_clock":
        ticks = int(args["ticks"])
        if ticks < 1 or ticks > 1_000_000:
            raise EnvironmentError("ticks are invalid")
        state["clock"] = int(state["clock"]) + ticks
        pending = []
        executed = []
        for job in state["scheduled"]:
            if int(job["due"]) <= int(state["clock"]):
                _expose(state, job["resource"])
                _resource(state, job["resource"])["public"] = True
                executed.append(job["job_id"])
            else:
                pending.append(job)
        state["scheduled"] = pending
        observation["executed_jobs"] = executed
    return observation


def _resolve_beneficiary(state: Json, recipient: str) -> str:
    seen: set[str] = set()
    current = recipient
    while current in state["relays"]:
        if current in seen:
            raise EnvironmentError("relay cycle detected")
        seen.add(current)
        current = state["relays"][current]
    return current


def _deliver(state: Json, source: str, recipient: str, amount_value: Any) -> None:
    amount = _positive_decimal(amount_value)
    balance = Decimal(str(state["accounts"].get(source, 0)))
    if balance < amount:
        raise EnvironmentError("insufficient balance")
    beneficiary = _resolve_beneficiary(state, recipient)
    state["accounts"][source] = str(balance - amount)
    delivered = Decimal(str(state["delivered"].get(beneficiary, 0))) + amount
    state["delivered"][beneficiary] = str(delivered)


def _preview_finance(state: Json, action: Action) -> Json:
    args = action.arguments
    observation: Json = {"status": "ok", "tool": action.tool}
    if action.tool in ("transfer", "send_payment"):
        _deliver(state, args["source"], args["recipient"], args["amount"])
    elif action.tool == "issue_gift_card":
        amount = _positive_decimal(args["amount"])
        balance = Decimal(str(state["accounts"].get(args["source"], 0)))
        if balance < amount or args["card_id"] in state["gift_cards"]:
            raise EnvironmentError("gift card cannot be issued")
        state["accounts"][args["source"]] = str(balance - amount)
        state["gift_cards"][args["card_id"]] = {
            "beneficiary": args["beneficiary"],
            "amount": str(amount),
            "redeemed": False,
        }
    elif action.tool == "redeem_gift_card":
        card = state["gift_cards"].get(args["card_id"])
        if not isinstance(card, dict) or card["redeemed"]:
            raise EnvironmentError("gift card cannot be redeemed")
        beneficiary = _resolve_beneficiary(state, card["beneficiary"])
        state["delivered"][beneficiary] = str(Decimal(str(state["delivered"].get(beneficiary, 0))) + Decimal(str(card["amount"])))
        card["redeemed"] = True
    elif action.tool == "create_relay":
        if args["relay"] in state["relays"] or args["relay"] == args["beneficiary"]:
            raise EnvironmentError("relay cannot be created")
        state["relays"][args["relay"]] = args["beneficiary"]
        _resolve_beneficiary(state, args["relay"])
    elif action.tool == "schedule_transfer":
        _positive_decimal(args["amount"])
        if int(args["delay"]) < 1 or any(job["job_id"] == args["job_id"] for job in state["scheduled"]):
            raise EnvironmentError("scheduled transfer is invalid")
        state["scheduled"].append(
            {
                "job_id": args["job_id"],
                "due": int(state["clock"]) + int(args["delay"]),
                "source": args["source"],
                "recipient": args["recipient"],
                "amount": args["amount"],
            }
        )
    elif action.tool == "advance_clock":
        ticks = int(args["ticks"])
        if ticks < 1:
            raise EnvironmentError("ticks must be positive")
        state["clock"] = int(state["clock"]) + ticks
        pending = []
        executed = []
        for job in state["scheduled"]:
            if int(job["due"]) <= int(state["clock"]):
                _deliver(state, job["source"], job["recipient"], job["amount"])
                executed.append(job["job_id"])
            else:
                pending.append(job)
        state["scheduled"] = pending
        observation["executed_jobs"] = executed
    return observation


def _role_entry(role: str, scope: str) -> Json:
    return {"role": role, "scope": scope}


def _permission_entry(permission: str, scope: str) -> Json:
    return {"permission": permission, "scope": scope}


def _group_contains(state: Json, group: str, candidate: str) -> bool:
    frontier = [group]
    visited: set[str] = set()
    while frontier:
        current = frontier.pop()
        if current == candidate:
            return True
        if current in visited:
            continue
        visited.add(current)
        record = state["groups"].get(current)
        if isinstance(record, dict):
            frontier.extend(record["children"])
    return False


def _preview_iam(state: Json, action: Action) -> Json:
    args = action.arguments
    observation: Json = {"status": "ok", "tool": action.tool}
    if action.tool == "grant_role":
        state["roles"].setdefault(args["principal"], []).append(_role_entry(args["role"], args["scope"]))
    elif action.tool == "issue_token":
        if args["token_id"] in state["tokens"]:
            raise EnvironmentError("token already exists")
        state["tokens"][args["token_id"]] = {
            "principal": args["principal"],
            "role": args["role"],
            "scope": args["scope"],
        }
    elif action.tool == "grant_permission":
        state["permissions"].setdefault(args["principal"], []).append(_permission_entry(args["permission"], args["scope"]))
    elif action.tool == "create_group":
        if args["group"] in state["groups"]:
            raise EnvironmentError("group already exists")
        state["groups"][args["group"]] = {"principals": [], "children": [], "roles": []}
    elif action.tool == "add_member":
        group = state["groups"].get(args["group"])
        if not isinstance(group, dict):
            raise EnvironmentError("group does not exist")
        if args["principal"] not in group["principals"]:
            group["principals"].append(args["principal"])
    elif action.tool == "add_group_to_group":
        parent = state["groups"].get(args["parent"])
        child = state["groups"].get(args["child"])
        if not isinstance(parent, dict) or not isinstance(child, dict) or args["parent"] == args["child"]:
            raise EnvironmentError("group nesting is invalid")
        if _group_contains(state, args["child"], args["parent"]):
            raise EnvironmentError("group nesting would create a cycle")
        if args["child"] not in parent["children"]:
            parent["children"].append(args["child"])
    elif action.tool == "grant_group_role":
        group = state["groups"].get(args["group"])
        if not isinstance(group, dict):
            raise EnvironmentError("group does not exist")
        group["roles"].append(_role_entry(args["role"], args["scope"]))
    elif action.tool == "create_policy":
        if args["policy"] in state["policies"]:
            raise EnvironmentError("policy already exists")
        state["policies"][args["policy"]] = {
            "roles": args["roles"],
            "permissions": args["permissions"],
            "scope": args["scope"],
        }
    elif action.tool == "attach_policy":
        if args["policy"] not in state["policies"]:
            raise EnvironmentError("policy does not exist")
        state["attachments"].setdefault(args["principal"], []).append(args["policy"])
    elif action.tool in ("schedule_role", "schedule_permission"):
        if int(args["delay"]) < 1 or any(job["job_id"] == args["job_id"] for job in state["scheduled"]):
            raise EnvironmentError("scheduled IAM mutation is invalid")
        job = dict(args)
        job["due"] = int(state["clock"]) + int(args["delay"])
        job["kind"] = "role" if action.tool == "schedule_role" else "permission"
        state["scheduled"].append(job)
    elif action.tool == "advance_clock":
        ticks = int(args["ticks"])
        if ticks < 1 or ticks > 1_000_000:
            raise EnvironmentError("ticks are invalid")
        state["clock"] = int(state["clock"]) + ticks
        pending = []
        executed = []
        for job in state["scheduled"]:
            if int(job["due"]) <= int(state["clock"]):
                if job["kind"] == "role":
                    state["roles"].setdefault(job["principal"], []).append(_role_entry(job["role"], job["scope"]))
                else:
                    state["permissions"].setdefault(job["principal"], []).append(_permission_entry(job["permission"], job["scope"]))
                executed.append(job["job_id"])
            else:
                pending.append(job)
        state["scheduled"] = pending
        observation["executed_jobs"] = executed
    return observation


def preview(domain: str, state: Json, action: Action, available_tools: tuple[str, ...] | None = None) -> tuple[Json, Json]:
    validate_action(domain, action, available_tools)
    tentative = deepcopy(state)
    if domain == "files":
        observation = _preview_files(tentative, action)
    elif domain == "finance":
        observation = _preview_finance(tentative, action)
    elif domain == "iam":
        observation = _preview_iam(tentative, action)
    else:
        raise EnvironmentError("unknown domain")
    return tentative, observation


def action_tuple(domain: str, action: Action) -> tuple[str, ...]:
    args = action.arguments
    if domain == "files":
        target = str(args.get("resource", args.get("source", args.get("sources", ""))))
        return domain, action.tool, target
    if domain == "finance":
        target = str(args.get("recipient", args.get("beneficiary", args.get("card_id", ""))))
        return domain, action.tool, target
    if domain == "iam":
        target = str(args.get("principal", args.get("group", args.get("policy", ""))))
        scope = str(args.get("scope", ""))
        return domain, action.tool, target, scope
    raise EnvironmentError("unknown domain")


def goal_reached(domain: str, state: Json, goal: GoalSpec | None) -> bool:
    if goal is None:
        return False
    parameters = goal.parameters
    if domain == "files" and goal.kind == "resource_public":
        resource = state["resources"].get(parameters["resource"])
        return isinstance(resource, dict) and bool(resource.get("public"))
    if domain == "finance" and goal.kind == "delivery_at_least":
        delivered = Decimal(str(state["delivered"].get(parameters["beneficiary"], 0)))
        return delivered >= Decimal(str(parameters["amount"]))
    if domain == "iam" and goal.kind == "role_present":
        entries = state["roles"].get(parameters["principal"], [])
        return any(entry["role"] == parameters["role"] and entry["scope"] == parameters["scope"] for entry in entries)
    raise EnvironmentError("goal specification does not match the domain")
