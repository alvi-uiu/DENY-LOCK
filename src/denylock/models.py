from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Literal

Json = dict[str, Any]
Outcome = Literal[
    "safe_completion",
    "safe_refusal",
    "forbidden_completion",
    "invalid_action",
    "abandoned",
    "timeout",
    "guard_error",
    "api_error",
]


@dataclass(frozen=True)
class Action:
    tool: str
    arguments: Json

    @classmethod
    def from_dict(cls, value: Json) -> Action:
        tool = value.get("tool")
        arguments = value.get("arguments")
        if not isinstance(tool, str) or not tool:
            raise ValueError("action.tool must be a non-empty string")
        if not isinstance(arguments, dict):
            raise ValueError("action.arguments must be an object")
        return cls(tool=tool, arguments=arguments)

    def to_dict(self) -> Json:
        return {"tool": self.tool, "arguments": self.arguments}


@dataclass(frozen=True)
class PolicySpec:
    policy_id: str
    kind: str
    scope: Json
    parameters: Json
    version: str = "1"

    @classmethod
    def from_dict(cls, value: Json) -> PolicySpec:
        required = ("policy_id", "kind", "scope", "parameters", "version")
        if any(key not in value for key in required):
            raise ValueError("policy is missing a required field")
        if not all(isinstance(value[key], str) for key in ("policy_id", "kind", "version")):
            raise ValueError("policy identifiers must be strings")
        if not isinstance(value["scope"], dict) or not isinstance(value["parameters"], dict):
            raise ValueError("policy scope and parameters must be objects")
        return cls(
            policy_id=value["policy_id"],
            kind=value["kind"],
            scope=value["scope"],
            parameters=value["parameters"],
            version=value["version"],
        )

    def to_dict(self) -> Json:
        return asdict(self)


@dataclass(frozen=True)
class GoalSpec:
    kind: str
    parameters: Json

    @classmethod
    def from_dict(cls, value: Json) -> GoalSpec:
        kind = value.get("kind")
        parameters = value.get("parameters")
        if not isinstance(kind, str) or not isinstance(parameters, dict):
            raise ValueError("goal_spec is malformed")
        return cls(kind=kind, parameters=parameters)

    def to_dict(self) -> Json:
        return asdict(self)


@dataclass(frozen=True)
class Scenario:
    scenario_id: str
    kind: Literal["unsafe", "benign"]
    domain: Literal["files", "finance", "iam"]
    route_family: Literal["tool_substitution", "cumulative_splitting", "state_indirection", "delayed_execution"]
    variant: str
    goal: str
    initial_state: Json
    policy: PolicySpec
    canonical_denied_action: Action
    available_tools: tuple[str, ...]
    known_plans: tuple[tuple[Action, ...], ...]
    goal_spec: GoalSpec | None
    max_steps: int
    seed: int

    @classmethod
    def from_dict(cls, value: Json) -> Scenario:
        kind = value.get("kind")
        domain = value.get("domain")
        route_family = value.get("route_family")
        if kind not in ("unsafe", "benign"):
            raise ValueError("scenario kind is invalid")
        if domain not in ("files", "finance", "iam"):
            raise ValueError("scenario domain is invalid")
        if route_family not in ("tool_substitution", "cumulative_splitting", "state_indirection", "delayed_execution"):
            raise ValueError("scenario route family is invalid")
        plans = tuple(
            tuple(Action.from_dict(action) for action in plan)
            for plan in value.get("known_plans", [])
        )
        goal_value = value.get("goal_spec")
        goal_spec = GoalSpec.from_dict(goal_value) if isinstance(goal_value, dict) else None
        tools = value.get("available_tools")
        if not isinstance(tools, list) or not all(isinstance(tool, str) for tool in tools):
            raise ValueError("available_tools must be a list of strings")
        max_steps = value.get("max_steps")
        seed = value.get("seed")
        if not isinstance(max_steps, int) or max_steps < 1:
            raise ValueError("max_steps must be positive")
        if not isinstance(seed, int):
            raise ValueError("seed must be an integer")
        return cls(
            scenario_id=str(value["scenario_id"]),
            kind=kind,
            domain=domain,
            route_family=route_family,
            variant=str(value["variant"]),
            goal=str(value["goal"]),
            initial_state=value["initial_state"],
            policy=PolicySpec.from_dict(value["policy"]),
            canonical_denied_action=Action.from_dict(value["canonical_denied_action"]),
            available_tools=tuple(tools),
            known_plans=plans,
            goal_spec=goal_spec,
            max_steps=max_steps,
            seed=seed,
        )

    def to_dict(self) -> Json:
        return {
            "scenario_id": self.scenario_id,
            "kind": self.kind,
            "domain": self.domain,
            "route_family": self.route_family,
            "variant": self.variant,
            "goal": self.goal,
            "initial_state": self.initial_state,
            "policy": self.policy.to_dict(),
            "canonical_denied_action": self.canonical_denied_action.to_dict(),
            "available_tools": list(self.available_tools),
            "known_plans": [[action.to_dict() for action in plan] for plan in self.known_plans],
            "goal_spec": self.goal_spec.to_dict() if self.goal_spec else None,
            "max_steps": self.max_steps,
            "seed": self.seed,
        }


@dataclass(frozen=True)
class DenialRecord:
    denial_id: str
    policy_id: str
    policy_version: str
    action_fingerprint: str
    action_tuple: tuple[str, ...]
    action: Action
    reason: str
    step: int

    def to_dict(self) -> Json:
        value = asdict(self)
        value["action_tuple"] = list(self.action_tuple)
        return value


@dataclass(frozen=True)
class Decision:
    allow: bool
    reason: str
    violated_policy_ids: tuple[str, ...] = ()
    tentative_state: Json | None = None
    observation: Json | None = None
    guard_error: bool = False
    evidence: Json | None = None


@dataclass(frozen=True)
class TraceEvent:
    index: int
    event: str
    payload: Json
    previous_hash: str
    event_hash: str

    def to_dict(self) -> Json:
        return asdict(self)


@dataclass
class Usage:
    prompt_tokens: int = 0
    completion_tokens: int = 0
    total_tokens: int = 0
    requests: int = 0

    def add(self, value: Json) -> None:
        self.prompt_tokens += int(value.get("prompt_tokens", 0))
        self.completion_tokens += int(value.get("completion_tokens", 0))
        self.total_tokens += int(value.get("total_tokens", 0))
        self.requests += 1

    def to_dict(self) -> Json:
        return asdict(self)


@dataclass(frozen=True)
class RunResult:
    run_id: str
    scenario_id: str
    repetition: int
    seed: int
    model: str
    condition: str
    outcome: Outcome
    domain: str
    route_family: str
    scenario_kind: str
    forbidden_reached: bool
    benign_goal_reached: bool
    committed_actions: int
    denied_actions: int
    invalid_actions: int
    steps: int
    latency_seconds: float
    usage: Json
    final_state_hash: str
    trace_root_hash: str
    initial_denial: int = 0
    median_enforcement_seconds: float = 0.0
    max_enforcement_seconds: float = 0.0
    prompt_variant: str = "original"
    error: str | None = None

    def to_dict(self) -> Json:
        return asdict(self)
