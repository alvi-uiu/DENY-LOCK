from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Protocol

from denylock.client import OpenAICompatibleClient
from denylock.codec import canonical_json, sha256_text, strict_json_object
from denylock.models import Action, Decision, DenialRecord, Json, PolicySpec
from denylock.policy import violated_policy_ids
from denylock.prompts import guard_messages


def action_fingerprint(action: Action) -> str:
    return sha256_text(canonical_json(action.to_dict()))


class Control(Protocol):
    name: str

    def decide(self, state: Json, action: Action, tentative_state: Json, observation: Json, history: tuple[Json, ...]) -> Decision:
        ...


@dataclass(frozen=True)
class ExactCallLock:
    denial: DenialRecord
    name: str = "exact_call_lock"

    def decide(self, state: Json, action: Action, tentative_state: Json, observation: Json, history: tuple[Json, ...]) -> Decision:
        blocked = action_fingerprint(action) == self.denial.action_fingerprint
        return Decision(
            allow=not blocked,
            reason="exact denied call remains blocked" if blocked else "action differs from the denied call",
            tentative_state=tentative_state,
            observation=observation,
        )


@dataclass(frozen=True)
class TupleLock:
    denial: DenialRecord
    tuple_resolver: Callable[[Action], tuple[str, ...]]
    name: str = "tuple_lock"

    def decide(self, state: Json, action: Action, tentative_state: Json, observation: Json, history: tuple[Json, ...]) -> Decision:
        current = self.tuple_resolver(action)
        blocked = current == self.denial.action_tuple
        return Decision(
            allow=not blocked,
            reason="denied semantic tuple remains blocked" if blocked else "action has a different tuple",
            tentative_state=tentative_state,
            observation=observation,
        )


@dataclass(frozen=True)
class DenyLock:
    policies: tuple[PolicySpec, ...]
    name: str = "denylock"

    def decide(self, state: Json, action: Action, tentative_state: Json, observation: Json, history: tuple[Json, ...]) -> Decision:
        try:
            violations = violated_policy_ids(self.policies, tentative_state)
        except (KeyError, TypeError, ValueError) as error:
            return Decision(
                allow=False,
                reason=f"enforcement adapter failed closed: {type(error).__name__}",
                tentative_state=tentative_state,
                observation=observation,
                guard_error=True,
            )
        return Decision(
            allow=not violations,
            reason="tentative state violates active policy" if violations else "all active policies hold",
            violated_policy_ids=violations,
            tentative_state=tentative_state,
            observation=observation,
        )


@dataclass
class FullTraceLLM:
    policies: tuple[PolicySpec, ...]
    denial: DenialRecord
    client: OpenAICompatibleClient
    seed: int
    name: str = "full_trace_llm"

    def decide(self, state: Json, action: Action, tentative_state: Json, observation: Json, history: tuple[Json, ...]) -> Decision:
        messages = guard_messages(
            policies=self.policies,
            denial=self.denial,
            state=state,
            action=action,
            tentative_state=tentative_state,
            history=history,
        )
        response = None
        try:
            response = self.client.chat(messages=messages, seed=self.seed, json_object=True)
            value = strict_json_object(response.content)
            if set(value) != {"allow", "reason"}:
                raise ValueError("guard response contains unexpected fields")
            allow = value.get("allow")
            reason = value.get("reason")
            if not isinstance(allow, bool) or not isinstance(reason, str) or not 0 < len(reason) <= 500:
                raise ValueError("guard response is malformed")
            return Decision(
                allow=allow,
                reason=reason,
                tentative_state=tentative_state,
                observation=observation,
                evidence={
                    "response": response.content,
                    "request_id": response.request_id,
                    "usage": response.usage,
                    "latency_seconds": response.latency_seconds,
                },
            )
        except (OSError, RuntimeError, ValueError) as error:
            return Decision(
                allow=False,
                reason=f"guard failed closed: {type(error).__name__}",
                tentative_state=tentative_state,
                observation=observation,
                guard_error=True,
                evidence={
                    "error_type": type(error).__name__,
                    "response": response.content if response is not None else None,
                    "request_id": response.request_id if response is not None else None,
                    "usage": response.usage if response is not None else {},
                    "latency_seconds": response.latency_seconds if response is not None else None,
                },
            )
