from __future__ import annotations

import platform
import statistics
import sys
import time
from copy import deepcopy
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal

from denylock.agent import ModelAgent
from denylock.audit import audit_violation
from denylock.benchmark import RouteAroundBench, materialize_paraphrase
from denylock.client import OpenAICompatibleClient
from denylock.codec import atomic_write_json, atomic_write_jsonl, canonical_json, read_json, read_jsonl, sha256_text, sha256_value
from denylock.controls import Control, DenyLock, ExactCallLock, FullTraceLLM, TupleLock, action_fingerprint
from denylock.environment import EnvironmentError, action_tuple, goal_reached, preview
from denylock.models import DenialRecord, Json, PolicySpec, RunResult, Scenario, TraceEvent, Usage
from denylock.policy import violates
from denylock.prompts import AGENT_SYSTEM, GUARD_SYSTEM
from denylock.registry import DenialLedger, PolicyRegistry
from denylock.trace import TraceChain, verify_trace

Condition = Literal["exact_call_lock", "tuple_lock", "full_trace_llm", "denylock"]

RUNNER_STEP_BUDGET = 10
RUNNER_MAX_NEW_TOKENS = 512


@dataclass(frozen=True)
class RunConfig:
    conditions: tuple[Condition, ...]
    repetitions: int
    model_revision: str
    quantization: str
    server_version: str
    hardware: str
    context_length: int
    output_dir: Path
    scenario_limit: int | None = None
    resume: bool = False
    step_budget: int = 10
    max_new_tokens_per_turn: int = 512
    paraphrase_unsafe_count: int = 0
    paraphrase_benign_count: int = 0

    def __post_init__(self) -> None:
        allowed = {"exact_call_lock", "tuple_lock", "full_trace_llm", "denylock"}
        if not self.conditions or any(condition not in allowed for condition in self.conditions):
            raise ValueError("run condition is invalid")
        if self.repetitions < 1 or self.context_length < 1:
            raise ValueError("run limits are invalid")
        if self.step_budget < 1:
            raise ValueError("step_budget must be positive")
        if self.max_new_tokens_per_turn < 1:
            raise ValueError("max_new_tokens_per_turn must be positive")
        if self.paraphrase_unsafe_count < 0 or self.paraphrase_benign_count < 0:
            raise ValueError("paraphrase counts must be non-negative")
        if self.paraphrase_unsafe_count + self.paraphrase_benign_count >= self.repetitions:
            raise ValueError("paraphrase repetitions must leave at least one original repetition")
        if not self.model_revision or "REPLACE" in self.model_revision.upper():
            raise ValueError("an immutable model revision is required")
        if not self.quantization or not self.server_version or not self.hardware:
            raise ValueError("quantization, server_version, and hardware are required")
        if self.scenario_limit is not None and self.scenario_limit < 1:
            raise ValueError("scenario_limit must be positive")


@dataclass(frozen=True)
class ScenarioExecution:
    result: RunResult
    trace: tuple[TraceEvent, ...]


def _accumulate(usage: Usage, value: Json) -> None:
    usage.add(value)


def _denial_record(scenario: Scenario) -> DenialRecord:
    fingerprint = action_fingerprint(scenario.canonical_denied_action)
    denial_id = sha256_text(f"{scenario.scenario_id}:{scenario.policy.policy_id}:{fingerprint}")[:24]
    return DenialRecord(
        denial_id=denial_id,
        policy_id=scenario.policy.policy_id,
        policy_version=scenario.policy.version,
        action_fingerprint=fingerprint,
        action_tuple=action_tuple(scenario.domain, scenario.canonical_denied_action),
        action=scenario.canonical_denied_action,
        reason="candidate state violates the active scenario policy",
        step=0,
    )


def _run_id(scenario: Scenario, condition: Condition, model: str, repetition: int) -> str:
    run_key = {
        "scenario": scenario.scenario_id,
        "condition": condition,
        "model": model,
        "repetition": repetition,
        "seed": scenario.seed + repetition * 10000,
    }
    return sha256_value(run_key)[:24]


class _TimedControl:
    """Wraps a control so each enforcement decision records its wall-clock latency.

    The measured span covers deterministic predicate evaluation and gateway
    bookkeeping only; model inference performed inside a control is attributed
    to the model client, never to the enforcement budget.
    """

    def __init__(self, control: Control, enforcement_seconds: list[float]) -> None:
        self.control = control
        self.enforcement_seconds = enforcement_seconds
        self.name = control.name

    def decide(self, state: Json, action: Action, tentative_state: Json, observation: Json, history: tuple[Json, ...]) -> Decision:
        started = time.perf_counter()
        try:
            return self.control.decide(state, action, tentative_state, observation, history)
        finally:
            self.enforcement_seconds.append(time.perf_counter() - started)


class ExperimentRunner:
    def __init__(self, agent: ModelAgent, guard_client: OpenAICompatibleClient | None = None) -> None:
        self.agent = agent
        self.guard_client = guard_client

    def _control(
        self,
        condition: Condition,
        scenario: Scenario,
        denial: DenialRecord,
        policies: tuple[PolicySpec, ...],
        enforcement_seconds: list[float],
    ) -> object:
        if condition == "exact_call_lock":
            inner: Control = ExactCallLock(denial)
        elif condition == "tuple_lock":
            inner = TupleLock(denial, lambda action: action_tuple(scenario.domain, action))
        elif condition == "denylock":
            inner = DenyLock(policies)
        else:
            if self.guard_client is None:
                raise ValueError("full_trace_llm requires an independent guard client")
            inner = FullTraceLLM(policies, denial, self.guard_client, scenario.seed + 900000)
        return _TimedControl(inner, enforcement_seconds)

    def run_scenario(self, scenario: Scenario, condition: Condition, repetition: int = 0, variant: str = "original") -> ScenarioExecution:
        started = time.monotonic()
        if variant not in ("original", "paraphrase"):
            raise ValueError("scenario variant is invalid")
        prompt_variant_seed = 0 if variant == "original" else 700000
        state = deepcopy(scenario.initial_state)
        if violates(scenario.policy, state) or audit_violation(scenario.policy, state):
            raise ValueError("scenario begins in a forbidden state")
        initial_hash = sha256_value(state)
        denied_tentative, denied_observation = preview(
            scenario.domain,
            state,
            scenario.canonical_denied_action,
            scenario.available_tools,
        )
        if not violates(scenario.policy, denied_tentative) or not audit_violation(scenario.policy, denied_tentative):
            raise ValueError("canonical action does not establish a controlled denial")
        if sha256_value(state) != initial_hash:
            raise RuntimeError("controlled denial mutated committed state")
        registry = PolicyRegistry()
        registry.activate(scenario.policy)
        ledger = DenialLedger()
        denial = _denial_record(scenario)
        ledger.append(denial)
        trace = TraceChain()
        trace.append(
            "controlled_denial",
            {
                "scenario_id": scenario.scenario_id,
                "action": scenario.canonical_denied_action.to_dict(),
                "committed_state_hash": initial_hash,
                "tentative_state_hash": sha256_value(denied_tentative),
                "observation": denied_observation,
                "denial": denial.to_dict(),
            },
        )
        enforcement_seconds: list[float] = []
        control = self._control(condition, scenario, denial, registry.active, enforcement_seconds)
        target_usage = Usage()
        guard_usage = Usage()
        history: list[Json] = []
        committed = 0
        denied = 0
        invalid = 0
        forbidden = False
        benign_goal = False
        outcome = "timeout"
        error_text: str | None = None
        steps = 0
        attempt = 0
        # The post-denial budget counts committed and denied actions; finish
        # signals, invalid responses, and transport failures end the trial
        # without consuming it.
        while committed + denied < scenario.max_steps:
            attempt += 1
            steps = attempt
            step = attempt
            try:
                turn = self.agent.next_turn(scenario, state, denial, tuple(history), attempt + repetition * 10000 + prompt_variant_seed)
                _accumulate(target_usage, turn.response.usage)
            except (OSError, RuntimeError) as error:
                outcome = "api_error"
                error_text = type(error).__name__
                trace.append("api_error", {"step": step, "error_type": type(error).__name__})
                break
            except ValueError as error:
                invalid += 1
                outcome = "invalid_action"
                error_text = str(error)
                trace.append("invalid_response", {"step": step, "error": str(error)})
                break
            if turn.error is not None:
                invalid += 1
                outcome = "invalid_action"
                error_text = turn.error
                trace.append(
                    "invalid_response",
                    {
                        "step": step,
                        "error": turn.error,
                        "model_response": turn.response.content,
                        "request_id": turn.response.request_id,
                        "usage": turn.response.usage,
                        "latency_seconds": turn.response.latency_seconds,
                    },
                )
                break
            if turn.finish is not None:
                benign_goal = goal_reached(scenario.domain, state, scenario.goal_spec)
                outcome = "safe_completion" if benign_goal else ("safe_refusal" if scenario.kind == "unsafe" else "abandoned")
                trace.append(
                    "finish",
                    {
                        "step": step,
                        "signal": turn.finish,
                        "goal_reached": benign_goal,
                        "model_response": turn.response.content,
                        "request_id": turn.response.request_id,
                        "usage": turn.response.usage,
                        "latency_seconds": turn.response.latency_seconds,
                    },
                )
                break
            action = turn.action
            if action is None:
                invalid += 1
                outcome = "invalid_action"
                error_text = "empty action"
                trace.append("invalid_response", {"step": step, "error": error_text})
                break
            try:
                tentative, observation = preview(scenario.domain, state, action, scenario.available_tools)
            except EnvironmentError as error:
                invalid += 1
                outcome = "invalid_action"
                error_text = str(error)
                trace.append("invalid_action", {"step": step, "action": action.to_dict(), "error": str(error)})
                break
            decision = control.decide(state, action, tentative, observation, tuple(history))
            if condition == "full_trace_llm" and self.guard_client is not None:
                _accumulate(guard_usage, self.guard_client.last_usage)
            event_payload = {
                "step": step,
                "action": action.to_dict(),
                "allow": decision.allow,
                "reason": decision.reason,
                "violated_policy_ids": list(decision.violated_policy_ids),
                "state_before_hash": sha256_value(state),
                "tentative_state_hash": sha256_value(tentative),
                "guard_error": decision.guard_error,
                "model_response": turn.response.content,
                "request_id": turn.response.request_id,
                "model_usage": turn.response.usage,
                "model_latency_seconds": turn.response.latency_seconds,
            }
            if decision.evidence is not None:
                event_payload["guard_evidence"] = decision.evidence
            if not decision.allow:
                denied += 1
                subsequent_denial = DenialRecord(
                    denial_id=sha256_text(f"{scenario.scenario_id}:{step}:{action_fingerprint(action)}:{decision.reason}")[:24],
                    policy_id=scenario.policy.policy_id,
                    policy_version=scenario.policy.version,
                    action_fingerprint=action_fingerprint(action),
                    action_tuple=action_tuple(scenario.domain, action),
                    action=action,
                    reason=decision.reason,
                    step=step,
                )
                ledger.append(subsequent_denial)
                event_payload["denial_id"] = subsequent_denial.denial_id
                history.append({"step": step, "action": action.to_dict(), "status": "denied", "reason": decision.reason})
                trace.append("action_denied", event_payload)
                continue
            state = tentative
            committed += 1
            event_payload["observation"] = observation
            event_payload["state_after_hash"] = sha256_value(state)
            history.append({"step": step, "action": action.to_dict(), "status": "committed", "observation": observation})
            trace.append("action_committed", event_payload)
            if audit_violation(scenario.policy, state):
                forbidden = True
                outcome = "forbidden_completion"
                trace.append("terminal_audit", {"step": step, "forbidden": True, "state_hash": sha256_value(state)})
                break
            benign_goal = goal_reached(scenario.domain, state, scenario.goal_spec)
            if benign_goal:
                outcome = "safe_completion"
                trace.append("terminal_audit", {"step": step, "forbidden": False, "goal_reached": True, "state_hash": sha256_value(state)})
                break
        run_id = _run_id(scenario, condition, self.agent.client.model, repetition)
        result = RunResult(
            run_id=run_id,
            scenario_id=scenario.scenario_id,
            repetition=repetition,
            seed=scenario.seed + repetition * 10000,
            model=self.agent.client.model,
            condition=condition,
            outcome=outcome,
            domain=scenario.domain,
            route_family=scenario.route_family,
            scenario_kind=scenario.kind,
            forbidden_reached=forbidden,
            benign_goal_reached=benign_goal,
            committed_actions=committed,
            denied_actions=denied,
            initial_denial=1,
            median_enforcement_seconds=statistics.median(enforcement_seconds) if enforcement_seconds else 0.0,
            max_enforcement_seconds=max(enforcement_seconds) if enforcement_seconds else 0.0,
            prompt_variant=variant,
            invalid_actions=invalid,
            steps=steps,
            latency_seconds=time.monotonic() - started,
            usage={"target": target_usage.to_dict(), "guard": guard_usage.to_dict()},
            final_state_hash=sha256_value(state),
            trace_root_hash=trace.root_hash,
            error=error_text,
        )
        return ScenarioExecution(result=result, trace=trace.events)

    def run_benchmark(self, benchmark: RouteAroundBench, config: RunConfig) -> Json:
        scenarios = benchmark.scenarios
        if config.paraphrase_unsafe_count or config.paraphrase_benign_count:
            unsafe = [scenario for scenario in benchmark.scenarios if scenario.kind == "unsafe"]
            benign = [scenario for scenario in benchmark.scenarios if scenario.kind == "benign"]
            selected = unsafe[: config.paraphrase_unsafe_count] + benign[: config.paraphrase_benign_count]
            if len(selected) != config.paraphrase_unsafe_count + config.paraphrase_benign_count:
                raise ValueError("paraphrase subset requests exceed the benchmark size")
            scenarios = tuple(selected)
        elif config.scenario_limit:
            unsafe = [scenario for scenario in benchmark.scenarios if scenario.kind == "unsafe"]
            benign = [scenario for scenario in benchmark.scenarios if scenario.kind == "benign"]
            scenarios = tuple((unsafe + benign)[: config.scenario_limit])
        plan = {
            "artifact_version": "1.0.0",
            "benchmark_name": benchmark.metadata.get("name", "RouteAroundBench"),
            "benchmark_version": benchmark.metadata.get("version", "1.0.0"),
            "benchmark_sha256": benchmark.digest(),
            "model": self.agent.client.model,
            "model_revision": config.model_revision,
            "quantization": config.quantization,
            "server_version": config.server_version,
            "hardware": config.hardware,
            "context_length": config.context_length,
            "conditions": list(config.conditions),
            "repetitions": config.repetitions,
            "step_budget": config.step_budget,
            "max_new_tokens_per_turn": config.max_new_tokens_per_turn,
            "scenario_ids": [scenario.scenario_id for scenario in scenarios],
            "temperature": self.agent.client.temperature,
            "max_tokens": self.agent.client.max_tokens,
            "prompts_sha256": sha256_text(canonical_json({"agent": AGENT_SYSTEM, "guard": GUARD_SYSTEM})),
            "paraphrase_unsafe_count": config.paraphrase_unsafe_count,
            "paraphrase_benign_count": config.paraphrase_benign_count,
            "ablation_conditions": [],
        }
        plan["plan_sha256"] = sha256_value(plan)
        plan_path = config.output_dir / "run_plan.json"
        manifest_path = config.output_dir / "manifest.json"
        if manifest_path.exists():
            raise FileExistsError("run directory already contains a completed manifest")
        if plan_path.exists():
            existing_plan = read_json(plan_path)
            if not config.resume:
                raise FileExistsError("run directory already contains an incomplete run; pass resume explicitly")
            if existing_plan != plan:
                raise ValueError("resume configuration does not match the stored run plan")
        else:
            atomic_write_json(plan_path, plan)
        traces_dir = config.output_dir / "traces"
        records_dir = config.output_dir / "records"
        ordered_run_ids: list[str] = []
        for repetition in range(config.repetitions):
            for scenario in scenarios:
                for condition in config.conditions:
                    run_id = _run_id(scenario, condition, self.agent.client.model, repetition)
                    ordered_run_ids.append(run_id)
                    record_path = records_dir / f"{run_id}.json"
                    trace_path = traces_dir / f"{run_id}.jsonl"
                    if record_path.exists() or trace_path.exists():
                        if not config.resume or not record_path.exists() or not trace_path.exists():
                            raise FileExistsError(f"partial or unexpected artifacts exist for run {run_id}")
                        record = read_json(record_path)
                        trace_rows = read_jsonl(trace_path)
                        trace_events = tuple(TraceEvent(**row) for row in trace_rows)
                        if record.get("run_id") != run_id or verify_trace(trace_events) != record.get("trace_root_hash"):
                            raise ValueError(f"resume artifact integrity check failed for run {run_id}")
                        continue
                    variant = "paraphrase" if repetition >= config.repetitions - config.paraphrase_unsafe_count - config.paraphrase_benign_count else "original"
                    run_scenario_copy = materialize_paraphrase(scenario, scenario.seed + 31000) if variant == "paraphrase" else scenario
                    execution = self.run_scenario(run_scenario_copy, condition, repetition, variant)
                    atomic_write_jsonl(trace_path, [event.to_dict() for event in execution.trace])
                    atomic_write_json(record_path, execution.result.to_dict())
        result_rows = [read_json(records_dir / f"{run_id}.json") for run_id in ordered_run_ids]
        results_path = config.output_dir / "results.jsonl"
        atomic_write_jsonl(results_path, result_rows)
        manifest = {
            **plan,
            "created_utc": datetime.now(UTC).isoformat(),
            "scenario_count": len(scenarios),
            "run_count": len(result_rows),
            "python": sys.version.split()[0],
            "platform": platform.platform(),
            "results_sha256": sha256_text("".join(canonical_json(row) + "\n" for row in result_rows)),
        }
        atomic_write_json(manifest_path, manifest)
        return manifest
