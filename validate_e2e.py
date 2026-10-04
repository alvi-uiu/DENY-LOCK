"""End-to-end validation of the DenyLock artifact with a scripted model client.

Exercises the full pipeline -- benchmark materialization, all four enforcement
conditions, the paraphrase subset, resume-safe artifacts, trace verification,
and paper-table generation -- without any external model calls.
"""
import json
import shutil
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "src"))

from denylock.agent import ModelAgent
from denylock.benchmark import RouteAroundBench
from denylock.client import ChatResponse
from denylock.reporting import write_report
from denylock.runner import ExperimentRunner, RunConfig
from denylock.codec import read_jsonl


class ScriptedClient:
    """Deterministic stand-in for an OpenAI-compatible model endpoint.

    Agent role: replays the scenario's witness plans in order (plan 0, then
    plan 1), then gives up -- the canonical route-around behavior. Guard role:
    always allows, exercising the comparator path that lets routes through.
    """

    def __init__(self, benchmark: RouteAroundBench, role: str) -> None:
        self.benchmark = benchmark
        self.role = role
        self.model = "scripted-agent-model" if role == "agent" else "scripted-guard-model"
        self.temperature = 0.0
        self.max_tokens = 512
        self.last_usage: dict = {}
        self.calls = 0
        self._by_goal = {scenario.goal: scenario for scenario in benchmark.scenarios}

    def _scenario_for(self, goal: str):
        if goal in self._by_goal:
            return self._by_goal[goal]
        for original_goal, scenario in self._by_goal.items():
            if original_goal and original_goal in goal:
                return scenario
        return None

    def chat(self, messages, seed=None, json_object=False) -> ChatResponse:
        self.calls += 1
        self.last_usage = {"prompt_tokens": 12, "completion_tokens": 6, "total_tokens": 18}
        user_payload = json.loads(messages[-1]["content"])
        if self.role == "guard":
            content = json.dumps({"allow": True, "reason": "scripted guard allows the tentative state"})
            return ChatResponse(content=content, usage={"prompt_tokens": 9, "completion_tokens": 4, "total_tokens": 13}, latency_seconds=0.002, request_id="guard")
        scenario = self._scenario_for(str(user_payload.get("goal", "")))
        history = tuple(user_payload.get("committed_and_denied_history", ()))
        if scenario is None or not scenario.known_plans:
            content = json.dumps({"finish": "impossible"})
        else:
            cursor = len(history)
            if cursor >= sum(len(plan) for plan in scenario.known_plans):
                content = json.dumps({"finish": "impossible"})
            else:
                for plan in scenario.known_plans:
                    if cursor < len(plan):
                        action = plan[cursor]
                        break
                    cursor -= len(plan)
                content = json.dumps(action.to_dict())
        return ChatResponse(content=content, usage={"prompt_tokens": 12, "completion_tokens": 6, "total_tokens": 18}, latency_seconds=0.001, request_id="agent")


def main() -> int:
    root = Path(__file__).resolve().parent
    shutil.rmtree(root / "validation_out", ignore_errors=True)
    benchmark = RouteAroundBench.from_spec(root / "data" / "routearoundbench_v1.spec.json")
    validation = benchmark.validate()
    assert validation["status"] == "valid" and validation["scenarios"] == 180, validation

    agent_client = ScriptedClient(benchmark, "agent")
    guard_client = ScriptedClient(benchmark, "guard")
    runner = ExperimentRunner(ModelAgent(agent_client), guard_client)
    config = RunConfig(
        conditions=("exact_call_lock", "tuple_lock", "full_trace_llm", "denylock"),
        repetitions=3,
        model_revision="scripted-r1",
        quantization="none",
        server_version="scripted-v1",
        hardware="validation-host",
        context_length=8192,
        output_dir=root / "validation_out",
        step_budget=10,
        max_new_tokens_per_turn=512,
        paraphrase_unsafe_count=1,
        paraphrase_benign_count=1,
    )
    manifest = runner.run_benchmark(benchmark, config)
    assert manifest["run_count"] == manifest["scenario_count"] * len(config.conditions) * config.repetitions, manifest["run_count"]
    print("runs:", manifest["run_count"], "benchmark_sha:", manifest["benchmark_sha256"][:12])

    rows = read_jsonl(root / "validation_out" / "results.jsonl")
    for row in rows:
        assert row["initial_denial"] == 1, row
        assert row["median_enforcement_seconds"] >= 0.0, row
        assert row["forbidden_reached"] in (True, False), row
        assert row["benign_goal_reached"] in (True, False), row
    variants = {str(row.get("prompt_variant")) for row in rows}
    assert variants == {"original", "paraphrase"}, variants

    report = write_report(
        root / "validation_out" / "results.jsonl",
        root / "validation_out" / "report",
        seed=91021,
        make_figure=False,
        paper_tables=True,
    )
    for key, summary in report["overall"].items():
        assert "route_around_success" in summary and "benign_recovery_rate" in summary, key
        assert "median_enforcement_seconds" in summary, key
    tables = root / "validation_out" / "report" / "tables"
    by_model = json.loads((tables / "by_model.json").read_text())
    by_route = json.loads((tables / "by_route_family.json").read_text())
    deltas = json.loads((tables / "paraphrase_deltas.json").read_text())
    assert isinstance(by_model, list) and by_model, "by_model table is empty"
    assert isinstance(by_route, dict) and by_route, "by_route table is empty"
    assert isinstance(deltas, list) and deltas, "paraphrase deltas are empty"

    for key in sorted(report["overall"]):
        s = report["overall"][key]
        print(f"  {key}: RAS={s['route_around_success']:.3f} BRR={s['benign_recovery_rate']:.3f} enforce_median={s['median_enforcement_seconds']:.6f}s")
    print("paraphrase deltas:", len(deltas))
    print("E2E VALIDATION OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
