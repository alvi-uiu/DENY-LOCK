from pathlib import Path
from unittest import TestCase

from denylock.agent import AgentTurn
from denylock.benchmark import RouteAroundBench
from denylock.client import ChatResponse
from denylock.runner import ExperimentRunner


ROOT = Path(__file__).resolve().parents[1]
SPEC = ROOT / "data" / "routearoundbench_v1.spec.json"


class DummyClient:
    model = "scripted-test-model"
    temperature = 0.0
    max_tokens = 1


class ScriptedAgent:
    def __init__(self, actions) -> None:
        self.client = DummyClient()
        self.actions = tuple(actions)
        self.index = 0

    def next_turn(self, scenario, state, denial, history, step) -> AgentTurn:
        response = ChatResponse(content="{}", usage={}, latency_seconds=0.0, request_id=None)
        if self.index >= len(self.actions):
            return AgentTurn(action=None, finish="impossible", response=response)
        action = self.actions[self.index]
        self.index += 1
        return AgentTurn(action=action, finish=None, response=response)


class RunnerTests(TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        benchmark = RouteAroundBench.from_spec(SPEC)
        cls.scenario = next(s for s in benchmark.scenarios if s.kind == "unsafe" and s.route_family == "state_indirection" and s.domain == "files")

    def test_exact_call_comparator_can_be_routed_around(self) -> None:
        agent = ScriptedAgent(self.scenario.known_plans[0])
        execution = ExperimentRunner(agent).run_scenario(self.scenario, "exact_call_lock")
        self.assertTrue(execution.result.forbidden_reached)
        self.assertEqual(execution.result.outcome, "forbidden_completion")

    def test_denylock_blocks_forbidden_commit(self) -> None:
        agent = ScriptedAgent(self.scenario.known_plans[0] + self.scenario.known_plans[1])
        execution = ExperimentRunner(agent).run_scenario(self.scenario, "denylock")
        self.assertFalse(execution.result.forbidden_reached)
        self.assertEqual(execution.result.outcome, "safe_refusal")
        self.assertGreaterEqual(execution.result.denied_actions, 2)
