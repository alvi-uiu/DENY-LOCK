from __future__ import annotations

from pathlib import Path
from unittest import TestCase

from denylock.agent import AgentTurn
from denylock.benchmark import RouteAroundBench, materialize_paraphrase
from denylock.client import ChatResponse
from denylock.runner import ExperimentRunner, RunConfig


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


class ParaphraseTests(TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.benchmark = RouteAroundBench.from_spec(SPEC)
        cls.scenario = next(s for s in cls.benchmark.scenarios if s.kind == "unsafe")

    def test_paraphrase_preserves_evaluated_quantities(self) -> None:
        variant = materialize_paraphrase(self.scenario, self.scenario.seed + 31000)
        self.assertEqual(variant.scenario_id, self.scenario.scenario_id)
        self.assertEqual(variant.initial_state, self.scenario.initial_state)
        self.assertEqual(variant.policy, self.scenario.policy)
        self.assertEqual(variant.canonical_denied_action, self.scenario.canonical_denied_action)
        self.assertEqual(variant.available_tools, self.scenario.available_tools)
        self.assertEqual(variant.known_plans, self.scenario.known_plans)
        self.assertEqual(variant.goal_spec, self.scenario.goal_spec)
        self.assertEqual(variant.max_steps, self.scenario.max_steps)
        self.assertEqual(variant.seed, self.scenario.seed)
        self.assertNotEqual(variant.goal, self.scenario.goal)
        self.assertTrue(variant.variant.endswith("_paraphrase"))

    def test_paraphrase_is_deterministic(self) -> None:
        first = materialize_paraphrase(self.scenario, 12345)
        second = materialize_paraphrase(self.scenario, 12345)
        self.assertEqual(first.goal, second.goal)

    def test_variant_recorded_in_results(self) -> None:
        agent = ScriptedAgent(self.scenario.known_plans[0])
        execution = ExperimentRunner(agent).run_scenario(self.scenario, "denylock", variant="paraphrase")
        self.assertEqual(execution.result.prompt_variant, "paraphrase")
        self.assertEqual(execution.result.scenario_id, self.scenario.scenario_id)

    def test_unknown_variant_is_rejected(self) -> None:
        agent = ScriptedAgent(self.scenario.known_plans[0])
        with self.assertRaises(ValueError):
            ExperimentRunner(agent).run_scenario(self.scenario, "denylock", variant="bogus")


class RunConfigTests(TestCase):
    @staticmethod
    def _config(**overrides):
        values = dict(
            conditions=("denylock",),
            repetitions=1,
            model_revision="r",
            quantization="none",
            server_version="s",
            hardware="h",
            context_length=8192,
            output_dir=Path("/tmp/denylock-config-test"),
        )
        values.update(overrides)
        return RunConfig(**values)

    def test_rejects_invalid_step_budget(self) -> None:
        with self.assertRaises(ValueError):
            self._config(step_budget=0)

    def test_rejects_max_new_tokens_below_one(self) -> None:
        with self.assertRaises(ValueError):
            self._config(max_new_tokens_per_turn=0)

    def test_rejects_paraphrase_without_original_repetition(self) -> None:
        with self.assertRaises(ValueError):
            self._config(repetitions=1, paraphrase_unsafe_count=1)

    def test_accepts_paired_paraphrase_configuration(self) -> None:
        config = self._config(repetitions=3, paraphrase_unsafe_count=1, paraphrase_benign_count=1)
        self.assertEqual(config.step_budget, 10)
        self.assertEqual(config.max_new_tokens_per_turn, 512)
