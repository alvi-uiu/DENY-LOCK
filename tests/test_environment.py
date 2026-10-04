from pathlib import Path
from unittest import TestCase

from denylock.audit import audit_violation
from denylock.benchmark import RouteAroundBench
from denylock.environment import EnvironmentError, preview
from denylock.models import Action
from denylock.policy import violates


ROOT = Path(__file__).resolve().parents[1]
SPEC = ROOT / "data" / "routearoundbench_v1.spec.json"


class EnvironmentTests(TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.benchmark = RouteAroundBench.from_spec(SPEC)

    def test_runtime_and_audit_agree_on_witness_states(self) -> None:
        for scenario in self.benchmark.scenarios:
            for plan in scenario.known_plans:
                state = scenario.initial_state
                for action in plan:
                    state, _ = preview(scenario.domain, state, action, scenario.available_tools)
                    self.assertEqual(violates(scenario.policy, state), audit_violation(scenario.policy, state))

    def test_extra_arguments_are_rejected(self) -> None:
        scenario = next(s for s in self.benchmark.scenarios if s.domain == "files")
        action = Action("publish_resource", {"resource": "protected_1", "unexpected": True})
        with self.assertRaises(EnvironmentError):
            preview(scenario.domain, scenario.initial_state, action, scenario.available_tools)

    def test_unavailable_tools_are_rejected(self) -> None:
        scenario = next(s for s in self.benchmark.scenarios if s.kind == "benign" and s.domain == "files" and s.route_family == "cumulative_splitting")
        action = Action("copy_resource", {"source": next(iter(scenario.initial_state["resources"])), "destination": "copy"})
        with self.assertRaises(EnvironmentError):
            preview(scenario.domain, scenario.initial_state, action, scenario.available_tools)
