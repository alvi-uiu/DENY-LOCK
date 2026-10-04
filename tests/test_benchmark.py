from pathlib import Path
from unittest import TestCase

from denylock.audit import audit_violation
from denylock.benchmark import DOMAINS, ROUTES, RouteAroundBench
from denylock.codec import sha256_value
from denylock.controls import DenyLock, ExactCallLock, TupleLock, action_fingerprint
from denylock.environment import action_tuple, goal_reached, preview
from denylock.models import DenialRecord


ROOT = Path(__file__).resolve().parents[1]
SPEC = ROOT / "data" / "routearoundbench_v1.spec.json"


class BenchmarkTests(TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.benchmark = RouteAroundBench.from_spec(SPEC)

    def test_matrix_counts(self) -> None:
        unsafe = [scenario for scenario in self.benchmark.scenarios if scenario.kind == "unsafe"]
        benign = [scenario for scenario in self.benchmark.scenarios if scenario.kind == "benign"]
        self.assertEqual(len(unsafe), 120)
        self.assertEqual(len(benign), 60)
        for domain in DOMAINS:
            for route in ROUTES:
                self.assertEqual(sum(s.domain == domain and s.route_family == route and s.kind == "unsafe" for s in unsafe), 10)
                self.assertEqual(sum(s.domain == domain and s.route_family == route and s.kind == "benign" for s in benign), 5)

    def test_validator(self) -> None:
        result = self.benchmark.validate()
        self.assertEqual(result["status"], "valid")

    def test_preview_never_mutates_input(self) -> None:
        for scenario in self.benchmark.scenarios:
            before = sha256_value(scenario.initial_state)
            preview(scenario.domain, scenario.initial_state, scenario.canonical_denied_action, scenario.available_tools)
            self.assertEqual(before, sha256_value(scenario.initial_state))

    def test_known_unsafe_plans_reach_oracle(self) -> None:
        for scenario in self.benchmark.scenarios:
            if scenario.kind != "unsafe":
                continue
            self.assertGreaterEqual(len(scenario.known_plans), 2)
            for plan in scenario.known_plans:
                state = scenario.initial_state
                reached = False
                for action in plan:
                    state, _ = preview(scenario.domain, state, action, scenario.available_tools)
                    reached = reached or audit_violation(scenario.policy, state)
                self.assertTrue(reached, scenario.scenario_id)

    def test_known_benign_plans_complete_safely(self) -> None:
        for scenario in self.benchmark.scenarios:
            if scenario.kind != "benign":
                continue
            for plan in scenario.known_plans:
                state = scenario.initial_state
                for action in plan:
                    state, _ = preview(scenario.domain, state, action, scenario.available_tools)
                    self.assertFalse(audit_violation(scenario.policy, state))
                self.assertTrue(goal_reached(scenario.domain, state, scenario.goal_spec))

    def test_denylock_preserves_every_unsafe_invariant(self) -> None:
        for scenario in self.benchmark.scenarios:
            if scenario.kind != "unsafe":
                continue
            control = DenyLock((scenario.policy,))
            for plan in scenario.known_plans:
                state = scenario.initial_state
                blocked = False
                history = ()
                for action in plan:
                    tentative, observation = preview(scenario.domain, state, action, scenario.available_tools)
                    decision = control.decide(state, action, tentative, observation, history)
                    if decision.allow:
                        state = tentative
                    else:
                        blocked = True
                    self.assertFalse(audit_violation(scenario.policy, state))
                self.assertTrue(blocked, scenario.scenario_id)

    def test_comparators_are_not_oracle_equivalents(self) -> None:
        exact_failures = 0
        tuple_failures = 0
        for scenario in self.benchmark.scenarios:
            if scenario.kind != "unsafe":
                continue
            canonical = scenario.canonical_denied_action
            denial = DenialRecord(
                denial_id=f"d-{scenario.scenario_id}",
                policy_id=scenario.policy.policy_id,
                policy_version=scenario.policy.version,
                action_fingerprint=action_fingerprint(canonical),
                action_tuple=action_tuple(scenario.domain, canonical),
                action=canonical,
                reason="test",
                step=0,
            )
            controls = (
                (ExactCallLock(denial), "exact"),
                (TupleLock(denial, lambda action, domain=scenario.domain: action_tuple(domain, action)), "tuple"),
            )
            for control, name in controls:
                state = scenario.initial_state
                for action in scenario.known_plans[0]:
                    tentative, observation = preview(scenario.domain, state, action, scenario.available_tools)
                    decision = control.decide(state, action, tentative, observation, ())
                    if decision.allow:
                        state = tentative
                    if audit_violation(scenario.policy, state):
                        if name == "exact":
                            exact_failures += 1
                        else:
                            tuple_failures += 1
                        break
        self.assertGreater(exact_failures, 0)
        self.assertGreater(tuple_failures, 0)
