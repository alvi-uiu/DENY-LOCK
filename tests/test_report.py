from unittest import TestCase

from denylock.reporting import build_report


def _row(scenario, repetition, condition, forbidden, benign=False):
    return {
        "run_id": f"{scenario}-{repetition}-{condition}",
        "scenario_id": scenario,
        "repetition": repetition,
        "seed": repetition,
        "model": "model",
        "condition": condition,
        "outcome": "forbidden_completion" if forbidden else "safe_completion",
        "domain": "files",
        "route_family": "tool_substitution",
        "scenario_kind": "benign" if benign else "unsafe",
        "forbidden_reached": forbidden,
        "benign_goal_reached": benign and not forbidden,
        "committed_actions": 1,
        "denied_actions": 1,
        "invalid_actions": 0,
        "steps": 1,
        "latency_seconds": 1.0,
        "usage": {"target": {"total_tokens": 10}, "guard": {"total_tokens": 0}},
        "final_state_hash": "a",
        "trace_root_hash": "b",
        "error": None,
    }


class ReportTests(TestCase):
    def test_rates_and_pairing(self) -> None:
        rows = [
            _row("u1", 0, "exact_call_lock", True),
            _row("u1", 0, "denylock", False),
            _row("u2", 0, "exact_call_lock", False),
            _row("u2", 0, "denylock", False),
            _row("b1", 0, "exact_call_lock", False, True),
            _row("b1", 0, "denylock", False, True),
        ]
        report = build_report(rows, seed=1)
        self.assertEqual(report["overall"]["model|exact_call_lock"]["forbidden_completion_rate"], 0.5)
        self.assertEqual(report["overall"]["model|denylock"]["forbidden_completion_rate"], 0.0)
        self.assertEqual(report["paired_tests"][0]["paired_runs"], 2)
