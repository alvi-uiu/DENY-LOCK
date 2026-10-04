from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import TestCase

from denylock.benchmark import RouteAroundBench
from denylock.client import OpenAICompatibleClient
from denylock.codec import read_json
from denylock.controls import DenyLock
from denylock.models import Action, PolicySpec
from denylock.registry import DenialLedger, PolicyRegistry


ROOT = Path(__file__).resolve().parents[1]
SPEC = ROOT / "data" / "routearoundbench_v1.spec.json"


class SecurityTests(TestCase):
    def test_remote_plaintext_endpoint_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            OpenAICompatibleClient("http://example.com/v1", "model")

    def test_endpoint_credentials_are_rejected(self) -> None:
        with self.assertRaises(ValueError):
            OpenAICompatibleClient("https://user:secret@example.com/v1", "model")

    def test_unknown_policy_fails_closed(self) -> None:
        policy = PolicySpec("unknown", "unknown_kind", {}, {}, "1")
        decision = DenyLock((policy,)).decide({}, Action("tool", {}), {}, {}, ())
        self.assertFalse(decision.allow)
        self.assertTrue(decision.guard_error)

    def test_policy_registry_rejects_identifier_collision(self) -> None:
        registry = PolicyRegistry()
        registry.activate(PolicySpec("policy", "resource_exposure", {"protected_origin": "a"}, {"max_units": 1}, "1"))
        with self.assertRaises(ValueError):
            registry.activate(PolicySpec("policy", "resource_exposure", {"protected_origin": "b"}, {"max_units": 1}, "1"))

    def test_benchmark_manifest_round_trip(self) -> None:
        benchmark = RouteAroundBench.from_spec(SPEC)
        with TemporaryDirectory() as directory:
            root = Path(directory)
            jsonl = root / "benchmark.jsonl"
            manifest = root / "manifest.json"
            benchmark.materialize(jsonl, manifest)
            loaded = RouteAroundBench.from_jsonl(jsonl, manifest)
            self.assertEqual(loaded.digest(), read_json(manifest)["sha256"])

    def test_denial_ledger_is_append_only_from_public_interface(self) -> None:
        ledger = DenialLedger()
        self.assertEqual(ledger.records, ())
        self.assertFalse(hasattr(ledger.records, "append"))
