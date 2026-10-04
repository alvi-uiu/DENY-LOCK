from unittest import TestCase

from denylock.codec import canonical_json, sha256_text, strict_json_object
from denylock.trace import TraceChain, verify_trace


class CodecTraceTests(TestCase):
    def test_json_extraction(self) -> None:
        self.assertEqual(strict_json_object('{"allow":false}')["allow"], False)
        with self.assertRaises(ValueError):
            strict_json_object('prefix {"allow":false}')

    def test_canonical_hash_is_order_invariant(self) -> None:
        first = {"b": 2, "a": 1}
        second = {"a": 1, "b": 2}
        self.assertEqual(canonical_json(first), canonical_json(second))
        self.assertEqual(sha256_text(canonical_json(first)), sha256_text(canonical_json(second)))

    def test_trace_chain(self) -> None:
        chain = TraceChain()
        chain.append("first", {"value": 1})
        chain.append("second", {"value": 2})
        self.assertEqual(verify_trace(chain.events), chain.root_hash)
