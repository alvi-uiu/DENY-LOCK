from __future__ import annotations

from denylock.codec import canonical_json, sha256_text
from denylock.models import Json, TraceEvent


class TraceChain:
    def __init__(self) -> None:
        self._events: list[TraceEvent] = []
        self._root = "0" * 64

    @property
    def root_hash(self) -> str:
        return self._root

    @property
    def events(self) -> tuple[TraceEvent, ...]:
        return tuple(self._events)

    def append(self, event: str, payload: Json) -> TraceEvent:
        index = len(self._events)
        envelope = {"index": index, "event": event, "payload": payload, "previous_hash": self._root}
        event_hash = sha256_text(canonical_json(envelope))
        record = TraceEvent(index=index, event=event, payload=payload, previous_hash=self._root, event_hash=event_hash)
        self._events.append(record)
        self._root = event_hash
        return record


def verify_trace(events: tuple[TraceEvent, ...]) -> str:
    root = "0" * 64
    for expected_index, record in enumerate(events):
        if record.index != expected_index or record.previous_hash != root:
            raise ValueError("trace chain ordering is invalid")
        envelope = {"index": record.index, "event": record.event, "payload": record.payload, "previous_hash": record.previous_hash}
        if sha256_text(canonical_json(envelope)) != record.event_hash:
            raise ValueError("trace event hash is invalid")
        root = record.event_hash
    return root
