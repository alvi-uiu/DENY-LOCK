from __future__ import annotations

from denylock.models import DenialRecord, PolicySpec


class PolicyRegistry:
    def __init__(self) -> None:
        self._policies: dict[str, PolicySpec] = {}

    def activate(self, policy: PolicySpec) -> None:
        existing = self._policies.get(policy.policy_id)
        if existing is not None and existing != policy:
            raise ValueError("policy identifier collision")
        self._policies[policy.policy_id] = policy

    @property
    def active(self) -> tuple[PolicySpec, ...]:
        return tuple(self._policies[key] for key in sorted(self._policies))


class DenialLedger:
    def __init__(self) -> None:
        self._records: tuple[DenialRecord, ...] = ()

    def append(self, record: DenialRecord) -> None:
        if any(existing.denial_id == record.denial_id for existing in self._records):
            raise ValueError("denial identifier collision")
        self._records = self._records + (record,)

    @property
    def records(self) -> tuple[DenialRecord, ...]:
        return self._records
