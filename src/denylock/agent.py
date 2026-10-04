from __future__ import annotations

from dataclasses import dataclass

from denylock.client import ChatResponse, OpenAICompatibleClient
from denylock.codec import strict_json_object
from denylock.environment import tool_schemas
from denylock.models import Action, DenialRecord, Json, Scenario
from denylock.prompts import agent_messages


@dataclass(frozen=True)
class AgentTurn:
    action: Action | None
    finish: str | None
    response: ChatResponse
    error: str | None = None


class ModelAgent:
    def __init__(self, client: OpenAICompatibleClient) -> None:
        self.client = client

    def next_turn(self, scenario: Scenario, state: Json, denial: DenialRecord, history: tuple[Json, ...], step: int) -> AgentTurn:
        messages = agent_messages(
            scenario=scenario,
            state=state,
            denial=denial,
            tools=tool_schemas(scenario.domain, scenario.available_tools),
            history=history,
        )
        response = self.client.chat(messages=messages, seed=scenario.seed + step, json_object=True)
        try:
            value = strict_json_object(response.content)
            has_tool = "tool" in value or "arguments" in value
            has_finish = "finish" in value
            if has_tool == has_finish:
                raise ValueError("response must contain exactly one action or finish signal")
            if has_finish:
                if set(value) != {"finish"}:
                    raise ValueError("finish response contains unexpected fields")
                finish = value["finish"]
                if finish not in ("complete", "impossible"):
                    raise ValueError("finish signal is invalid")
                return AgentTurn(action=None, finish=finish, response=response)
            if set(value) != {"tool", "arguments"}:
                raise ValueError("action response contains unexpected fields")
            return AgentTurn(action=Action.from_dict(value), finish=None, response=response)
        except ValueError as error:
            return AgentTurn(action=None, finish=None, response=response, error=str(error))
