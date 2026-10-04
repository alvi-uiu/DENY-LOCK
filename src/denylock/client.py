from __future__ import annotations

import json
import socket
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Any

from denylock.models import Json


@dataclass(frozen=True)
class ChatResponse:
    content: str
    usage: Json
    latency_seconds: float
    request_id: str | None


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, file_pointer, code, message, headers, new_url):
        return None


class OpenAICompatibleClient:
    def __init__(
        self,
        base_url: str,
        model: str,
        api_key: str | None = None,
        timeout_seconds: float = 120.0,
        retries: int = 2,
        temperature: float = 0.0,
        max_tokens: int = 256,
        max_response_bytes: int = 10_000_000,
    ) -> None:
        parsed = urllib.parse.urlparse(base_url)
        if parsed.scheme not in ("http", "https") or not parsed.netloc:
            raise ValueError("base_url must be an absolute HTTP or HTTPS URL")
        if parsed.username or parsed.password or parsed.query or parsed.fragment:
            raise ValueError("base_url cannot contain credentials, a query, or a fragment")
        if timeout_seconds <= 0 or retries < 0 or max_tokens < 1:
            raise ValueError("client limits are invalid")
        if parsed.scheme == "http" and parsed.hostname not in ("127.0.0.1", "localhost", "::1"):
            raise ValueError("unencrypted HTTP is restricted to loopback endpoints")
        if max_response_bytes < 1:
            raise ValueError("max_response_bytes must be positive")
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.api_key = api_key
        self.timeout_seconds = timeout_seconds
        self.retries = retries
        self.temperature = temperature
        self.max_tokens = max_tokens
        self.max_response_bytes = max_response_bytes
        self.last_usage: Json = {}
        self._opener = urllib.request.build_opener(_NoRedirect())

    def _endpoint(self) -> str:
        if self.base_url.endswith("/v1"):
            return f"{self.base_url}/chat/completions"
        return f"{self.base_url}/v1/chat/completions"

    def chat(self, messages: list[Json], seed: int, json_object: bool = True) -> ChatResponse:
        self.last_usage = {}
        payload: Json = {
            "model": self.model,
            "messages": messages,
            "temperature": self.temperature,
            "max_tokens": self.max_tokens,
            "seed": seed,
            "stream": False,
        }
        if json_object:
            payload["response_format"] = {"type": "json_object"}
        body = json.dumps(payload, ensure_ascii=False, allow_nan=False).encode("utf-8")
        headers = {"Content-Type": "application/json", "Accept": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        last_error: BaseException | None = None
        for attempt in range(self.retries + 1):
            request = urllib.request.Request(self._endpoint(), data=body, headers=headers, method="POST")
            started = time.monotonic()
            try:
                with self._opener.open(request, timeout=self.timeout_seconds) as response:
                    raw = response.read(self.max_response_bytes + 1)
                    request_id = response.headers.get("x-request-id")
                if len(raw) > self.max_response_bytes:
                    raise RuntimeError("API response exceeds the configured size limit")
                value = json.loads(raw.decode("utf-8"))
                if not isinstance(value, dict):
                    raise RuntimeError("API response must be an object")
                choices = value.get("choices")
                if not isinstance(choices, list) or not choices or not isinstance(choices[0], dict):
                    raise RuntimeError("API response has no choices")
                content = choices[0].get("message", {}).get("content")
                if not isinstance(content, str):
                    raise RuntimeError("API response content is missing")
                usage = value.get("usage") if isinstance(value.get("usage"), dict) else {}
                self.last_usage = usage
                return ChatResponse(content=content, usage=usage, latency_seconds=time.monotonic() - started, request_id=request_id)
            except urllib.error.HTTPError as error:
                last_error = error
                retryable = error.code == 429 or 500 <= error.code < 600
                if not retryable or attempt == self.retries:
                    break
            except (urllib.error.URLError, socket.timeout, TimeoutError, json.JSONDecodeError, RuntimeError) as error:
                last_error = error
                if attempt == self.retries:
                    break
            time.sleep(min(2.0 ** attempt, 4.0))
        raise RuntimeError(f"chat request failed: {type(last_error).__name__}") from last_error
