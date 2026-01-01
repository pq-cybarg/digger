"""OpenAI-compatible chat client.

Default target is llama.cpp's ``llama-server`` running on
``http://127.0.0.1:8080/v1`` with a GLM, Qwen, Llama, or other GGUF model
loaded. ollama (``http://127.0.0.1:11434/v1``) works the same way, as does
vllm and any other OpenAI-compatible local backend.

We do **not** require an `openai` python client — the request is a plain
HTTP POST. This keeps the dependency surface small and avoids vendor lock.
"""

from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass, field
from typing import Any, Iterable, Optional

import requests


@dataclass
class LLMConfig:
    base_url: str = "http://127.0.0.1:8080/v1"
    model: str = "GLM-4.6"
    api_key: str = "local"  # llama.cpp ignores this; ollama/openai-compat may want a token
    temperature: float = 0.2
    max_tokens: int = 1024
    timeout: float = 120.0
    system_prompt: str = ""
    extra_headers: dict[str, str] = field(default_factory=dict)

    @classmethod
    def from_env(cls) -> "LLMConfig":
        return cls(
            base_url=os.environ.get("DIGGER_LLM_BASE_URL", cls.base_url),
            model=os.environ.get("DIGGER_LLM_MODEL", cls.model),
            api_key=os.environ.get("DIGGER_LLM_API_KEY", cls.api_key),
            temperature=float(os.environ.get("DIGGER_LLM_TEMPERATURE", cls.temperature)),
            max_tokens=int(os.environ.get("DIGGER_LLM_MAX_TOKENS", cls.max_tokens)),
            timeout=float(os.environ.get("DIGGER_LLM_TIMEOUT", cls.timeout)),
        )


class LLMError(RuntimeError):
    pass


class LLMClient:
    def __init__(self, config: Optional[LLMConfig] = None):
        self.config = config or LLMConfig.from_env()

    def health(self) -> dict[str, Any]:
        url = self.config.base_url.rstrip("/") + "/models"
        try:
            r = requests.get(
                url,
                headers={"Authorization": f"Bearer {self.config.api_key}"},
                timeout=10,
            )
            return {"ok": r.status_code == 200, "status": r.status_code, "body": r.text[:200]}
        except requests.RequestException as exc:
            return {"ok": False, "error": str(exc)}

    def chat(self, messages: list[dict[str, str]], **kwargs) -> str:
        """Send chat-completion request, return assistant content."""
        from digger.opsec.airgap import assert_network_allowed
        assert_network_allowed(f"llm-chat:{self.config.base_url}")
        url = self.config.base_url.rstrip("/") + "/chat/completions"
        payload = {
            "model": kwargs.get("model", self.config.model),
            "messages": messages,
            "temperature": kwargs.get("temperature", self.config.temperature),
            "max_tokens": kwargs.get("max_tokens", self.config.max_tokens),
            "stream": False,
        }
        # llama.cpp jinja templating accepts grammar/format constraints
        if "response_format" in kwargs:
            payload["response_format"] = kwargs["response_format"]
        if "tools" in kwargs:
            payload["tools"] = kwargs["tools"]
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.config.api_key}",
            **self.config.extra_headers,
        }
        try:
            r = requests.post(url, json=payload, headers=headers, timeout=self.config.timeout)
        except requests.RequestException as exc:
            raise LLMError(f"request to {url} failed: {exc}") from exc
        if r.status_code != 200:
            raise LLMError(f"LLM returned {r.status_code}: {r.text[:500]}")
        try:
            data = r.json()
        except json.JSONDecodeError as exc:
            raise LLMError(f"non-JSON response: {r.text[:500]}") from exc
        choices = data.get("choices") or []
        if not choices:
            raise LLMError(f"no choices in response: {data}")
        return choices[0].get("message", {}).get("content", "") or ""

    def json_chat(self, messages: list[dict[str, str]], schema: Optional[dict] = None, **kwargs) -> dict:
        """Chat with JSON-mode request; parse the response as a JSON object."""
        if schema:
            kwargs["response_format"] = {"type": "json_schema", "json_schema": {"name": "out", "schema": schema, "strict": True}}
        else:
            kwargs["response_format"] = {"type": "json_object"}
        raw = self.chat(messages, **kwargs)
        # Some local servers leak prose before JSON; salvage by hunting braces.
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            start = raw.find("{")
            end = raw.rfind("}")
            if start >= 0 and end > start:
                try:
                    return json.loads(raw[start : end + 1])
                except json.JSONDecodeError:
                    pass
            raise LLMError(f"could not parse JSON from response: {raw[:500]}")
