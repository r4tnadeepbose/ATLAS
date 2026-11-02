"""Provider-independent LLM access.

Supported providers: OpenAI-compatible chat completions, Anthropic Messages,
Ollama chat, or "none" (deterministic heuristic triage). Output is treated as
advisory only; ATLAS never mutates findings, executes remediation, or closes
anything based on model output.
"""

from __future__ import annotations

import json
from dataclasses import dataclass

import httpx

from app.config import settings

SYSTEM_PROMPT = (
    "You are a senior security analyst for ATLAS, an enterprise security orchestration platform. "
    "Analyse the supplied finding conservatively. Do not invent evidence, CVE details, or exploitation status. "
    "If context is insufficient, say so and lower confidence. Respond with a single JSON object using exactly "
    "these keys: classification, summary, technical_impact, business_impact, recommendation, priority, "
    "false_positive_likelihood, confidence. priority must be one of critical/high/medium/low. "
    "false_positive_likelihood and confidence are floats between 0 and 1. "
    "Never claim to have performed remediation."
)


@dataclass
class LlmResponse:
    text: str
    provider: str
    model: str
    tokens_input: int
    tokens_output: int


class ProviderNotConfigured(RuntimeError):
    pass


class ProviderError(RuntimeError):
    pass


def _post_json(url: str, payload: dict, headers: dict, timeout: int) -> dict:
    try:
        response = httpx.post(url, json=payload, headers=headers, timeout=timeout)
        response.raise_for_status()
        return response.json()
    except httpx.HTTPStatusError as exc:
        raise ProviderError(f"AI provider returned HTTP {exc.response.status_code}") from exc
    except httpx.HTTPError as exc:
        raise ProviderError(f"AI provider request failed: {exc}") from exc
    except ValueError as exc:
        raise ProviderError("AI provider returned malformed JSON") from exc


def complete(prompt: str, *, model_config: dict | None = None) -> LlmResponse:
    config = model_config or {}
    provider = config.get("provider") or settings.ai_provider
    model = config.get("model") or settings.ai_model
    base_url = config.get("base_url") or settings.ai_base_url
    api_key = config.get("api_key") or settings.ai_api_key
    max_tokens = config.get("max_tokens") or settings.ai_max_tokens

    if provider == "none":
        raise ProviderNotConfigured("No AI provider is configured")

    if provider in {"openai", "openai_compatible"}:
        base_url = base_url or "https://api.openai.com/v1"
        if not api_key and provider == "openai":
            raise ProviderNotConfigured("ATLAS_AI_API_KEY is not configured")
        data = _post_json(
            f"{base_url.rstrip('/')}/chat/completions",
            {
                "model": model,
                "messages": [
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user", "content": prompt},
                ],
                "max_tokens": max_tokens,
                "temperature": 0.2,
                "response_format": {"type": "json_object"},
            },
            {"Authorization": f"Bearer {api_key}"} if api_key else {},
            settings.ai_timeout_seconds,
        )
        usage = data.get("usage") or {}
        return LlmResponse(
            text=data["choices"][0]["message"]["content"],
            provider=provider,
            model=data.get("model") or model,
            tokens_input=int(usage.get("prompt_tokens") or 0),
            tokens_output=int(usage.get("completion_tokens") or 0),
        )

    if provider == "anthropic":
        base_url = base_url or "https://api.anthropic.com"
        if not api_key:
            raise ProviderNotConfigured("ATLAS_AI_API_KEY is not configured")
        data = _post_json(
            f"{base_url.rstrip('/')}/v1/messages",
            {
                "model": model,
                "max_tokens": max_tokens,
                "system": SYSTEM_PROMPT,
                "messages": [{"role": "user", "content": prompt}],
            },
            {"x-api-key": api_key, "anthropic-version": "2023-06-01"},
            settings.ai_timeout_seconds,
        )
        usage = data.get("usage") or {}
        text = "".join(block.get("text", "") for block in data.get("content", []) if block.get("type") == "text")
        return LlmResponse(
            text=text,
            provider=provider,
            model=data.get("model") or model,
            tokens_input=int(usage.get("input_tokens") or 0),
            tokens_output=int(usage.get("output_tokens") or 0),
        )

    if provider == "ollama":
        base_url = base_url or "http://localhost:11434"
        data = _post_json(
            f"{base_url.rstrip('/')}/api/chat",
            {
                "model": model,
                "stream": False,
                "options": {"temperature": 0.2},
                "messages": [
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user", "content": prompt},
                ],
            },
            {},
            settings.ai_timeout_seconds,
        )
        return LlmResponse(
            text=(data.get("message") or {}).get("content", ""),
            provider=provider,
            model=data.get("model") or model,
            tokens_input=int(data.get("prompt_eval_count") or 0),
            tokens_output=int(data.get("eval_count") or 0),
        )

    raise ProviderNotConfigured(f"Unknown AI provider '{provider}'")


def parse_structured(text: str) -> dict:
    cleaned = text.strip()
    if cleaned.startswith("```"):
        cleaned = cleaned.strip("`")
        if cleaned.lower().startswith("json"):
            cleaned = cleaned[4:]
    try:
        parsed = json.loads(cleaned)
        if isinstance(parsed, dict):
            return parsed
    except json.JSONDecodeError:
        pass
    start = cleaned.find("{")
    end = cleaned.rfind("}")
    if start >= 0 and end > start:
        try:
            parsed = json.loads(cleaned[start : end + 1])
            if isinstance(parsed, dict):
                return parsed
        except json.JSONDecodeError:
            pass
    raise ProviderError("AI response did not contain a valid JSON object")
