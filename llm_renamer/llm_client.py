"""Ollama HTTP client for llm_renamer. Uses only stdlib (urllib) — no third-party dependencies."""

import json
import re
import urllib.request
import urllib.error


class LLMError(Exception):
    """Raised when the LLM call fails in an unrecoverable way."""


# Conservative overestimate of tokens-per-char for dense, punctuation-heavy
# C-like pseudocode -- better to over-allocate num_ctx than silently truncate
# a large prompt. A fixed default num_ctx (whatever config sets, 8192 if
# unset) is fine for most functions but silently truncates the tail of a
# large one instead of erroring -- confirmed live 2026-08-13 on a Mirai
# sample's ~200-line main loop: its attack-command dispatch (`!kill`,
# `!update`, the udpplain/syn/std/http/pps/ack strcmp cascade) sat past the
# truncation point and never made it into the summary. Originally built for
# `diff` (see that module's docstring) after the same failure mode showed up
# there first; `analyze_sized` below is the shared version both use.
_CHARS_PER_TOKEN = 2.86
_CTX_BUFFER_TOKENS = 2048
_CTX_BUCKETS = (8192, 16384, 32768, 65536, 131072)


def size_num_ctx(prompt_chars: int) -> int:
    """Smallest bucket in `_CTX_BUCKETS` that comfortably fits `prompt_chars`."""
    needed = int(prompt_chars / _CHARS_PER_TOKEN) + _CTX_BUFFER_TOKENS
    for bucket in _CTX_BUCKETS:
        if bucket >= needed:
            return bucket
    return _CTX_BUCKETS[-1]


def is_truncation_error(e: LLMError) -> bool:
    """True for the two LLMError shapes that mean 'the model ran out of room
    mid-response' (malformed JSON from a cut-off string, or thinking burning
    the whole output budget) -- as opposed to network/HTTP errors, where a
    bigger num_ctx wouldn't help and retrying just wastes a call."""
    msg = str(e)
    return "is not valid JSON" in msg or "only reasoning" in msg


def _param_billions(model: dict) -> float:
    """Parse Ollama's details.parameter_size (e.g. "25.8B", "671M") into billions.

    Falls back to raw download size (bytes) if parameter_size is absent/unparsable,
    since that's still a reasonable proxy for "bigger model".
    """
    size_str = model.get("details", {}).get("parameter_size", "")
    m = re.match(r"([\d.]+)\s*([BM])", size_str.upper())
    if m:
        value = float(m.group(1))
        return value / 1000 if m.group(2) == "M" else value
    return model.get("size", 0) / 1e9


class OllamaClient:
    # Sentinel so config can distinguish "omit the think field entirely"
    # (value None) from the default of sending think=false.
    _THINK_UNSET = object()

    def __init__(self, config: dict):
        self._url = config["ollama"]["url"].rstrip("/")
        self._model = config["ollama"]["model"]
        self._timeout = int(config["ollama"]["timeout_seconds"])
        self._temperature = float(config["ollama"]["temperature"])
        self._num_ctx = int(config["ollama"].get("num_ctx", 8192))
        # `think` is configurable because reasoning models differ: gemma
        # tolerates `format=json` + `think=false`, but gpt-oss returns garbage
        # for that exact combination and needs think omitted. Config values:
        #   absent  -> send think=false (default, works for gemma)
        #   null    -> omit the field   (needed for gpt-oss-style models)
        #   true    -> send think=true
        self._think = config["ollama"].get("think", False)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def analyze(self, system_prompt: str, user_prompt: str, num_ctx: int | None = None) -> dict:
        """
        Send system + user prompts to Ollama /api/chat and return parsed JSON.

        `num_ctx` overrides the configured default for this one call --
        `analyze_sized` uses this to size the request to the actual prompt
        instead of relying on a fixed ceiling.

        Raises:
            LLMError  — network error or the response cannot be parsed as JSON.
        """
        payload = {
            "model": self._model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user",   "content": user_prompt},
            ],
            "stream": False,
            "format": "json",
            "options": {
                "temperature": self._temperature,
                "num_ctx":     num_ctx if num_ctx is not None else self._num_ctx,
            },
        }
        # Omit `think` entirely when config sets it to null (gpt-oss); else send
        # the configured value (default False).
        if self._think is not None:
            payload["think"] = self._think

        raw_body = self._post("/api/chat", payload)
        content = self._extract_content(raw_body)
        return self._parse_json(content)

    def analyze_sized(self, system_prompt: str, user_prompt: str) -> tuple[dict, int, int]:
        """Like `analyze`, but sizes num_ctx to the actual prompt (see
        `size_num_ctx`) instead of the fixed config default, and retries once
        at the next bucket up if the response comes back looking truncated.

        Ollama's num_ctx covers prompt + response combined (no separate
        output cap is set), so a response that needs more room than the
        chosen bucket left over gets cut off mid-generation even when the
        prompt itself fit -- the retry accounts for that too, not just an
        undersized prompt estimate.

        Returns (parsed_json, num_ctx_used, prompt_chars) -- the latter two
        are for the caller to persist, so a specific function's analysis can
        be audited after the fact instead of only being provably correct
        during the run that produced it.
        """
        prompt_chars = len(system_prompt) + len(user_prompt)
        num_ctx = size_num_ctx(prompt_chars)
        try:
            raw = self.analyze(system_prompt, user_prompt, num_ctx=num_ctx)
        except LLMError as e:
            if not is_truncation_error(e):
                raise
            idx = _CTX_BUCKETS.index(num_ctx) if num_ctx in _CTX_BUCKETS else len(_CTX_BUCKETS) - 1
            retry_ctx = _CTX_BUCKETS[min(idx + 1, len(_CTX_BUCKETS) - 1)]
            if retry_ctx == num_ctx:
                raise  # already at the largest bucket -- nothing more room to give
            print(f"  [retry] truncated response at num_ctx={num_ctx} ({e}); "
                  f"retrying once at num_ctx={retry_ctx}…")
            raw = self.analyze(system_prompt, user_prompt, num_ctx=retry_ctx)
            num_ctx = retry_ctx
        return raw, num_ctx, prompt_chars

    def generate_text(self, system_prompt: str, user_prompt: str,
                      num_ctx: int | None = None, num_predict: int | None = None) -> str:
        """Like `analyze`, but for free-form prose output (macro reports)
        instead of the tool's usual structured per-function JSON -- no
        `format=json` constraint, returns the raw response text.

        Raises:
            LLMError — network error, or the model returned only reasoning
            with no final content (see `_extract_content`).
        """
        payload = {
            "model": self._model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user",   "content": user_prompt},
            ],
            "stream": False,
            "options": {
                "temperature": self._temperature,
                "num_ctx":     num_ctx if num_ctx is not None else self._num_ctx,
            },
        }
        if num_predict is not None:
            payload["options"]["num_predict"] = num_predict
        if self._think is not None:
            payload["think"] = self._think

        raw_body = self._post("/api/chat", payload)
        return self._extract_content(raw_body)

    def generate_text_sized(self, system_prompt: str, user_prompt: str,
                            num_predict: int | None = None) -> tuple[str, int, int]:
        """`generate_text`, auto-sized to the prompt like `analyze_sized` (see
        there for why). The only retryable failure here is "only reasoning,
        no content" -- unlike `analyze_sized`, there's no JSON to come back
        truncated, so "not valid JSON" isn't a meaningful retry signal for
        free-form text output.

        Returns (text, num_ctx_used, prompt_chars).
        """
        prompt_chars = len(system_prompt) + len(user_prompt)
        num_ctx = size_num_ctx(prompt_chars)
        try:
            text = self.generate_text(system_prompt, user_prompt, num_ctx=num_ctx, num_predict=num_predict)
        except LLMError as e:
            if "only reasoning" not in str(e):
                raise
            idx = _CTX_BUCKETS.index(num_ctx) if num_ctx in _CTX_BUCKETS else len(_CTX_BUCKETS) - 1
            retry_ctx = _CTX_BUCKETS[min(idx + 1, len(_CTX_BUCKETS) - 1)]
            if retry_ctx == num_ctx:
                raise  # already at the largest bucket -- nothing more room to give
            print(f"  [retry] truncated at num_ctx={num_ctx} ({e}); "
                  f"retrying once at num_ctx={retry_ctx}…")
            text = self.generate_text(system_prompt, user_prompt, num_ctx=retry_ctx, num_predict=num_predict)
            num_ctx = retry_ctx
        return text, num_ctx, prompt_chars

    def list_models(self) -> list[dict]:
        """Raw /api/tags model entries. Empty list if unreachable or none installed."""
        try:
            req = urllib.request.Request(f"{self._url}/api/tags", method="GET")
            with urllib.request.urlopen(req, timeout=5) as resp:
                if resp.status != 200:
                    return []
                body = json.loads(resp.read().decode("utf-8"))
                return body.get("models", [])
        except Exception:
            return []

    def resolve_model(self) -> tuple[str, bool] | None:
        """
        Confirm the configured model actually exists on the server; if not,
        fall back to the largest model available there (by parameter count).

        Returns (model_name_in_use, changed) or None if Ollama is unreachable
        or has no models installed at all.
        """
        models = self.list_models()
        if not models:
            return None

        names = [m.get("name", "") for m in models]
        if any(self._model in n or n in self._model for n in names):
            return self._model, False

        best = max(models, key=_param_billions)
        self._model = best.get("name", self._model)
        return self._model, True

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _post(self, path: str, payload: dict) -> dict:
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            f"{self._url}{path}",
            data=data,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=self._timeout) as resp:
                body = resp.read().decode("utf-8")
        except urllib.error.URLError as e:
            raise LLMError(f"Network error contacting Ollama: {e}") from e
        except Exception as e:
            raise LLMError(f"Unexpected HTTP error: {e}") from e

        try:
            return json.loads(body)
        except json.JSONDecodeError as e:
            raise LLMError(f"Ollama returned non-JSON body: {e}") from e

    @staticmethod
    def _extract_content(resp: dict) -> str:
        """Pull the assistant message content out of an /api/chat response."""
        if "message" in resp:
            content = resp["message"].get("content", "")
            if not content.strip() and resp["message"].get("thinking"):
                raise LLMError(
                    "Model returned only reasoning ('thinking'), no final "
                    "content — it likely burned its output budget thinking. "
                    "Reduce prompt size / raise num_ctx / num_predict, or "
                    "check the model actually honours \"think\": false."
                )
        elif "response" in resp:
            content = resp["response"]
        else:
            raise LLMError(
                f"Unrecognised Ollama response structure: {list(resp.keys())}"
            )
        return content.strip()

    @staticmethod
    def _parse_json(content: str) -> dict:
        """Parse a JSON string, stripping accidental markdown fences first."""
        # Strip ``` or ```json fences
        if content.startswith("```"):
            lines = content.splitlines()
            # Drop first line (```json or ``` ) and trailing ``` if present
            inner = lines[1:]
            if inner and inner[-1].strip() == "```":
                inner = inner[:-1]
            content = "\n".join(inner).strip()

        try:
            return json.loads(content)
        except json.JSONDecodeError as e:
            snippet = content[:300]
            raise LLMError(f"LLM response is not valid JSON: {e}\n---\n{snippet}") from e
