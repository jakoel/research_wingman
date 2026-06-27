"""Ollama HTTP client for llm_renamer. Uses only stdlib (urllib) — no third-party dependencies."""

import json
import urllib.request
import urllib.error


class LLMError(Exception):
    """Raised when the LLM call fails in an unrecoverable way."""


class OllamaClient:
    def __init__(self, config: dict):
        self._url = config["ollama"]["url"].rstrip("/")
        self._model = config["ollama"]["model"]
        self._timeout = int(config["ollama"]["timeout_seconds"])
        self._temperature = float(config["ollama"]["temperature"])
        self._num_ctx = int(config["ollama"].get("num_ctx", 8192))

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def analyze(self, system_prompt: str, user_prompt: str) -> dict:
        """
        Send system + user prompts to Ollama /api/chat and return parsed JSON.

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
                "num_ctx":     self._num_ctx,
            },
        }

        raw_body = self._post("/api/chat", payload)
        content = self._extract_content(raw_body)
        return self._parse_json(content)

    def health_check(self) -> bool:
        """Return True if Ollama is reachable and the configured model is available."""
        try:
            req = urllib.request.Request(
                f"{self._url}/api/tags", method="GET"
            )
            with urllib.request.urlopen(req, timeout=5) as resp:
                if resp.status != 200:
                    return False
                body = json.loads(resp.read().decode("utf-8"))
                models = [m.get("name", "") for m in body.get("models", [])]
                # Accept partial match — "codellama:13b-instruct" matches "codellama:13b-instruct"
                return any(self._model in m or m in self._model for m in models) or len(models) == 0
        except Exception:
            return False

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
