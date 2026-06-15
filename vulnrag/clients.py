from __future__ import annotations
import hashlib
import math
from typing import Protocol


class EmbeddingClient(Protocol):
    def embed(self, texts: list[str]) -> list[list[float]]: ...


class LLMClient(Protocol):
    def complete(self, *, system: str, prompt: str) -> str: ...


class StubEmbedder:
    """Deterministic pseudo-embedding for tests (no Ollama needed)."""
    def __init__(self, dim: int = 1024):
        self.dim = dim

    def embed(self, texts: list[str]) -> list[list[float]]:
        out = []
        for t in texts:
            h = hashlib.sha256(t.encode()).digest()
            seed = int.from_bytes(h[:8], "big")
            vec = [math.sin(seed * (i + 1)) for i in range(self.dim)]
            out.append(vec)
        return out


class StubLLM:
    def __init__(self, reply: str = ""):
        self.reply = reply
        self.last_prompt = None

    def complete(self, *, system: str, prompt: str) -> str:
        self.last_prompt = prompt
        return self.reply


class OllamaEmbedder:
    def __init__(self, model: str, host: str):
        import ollama
        self._client = ollama.Client(host=host)
        self.model = model

    def embed(self, texts: list[str]) -> list[list[float]]:
        resp = self._client.embed(model=self.model, input=texts)
        return resp["embeddings"]


class OllamaLLM:
    def __init__(self, model: str, host: str):
        import ollama
        self._client = ollama.Client(host=host)
        self.model = model

    def complete(self, *, system: str, prompt: str) -> str:
        resp = self._client.chat(model=self.model, messages=[
            {"role": "system", "content": system},
            {"role": "user", "content": prompt},
        ], options={"temperature": 0.1})
        return resp["message"]["content"]
