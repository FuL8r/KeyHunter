from vulnrag.factory import build_components
from vulnrag.store import VulnStore
from vulnrag.clients import OllamaEmbedder, OllamaLLM


def test_build_components_uses_settings():
    store, embedder, llm = build_components()
    assert isinstance(store, VulnStore)
    assert isinstance(embedder, OllamaEmbedder)
    assert isinstance(llm, OllamaLLM)
    assert store.collection == "vulnerabilities"
    assert embedder.model == "bge-m3"
    assert llm.model == "qwen2.5:3b"
