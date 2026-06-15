from vulnrag.config import Settings


def test_defaults():
    s = Settings()
    assert s.nvd_start_date == "2019-01-01"
    assert s.qdrant_host == "localhost"
    assert s.qdrant_port == 6333
    assert s.collection == "vulnerabilities"
    assert s.embed_model == "bge-m3"
    assert s.llm_model == "qwen2.5:3b"
    assert s.embed_dim == 1024
    assert s.top_k == 8


def test_env_override(monkeypatch):
    monkeypatch.setenv("VULNRAG_TOP_K", "3")
    assert Settings().top_k == 3
