from vulnrag.clients import StubEmbedder, StubLLM


def test_stub_embedder_is_deterministic_and_right_dim():
    e = StubEmbedder(dim=1024)
    v1 = e.embed(["log4j rce"])[0]
    v2 = e.embed(["log4j rce"])[0]
    assert len(v1) == 1024
    assert v1 == v2
    assert e.embed(["different"])[0] != v1


def test_stub_llm_returns_scripted_answer():
    llm = StubLLM(reply="SAFE")
    assert llm.complete(system="s", prompt="p") == "SAFE"
