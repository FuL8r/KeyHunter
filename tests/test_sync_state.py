from vulnrag.ingest.sync import SyncState


def test_state_roundtrip(tmp_path):
    path = tmp_path / "state.json"
    state = SyncState(str(path))
    assert state.last_sync("nvd") is None
    state.set_last_sync("nvd", "2024-01-01T00:00:00")
    assert SyncState(str(path)).last_sync("nvd") == "2024-01-01T00:00:00"
