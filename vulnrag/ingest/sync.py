import json
from pathlib import Path


class SyncState:
    def __init__(self, path: str):
        self.path = Path(path)
        self._data = json.loads(self.path.read_text()) if self.path.exists() else {}

    def last_sync(self, source: str) -> str | None:
        return self._data.get(source)

    def set_last_sync(self, source: str, when: str):
        self._data[source] = when
        self.path.write_text(json.dumps(self._data, indent=2))
