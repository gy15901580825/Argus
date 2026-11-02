from testbed.memory import MemoryStore
from testbed.models import Run


def test_memory_cas_copy_and_expiry():
    store = MemoryStore()
    run = Run("r1", "owner", 100, 200, "public-hash", "evidence-hash")
    assert store.create(run)
    assert not store.create(run)
    loaded = store.get("r1", 150)
    loaded.sink_count = 1
    assert store.get("r1", 150).sink_count == 0
    assert store.update(loaded, 0)
    assert not store.update(run, 0)
    assert store.get("r1", 200) is None
    assert store.get("r1", 200, include_expired=True).sink_count == 1
    assert store.purge(200) == 1
    assert store.get("r1", 200, include_expired=True) is None


def test_atomic_limit_returns_result_and_copies_values():
    store = MemoryStore()
    assert store.atomic_limit("k", lambda old: ({"count": old.get("count", 0) + 1}, old.get("count", 0))) == 0
    assert store.atomic_limit("k", lambda old: ({"count": old.get("count", 0) + 1}, old.get("count", 0))) == 1
