from src.cache import CacheBase
from tests.fixtures import temp_cache_dir


def test_cache_set_and_get(temp_cache_dir: str) -> None:
    cache = CacheBase(filename="test_cache_set_and_get.json", cache_dir=temp_cache_dir)
    cache.set("key1", "value1")
    assert cache.get("key1") == "value1"


def test_cache_get_nonexistent_key(temp_cache_dir: str) -> None:
    cache = CacheBase(filename="test_cache_get_nonexistent_key.json", cache_dir=temp_cache_dir)
    assert cache.get("nonexistent") is None


def test_cache_clear(temp_cache_dir: str) -> None:
    cache = CacheBase(filename="test_cache_clear.json", cache_dir=temp_cache_dir)
    cache.set("key1", "value1")
    cache.clear()
    assert cache.size() == 0


def test_cache_size(temp_cache_dir: str) -> None:
    cache = CacheBase(filename="test_cache_size.json", cache_dir=temp_cache_dir)
    cache.set("key1", "value1")
    cache.set("key2", "value2")
    assert cache.size() == 2


def test_cache_persistence(temp_cache_dir: str) -> None:
    cache = CacheBase(filename="test_cache_persistence.json", cache_dir=temp_cache_dir)
    cache.set("key1", "value1")

    del cache

    cache_reloaded = CacheBase(filename="test_cache_persistence.json", cache_dir=temp_cache_dir)
    assert cache_reloaded.get("key1") == "value1"


def test_mx_cache(temp_cache_dir: str) -> None:
    cache = CacheBase(filename="test_mx_cache.json", cache_dir=temp_cache_dir)
    cache.set("mx_key", "mx_value")
    assert cache.get("mx_key") == "mx_value"


def test_spf_cache(temp_cache_dir: str) -> None:
    cache = CacheBase(filename="test_spf_cache.json", cache_dir=temp_cache_dir)
    cache.set("spf_key", "spf_value")
    assert cache.get("spf_key") == "spf_value"


def test_dkim_cache(temp_cache_dir: str) -> None:
    cache = CacheBase(filename="test_dkim_cache.json", cache_dir=temp_cache_dir)
    cache.set("dkim_key", "dkim_value")
    assert cache.get("dkim_key") == "dkim_value"


def test_dmarc_cache(temp_cache_dir: str) -> None:
    cache = CacheBase(filename="test_dmarc_cache.json", cache_dir=temp_cache_dir)
    cache.set("dmarc_key", "dmarc_value")
    assert cache.get("dmarc_key") == "dmarc_value"


def test_catchall_cache(temp_cache_dir: str) -> None:
    cache = CacheBase(filename="test_catchall_cache.json", cache_dir=temp_cache_dir)
    cache.set("catchall_key", "catchall_value")
    assert cache.get("catchall_key") == "catchall_value"


def test_mx_availability_cache(temp_cache_dir: str) -> None:
    cache = CacheBase(filename="test_mx_availability_cache.json", cache_dir=temp_cache_dir)
    cache.set("mx_availability_key", "mx_availability_value")
    assert cache.get("mx_availability_key") == "mx_availability_value"
