import time
import logging
from collections import OrderedDict
from typing import Optional

logger = logging.getLogger("phishguard.cache")

DEFAULT_TTL_SECONDS = 3600
MAX_CACHE_SIZE = 10_000

class CacheEntry:
    __slots__ = ("result", "created_at", "source")

    def __init__(self, result: dict, source: str = ""):
        self.result = result
        self.created_at = time.time()
        self.source = source

class ResultCache:
    def __init__(self, ttl: int = DEFAULT_TTL_SECONDS, max_size: int = MAX_CACHE_SIZE):
        self._store: OrderedDict[str, CacheEntry] = OrderedDict()
        self._ttl = ttl
        self._max_size = max_size
        self._hits = 0
        self._misses = 0

    @staticmethod
    def _key(url: str) -> str:
        url = url.strip().lower()
        for prefix in ("https://", "http://", "//"):
            if url.startswith(prefix):
                url = url[len(prefix):]
        if url.startswith("www."):
            url = url[4:]
        return url.rstrip("/")

    def get(self, url: str) -> Optional[dict]:
        key = self._key(url)
        entry = self._store.get(key)
        if entry is None:
            self._misses += 1
            return None
        age = time.time() - entry.created_at
        if age > self._ttl:
            del self._store[key]
            self._misses += 1
            logger.debug("Cache expired for %s (age=%.0fs)", key, age)
            return None
        self._store.move_to_end(key)
        self._hits += 1
        return entry.result

    def put(self, url: str, result: dict, source: str = "") -> None:
        key = self._key(url)
        if key in self._store:
            del self._store[key]
        elif len(self._store) >= self._max_size:
            evicted_key, _ = self._store.popitem(last=False)
            logger.debug("Cache LRU eviction: %s", evicted_key)
        self._store[key] = CacheEntry(result=result, source=source)

    def invalidate(self, url: str) -> bool:
        key = self._key(url)
        if key in self._store:
            del self._store[key]
            return True
        return False

    def clear(self) -> int:
        count = len(self._store)
        self._store.clear()
        self._hits = 0
        self._misses = 0
        return count

    def stats(self) -> dict:
        total = self._hits + self._misses
        return {
            "size": len(self._store),
            "max_size": self._max_size,
            "ttl_seconds": self._ttl,
            "hits": self._hits,
            "misses": self._misses,
            "hit_rate": round(self._hits / total, 4) if total > 0 else 0.0,
        }
