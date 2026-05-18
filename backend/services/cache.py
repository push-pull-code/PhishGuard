"""
Server-side Result Cache
========================
TTL-based in-memory cache for scan results keyed by normalised URL.
Avoids repeated dataset lookups and ML inference for the same URL.

Uses an OrderedDict for LRU eviction when max capacity is reached.
"""

import time
import logging
from collections import OrderedDict
from typing import Any, Optional

logger = logging.getLogger("phishguard.cache")

# ──────────────────────────────────────────────────────────────
# Configuration
# ──────────────────────────────────────────────────────────────
DEFAULT_TTL_SECONDS = 3600       # 1 hour
MAX_CACHE_SIZE = 10_000          # max entries before LRU eviction


class CacheEntry:
    """Single cached result with timestamp."""
    __slots__ = ("result", "created_at", "source")

    def __init__(self, result: dict, source: str = ""):
        self.result = result
        self.created_at = time.time()
        self.source = source        # "dataset" or "ml" — for diagnostics


class ResultCache:
    """
    Thread-safe (for async FastAPI), TTL-expiring, LRU-evicting cache.
    """

    def __init__(self, ttl: int = DEFAULT_TTL_SECONDS, max_size: int = MAX_CACHE_SIZE):
        self._store: OrderedDict[str, CacheEntry] = OrderedDict()
        self._ttl = ttl
        self._max_size = max_size
        self._hits = 0
        self._misses = 0

    # ── normalise key ──
    @staticmethod
    def _key(url: str) -> str:
        url = url.strip().lower()
        for prefix in ("https://", "http://", "//"):
            if url.startswith(prefix):
                url = url[len(prefix):]
        if url.startswith("www."):
            url = url[4:]
        return url.rstrip("/")

    # ── public API ──
    def get(self, url: str) -> Optional[dict]:
        """Return cached result or None if miss / expired."""
        key = self._key(url)
        entry = self._store.get(key)
        if entry is None:
            self._misses += 1
            return None
        age = time.time() - entry.created_at
        if age > self._ttl:
            # expired — evict
            del self._store[key]
            self._misses += 1
            logger.debug("Cache expired for %s (age=%.0fs)", key, age)
            return None
        # move to end (most recently used)
        self._store.move_to_end(key)
        self._hits += 1
        return entry.result

    def put(self, url: str, result: dict, source: str = "") -> None:
        """Store a result.  Evicts LRU entry if at capacity."""
        key = self._key(url)
        if key in self._store:
            del self._store[key]
        elif len(self._store) >= self._max_size:
            evicted_key, _ = self._store.popitem(last=False)
            logger.debug("Cache LRU eviction: %s", evicted_key)
        self._store[key] = CacheEntry(result=result, source=source)

    def invalidate(self, url: str) -> bool:
        """Remove a specific URL from the cache.  Returns True if it existed."""
        key = self._key(url)
        if key in self._store:
            del self._store[key]
            return True
        return False

    def clear(self) -> int:
        """Flush the entire cache.  Returns the number of entries cleared."""
        count = len(self._store)
        self._store.clear()
        self._hits = 0
        self._misses = 0
        return count

    def stats(self) -> dict:
        """Return cache statistics."""
        total = self._hits + self._misses
        return {
            "size": len(self._store),
            "max_size": self._max_size,
            "ttl_seconds": self._ttl,
            "hits": self._hits,
            "misses": self._misses,
            "hit_rate": round(self._hits / total, 4) if total > 0 else 0.0,
        }
