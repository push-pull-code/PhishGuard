"""
Dataset Lookup Service
======================
Loads the ISCX-URL-2016, URLhaus, PhishTank/OpenPhish, and Tranco datasets
into fast in-memory hash-sets at startup.  Provides O(1) URL/domain lookup
to short-circuit the full ML pipeline when the answer is already known.

Priority order:
  1. URLhaus    → known malware       → "malicious"
  2. PhishTank  → verified phishing   → "malicious"
  3. ISCX       → phishing / benign   → "malicious" / "safe"
  4. Tranco     → top-1M legit sites  → "safe"
  5. Not found  → fall through to ML
"""

import os
import csv
import logging
from urllib.parse import urlparse
from typing import Optional

logger = logging.getLogger("phishguard.dataset_lookup")

# ──────────────────────────────────────────────────────────────
# Paths
# ──────────────────────────────────────────────────────────────
_SERVICE_DIR = os.path.dirname(os.path.abspath(__file__))
_BACKEND_DIR = os.path.dirname(_SERVICE_DIR)
_PROJECT_ROOT = os.path.dirname(_BACKEND_DIR)
_DATA_DIR = os.path.join(_PROJECT_ROOT, "ml", "data")

_ISCX_PATH = os.path.join(_DATA_DIR, "iscx_url_2016.csv")
_URLHAUS_PATH = os.path.join(_DATA_DIR, "urlhaus.csv")
_PHISHTANK_PATH = os.path.join(_DATA_DIR, "phishtank.csv")
_TRANCO_PATH = os.path.join(_DATA_DIR, "tranco_top1m.csv")

# ──────────────────────────────────────────────────────────────
# In-memory sets (populated by load_datasets())
# ──────────────────────────────────────────────────────────────
_iscx_phishing: set[str] = set()       # normalised URLs labelled 'phishing'
_iscx_malware: set[str] = set()        # normalised URLs labelled 'malware' / 'defacement'
_iscx_benign: set[str] = set()         # normalised URLs labelled 'benign'
_urlhaus_urls: set[str] = set()        # URLs from URLhaus (all malicious)
_phishtank_urls: set[str] = set()      # URLs from PhishTank/OpenPhish (all phishing)
_tranco_domains: set[str] = set()      # top-1M legitimate domains

_datasets_loaded: bool = False


# ──────────────────────────────────────────────────────────────
# Normalisation helpers
# ──────────────────────────────────────────────────────────────
def _normalise_url(raw: str) -> str:
    """
    Strip protocol, trailing slashes, and lowercase for consistent matching.
    Returns  domain.tld/path  (no scheme, no trailing slash).
    """
    raw = raw.strip().lower()
    for prefix in ("https://", "http://", "//"):
        if raw.startswith(prefix):
            raw = raw[len(prefix):]
    if raw.startswith("www."):
        raw = raw[4:]
    return raw.rstrip("/")


def _extract_domain(url: str) -> str:
    """Extract bare domain from any URL string."""
    normalised = _normalise_url(url)
    return normalised.split("/")[0].split(":")[0].split("?")[0]


# ──────────────────────────────────────────────────────────────
# Dataset loading (called once at startup)
# ──────────────────────────────────────────────────────────────
def load_datasets() -> dict[str, int]:
    """
    Load all CSV datasets into memory.  Returns a stats dict with counts.
    Safe to call multiple times (idempotent).
    """
    global _datasets_loaded
    stats: dict[str, int] = {}

    # ── ISCX-URL-2016 ──
    _iscx_phishing.clear()
    _iscx_malware.clear()
    _iscx_benign.clear()
    if os.path.isfile(_ISCX_PATH):
        with open(_ISCX_PATH, "r", encoding="utf-8", errors="replace") as f:
            reader = csv.reader(f)
            header = next(reader, None)  # skip header row: url,type
            for row in reader:
                if len(row) < 2:
                    continue
                url_raw, label = row[0].strip(), row[1].strip().lower()
                key = _normalise_url(url_raw)
                if label == "phishing":
                    _iscx_phishing.add(key)
                elif label in ("malware", "defacement"):
                    _iscx_malware.add(key)
                elif label == "benign":
                    _iscx_benign.add(key)
        stats["iscx_phishing"] = len(_iscx_phishing)
        stats["iscx_malware"] = len(_iscx_malware)
        stats["iscx_benign"] = len(_iscx_benign)
        logger.info(
            "ISCX loaded — phishing: %d, malware/defacement: %d, benign: %d",
            len(_iscx_phishing), len(_iscx_malware), len(_iscx_benign),
        )
    else:
        logger.warning("ISCX dataset not found at %s", _ISCX_PATH)

    # ── URLhaus ──
    _urlhaus_urls.clear()
    if os.path.isfile(_URLHAUS_PATH):
        with open(_URLHAUS_PATH, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                # CSV format: id,dateadded,url,url_status,...
                try:
                    parts = next(csv.reader([line]))
                    if len(parts) >= 3:
                        _urlhaus_urls.add(_normalise_url(parts[2]))
                except Exception:
                    continue
        stats["urlhaus"] = len(_urlhaus_urls)
        logger.info("URLhaus loaded — %d malicious URLs", len(_urlhaus_urls))
    else:
        logger.warning("URLhaus dataset not found at %s", _URLHAUS_PATH)

    # ── PhishTank / OpenPhish ──
    _phishtank_urls.clear()
    if os.path.isfile(_PHISHTANK_PATH):
        with open(_PHISHTANK_PATH, "r", encoding="utf-8", errors="replace") as f:
            reader = csv.reader(f)
            header = next(reader, None)  # skip header row
            for row in reader:
                if len(row) >= 2:
                    url_raw = row[1].strip()
                    if url_raw and url_raw.startswith("http"):
                        _phishtank_urls.add(_normalise_url(url_raw))
                elif len(row) == 1:
                    url_raw = row[0].strip()
                    if url_raw and url_raw.startswith("http"):
                        _phishtank_urls.add(_normalise_url(url_raw))
        stats["phishtank"] = len(_phishtank_urls)
        logger.info("PhishTank loaded — %d phishing URLs", len(_phishtank_urls))
    else:
        logger.warning("PhishTank dataset not found at %s", _PHISHTANK_PATH)

    # ── Tranco top-1M ──
    _tranco_domains.clear()
    if os.path.isfile(_TRANCO_PATH):
        with open(_TRANCO_PATH, "r", encoding="utf-8", errors="replace") as f:
            reader = csv.reader(f)
            for row in reader:
                if len(row) >= 2:
                    _tranco_domains.add(row[1].strip().lower())
        stats["tranco"] = len(_tranco_domains)
        logger.info("Tranco loaded — %d legitimate domains", len(_tranco_domains))
    else:
        logger.warning("Tranco dataset not found at %s", _TRANCO_PATH)

    _datasets_loaded = True
    return stats


# ──────────────────────────────────────────────────────────────
# Lookup function (O(1) per check)
# ──────────────────────────────────────────────────────────────
class DatasetMatch:
    """Result of a dataset lookup."""
    __slots__ = ("found", "source", "label", "confidence")

    def __init__(self, found: bool, source: str = "", label: str = "", confidence: float = 0.0):
        self.found = found
        self.source = source        # e.g. "iscx", "urlhaus", "tranco", "phishtank"
        self.label = label          # "phishing", "malware", "benign", "genuine"
        self.confidence = confidence  # 1.0 for exact match, 0.0 for not found

    def to_dict(self) -> dict:
        return {
            "found": self.found,
            "source": self.source,
            "label": self.label,
            "confidence": self.confidence,
        }


def lookup_url(url: str) -> DatasetMatch:
    """
    Check url against all loaded datasets.
    Priority: URLhaus → PhishTank → ISCX phishing → ISCX malware → ISCX benign → Tranco.
    Returns DatasetMatch with found=False if nothing matches.
    """
    if not _datasets_loaded:
        logger.warning("Datasets not loaded yet — skipping dataset lookup")
        return DatasetMatch(found=False)

    key = _normalise_url(url)
    domain = _extract_domain(url)

    # 1. URLhaus — known malware (exact URL match)
    if key in _urlhaus_urls:
        return DatasetMatch(found=True, source="urlhaus", label="malware", confidence=1.0)

    # 2. PhishTank — verified phishing (exact URL match)
    if key in _phishtank_urls:
        return DatasetMatch(found=True, source="phishtank", label="phishing", confidence=1.0)

    # 3. ISCX — phishing (exact URL match)
    if key in _iscx_phishing:
        return DatasetMatch(found=True, source="iscx", label="phishing", confidence=1.0)

    # 4. ISCX — malware / defacement (exact URL match)
    if key in _iscx_malware:
        return DatasetMatch(found=True, source="iscx", label="malware", confidence=1.0)

    # 5. ISCX — benign (exact URL match)
    if key in _iscx_benign:
        return DatasetMatch(found=True, source="iscx", label="benign", confidence=1.0)

    # 6. Tranco — top-1M legitimate domains (domain-only match)
    if domain in _tranco_domains:
        return DatasetMatch(found=True, source="tranco", label="genuine", confidence=0.95)

    # 7. Also try domain-only against URLhaus URLs (some entries are just domains)
    if domain in _urlhaus_urls:
        return DatasetMatch(found=True, source="urlhaus", label="malware", confidence=0.9)

    # 8. PhishTank domain-level check
    if domain in _phishtank_urls:
        return DatasetMatch(found=True, source="phishtank", label="phishing", confidence=0.85)

    return DatasetMatch(found=False)
