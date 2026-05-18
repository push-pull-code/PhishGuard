import os
import csv
import logging
from urllib.parse import urlparse
from typing import Optional

logger = logging.getLogger("phishguard.dataset_lookup")

_SERVICE_DIR = os.path.dirname(os.path.abspath(__file__))
_BACKEND_DIR = os.path.dirname(_SERVICE_DIR)
_PROJECT_ROOT = os.path.dirname(_BACKEND_DIR)
_DATA_DIR = os.path.join(_PROJECT_ROOT, "ml", "data")

_ISCX_PATH = os.path.join(_DATA_DIR, "iscx_url_2016.csv")
_URLHAUS_PATH = os.path.join(_DATA_DIR, "urlhaus.csv")
_PHISHTANK_PATH = os.path.join(_DATA_DIR, "phishtank.csv")
_TRANCO_PATH = os.path.join(_DATA_DIR, "tranco_top1m.csv")

_iscx_phishing: set[str] = set()
_iscx_malware: set[str] = set()
_iscx_benign: set[str] = set()
_urlhaus_urls: set[str] = set()
_phishtank_urls: set[str] = set()
_tranco_domains: set[str] = set()

_datasets_loaded: bool = False

def _normalise_url(raw: str) -> str:
    raw = raw.strip().lower()
    for prefix in ("https://", "http://", "//"):
        if raw.startswith(prefix):
            raw = raw[len(prefix):]
    if raw.startswith("www."):
        raw = raw[4:]
    return raw.rstrip("/")

def _extract_domain(url: str) -> str:
    normalised = _normalise_url(url)
    return normalised.split("/")[0].split(":")[0].split("?")[0]

def load_datasets() -> dict[str, int]:
    global _datasets_loaded
    stats: dict[str, int] = {}

    # ISCX-URL-2016
    _iscx_phishing.clear()
    _iscx_malware.clear()
    _iscx_benign.clear()
    if os.path.isfile(_ISCX_PATH):
        with open(_ISCX_PATH, "r", encoding="utf-8", errors="replace") as f:
            reader = csv.reader(f)
            next(reader, None)
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
            "ISCX loaded — phishing: %d, malware: %d, benign: %d",
            len(_iscx_phishing), len(_iscx_malware), len(_iscx_benign),
        )
    else:
        logger.warning("ISCX dataset not found at %s", _ISCX_PATH)

    # URLhaus
    _urlhaus_urls.clear()
    if os.path.isfile(_URLHAUS_PATH):
        with open(_URLHAUS_PATH, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                try:
                    parts = next(csv.reader([line]))
                    if len(parts) >= 3:
                        _urlhaus_urls.add(_normalise_url(parts[2]))
                except Exception:
                    continue
        stats["urlhaus"] = len(_urlhaus_urls)
        logger.info("URLhaus loaded — %d URLs", len(_urlhaus_urls))
    else:
        logger.warning("URLhaus dataset not found at %s", _URLHAUS_PATH)

    # PhishTank
    _phishtank_urls.clear()
    if os.path.isfile(_PHISHTANK_PATH):
        with open(_PHISHTANK_PATH, "r", encoding="utf-8", errors="replace") as f:
            reader = csv.reader(f)
            next(reader, None)
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
        logger.info("PhishTank loaded — %d URLs", len(_phishtank_urls))
    else:
        logger.warning("PhishTank dataset not found at %s", _PHISHTANK_PATH)

    # Tranco Top-1M
    _tranco_domains.clear()
    if os.path.isfile(_TRANCO_PATH):
        with open(_TRANCO_PATH, "r", encoding="utf-8", errors="replace") as f:
            reader = csv.reader(f)
            for row in reader:
                if len(row) >= 2:
                    _tranco_domains.add(row[1].strip().lower())
        stats["tranco"] = len(_tranco_domains)
        logger.info("Tranco loaded — %d domains", len(_tranco_domains))
    else:
        logger.warning("Tranco dataset not found at %s", _TRANCO_PATH)

    _datasets_loaded = True
    return stats

class DatasetMatch:
    __slots__ = ("found", "source", "label", "confidence")

    def __init__(self, found: bool, source: str = "", label: str = "", confidence: float = 0.0):
        self.found = found
        self.source = source
        self.label = label
        self.confidence = confidence

    def to_dict(self) -> dict:
        return {
            "found": self.found,
            "source": self.source,
            "label": self.label,
            "confidence": self.confidence,
        }

def lookup_url(url: str) -> DatasetMatch:
    if not _datasets_loaded:
        logger.warning("Datasets not loaded yet")
        return DatasetMatch(found=False)

    key = _normalise_url(url)
    domain = _extract_domain(url)

    if key in _urlhaus_urls:
        return DatasetMatch(found=True, source="urlhaus", label="malware", confidence=1.0)

    if key in _phishtank_urls:
        return DatasetMatch(found=True, source="phishtank", label="phishing", confidence=1.0)

    if key in _iscx_phishing:
        return DatasetMatch(found=True, source="iscx", label="phishing", confidence=1.0)

    if key in _iscx_malware:
        return DatasetMatch(found=True, source="iscx", label="malware", confidence=1.0)

    if key in _iscx_benign:
        return DatasetMatch(found=True, source="iscx", label="benign", confidence=1.0)

    if domain in _tranco_domains:
        return DatasetMatch(found=True, source="tranco", label="genuine", confidence=0.95)

    if domain in _urlhaus_urls:
        return DatasetMatch(found=True, source="urlhaus", label="malware", confidence=0.9)

    if domain in _phishtank_urls:
        return DatasetMatch(found=True, source="phishtank", label="phishing", confidence=0.85)

    return DatasetMatch(found=False)
