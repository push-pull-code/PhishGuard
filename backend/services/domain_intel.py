# FILE: domain_intel.py
# PURPOSE: WHOIS lookups, DNS record checks, and typosquatting detection for domain-level forensics
# CONNECTS TO: backend/routes/scan.py, ml/data/tranco_top1m.csv

import os
import logging
from datetime import datetime, timezone
from typing import Optional

import whois
import dns.resolver
import Levenshtein
import pandas as pd

logger = logging.getLogger("phishguard.domain_intel")

# ---------------------------------------------------------------------------
# Project paths
# ---------------------------------------------------------------------------
_SERVICE_DIR = os.path.dirname(os.path.abspath(__file__))
_BACKEND_DIR = os.path.dirname(_SERVICE_DIR)
_PROJECT_ROOT = os.path.dirname(_BACKEND_DIR)
_TRANCO_PATH = os.path.join(_PROJECT_ROOT, "ml", "data", "tranco_top1m.csv")


# =====================================================================
# TRANCO TOP-1000 CACHE (loaded once at import time)
# =====================================================================
# We only load the top 1000 domains for the typosquatting check.
#
# WHY 10 000?
#   detect_typosquatting() computes the Levenshtein distance between the
#   input domain and EVERY entry in this list.  That's O(n × m) where
#   n = list size and m = average domain length.
#   • Top 1 000  → ~1 000 comparisons → < 2 ms   ✓ fast
#   • Top 10 000 → ~10 000 comparisons → ~15 ms  ✓ acceptable
#   • Full 1M    → ~1 000 000 comparisons → 1-2 s ✗ way too slow
#   Since virtually all typosquatting targets well-known brands (Google,
#   PayPal, Amazon, etc.) the top 10 000 covers the vast majority of cases.

_TOP_DOMAINS: list[str] = []

try:
    if os.path.isfile(_TRANCO_PATH):
        _df = pd.read_csv(_TRANCO_PATH, header=None, names=["rank", "domain"], nrows=10000)
        _TOP_DOMAINS = _df["domain"].tolist()
        logger.info("Loaded %d Tranco domains for typosquatting check", len(_TOP_DOMAINS))
    else:
        logger.warning("Tranco list not found at %s — typosquatting check disabled", _TRANCO_PATH)
except Exception as exc:
    logger.error("Failed to load Tranco list: %s", exc)


# =====================================================================
# WHOIS LOOKUP
# =====================================================================
# WHAT IS WHOIS?
#   WHOIS is a public protocol that lets you query the registration
#   database for a domain name.  It returns metadata such as:
#     • Registrar  — the company that sold the domain (e.g. GoDaddy)
#     • Creation date — when the domain was first registered
#     • Expiry date — when the registration expires
#     • Name servers — the DNS servers that resolve the domain
#
# WHY NEW DOMAINS = HIGHER PHISHING RISK:
#   Legitimate businesses register domains years in advance and keep them
#   for a long time.  Phishing campaigns, on the other hand, spin up
#   throwaway domains hours or days before an attack and abandon them
#   once they get blocklisted.  A domain younger than ~180 days is a
#   significant red flag — it hasn't had time to build reputation.
#
# GOTCHA: WHOIS lookups fail roughly 20% of the time because:
#   1. The WHOIS server for that TLD might be down or rate-limiting.
#   2. Some TLDs (.tk, .ml, etc.) simply don't expose WHOIS data.
#   3. Privacy / proxy registrations hide all useful fields.
#   4. Network timeouts on slow connections.
#   We wrap EVERYTHING in try/except and return sensible defaults so a
#   WHOIS failure never crashes the scan pipeline.  The caller should
#   check the "available" flag before trusting the data.

def get_whois_info(domain: str) -> dict:
    """Perform a WHOIS lookup on *domain* and return registration metadata.

    Returns
    -------
    dict
        {
            registrar: str | None,
            creation_date: str | None,       # ISO-8601 string
            domain_age_days: int | None,
            is_newly_registered: bool,       # True if age < 180 days
            available: bool                  # False if WHOIS failed
        }
    """
    try:
        # python-whois sends a WHOIS query to the appropriate server for
        # the domain's TLD and parses the free-text response into a dict.
        #
        # GOTCHA: This call can hang for 5-10 s if the WHOIS server is
        #   slow.  python-whois doesn't expose a timeout parameter, so
        #   the only defence is the outer try/except + the caller's own
        #   asyncio timeout.  In production consider running this in a
        #   thread with asyncio.wait_for(timeout=3).
        w = whois.whois(domain)

        # --- Registrar ---------------------------------------------------
        registrar = w.registrar  # str or None

        # --- Creation date -----------------------------------------------
        # whois sometimes returns a list of dates or a single datetime.
        creation_date_raw = w.creation_date
        if isinstance(creation_date_raw, list):
            creation_date_raw = creation_date_raw[0]

        creation_date: Optional[datetime] = None
        creation_date_str: Optional[str] = None
        domain_age_days: Optional[int] = None
        is_newly_registered = False

        if isinstance(creation_date_raw, datetime):
            creation_date = creation_date_raw
            # Make timezone-aware if naive
            if creation_date.tzinfo is None:
                creation_date = creation_date.replace(tzinfo=timezone.utc)

            creation_date_str = creation_date.isoformat()
            domain_age_days = (datetime.now(timezone.utc) - creation_date).days

            # Flag if the domain is younger than 180 days (~6 months).
            # Most phishing domains are used within days of registration
            # and rarely survive past a few weeks.
            is_newly_registered = domain_age_days < 180

        return {
            "registrar": registrar,
            "creation_date": creation_date_str,
            "domain_age_days": domain_age_days,
            "is_newly_registered": is_newly_registered,
            "available": True,
        }

    except Exception as exc:
        # GOTCHA: whois.whois() raises a zoo of exceptions —
        #   ConnectionResetError, socket.timeout, whois.parser.PywhoisError,
        #   etc.  We catch everything and return a safe fallback.
        logger.warning("WHOIS lookup failed for %s: %s", domain, exc)
        return {
            "registrar": None,
            "creation_date": None,
            "domain_age_days": None,
            "is_newly_registered": False,
            "available": False,
            "error": str(exc),
        }


# =====================================================================
# DNS RECORDS
# =====================================================================
# DNS (Domain Name System) translates domain names to IP addresses and
# provides routing information for email and other services.  We check
# three record types:
#
#   A record (Address)
#     Maps the domain to one or more IPv4 addresses.
#     If a domain has NO A record it likely doesn't host a website at all,
#     which is unusual for a legitimate site but can happen with brand-new
#     phishing domains where DNS hasn't fully propagated yet.
#
#   MX record (Mail Exchange)
#     Points to the mail server(s) that handle email for the domain.
#     Phishing domains often lack MX records because the attacker only
#     needs a web page, not an email inbox.  Legitimate companies almost
#     always have MX records.
#
#   NS record (Name Server)
#     Lists the authoritative DNS servers for the domain.
#     These are useful for fingerprinting the hosting provider.  Cheap
#     or free DNS providers are disproportionately used by phishers.

def get_dns_records(domain: str) -> dict:
    """Query A, MX, and NS records for *domain*.

    Returns
    -------
    dict
        {
            has_a_record: bool,
            has_mx_record: bool,
            nameservers: list[str],
            ip_addresses: list[str],
            available: bool
        }
    """
    result = {
        "has_a_record": False,
        "has_mx_record": False,
        "nameservers": [],
        "ip_addresses": [],
        "available": True,
    }

    # --- A records (IPv4 addresses) -----------------------------------
    try:
        # dns.resolver.resolve() sends a DNS query and returns an answer
        # set.  Each answer in an A-record response is an IPv4 address.
        a_answers = dns.resolver.resolve(domain, "A", lifetime=3)
        result["ip_addresses"] = [rdata.address for rdata in a_answers]
        result["has_a_record"] = len(result["ip_addresses"]) > 0
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer,
            dns.resolver.NoNameservers, dns.resolver.LifetimeTimeout,
            dns.exception.DNSException):
        # Domain doesn't exist, has no A record, or DNS timed out.
        pass

    # --- MX records (mail servers) ------------------------------------
    try:
        # Each MX record has a "preference" (priority) and an "exchange"
        # (the hostname of the mail server).
        mx_answers = dns.resolver.resolve(domain, "MX", lifetime=3)
        result["has_mx_record"] = len(list(mx_answers)) > 0
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer,
            dns.resolver.NoNameservers, dns.resolver.LifetimeTimeout,
            dns.exception.DNSException):
        pass

    # --- NS records (authoritative name servers) ----------------------
    try:
        ns_answers = dns.resolver.resolve(domain, "NS", lifetime=3)
        result["nameservers"] = [rdata.target.to_text() for rdata in ns_answers]
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer,
            dns.resolver.NoNameservers, dns.resolver.LifetimeTimeout,
            dns.exception.DNSException):
        pass

    return result


# =====================================================================
# TYPOSQUATTING DETECTION
# =====================================================================
# WHAT IS TYPOSQUATTING?
#   Typosquatting is registering a domain that looks almost identical to a
#   famous brand's domain, hoping users will mistype or not notice the
#   difference.  Examples:
#     "paypal.com"  → "paypa1.com"   (l → 1, distance 1)
#     "google.com"  → "gooogle.com"  (extra 'o', distance 1)
#     "amazon.com"  → "amaz0n.com"   (o → 0, distance 1)
#
# WHAT IS LEVENSHTEIN DISTANCE?
#   The Levenshtein distance between two strings is the minimum number of
#   single-character edits (insertions, deletions, or substitutions)
#   needed to turn one string into the other.
#
#   Example:
#     "paypal" → "paypa1"
#       Step 1: substitute 'l' → '1'       (1 edit)
#       → Levenshtein distance = 1
#
#     "google" → "gooogle"
#       Step 1: insert 'o' at position 2   (1 edit)
#       → Levenshtein distance = 1
#
# ALGORITHM COST:
#   We compare the input domain against each of the top-N Tranco domains.
#   Each comparison is O(m₁ × m₂) where m = domain length (~10 chars avg),
#   so each comparison is essentially O(1) in practice.
#   Total cost = O(n) where n = size of the Tranco list we load.
#   With n = 1000, this runs in < 2 ms — negligible.

def detect_typosquatting(domain: str) -> dict:
    """Check if *domain* is suspiciously close to a top-1000 legitimate domain.

    Uses Levenshtein edit distance to find the closest match.
    Flags a typosquat if edit_distance ≤ 2.

    Returns
    -------
    dict
        {
            is_typosquat: bool,
            closest_match: str | None,
            edit_distance: int | None,
            original_brand: str | None     # the well-known domain being mimicked
        }
    """
    if not _TOP_DOMAINS:
        return {
            "is_typosquat": False,
            "closest_match": None,
            "edit_distance": None,
            "original_brand": None,
            "note": "Tranco list not loaded — typosquatting check skipped",
        }

    # Strip any TLD suffix for a fairer comparison.
    # "paypa1.com" → "paypa1"  vs  "paypal.com" → "paypal"
    domain_base = domain.split(".")[0].lower()

    best_match: Optional[str] = None
    best_distance: int = 999

    for legit_domain in _TOP_DOMAINS:
        legit_base = legit_domain.split(".")[0].lower()

        # Skip if the input IS the legitimate domain (exact match ≠ typosquat)
        if domain_base == legit_base:
            return {
                "is_typosquat": False,
                "closest_match": legit_domain,
                "edit_distance": 0,
                "original_brand": None,
            }

        # Levenshtein.distance() computes the edit distance between two
        # strings.  The python-Levenshtein C extension makes this ~100×
        # faster than a pure-Python implementation.
        dist = Levenshtein.distance(domain_base, legit_base)

        if dist < best_distance:
            best_distance = dist
            best_match = legit_domain

    # Flag as typosquat if the closest legitimate domain is within 2 edits.
    # Distance 1 = very likely intentional (paypa1 → paypal).
    # Distance 2 = possible (amaazon → amazon), worth flagging.
    # Distance 3+ = probably just a different unrelated domain.
    is_typosquat = best_distance <= 2

    return {
        "is_typosquat": is_typosquat,
        "closest_match": best_match,
        "edit_distance": best_distance,
        "original_brand": best_match if is_typosquat else None,
    }


# =====================================================================
# COMBINED DOMAIN FORENSICS
# =====================================================================

def run_domain_forensics(domain: str) -> dict:
    """Run all domain-level checks and return a combined forensics dict.

    Catches individual failures so one broken check doesn't block the rest.

    Returns
    -------
    dict
        {
            "whois": { … },
            "dns": { … },
            "typosquatting": { … }
        }
    """
    # --- WHOIS ---------------------------------------------------------
    # GOTCHA: WHOIS fails ~20% of the time (timeouts, missing data, privacy
    #   shields).  We never let it crash the pipeline.
    try:
        whois_data = get_whois_info(domain)
    except Exception as exc:
        logger.error("WHOIS unexpected error for %s: %s", domain, exc)
        whois_data = {
            "registrar": None, "creation_date": None,
            "domain_age_days": None, "is_newly_registered": False,
            "available": False, "error": str(exc),
        }

    # --- DNS -----------------------------------------------------------
    try:
        dns_data = get_dns_records(domain)
    except Exception as exc:
        logger.error("DNS unexpected error for %s: %s", domain, exc)
        dns_data = {
            "has_a_record": False, "has_mx_record": False,
            "nameservers": [], "ip_addresses": [],
            "available": False, "error": str(exc),
        }

    # --- Typosquatting -------------------------------------------------
    try:
        typo_data = detect_typosquatting(domain)
    except Exception as exc:
        logger.error("Typosquatting check error for %s: %s", domain, exc)
        typo_data = {
            "is_typosquat": False, "closest_match": None,
            "edit_distance": None, "original_brand": None,
            "error": str(exc),
        }

    return {
        "whois": whois_data,
        "dns": dns_data,
        "typosquatting": typo_data,
    }
