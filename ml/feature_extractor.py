# FILE: feature_extractor.py
# PURPOSE: Extracts numerical features from URLs and decodes obfuscation tricks for phishing detection
# CONNECTS TO: backend/routes/scan.py, ml/train.py, backend/services/domain_intel.py

import re
import math
import struct
import socket
from urllib.parse import urlparse, unquote
from collections import Counter


# ---------------------------------------------------------------------------
# Feature extraction
# ---------------------------------------------------------------------------

def extract_features(url: str) -> dict:
    """Extract phishing-relevant numerical features from a raw URL string.

    Parameters
    ----------
    url : str
        The full URL to analyse (e.g. "https://example.com/path?q=1").

    Returns
    -------
    dict
        A flat dictionary of feature-name → numeric-value pairs.
    """
    parsed = urlparse(url)
    domain = parsed.netloc or ""
    full = url

    # Strip optional port and userinfo from domain for length measurement
    bare_domain = domain.split("@")[-1].split(":")[0]

    features: dict = {}

    # ------------------------------------------------------------------
    # 1. Basic character-count features
    # ------------------------------------------------------------------

    # WHY: Phishing URLs tend to be abnormally long because attackers pack
    #       extra sub-domains, path segments, or query params to mimic legit
    #       sites (e.g. "login.paypal.com.secure-verify.evil.com/…").
    features["url_length"] = len(full)

    # WHY: More dots usually means more sub-domains, a classic trick to
    #       visually bury the real domain deep inside the hostname.
    features["num_dots"] = full.count(".")

    # WHY: Hyphens are cheap filler in domain names.  Legitimate brands
    #       rarely use many hyphens, but "paypal-secure-login.com" is common
    #       in phishing kits.
    features["num_hyphens"] = full.count("-")

    # WHY: The '@' in a URL is the "userinfo" separator.  Browsers ignore
    #       everything before it, so "http://google.com@evil.com" actually
    #       navigates to evil.com — a well-known deception trick.
    features["num_at_symbols"] = full.count("@")

    # ------------------------------------------------------------------
    # 2. Special-character density
    # ------------------------------------------------------------------

    # WHY: A high ratio of query / fragment metacharacters often signals an
    #       overly-complex URL designed to confuse the user or carry a
    #       payload (open-redirect chains, encoded scripts, etc.).
    #
    # REFINEMENT: We ignore common tracking parameters like "utm_" which are
    #              ubiquitous on legitimate sites but rare in phishing.
    clean_for_chars = full
    if "utm_" in clean_for_chars:
        clean_for_chars = re.sub(r"[?&]utm_[^&]+", "", clean_for_chars)

    _SPECIAL = set("?=&%#/")
    features["num_special_chars"] = sum(1 for ch in clean_for_chars if ch in _SPECIAL)

    # ------------------------------------------------------------------
    # 3. Subdomain depth
    # ------------------------------------------------------------------

    # WHY: Legitimate sites rarely exceed 1-2 subdomain levels.  A depth of
    #       3+ (e.g. "login.secure.paypal.com.evil.com") is a strong phishing
    #       indicator — the attacker prepends trusted-looking labels.
    #
    # We count the dots in the hostname *before* the registered domain.
    # A simple heuristic: total dots minus 1 (for the TLD separator).
    # For "a.b.c.example.com" → 4 dots → depth = 3.
    domain_dots = bare_domain.count(".")
    features["subdomain_depth"] = max(domain_dots - 1, 0)

    # ------------------------------------------------------------------
    # 4. IP-address presence
    # ------------------------------------------------------------------

    # WHY: Almost no legitimate website asks users to visit a raw IP address.
    #       Phishing kits frequently host pages on bare IPs to avoid domain
    #       takedowns and DNS-based blocklists.
    #
    # GOTCHA: This regex matches simple dotted-quad IPv4 only.  It will NOT
    #         catch IPv6 addresses, hex-encoded IPs (0x7f.0x00…), or octal
    #         notation.  The decode_obfuscation() function handles those
    #         separately.
    _IPV4_RE = re.compile(
        r"(?:^|(?<=[@/]))(\d{1,3}\.){3}\d{1,3}(?=(?:[:/?#]|$))"
    )
    features["has_ip_address"] = int(bool(_IPV4_RE.search(bare_domain)))

    # ------------------------------------------------------------------
    # 5. HTTPS flag
    # ------------------------------------------------------------------

    # WHY: While HTTPS alone doesn't guarantee safety, *lack* of HTTPS is a
    #       useful signal — many quick-and-dirty phishing pages skip TLS
    #       because free cert provisioning adds an extra step.
    features["has_https"] = int(parsed.scheme.lower() == "https")

    # ------------------------------------------------------------------
    # 6. Shannon entropy
    # ------------------------------------------------------------------

    # WHY: Randomly-generated or heavily-obfuscated URLs have high entropy.
    #       Legit domains are usually pronounceable words with low entropy.
    #       A value above ~4.5 is suspicious for a domain string.
    features["shannon_entropy"] = _shannon_entropy(full)

    # ------------------------------------------------------------------
    # 7. Domain length
    # ------------------------------------------------------------------

    # WHY: Very short domains may be typo-squats (e.g. "g00gle.com") while
    #       very long domains are often auto-generated by phishing kits.
    #       Both extremes deviate from the typical 6-15 char range.
    features["domain_length"] = len(bare_domain)

    # ------------------------------------------------------------------
    # 8. Common TLD check
    # ------------------------------------------------------------------

    # WHY: Phishing disproportionately uses .com, .net, .org, or cheap/free
    #       TLDs (.tk, .cf).  Legitimate sites often use regional TLDs
    #       (.co.uk, .in, .de) which phishers avoid to maintain a global feel.
    _COMMON_TLDS = {".com", ".net", ".org", ".edu", ".gov"}
    tld = "." + bare_domain.split(".")[-1].lower()
    features["is_common_tld"] = int(tld in _COMMON_TLDS)

    return features


def _shannon_entropy(text: str) -> float:
    """Compute the Shannon entropy (bits) of *text*.

    Higher values indicate more randomness / less structure.
    """
    if not text:
        return 0.0
    length = len(text)
    freq = Counter(text)
    return -sum(
        (count / length) * math.log2(count / length)
        for count in freq.values()
    )


# ---------------------------------------------------------------------------
# Obfuscation decoder
# ---------------------------------------------------------------------------

def decode_obfuscation(url: str) -> dict:
    """Detect and decode common URL-obfuscation techniques used by phishers.

    Parameters
    ----------
    url : str
        The raw (potentially obfuscated) URL.

    Returns
    -------
    dict
        {
            "cleaned_url": str,              # the URL after decoding
            "obfuscation_techniques_found": list[str]  # human-readable labels
        }
    """
    techniques_found: list[str] = []
    cleaned = url

    # ------------------------------------------------------------------
    # Step 1 — Percent-encoding (%xx)
    # ------------------------------------------------------------------

    # OBFUSCATION: Attackers encode normal characters (e.g. "." → "%2e") so
    #              the URL looks harmless to the naked eye but still resolves
    #              to the malicious host.  urllib.parse.unquote reverses this.
    decoded = unquote(cleaned)
    if decoded != cleaned:
        techniques_found.append("percent_encoding")
        cleaned = decoded

    # ------------------------------------------------------------------
    # Step 2 — The '@' trick (userinfo abuse)
    # ------------------------------------------------------------------

    # OBFUSCATION: RFC 3986 allows "user:pass@host" in the authority.  Most
    #              browsers silently ignore everything before the '@'.
    #              "http://www.google.com@evil.com" actually loads evil.com,
    #              but the user sees "google.com" first and trusts the link.
    parsed = urlparse(cleaned)
    if "@" in (parsed.netloc or ""):
        techniques_found.append("at_sign_trick")

    # ------------------------------------------------------------------
    # Step 3 — Hex-encoded IPs (e.g. 0x7f000001 → 127.0.0.1)
    # ------------------------------------------------------------------

    # OBFUSCATION: Instead of "192.168.1.1", an attacker can write the IP as
    #              a single 32-bit hex integer "0xC0A80101" or even an octal
    #              string "0300.0250.0001.0001".  Browsers still resolve these
    #              but most humans can't read them.
    #
    # GOTCHA: The regex below targets the common "0x[0-9a-fA-F]+" pattern in
    #         the host portion.  It will NOT decode every exotic representation
    #         (e.g. mixed hex-per-octet "0x7f.0.0.1") — those are rare in the
    #         wild but possible.
    host = (parsed.netloc or "").split("@")[-1].split(":")[0]

    # Check for a single large hex integer (0xHHHHHHHH)
    _HEX_IP_RE = re.compile(r"^0x([0-9a-fA-F]{1,8})$")
    hex_match = _HEX_IP_RE.match(host)
    if hex_match:
        try:
            ip_int = int(hex_match.group(1), 16)
            readable_ip = socket.inet_ntoa(struct.pack("!I", ip_int))
            cleaned = cleaned.replace(host, readable_ip, 1)
            techniques_found.append(f"hex_encoded_ip ({host} → {readable_ip})")
        except (struct.error, OSError):
            pass

    # Check for octal-per-octet notation (e.g. 0177.0000.0000.0001)
    # GOTCHA: This simple regex requires all four octets to start with a
    #         leading zero.  A mixed decimal/octal host will be missed.
    _OCTAL_IP_RE = re.compile(
        r"^(0\d{1,4})\.(0\d{1,4})\.(0\d{1,4})\.(0\d{1,4})$"
    )
    octal_match = _OCTAL_IP_RE.match(host)
    if octal_match:
        try:
            octets = [int(o, 8) for o in octal_match.groups()]
            if all(0 <= o <= 255 for o in octets):
                readable_ip = ".".join(str(o) for o in octets)
                cleaned = cleaned.replace(host, readable_ip, 1)
                techniques_found.append(
                    f"octal_encoded_ip ({host} → {readable_ip})"
                )
        except ValueError:
            pass

    return {
        "cleaned_url": cleaned,
        "obfuscation_techniques_found": techniques_found,
    }


# ---------------------------------------------------------------------------
# Quick self-test
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    test_urls = [
        "http://192.168.1.1/login",
        "https://paypa1.com/secure",
        "http://evil%2ecom/phish",
    ]

    print("=" * 70)
    print("FEATURE EXTRACTION")
    print("=" * 70)
    for url in test_urls:
        print(f"\n>>> {url}")
        feats = extract_features(url)
        for k, v in feats.items():
            print(f"    {k:25s} = {v}")

    print("\n" + "=" * 70)
    print("OBFUSCATION DECODING")
    print("=" * 70)
    for url in test_urls:
        print(f"\n>>> {url}")
        result = decode_obfuscation(url)
        print(f"    cleaned_url  : {result['cleaned_url']}")
        print(f"    techniques   : {result['obfuscation_techniques_found']}")
