"""
URL Feature Extractor
=====================
Extracts 21 features from a URL for phishing detection.

Features cover:
  - URL structure (length, depth, special chars)
  - Domain analysis (age indicators, digit ratio, brand impersonation)
  - Security signals (HTTPS, IP address, shorteners)
  - Statistical properties (entropy, vowel/consonant ratio)
"""

import re
import math
import struct
import socket
from urllib.parse import urlparse, unquote
from collections import Counter


# ──────────────────────────────────────────────────────────────
# Known URL shortener domains
# ──────────────────────────────────────────────────────────────
_SHORTENER_DOMAINS = frozenset({
    'bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly', 'is.gd',
    'buff.ly', 'adf.ly', 'cutt.ly', 'rb.gy', 'shorturl.at',
    'tiny.cc', 'short.io', 'v.gd', 'clck.ru', 'rebrand.ly',
    'bl.ink', 'lnkd.in', 'youtu.be', 'amzn.to',
})

# ──────────────────────────────────────────────────────────────
# Popular brand names for brand-in-subdomain detection
# ──────────────────────────────────────────────────────────────
_BRAND_KEYWORDS = frozenset({
    'paypal', 'apple', 'google', 'microsoft', 'amazon', 'netflix',
    'facebook', 'instagram', 'twitter', 'linkedin', 'chase', 'wells',
    'bankofamerica', 'citibank', 'dropbox', 'icloud', 'outlook',
    'yahoo', 'ebay', 'steam', 'roblox', 'adobe', 'spotify',
    'whatsapp', 'telegram', 'coinbase', 'binance', 'blockchain',
    'metamask', 'dhl', 'fedex', 'usps', 'ups', 'walmart',
})

_SPECIAL = frozenset('?=&%#/')
_COMMON_TLDS = frozenset({'.com', '.net', '.org', '.edu', '.gov'})
_SUSPICIOUS_TLDS = frozenset({
    '.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.buzz',
    '.club', '.work', '.info', '.online', '.site', '.icu', '.su',
    '.pw', '.cc', '.ws', '.click', '.link', '.win', '.bid',
})
_IPV4_RE = re.compile(r'(?:^|(?<=[@/]))(\d{1,3}\.){3}\d{1,3}(?=(?:[:/?#]|$))')


def extract_features(url: str) -> dict:
    """
    Extract 21 features from a URL string.
    Returns a dict with feature_name → numeric_value.
    """
    parsed = urlparse(url)
    full = url
    domain = parsed.netloc or ''
    bare_domain = domain.split('@')[-1].split(':')[0]
    path = parsed.path or ''
    query = parsed.query or ''

    features: dict = {}

    # ── 1. URL structure features ──
    features['url_length'] = len(full)
    features['num_dots'] = full.count('.')
    features['num_hyphens'] = full.count('-')
    features['num_at_symbols'] = full.count('@')

    # Strip UTM params before counting special chars
    clean_for_chars = full
    if 'utm_' in clean_for_chars:
        clean_for_chars = re.sub(r'[?&]utm_[^&]+', '', clean_for_chars)
    features['num_special_chars'] = sum(1 for ch in clean_for_chars if ch in _SPECIAL)

    # ── 2. Domain features ──
    domain_dots = bare_domain.count('.')
    features['subdomain_depth'] = max(domain_dots - 1, 0)
    features['has_ip_address'] = int(bool(_IPV4_RE.search(bare_domain)))
    features['has_https'] = int(parsed.scheme.lower() == 'https')
    features['domain_length'] = len(bare_domain)

    tld = '.' + bare_domain.split('.')[-1].lower() if '.' in bare_domain else ''
    features['is_common_tld'] = int(tld in _COMMON_TLDS)

    # ── 3. Statistical features ──
    features['shannon_entropy'] = _shannon_entropy(full)

    # ── 4. NEW features for improved detection ──

    # Path analysis
    features['path_length'] = len(path)
    features['path_depth'] = path.count('/') - 1 if path else 0  # subtract leading /

    # Domain digit analysis
    digits_in_domain = sum(1 for c in bare_domain if c.isdigit())
    features['num_digits_in_domain'] = digits_in_domain
    features['digit_ratio'] = digits_in_domain / max(len(bare_domain), 1)

    # Subdomain count (more precise than depth)
    parts = bare_domain.split('.')
    features['num_subdomains'] = max(len(parts) - 2, 0)

    # Port detection
    features['has_port'] = int(':' in domain and not domain.endswith(':'))

    # Redirect trick: double-slash in path (e.g., //evil.com)
    features['has_double_slash_redirect'] = int('//' in path)

    # URL shortener detection
    base_domain = '.'.join(parts[-2:]).lower() if len(parts) >= 2 else bare_domain.lower()
    features['has_shortener'] = int(base_domain in _SHORTENER_DOMAINS)

    # Vowel-consonant ratio (random DGA domains have very few vowels)
    vowels = set('aeiouAEIOU')
    consonants = set('bcdfghjklmnpqrstvwxyzBCDFGHJKLMNPQRSTVWXYZ')
    v_count = sum(1 for c in bare_domain if c in vowels)
    c_count = sum(1 for c in bare_domain if c in consonants)
    features['vowel_consonant_ratio'] = v_count / max(c_count, 1)

    # Brand name in subdomain (e.g., paypal.evil.com)
    subdomain_part = '.'.join(parts[:-2]).lower() if len(parts) > 2 else ''
    features['brand_in_subdomain'] = int(any(
        brand in subdomain_part for brand in _BRAND_KEYWORDS
    ))

    # Suspicious TLD
    features['is_suspicious_tld'] = int(tld in _SUSPICIOUS_TLDS)

    return features


def _shannon_entropy(text: str) -> float:
    """Calculate Shannon entropy of a string."""
    if not text:
        return 0.0
    length = len(text)
    freq = Counter(text)
    return -sum(count / length * math.log2(count / length) for count in freq.values())


def decode_obfuscation(url: str) -> dict:
    """
    Detect and decode common URL obfuscation techniques.
    Returns cleaned URL and list of techniques found.
    """
    techniques_found: list[str] = []
    cleaned = url

    # Percent-encoding
    decoded = unquote(cleaned)
    if decoded != cleaned:
        techniques_found.append('percent_encoding')
        cleaned = decoded

    parsed = urlparse(cleaned)

    # @ sign trick (user@evil.com in URL)
    if '@' in (parsed.netloc or ''):
        techniques_found.append('at_sign_trick')

    host = (parsed.netloc or '').split('@')[-1].split(':')[0]

    # Hex-encoded IP
    _HEX_IP_RE = re.compile(r'^0x([0-9a-fA-F]{1,8})$')
    hex_match = _HEX_IP_RE.match(host)
    if hex_match:
        try:
            ip_int = int(hex_match.group(1), 16)
            readable_ip = socket.inet_ntoa(struct.pack('!I', ip_int))
            cleaned = cleaned.replace(host, readable_ip, 1)
            techniques_found.append(f'hex_encoded_ip ({host} → {readable_ip})')
        except (struct.error, OSError):
            pass

    # Octal-encoded IP
    _OCTAL_IP_RE = re.compile(r'^(0\d{1,4})\.(0\d{1,4})\.(0\d{1,4})\.(0\d{1,4})$')
    octal_match = _OCTAL_IP_RE.match(host)
    if octal_match:
        try:
            octets = [int(o, 8) for o in octal_match.groups()]
            if all(0 <= o <= 255 for o in octets):
                readable_ip = '.'.join(str(o) for o in octets)
                cleaned = cleaned.replace(host, readable_ip, 1)
                techniques_found.append(f'octal_encoded_ip ({host} → {readable_ip})')
        except ValueError:
            pass

    return {'cleaned_url': cleaned, 'obfuscation_techniques_found': techniques_found}


if __name__ == '__main__':
    test_urls = [
        'http://192.168.1.1/login',
        'https://paypa1.com/secure',
        'http://evil%2ecom/phish',
        'https://login-paypal.suspicious.tk/account/verify',
        'https://bit.ly/3xAbCd',
        'https://google.com',
    ]
    print('=' * 70)
    print('FEATURE EXTRACTION (21 features)')
    print('=' * 70)
    for url in test_urls:
        print(f'\n>>> {url}')
        feats = extract_features(url)
        for k, v in feats.items():
            print(f'    {k:30s} = {v}')
    print('\n' + '=' * 70)
    print('OBFUSCATION DECODING')
    print('=' * 70)
    for url in test_urls:
        print(f'\n>>> {url}')
        result = decode_obfuscation(url)
        print(f"    cleaned_url  : {result['cleaned_url']}")
        print(f"    techniques   : {result['obfuscation_techniques_found']}")