import re
import math
import struct
import socket
from urllib.parse import urlparse, unquote
from collections import Counter

def extract_features(url: str) -> dict:
    parsed = urlparse(url)
    domain = parsed.netloc or ''
    full = url
    bare_domain = domain.split('@')[-1].split(':')[0]
    features: dict = {}
    features['url_length'] = len(full)
    features['num_dots'] = full.count('.')
    features['num_hyphens'] = full.count('-')
    features['num_at_symbols'] = full.count('@')
    clean_for_chars = full
    if 'utm_' in clean_for_chars:
        clean_for_chars = re.sub('[?&]utm_[^&]+', '', clean_for_chars)
    _SPECIAL = set('?=&%#/')
    features['num_special_chars'] = sum((1 for ch in clean_for_chars if ch in _SPECIAL))
    domain_dots = bare_domain.count('.')
    features['subdomain_depth'] = max(domain_dots - 1, 0)
    _IPV4_RE = re.compile('(?:^|(?<=[@/]))(\\d{1,3}\\.){3}\\d{1,3}(?=(?:[:/?#]|$))')
    features['has_ip_address'] = int(bool(_IPV4_RE.search(bare_domain)))
    features['has_https'] = int(parsed.scheme.lower() == 'https')
    features['shannon_entropy'] = _shannon_entropy(full)
    features['domain_length'] = len(bare_domain)
    _COMMON_TLDS = {'.com', '.net', '.org', '.edu', '.gov'}
    tld = '.' + bare_domain.split('.')[-1].lower()
    features['is_common_tld'] = int(tld in _COMMON_TLDS)
    return features

def _shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    length = len(text)
    freq = Counter(text)
    return -sum((count / length * math.log2(count / length) for count in freq.values()))

def decode_obfuscation(url: str) -> dict:
    techniques_found: list[str] = []
    cleaned = url
    decoded = unquote(cleaned)
    if decoded != cleaned:
        techniques_found.append('percent_encoding')
        cleaned = decoded
    parsed = urlparse(cleaned)
    if '@' in (parsed.netloc or ''):
        techniques_found.append('at_sign_trick')
    host = (parsed.netloc or '').split('@')[-1].split(':')[0]
    _HEX_IP_RE = re.compile('^0x([0-9a-fA-F]{1,8})$')
    hex_match = _HEX_IP_RE.match(host)
    if hex_match:
        try:
            ip_int = int(hex_match.group(1), 16)
            readable_ip = socket.inet_ntoa(struct.pack('!I', ip_int))
            cleaned = cleaned.replace(host, readable_ip, 1)
            techniques_found.append(f'hex_encoded_ip ({host} → {readable_ip})')
        except (struct.error, OSError):
            pass
    _OCTAL_IP_RE = re.compile('^(0\\d{1,4})\\.(0\\d{1,4})\\.(0\\d{1,4})\\.(0\\d{1,4})$')
    octal_match = _OCTAL_IP_RE.match(host)
    if octal_match:
        try:
            octets = [int(o, 8) for o in octal_match.groups()]
            if all((0 <= o <= 255 for o in octets)):
                readable_ip = '.'.join((str(o) for o in octets))
                cleaned = cleaned.replace(host, readable_ip, 1)
                techniques_found.append(f'octal_encoded_ip ({host} → {readable_ip})')
        except ValueError:
            pass
    return {'cleaned_url': cleaned, 'obfuscation_techniques_found': techniques_found}
if __name__ == '__main__':
    test_urls = ['http://192.168.1.1/login', 'https://paypa1.com/secure', 'http://evil%2ecom/phish']
    print('=' * 70)
    print('FEATURE EXTRACTION')
    print('=' * 70)
    for url in test_urls:
        print(f'\n>>> {url}')
        feats = extract_features(url)
        for k, v in feats.items():
            print(f'    {k:25s} = {v}')
    print('\n' + '=' * 70)
    print('OBFUSCATION DECODING')
    print('=' * 70)
    for url in test_urls:
        print(f'\n>>> {url}')
        result = decode_obfuscation(url)
        print(f'    cleaned_url  : {result['cleaned_url']}')
        print(f'    techniques   : {result['obfuscation_techniques_found']}')