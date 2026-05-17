import os
import logging
from datetime import datetime, timezone
from typing import Optional
import whois
import dns.resolver
import Levenshtein
import pandas as pd
logger = logging.getLogger('phishguard.domain_intel')
_SERVICE_DIR = os.path.dirname(os.path.abspath(__file__))
_BACKEND_DIR = os.path.dirname(_SERVICE_DIR)
_PROJECT_ROOT = os.path.dirname(_BACKEND_DIR)
_TRANCO_PATH = os.path.join(_PROJECT_ROOT, 'ml', 'data', 'tranco_top1m.csv')
_TOP_DOMAINS: list[str] = []
try:
    if os.path.isfile(_TRANCO_PATH):
        _df = pd.read_csv(_TRANCO_PATH, header=None, names=['rank', 'domain'], nrows=10000)
        _TOP_DOMAINS = _df['domain'].tolist()
        logger.info('Loaded %d Tranco domains for typosquatting check', len(_TOP_DOMAINS))
    else:
        logger.warning('Tranco list not found at %s — typosquatting check disabled', _TRANCO_PATH)
except Exception as exc:
    logger.error('Failed to load Tranco list: %s', exc)

def get_whois_info(domain: str) -> dict:
    try:
        w = whois.whois(domain)
        registrar = w.registrar
        creation_date_raw = w.creation_date
        if isinstance(creation_date_raw, list):
            creation_date_raw = creation_date_raw[0]
        creation_date: Optional[datetime] = None
        creation_date_str: Optional[str] = None
        domain_age_days: Optional[int] = None
        is_newly_registered = False
        if isinstance(creation_date_raw, datetime):
            creation_date = creation_date_raw
            if creation_date.tzinfo is None:
                creation_date = creation_date.replace(tzinfo=timezone.utc)
            creation_date_str = creation_date.isoformat()
            domain_age_days = (datetime.now(timezone.utc) - creation_date).days
            is_newly_registered = domain_age_days < 180
        return {'registrar': registrar, 'creation_date': creation_date_str, 'domain_age_days': domain_age_days, 'is_newly_registered': is_newly_registered, 'available': True}
    except Exception as exc:
        logger.warning('WHOIS lookup failed for %s: %s', domain, exc)
        return {'registrar': None, 'creation_date': None, 'domain_age_days': None, 'is_newly_registered': False, 'available': False, 'error': str(exc)}

def get_dns_records(domain: str) -> dict:
    result = {'has_a_record': False, 'has_mx_record': False, 'nameservers': [], 'ip_addresses': [], 'available': True}
    try:
        a_answers = dns.resolver.resolve(domain, 'A', lifetime=3)
        result['ip_addresses'] = [rdata.address for rdata in a_answers]
        result['has_a_record'] = len(result['ip_addresses']) > 0
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers, dns.resolver.LifetimeTimeout, dns.exception.DNSException):
        pass
    try:
        mx_answers = dns.resolver.resolve(domain, 'MX', lifetime=3)
        result['has_mx_record'] = len(list(mx_answers)) > 0
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers, dns.resolver.LifetimeTimeout, dns.exception.DNSException):
        pass
    try:
        ns_answers = dns.resolver.resolve(domain, 'NS', lifetime=3)
        result['nameservers'] = [rdata.target.to_text() for rdata in ns_answers]
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers, dns.resolver.LifetimeTimeout, dns.exception.DNSException):
        pass
    return result

def detect_typosquatting(domain: str) -> dict:
    if not _TOP_DOMAINS:
        return {'is_typosquat': False, 'closest_match': None, 'edit_distance': None, 'original_brand': None, 'note': 'Tranco list not loaded — typosquatting check skipped'}
    domain_base = domain.split('.')[0].lower()
    best_match: Optional[str] = None
    best_distance: int = 999
    for legit_domain in _TOP_DOMAINS:
        legit_base = legit_domain.split('.')[0].lower()
        if domain_base == legit_base:
            return {'is_typosquat': False, 'closest_match': legit_domain, 'edit_distance': 0, 'original_brand': None}
        dist = Levenshtein.distance(domain_base, legit_base)
        if dist < best_distance:
            best_distance = dist
            best_match = legit_domain
    is_typosquat = best_distance <= 2
    return {'is_typosquat': is_typosquat, 'closest_match': best_match, 'edit_distance': best_distance, 'original_brand': best_match if is_typosquat else None}

def run_domain_forensics(domain: str) -> dict:
    try:
        whois_data = get_whois_info(domain)
    except Exception as exc:
        logger.error('WHOIS unexpected error for %s: %s', domain, exc)
        whois_data = {'registrar': None, 'creation_date': None, 'domain_age_days': None, 'is_newly_registered': False, 'available': False, 'error': str(exc)}
    try:
        dns_data = get_dns_records(domain)
    except Exception as exc:
        logger.error('DNS unexpected error for %s: %s', domain, exc)
        dns_data = {'has_a_record': False, 'has_mx_record': False, 'nameservers': [], 'ip_addresses': [], 'available': False, 'error': str(exc)}
    try:
        typo_data = detect_typosquatting(domain)
    except Exception as exc:
        logger.error('Typosquatting check error for %s: %s', domain, exc)
        typo_data = {'is_typosquat': False, 'closest_match': None, 'edit_distance': None, 'original_brand': None, 'error': str(exc)}
    return {'whois': whois_data, 'dns': dns_data, 'typosquatting': typo_data}