import os
import asyncio
import logging
from typing import Any
import httpx

logger = logging.getLogger('phishguard.threat_intel')
VIRUSTOTAL_API_KEY = os.environ.get('VIRUSTOTAL_API_KEY', '')
HTTP_TIMEOUT = 5.0

async def check_virustotal(url: str) -> dict:
    if not VIRUSTOTAL_API_KEY:
        logger.warning('VIRUSTOTAL_API_KEY not set — skipping VT check')
        return _vt_unavailable('api_key_missing')
    headers = {'x-apikey': VIRUSTOTAL_API_KEY}
    try:
        async with httpx.AsyncClient(timeout=HTTP_TIMEOUT) as client:
            submit_resp = await client.post('https://www.virustotal.com/api/v3/urls', headers=headers, data={'url': url})
            submit_resp.raise_for_status()
            analysis_id = submit_resp.json()['data']['id']
            report_resp = await client.get(f'https://www.virustotal.com/api/v3/analyses/{analysis_id}', headers=headers)
            report_resp.raise_for_status()
            stats = report_resp.json().get('data', {}).get('attributes', {}).get('stats', {})
        malicious = int(stats.get('malicious', 0))
        suspicious = int(stats.get('suspicious', 0))
        undetected = int(stats.get('undetected', 0))
        harmless = int(stats.get('harmless', 0))
        total = malicious + suspicious + undetected + harmless
        if malicious >= 5:
            verdict = 'malicious'
        elif malicious >= 2 or suspicious >= 4:
            verdict = 'suspicious'
        else:
            verdict = 'clean'
        return {'source': 'virustotal', 'malicious_count': malicious, 'suspicious_count': suspicious, 'total_engines': total, 'verdict': verdict, 'available': True}
    except Exception as exc:
        logger.error('VirusTotal check failed: %s', exc)
        return _vt_unavailable(str(exc))

def _vt_unavailable(reason: str) -> dict:
    return {'source': 'virustotal', 'malicious_count': 0, 'suspicious_count': 0, 'total_engines': 0, 'verdict': 'unavailable', 'available': False, 'error': reason}

async def check_urlhaus(url: str) -> dict:
    try:
        async with httpx.AsyncClient(timeout=HTTP_TIMEOUT) as client:
            resp = await client.post('https://urlhaus-api.abuse.ch/v1/url/', data={'url': url})
            resp.raise_for_status()
            data = resp.json()
        is_known = data.get('query_status') != 'no_results'
        tags = data.get('tags') or []
        if isinstance(tags, str):
            tags = [tags]
        date_added = data.get('date_added')
        return {'source': 'urlhaus', 'is_known_malicious': is_known, 'tags': tags, 'date_added': date_added, 'available': True}
    except Exception as exc:
        logger.error('URLhaus check failed: %s', exc)
        return {'source': 'urlhaus', 'is_known_malicious': False, 'tags': [], 'date_added': None, 'available': False, 'error': str(exc)}

async def run_threat_intel(url: str) -> dict:
    vt_result, uh_result = await asyncio.gather(check_virustotal(url), check_urlhaus(url), return_exceptions=True)
    if isinstance(vt_result, Exception):
        logger.error('VT gather exception: %s', vt_result)
        vt_result = _vt_unavailable(str(vt_result))
    if isinstance(uh_result, Exception):
        logger.error('URLhaus gather exception: %s', uh_result)
        uh_result = {'source': 'urlhaus', 'is_known_malicious': False, 'tags': [], 'date_added': None, 'available': False, 'error': str(uh_result)}
    return {'virustotal': vt_result, 'urlhaus': uh_result}

def combine_final_score(ml_confidence: float, threat_intel: dict, forensics: dict=None) -> dict:
    reasons: list[str] = []
    forensics = forensics or {}
    ml_score = ml_confidence
    if ml_confidence >= 0.5:
        reasons.append(f'ML model flagged as phishing ({ml_confidence:.1%} confidence)')
    vt = threat_intel.get('virustotal', {})
    vt_total = vt.get('total_engines', 0)
    vt_malicious = vt.get('malicious_count', 0)
    if vt.get('available') and vt_total > 0:
        vt_ratio = vt_malicious / vt_total
    else:
        vt_ratio = 0.0
    if vt_malicious >= 1:
        reasons.append(f'VirusTotal: {vt_malicious}/{vt_total} engines flagged as malicious')
    uh = threat_intel.get('urlhaus', {})
    uh_flag = 1.0 if uh.get('is_known_malicious') else 0.0
    if uh.get('is_known_malicious'):
        tags = ', '.join(uh.get('tags', [])) or 'unknown'
        reasons.append(f'URLhaus: known malicious URL (tags: {tags})')
        
    ml_weight = 0.4
    vt_weight = 0.4 if (vt.get('available') and vt_total > 0) else 0.0
    uh_weight = 0.2 if uh.get('available') else 0.0
    
    total_weight = ml_weight + vt_weight + uh_weight
    if total_weight > 0:
        raw_score = (ml_score * ml_weight + vt_ratio * vt_weight + uh_flag * uh_weight) / total_weight
    else:
        raw_score = ml_score

    forensics_penalty = 0.0
    typo = forensics.get('typosquatting', {})
    if typo.get('is_typosquat'):
        dist = typo.get('edit_distance', 99)
        brand = typo.get('original_brand', 'brand')
        if dist == 1:
            forensics_penalty += 0.5
            reasons.append(f"High-confidence typosquat detected (looks like '{brand}')")
        elif dist == 2:
            forensics_penalty += 0.3
            reasons.append(f"Potential typosquat detected (similar to '{brand}')")
            
    whois = forensics.get('whois', {})
    if whois.get('is_newly_registered'):
        age = whois.get('domain_age_days', 999)
        if age < 30:
            forensics_penalty += 0.4
            reasons.append(f'Extreme risk: domain is brand new ({age} days old)')
        else:
            forensics_penalty += 0.2
            reasons.append(f'Risk: domain is newly registered ({age} days old)')
            
    dns = forensics.get('dns', {})
    domain_age = whois.get('domain_age_days')
    if dns.get('available') and (not dns.get('has_mx_record')) and (domain_age is not None and domain_age < 365):
        forensics_penalty += 0.1
        reasons.append('Missing mail records on a young domain is highly suspicious')
        
    final_score_raw = raw_score + forensics_penalty
    score = 100 - int(round(final_score_raw * 100))
    
    if ml_confidence >= 0.8:
        score = min(score, 29)
    elif ml_confidence >= 0.5:
        score = min(score, 59)

    score = max(0, min(100, score))
    if score >= 60:
        threat_level = 'safe'
    elif score >= 30:
        threat_level = 'suspicious'
    else:
        threat_level = 'malicious'
    if not reasons:
        reasons.append('No threats detected')
    return {'threat_level': threat_level, 'score': score, 'reasons': reasons}