import asyncio
import time
from typing import Any
from urllib.parse import urlparse
from fastapi import APIRouter, Request
from pydantic import BaseModel, Field
from ml.feature_extractor import extract_features, decode_obfuscation
from services.threat_intel import run_threat_intel, combine_final_score
from services.domain_intel import get_whois_info, get_dns_records, detect_typosquatting
router = APIRouter(prefix='/scan', tags=['Scan'])

class ScanRequest(BaseModel):
    url: str = Field(..., description='The URL to analyse for phishing')

class MLResult(BaseModel):
    is_phishing: bool
    confidence: float

class ThreatScoreResponse(BaseModel):
    threat_level: str
    score: int
    reasons: list[str]

class ScanResponse(BaseModel):
    url: str
    cleaned_url: str
    obfuscation_found: list[str]
    ml: MLResult
    threat_intel: dict[str, Any]
    forensics: dict[str, Any]
    final: ThreatScoreResponse
    response_time_ms: float

@router.post('/', response_model=ScanResponse)
async def scan_url(req: ScanRequest, request: Request):
    start = time.perf_counter()
    url_to_scan = req.url.strip()
    if not url_to_scan.startswith(('http://', 'https://')):
        url_to_scan = 'http://' + url_to_scan
    obfus = decode_obfuscation(url_to_scan)
    cleaned_url: str = obfus['cleaned_url']
    obfuscation_found: list[str] = obfus['obfuscation_techniques_found']
    features: dict = extract_features(cleaned_url)
    feature_order: list[str] = request.app.state.feature_order
    aligned_values = [features.get(col, 0) for col in feature_order]
    model = request.app.state.model
    if model is not None and feature_order:
        proba = model.predict_proba([aligned_values])[0]
        ml_confidence = float(proba[1])
        is_phishing = ml_confidence >= 0.5
    else:
        ml_confidence = 0.0
        is_phishing = False
    parsed = urlparse(cleaned_url)
    bare_domain = (parsed.netloc or '').split('@')[-1].split(':')[0]
    if bare_domain.startswith('www.'):
        bare_domain = bare_domain[4:]
    loop = asyncio.get_event_loop()

    async def run_sync(func, *args):
        return await loop.run_in_executor(None, func, *args)
    threat_intel_result, whois_result, dns_result, typo_result = await asyncio.gather(run_threat_intel(cleaned_url), run_sync(get_whois_info, bare_domain), run_sync(get_dns_records, bare_domain), run_sync(detect_typosquatting, bare_domain), return_exceptions=True)
    if isinstance(threat_intel_result, Exception):
        threat_intel_result = {'virustotal': {}, 'urlhaus': {}, 'error': str(threat_intel_result)}
    if isinstance(whois_result, Exception):
        whois_result = {'error': str(whois_result)}
    if isinstance(dns_result, Exception):
        dns_result = {'error': str(dns_result)}
    if isinstance(typo_result, Exception):
        typo_result = {'error': str(typo_result)}
    if typo_result.get('edit_distance') == 0:
        ml_confidence = 0.0
        is_phishing = False
    forensics_data = {'whois': whois_result, 'dns': dns_result, 'typosquatting': typo_result}
    threat_score_data = combine_final_score(ml_confidence, threat_intel_result, forensics_data)
    if whois_result.get('is_newly_registered'):
        age = whois_result.get('domain_age_days', '?')
        threat_score_data['reasons'].append(f'Domain is newly registered ({age} days old — phishing domains are typically < 180 days)')
    if typo_result.get('is_typosquat'):
        brand = typo_result.get('original_brand', '?')
        dist = typo_result.get('edit_distance', '?')
        threat_score_data['reasons'].append(f"Possible typosquat of '{brand}' (edit distance: {dist})")
    domain_age = whois_result.get('domain_age_days')
    is_new = domain_age is not None and domain_age < 365
    if dns_result.get('available') and (not dns_result.get('has_mx_record')) and is_new:
        threat_score_data['reasons'].append('Domain has no MX record and is relatively new — suspicious for a business')
    if threat_score_data['threat_level'] == 'malicious':
        is_phishing = True
    elapsed_ms = (time.perf_counter() - start) * 1000.0
    result = ScanResponse(url=req.url, cleaned_url=cleaned_url, obfuscation_found=obfuscation_found, ml=MLResult(is_phishing=is_phishing, confidence=round(ml_confidence, 4)), threat_intel=threat_intel_result, forensics={'whois': whois_result, 'dns': dns_result, 'typosquatting': typo_result}, final=ThreatScoreResponse(**threat_score_data), response_time_ms=round(elapsed_ms, 2))
    history: list = request.app.state.scan_history
    history.append(result.model_dump())
    if len(history) > 100:
        request.app.state.scan_history = history[-100:]
    return result

@router.get('/history')
async def scan_history(request: Request):
    history: list = request.app.state.scan_history
    return {'count': len(history), 'scans': history}