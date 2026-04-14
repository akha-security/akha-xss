"""
Content Security Policy (CSP) Analyzer
Analyzes CSP headers to determine if found XSS is actually exploitable
"""

import re
import logging
from typing import Dict, List, Optional

logger = logging.getLogger("akha.csp_analyzer")


class CSPAnalyzer:
    """Analyzes Content-Security-Policy headers"""
    
    def __init__(self, http_client=None):
        self.client = http_client
        self._cache = {}
    
    def _domain_key(self, url: str) -> str:
        """Extract domain-level cache key from URL"""
        try:
            from urllib.parse import urlparse
            p = urlparse(url)
            return f"{p.scheme}://{p.netloc}"
        except Exception:
            return url

    def analyze(self, url: str, response=None) -> Dict:
        """
        Analyze CSP for a URL.
        Cache is domain-level — same CSP for all pages on same domain.
        
        Returns:
            CSP analysis result with exploitability assessment
        """
        cache_key = self._domain_key(url)
        if cache_key in self._cache:
            return self._cache[cache_key]
        
        csp_header = None
        
        if response:
            csp_header = (
                response.headers.get('Content-Security-Policy') or
                response.headers.get('Content-Security-Policy-Report-Only') or
                response.headers.get('X-Content-Security-Policy')
            )
        elif self.client:
            try:
                resp = self.client.get(url, timeout=10)
                csp_header = (
                    resp.headers.get('Content-Security-Policy') or
                    resp.headers.get('Content-Security-Policy-Report-Only') or
                    resp.headers.get('X-Content-Security-Policy')
                )
            except Exception:
                logger.debug("Failed to fetch CSP headers from target", exc_info=True)
        
        result = self._parse_csp(csp_header)
        self._cache[cache_key] = result  # Store under domain key
        return result
    
    def _parse_csp(self, csp_header: Optional[str]) -> Dict:
        """Parse CSP header and assess exploitability"""
        result = {
            'has_csp': False,
            'raw': csp_header or '',
            'directives': {},
            'allows_inline_script': True,
            'allows_eval': True,
            'allows_unsafe_inline': True,
            'allows_data_uri': True,
            'xss_exploitable': True,
            'bypass_possible': False,
            'bypass_methods': [],
            'risk_level': 'no_csp',
            'details': [],
        }
        
        if not csp_header:
            result['details'].append('No CSP header found - XSS is exploitable if reflected')
            return result
        
        result['has_csp'] = True
        
        directives = {}
        for directive in csp_header.split(';'):
            directive = directive.strip()
            if not directive:
                continue
            parts = directive.split(None, 1)
            name = parts[0].lower()
            values = parts[1].split() if len(parts) > 1 else []
            directives[name] = values
        
        result['directives'] = directives
        
        script_src = directives.get('script-src', directives.get('default-src', []))
        
        if not script_src:
            result['details'].append('No script-src or default-src directive - scripts allowed from any source')
            result['risk_level'] = 'low'
            return result
        
        if "'unsafe-inline'" in script_src:
            result['allows_unsafe_inline'] = True
            result['details'].append("'unsafe-inline' present - inline scripts allowed")
            result['bypass_methods'].append('inline_script')
        else:
            result['allows_unsafe_inline'] = False
            result['allows_inline_script'] = False
            result['details'].append("'unsafe-inline' NOT present - inline scripts blocked")
        
        if "'unsafe-eval'" in script_src:
            result['allows_eval'] = True
            result['details'].append("'unsafe-eval' present - eval() allowed")
            result['bypass_methods'].append('eval')
        else:
            result['allows_eval'] = False
            result['details'].append("'unsafe-eval' NOT present - eval() blocked")
        
        if 'data:' in script_src:
            result['allows_data_uri'] = True
            result['details'].append("'data:' scheme allowed - can use data: URIs for script execution")
            result['bypass_methods'].append('data_uri')
        else:
            result['allows_data_uri'] = False
        
        if '*' in script_src:
            result['details'].append("Wildcard '*' in script-src - scripts from any domain allowed")
            result['bypass_methods'].append('wildcard')
        
        has_nonce = any("'nonce-" in v for v in script_src)
        has_hash = any(v.startswith("'sha") for v in script_src)
        
        if has_nonce:
            result['details'].append('CSP uses nonce - requires nonce value to execute inline scripts')
        if has_hash:
            result['details'].append('CSP uses hash - only pre-approved scripts execute')
        
        if "'self'" in script_src:
            result['details'].append("'self' allowed - scripts from same origin permitted")
        
        jsonp_domains = ['googleapis.com', 'accounts.google.com', 'cdnjs.cloudflare.com', 
                         'cdn.jsdelivr.net', 'ajax.googleapis.com', 'unpkg.com']
        for domain in script_src:
            for jsonp in jsonp_domains:
                if jsonp in domain:
                    result['bypass_possible'] = True
                    result['bypass_methods'].append(f'jsonp_endpoint:{domain}')
                    result['details'].append(f"JSONP-capable domain whitelisted: {domain} - CSP bypass possible")
        
        if "'strict-dynamic'" in script_src:
            result['details'].append("'strict-dynamic' present - trusted scripts can load additional scripts")
        
        if result['allows_unsafe_inline'] or result['allows_data_uri'] or '*' in script_src:
            result['xss_exploitable'] = True
            result['risk_level'] = 'weak'
        elif result['bypass_possible']:
            result['xss_exploitable'] = True
            result['risk_level'] = 'bypassable'
        elif has_nonce or has_hash:
            result['xss_exploitable'] = False
            result['risk_level'] = 'strong'
        else:
            result['xss_exploitable'] = False
            result['risk_level'] = 'moderate'
        
        object_src = directives.get('object-src', directives.get('default-src', []))
        if not object_src or "'none'" not in object_src:
            result['details'].append("object-src not set to 'none' - Flash/Java XSS may be possible")
        
        base_uri = directives.get('base-uri', [])
        if not base_uri:
            result['details'].append("base-uri not set - base tag injection possible for script loading")
            result['bypass_methods'].append('base_tag_injection')
        
        return result
    
    def is_xss_exploitable(self, csp_result: Dict, payload: str) -> bool:
        """Check if a specific XSS payload would work given CSP"""
        if not csp_result['has_csp']:
            return True
        
        payload_lower = payload.lower()
        
        if '<script' in payload_lower:
            if csp_result['allows_unsafe_inline']:
                return True
            return False
        
        if re.search(r'on\w+=', payload_lower):
            if csp_result['allows_unsafe_inline']:
                return True
            return False
        
        if 'javascript:' in payload_lower:
            if csp_result['allows_unsafe_inline']:
                return True
            return False
        
        if 'data:' in payload_lower:
            if csp_result['allows_data_uri']:
                return True
            return False
        
        if 'eval(' in payload_lower:
            if csp_result['allows_eval']:
                return True
            return False
        
        return csp_result['xss_exploitable']
    
    def get_summary(self, csp_result: Dict) -> str:
        """Get human-readable CSP summary"""
        if not csp_result['has_csp']:
            return "No CSP - XSS payloads will execute if reflected"
        
        level = csp_result['risk_level']
        if level == 'weak':
            return "Weak CSP (unsafe-inline/wildcard) - XSS likely exploitable"
        elif level == 'bypassable':
            methods = ', '.join(csp_result['bypass_methods'])
            return f"CSP present but bypassable via: {methods}"
        elif level == 'moderate':
            return "Moderate CSP - some payloads may be blocked"
        elif level == 'strong':
            return "Strong CSP (nonce/hash) - inline XSS unlikely to execute"
        
        return "CSP analysis inconclusive"
