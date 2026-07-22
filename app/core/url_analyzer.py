import re
from urllib.parse import urlparse
from typing import List, Dict
import tldextract

class AdvancedURLAnalyzer:
    """Advanced URL analysis with threat detection."""
    
    def __init__(self):
        self.suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.click', '.top', '.xyz']
        self.url_shorteners = ['bit.ly', 'tinyurl', 'goo.gl', 'ow.ly', 'is.gd']
        self.suspicious_keywords = ['verify', 'confirm', 'update', 'secure', 'login']
    
    def analyze(self, text: str) -> Dict:
        """Analyze all URLs in text."""
        urls = self._extract_urls(text)
        
        if not urls:
            return {
                'url_count': 0,
                'risk_score': 0,
                'flags': [],
                'urls': []
            }
        
        flags = []
        risk_score = 0
        
        for url in urls:
            analysis = self._analyze_single_url(url)
            flags.extend(analysis.get('flags', []))
            risk_score += analysis.get('risk_score', 0)
        
        risk_score = min(100, risk_score / len(urls) if urls else 0)
        
        return {
            'url_count': len(urls),
            'risk_score': round(risk_score, 2),
            'flags': list(set(flags)),
            'urls': urls
        }
    
    def _extract_urls(self, text: str) -> List[str]:
        """Extract URLs from text."""
        pattern = r'https?://[^\s<>"\'(){}|\\^`\[\]]+'
        return re.findall(pattern, text)
    
    def _analyze_single_url(self, url: str) -> Dict:
        """Analyze a single URL."""
        analysis = {
            'url': url,
            'risk_score': 0,
            'flags': []
        }
        
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        
        # Check protocol
        if parsed.scheme == 'http':
            analysis['flags'].append("HTTP (non-HTTPS) URL")
            analysis['risk_score'] += 20
        
        # Check TLD
        extracted = tldextract.extract(domain)
        tld = f".{extracted.suffix}"
        if tld in self.suspicious_tlds:
            analysis['flags'].append(f"Suspicious TLD: {tld}")
            analysis['risk_score'] += 25
        
        # Check URL shorteners
        if any(short in domain for short in self.url_shorteners):
            analysis['flags'].append("URL shortener detected")
            analysis['risk_score'] += 10
        
        # Check suspicious keywords
        if any(kw in parsed.path.lower() for kw in self.suspicious_keywords):
            analysis['flags'].append("Suspicious URL path")
            analysis['risk_score'] += 15
        
        # Check for IP address
        if re.match(r'\d+\.\d+\.\d+\.\d+', domain):
            analysis['flags'].append("IP address used instead of domain")
            analysis['risk_score'] += 20
        
        analysis['risk_score'] = min(100, analysis['risk_score'])
        return analysis
