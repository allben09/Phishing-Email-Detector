import re
from typing import Dict, List
from datetime import datetime

class EmailHeaderAnalyzer:
    """Analyzes email headers for forgery and anomalies."""
    
    def __init__(self):
        self.suspicious_patterns = [
            r'\d+[a-z]+',
            r'[a-z]+\d+',
            r'[^a-zA-Z0-9.-]',
            r'\.{2,}'
        ]
    
    def analyze(self, headers: Dict) -> Dict:
        """Analyze email headers."""
        results = {
            'risk_score': 0,
            'flags': [],
            'details': {}
        }
        
        # Check missing headers
        missing = self._check_missing_headers(headers)
        if missing:
            results['flags'].append(f"Missing headers: {', '.join(missing)}")
            results['risk_score'] += 10
        
        # Check sender domain
        domain_analysis = self._analyze_sender_domain(headers)
        if domain_analysis.get('suspicious'):
            results['flags'].append(domain_analysis.get('details'))
            results['risk_score'] += 20
        
        # Check authentication
        auth_results = self._check_authentication(headers)
        if not auth_results.get('spf'):
            results['flags'].append("SPF check failed")
            results['risk_score'] += 15
        if not auth_results.get('dkim'):
            results['flags'].append("DKIM check failed")
            results['risk_score'] += 15
        
        results['risk_score'] = min(100, results['risk_score'])
        return results
    
    def _check_missing_headers(self, headers: Dict) -> List[str]:
        """Check for missing critical headers."""
        critical = ['From', 'To', 'Subject', 'Date']
        return [h for h in critical if h not in headers]
    
    def _analyze_sender_domain(self, headers: Dict) -> Dict:
        """Analyze sender domain for suspicious patterns."""
        from_header = headers.get('From', '')
        if '@' in from_header:
            domain = from_header.split('@')[1].split('>')[0].strip()
            
            for pattern in self.suspicious_patterns:
                if re.search(pattern, domain):
                    return {
                        'suspicious': True,
                        'details': f"Suspicious domain pattern: {domain}"
                    }
            
            # Check common brand spoofing
            brands = ['paypal', 'amazon', 'microsoft', 'google', 'apple']
            for brand in brands:
                if brand in domain.lower() and not domain.lower().startswith(brand):
                    return {
                        'suspicious': True,
                        'details': f"Possible brand spoofing: {domain}"
                    }
        
        return {'suspicious': False, 'details': ''}
    
    def _check_authentication(self, headers: Dict) -> Dict:
        """Check authentication headers."""
        return {
            'spf': bool(headers.get('Received-SPF')),
            'dkim': bool(headers.get('DKIM-Signature')),
            'dmarc': bool(headers.get('Authentication-Results'))
          }
