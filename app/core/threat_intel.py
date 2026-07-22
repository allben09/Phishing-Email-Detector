from typing import Dict
import requests
import os
import json

class ThreatIntelligence:
    """Threat intelligence integration."""
    
    def __init__(self):
        self.virustotal_key = os.getenv('VIRUSTOTAL_API_KEY', '')
        self.abuseipdb_key = os.getenv('ABUSEIPDB_API_KEY', '')
        self.cache = {}
    
    async def check(self, email_data: Dict) -> Dict:
        """Check email against threat intelligence feeds."""
        results = {
            'risk_score': 0,
            'flags': [],
            'details': {}
        }
        
        # Check sender domain
        sender = email_data.get('sender', '')
        if '@' in sender:
            domain = sender.split('@')[1]
            domain_check = self._check_domain(domain)
            if domain_check:
                results['details']['domain'] = domain_check
                if domain_check.get('suspicious'):
                    results['flags'].append(f"Suspicious domain: {domain}")
                    results['risk_score'] += 20
        
        # Check URLs
        body = email_data.get('body', '')
        urls = self._extract_urls(body)
        for url in urls[:5]:  # Limit to 5 URLs
            url_check = self._check_url(url)
            if url_check:
                results['details'][f'url_{url}'] = url_check
                if url_check.get('suspicious'):
                    results['flags'].append(f"Suspicious URL: {url[:50]}")
                    results['risk_score'] += 15
        
        return results
    
    def _check_domain(self, domain: str) -> Dict:
        """Check domain reputation."""
        # In production, use VirusTotal/AbuseIPDB APIs
        suspicious_domains = ['fake-bank.com', 'secure-verify.com', 'phishing-site.com']
        
        if domain in suspicious_domains:
            return {'suspicious': True, 'reputation': 'malicious'}
        
        return {'suspicious': False}
    
    def _check_url(self, url: str) -> Dict:
        """Check URL reputation."""
        suspicious_patterns = ['verify', 'secure', 'login', 'confirm']
        
        if any(pattern in url.lower() for pattern in suspicious_patterns):
            return {'suspicious': True}
        
        return {'suspicious': False}
    
    def _extract_urls(self, text: str) -> list:
        """Extract URLs from text."""
        import re
        pattern = r'https?://[^\s<>"\'(){}|\\^`\[\]]+'
        return re.findall(pattern, text)
