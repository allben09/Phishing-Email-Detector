from typing import List, Dict
import magic
import hashlib

class AttachmentAnalyzer:
    """Analyzes email attachments for suspicious content."""
    
    def __init__(self):
        self.suspicious_extensions = [
            '.exe', '.scr', '.bat', '.cmd', '.com', '.pif',
            '.vbs', '.js', '.jar', '.app', '.msi'
        ]
        self.max_file_size = 10 * 1024 * 1024  # 10MB
    
    def analyze(self, attachments: List[Dict]) -> Dict:
        """Analyze attachments."""
        if not attachments:
            return {
                'risk_score': 0,
                'flags': [],
                'details': {'count': 0}
            }
        
        flags = []
        risk_score = 0
        
        for attachment in attachments:
            analysis = self._analyze_single(attachment)
            flags.extend(analysis.get('flags', []))
            risk_score += analysis.get('risk_score', 0)
        
        risk_score = min(100, risk_score / len(attachments) if attachments else 0)
        
        return {
            'risk_score': round(risk_score, 2),
            'flags': list(set(flags)),
            'details': {
                'count': len(attachments),
                'attachments': attachments
            }
        }
    
    def _analyze_single(self, attachment: Dict) -> Dict:
        """Analyze a single attachment."""
        analysis = {
            'risk_score': 0,
            'flags': []
        }
        
        filename = attachment.get('filename', '')
        
        # Check extension
        for ext in self.suspicious_extensions:
            if filename.lower().endswith(ext):
                analysis['flags'].append(f"Suspicious file extension: {ext}")
                analysis['risk_score'] += 30
                break
        
        # Check file size
        size = attachment.get('size', 0)
        if size > self.max_file_size:
            analysis['flags'].append("Large file size")
            analysis['risk_score'] += 10
        
        return analysis
