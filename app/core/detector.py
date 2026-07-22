import asyncio
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, field
from datetime import datetime
import hashlib
import re
import json
import yaml

from .ml_detector import MLPhishingDetector
from .header_analyzer import EmailHeaderAnalyzer
from .url_analyzer import AdvancedURLAnalyzer
from .attachment_analyzer import AttachmentAnalyzer
from .threat_intel import ThreatIntelligence
from ..utils.preprocessing import EmailPreprocessor

@dataclass
class AnalysisResult:
    """Comprehensive analysis result for an email."""
    email_id: str
    timestamp: datetime
    risk_score: float
    confidence: float
    risk_level: str
    flags: List[str] = field(default_factory=list)
    ml_analysis: Dict = field(default_factory=dict)
    header_analysis: Dict = field(default_factory=dict)
    url_analysis: Dict = field(default_factory=dict)
    attachment_analysis: Dict = field(default_factory=dict)
    threat_intel: Dict = field(default_factory=dict)
    subject: Optional[str] = None
    sender: Optional[str] = None
    recipients: List[str] = field(default_factory=list)
    body_preview: Optional[str] = None
    recommendations: List[str] = field(default_factory=list)
    action_required: bool = False
    quarantine_recommended: bool = False
    
    def to_dict(self) -> Dict:
        """Convert result to dictionary."""
        return {
            'email_id': self.email_id,
            'timestamp': self.timestamp.isoformat(),
            'risk_score': self.risk_score,
            'confidence': self.confidence,
            'risk_level': self.risk_level,
            'flags': self.flags,
            'ml_analysis': self.ml_analysis,
            'header_analysis': self.header_analysis,
            'url_analysis': self.url_analysis,
            'attachment_analysis': self.attachment_analysis,
            'threat_intel': self.threat_intel,
            'subject': self.subject,
            'sender': self.sender,
            'recipients': self.recipients,
            'body_preview': self.body_preview[:500] if self.body_preview else None,
            'recommendations': self.recommendations,
            'action_required': self.action_required,
            'quarantine_recommended': self.quarantine_recommended
        }

class AdvancedPhishingDetector:
    """Advanced phishing email detector with ML and threat intelligence."""
    
    def __init__(self, config_path: str = "config.yaml"):
        self.config = self._load_config(config_path)
        self.preprocessor = EmailPreprocessor()
        self.ml_detector = MLPhishingDetector()
        self.header_analyzer = EmailHeaderAnalyzer()
        self.url_analyzer = AdvancedURLAnalyzer()
        self.attachment_analyzer = AttachmentAnalyzer()
        self.threat_intel = ThreatIntelligence()
        
        # Initialize ML model
        self.ml_detector.load_model()
        
        # Cache for performance
        self._cache = {}
    
    def _load_config(self, config_path: str) -> Dict:
        """Load configuration from YAML file."""
        try:
            with open(config_path, 'r') as f:
                return yaml.safe_load(f)
        except FileNotFoundError:
            return {}
    
    async def analyze_email(self, email_data: Dict) -> AnalysisResult:
        """Comprehensive email analysis pipeline."""
        # Generate unique ID
        email_id = hashlib.md5(
            f"{email_data.get('sender', '')}{email_data.get('subject', '')}{datetime.now()}".encode()
        ).hexdigest()[:16]
        
        # Preprocess email
        processed = self.preprocessor.process(email_data)
        
        # Run parallel analyses
        tasks = [
            self._analyze_ml(processed),
            self._analyze_headers(processed),
            self._analyze_urls(processed),
            self._analyze_attachments(processed),
            self._check_threat_intel(processed)
        ]
        
        ml_result, header_result, url_result, attachment_result, threat_result = await asyncio.gather(*tasks)
        
        # Combine results
        combined_result = self._combine_analyses(
            ml_result, header_result, url_result,
            attachment_result, threat_result
        )
        
        # Generate recommendations
        recommendations = self._generate_recommendations(combined_result)
        
        # Create final result
        result = AnalysisResult(
            email_id=email_id,
            timestamp=datetime.now(),
            risk_score=combined_result['risk_score'],
            confidence=combined_result['confidence'],
            risk_level=combined_result['risk_level'],
            flags=combined_result['flags'],
            ml_analysis=ml_result,
            header_analysis=header_result,
            url_analysis=url_result,
            attachment_analysis=attachment_result,
            threat_intel=threat_result,
            subject=processed.get('subject'),
            sender=processed.get('sender'),
            recipients=processed.get('recipients', []),
            body_preview=processed.get('body', '')[:500],
            recommendations=recommendations,
            action_required=combined_result['risk_score'] > 70,
            quarantine_recommended=combined_result['risk_score'] > 85
        )
        
        return result
    
    async def _analyze_ml(self, processed: Dict) -> Dict:
        """Run ML-based detection."""
        try:
            return self.ml_detector.predict(processed)
        except Exception as e:
            return {'error': str(e), 'score': 0, 'confidence': 0}
    
    async def _analyze_headers(self, processed: Dict) -> Dict:
        """Analyze email headers."""
        try:
            return self.header_analyzer.analyze(processed.get('headers', {}))
        except Exception as e:
            return {'error': str(e)}
    
    async def _analyze_urls(self, processed: Dict) -> Dict:
        """Analyze URLs in email body."""
        try:
            return self.url_analyzer.analyze(processed.get('body', ''))
        except Exception as e:
            return {'error': str(e)}
    
    async def _analyze_attachments(self, processed: Dict) -> Dict:
        """Analyze attachments."""
        try:
            return self.attachment_analyzer.analyze(processed.get('attachments', []))
        except Exception as e:
            return {'error': str(e)}
    
    async def _check_threat_intel(self, processed: Dict) -> Dict:
        """Check against threat intelligence feeds."""
        try:
            return await self.threat_intel.check(processed)
        except Exception as e:
            return {'error': str(e)}
    
    def _combine_analyses(self, *analyses) -> Dict:
        """Combine multiple analysis results."""
        ml_score = analyses[0].get('score', 0)
        header_score = self._calculate_header_score(analyses[1])
        url_score = self._calculate_url_score(analyses[2])
        attachment_score = self._calculate_attachment_score(analyses[3])
        threat_score = analyses[4].get('risk_score', 0)
        
        # Weighted combination
        weights = self.config.get('detection', {})
        risk_score = (
            ml_score * weights.get('ml_weight', 0.35) +
            header_score * weights.get('header_weight', 0.15) +
            url_score * weights.get('url_weight', 0.20) +
            attachment_score * weights.get('attachment_weight', 0.15) +
            threat_score * weights.get('threat_intel_weight', 0.15)
        )
        
        # Confidence based on agreement between analyses
        confidence = self._calculate_confidence(analyses)
        
        # Collect all flags
        flags = []
        for analysis in analyses:
            flags.extend(analysis.get('flags', []))
        
        return {
            'risk_score': round(risk_score, 2),
            'confidence': round(confidence, 2),
            'risk_level': self._determine_risk_level(risk_score),
            'flags': list(set(flags))  # Remove duplicates
        }
    
    def _calculate_header_score(self, header_analysis: Dict) -> float:
        if 'error' in header_analysis:
            return 0
        return header_analysis.get('risk_score', 0)
    
    def _calculate_url_score(self, url_analysis: Dict) -> float:
        if 'error' in url_analysis:
            return 0
        return url_analysis.get('risk_score', 0)
    
    def _calculate_attachment_score(self, attachment_analysis: Dict) -> float:
        if 'error' in attachment_analysis:
            return 0
        return attachment_analysis.get('risk_score', 0)
    
    def _calculate_confidence(self, analyses) -> float:
        scores = []
        for analysis in analyses:
            if 'confidence' in analysis:
                scores.append(analysis['confidence'])
            elif 'risk_score' in analysis:
                scores.append(analysis['risk_score'])
        
        if not scores:
            return 0
        
        avg_score = sum(scores) / len(scores)
        std_dev = (sum((s - avg_score) ** 2 for s in scores) / len(scores)) ** 0.5
        normalized_std = min(100, std_dev * 5)
        confidence = 100 - normalized_std
        
        return round(confidence, 2)
    
    def _determine_risk_level(self, score: float) -> str:
        thresholds = self.config.get('thresholds', {})
        if score >= thresholds.get('critical', 85):
            return "CRITICAL"
        elif score >= thresholds.get('high', 70):
            return "HIGH"
        elif score >= thresholds.get('medium', 45):
            return "MEDIUM"
        elif score >= thresholds.get('low', 20):
            return "LOW"
        else:
            return "SAFE"
    
    def _generate_recommendations(self, result: Dict) -> List[str]:
        """Generate actionable recommendations."""
        recommendations = []
        score = result['risk_score']
        flags = result['flags']
        
        if score >= 85:
            recommendations.append("🚨 IMMEDIATE ACTION: Quarantine this email and block sender")
            recommendations.append("🔒 Do not click any links or open attachments")
            recommendations.append("📢 Report to security team immediately")
        elif score >= 70:
            recommendations.append("⚠️ High risk: Verify sender identity through out-of-band communication")
            recommendations.append("🔍 Do not reply or click links without verification")
        elif score >= 45:
            recommendations.append("ℹ️ Exercise caution: Some suspicious elements detected")
            recommendations.append("🔎 Verify URL destinations before clicking")
        else:
            recommendations.append("✅ No significant threats detected")
            recommendations.append("🛡️ Practice standard email safety")
        
        # Specific recommendations
        if any('url' in f.lower() for f in flags) and score >= 45:
            recommendations.append("🌐 Suspicious URLs detected - verify before clicking")
        
        if any('attachment' in f.lower() for f in flags):
            recommendations.append("📎 Caution with attachments - scan with antivirus")
        
        return recommendations
