import pytest
from app.core.detector import AdvancedPhishingDetector
import asyncio

@pytest.fixture
def detector():
    return AdvancedPhishingDetector()

@pytest.mark.asyncio
async def test_phishing_email(detector):
    email = {
        'subject': 'URGENT: Your Account Will Be Suspended',
        'sender': 'security@fake-bank.com',
        'body': 'Please verify your credentials at http://fake-bank-verify.com'
    }
    
    result = await detector.analyze_email(email)
    assert result.risk_score >= 40
    assert result.risk_level in ['MEDIUM', 'HIGH', 'CRITICAL']
    assert len(result.flags) > 0

@pytest.mark.asyncio
async def test_safe_email(detector):
    email = {
        'subject': 'Weekly Team Meeting',
        'sender': 'manager@company.com',
        'body': 'Meeting at 2 PM tomorrow'
    }
    
    result = await detector.analyze_email(email)
    assert result.risk_score < 40
    assert result.risk_level in ['SAFE', 'LOW']

@pytest.mark.asyncio
async def test_batch_analysis(detector):
    emails = [
        {'subject': 'URGENT: Verify now', 'body': 'http://suspicious.com'},
        {'subject': 'Team meeting', 'body': 'Meeting at 2 PM'},
        {'subject': 'PayPal alert', 'body': 'http://paypal-verify.com'}
    ]
    
    results = []
    for email in emails:
        result = await detector.analyze_email(email)
        results.append(result)
    
    assert len(results) == 3
    assert all(r.risk_score >= 0 for r in results)
