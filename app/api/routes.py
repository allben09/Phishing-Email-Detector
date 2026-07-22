from fastapi import APIRouter, HTTPException, UploadFile, File, Form
from typing import List, Optional
from datetime import datetime
import json

from .models import EmailAnalysisRequest, AnalysisResponse, BatchAnalysisRequest
from ..core.detector import AdvancedPhishingDetector
from ..utils.validators import validate_email_data
from ..utils.logger import logger
from ..utils.metrics import MetricsCollector

router = APIRouter()
detector = AdvancedPhishingDetector()

@router.post("/analyze", response_model=AnalysisResponse)
async def analyze_email(request: EmailAnalysisRequest):
    """
    Analyze a single email for phishing indicators.
    """
    try:
        logger.info(f"Analyzing email: {request.subject}")
        
        # Validate input
        validate_email_data(request.dict())
        
        # Run analysis
        result = await detector.analyze_email(request.dict())
        
        # Record metrics
        MetricsCollector.record_analysis(result.to_dict())
        
        logger.info(f"Analysis complete - Risk Score: {result.risk_score}, Level: {result.risk_level}")
        
        return AnalysisResponse(
            status="success",
            result=result.to_dict(),
            timestamp=datetime.now().isoformat()
        )
    except Exception as e:
        logger.error(f"Analysis failed: {str(e)}")
        raise HTTPException(status_code=400, detail=str(e))

@router.post("/analyze/batch", response_model=List[AnalysisResponse])
async def analyze_batch(request: BatchAnalysisRequest):
    """
    Analyze multiple emails in batch.
    """
    try:
        logger.info(f"Batch analysis started: {len(request.emails)} emails")
        
        results = []
        for email_data in request.emails:
            validate_email_data(email_data.dict())
            result = await detector.analyze_email(email_data.dict())
            results.append(AnalysisResponse(
                status="success",
                result=result.to_dict(),
                timestamp=datetime.now().isoformat()
            ))
        
        logger.info(f"Batch analysis complete: {len(results)} emails processed")
        return results
    except Exception as e:
        logger.error(f"Batch analysis failed: {str(e)}")
        raise HTTPException(status_code=400, detail=str(e))

@router.post("/analyze/with-attachments")
async def analyze_with_attachments(
    subject: Optional[str] = Form(None),
    sender: Optional[str] = Form(None),
    body: Optional[str] = Form(None),
    attachments: List[UploadFile] = File(None)
):
    """
    Analyze email with file attachments.
    """
    try:
        email_data = {
            'subject': subject,
            'sender': sender,
            'body': body,
            'attachments': []
        }
        
        # Process attachments
        if attachments:
            for attachment in attachments:
                content = await attachment.read()
                email_data['attachments'].append({
                    'filename': attachment.filename,
                    'content_type': attachment.content_type,
                    'size': len(content),
                    'content': content
                })
        
        # Run analysis
        result = await detector.analyze_email(email_data)
        
        return AnalysisResponse(
            status="success",
            result=result.to_dict(),
            timestamp=datetime.now().isoformat()
        )
    except Exception as e:
        logger.error(f"Attachment analysis failed: {str(e)}")
        raise HTTPException(status_code=400, detail=str(e))

@router.get("/stats")
async def get_statistics():
    """
    Get detection statistics.
    """
    # In production, fetch from database
    return {
        'total_analyzed': 1247,
        'phishing_detected': 89,
        'detection_rate': 95.2,
        'risk_distribution': {
            'critical': 12,
            'high': 25,
            'medium': 30,
            'low': 15,
            'safe': 7
        },
        'trends': {
            'last_7_days': [8, 12, 9, 15, 11, 18, 16],
            'dates': ['2026-07-16', '2026-07-17', '2026-07-18', '2026-07-19', '2026-07-20', '2026-07-21', '2026-07-22']
        },
        'system_status': 'operational'
    }

@router.get("/metrics")
async def get_metrics():
    """
    Get Prometheus metrics.
    """
    from ..utils.metrics import MetricsCollector
    return MetricsCollector.get_metrics()
