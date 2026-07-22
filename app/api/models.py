from pydantic import BaseModel, Field, EmailStr
from typing import List, Optional, Dict, Any
from datetime import datetime

class EmailAnalysisRequest(BaseModel):
    """Request model for email analysis."""
    subject: Optional[str] = Field(None, description="Email subject")
    sender: Optional[str] = Field(None, description="Sender email address")
    recipients: List[str] = Field(default=[], description="Recipient email addresses")
    body: Optional[str] = Field(None, description="Email body content")
    headers: Dict[str, Any] = Field(default={}, description="Email headers")
    attachments: List[Dict[str, Any]] = Field(default=[], description="Email attachments")
    
    class Config:
        schema_extra = {
            "example": {
                "subject": "URGENT: Account Suspension Notice",
                "sender": "security@fake-bank.com",
                "recipients": ["user@example.com"],
                "body": "Your account has been flagged for suspicious activity...",
                "headers": {
                    "From": "security@fake-bank.com",
                    "To": "user@example.com",
                    "Date": "Mon, 22 Jul 2026 15:55:38 +0000"
                }
            }
        }

class BatchAnalysisRequest(BaseModel):
    """Request model for batch email analysis."""
    emails: List[EmailAnalysisRequest] = Field(..., description="List of emails to analyze")
    parallel: bool = Field(True, description="Run analysis in parallel")

class AnalysisResponse(BaseModel):
    """Response model for analysis results."""
    status: str
    result: Dict[str, Any]
    timestamp: str

class DetectionResult(BaseModel):
    """Detection result model."""
    email_id: str
    risk_score: float
    confidence: float
    risk_level: str
    flags: List[str]
    recommendations: List[str]
    action_required: bool
    quarantine_recommended: bool
    timestamp: datetime
