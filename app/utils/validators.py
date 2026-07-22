from typing import Dict
import re

def validate_email_data(data: Dict) -> bool:
    """Validate email data before analysis."""
    
    # Check if data is empty
    if not data:
        raise ValueError("Email data is empty")
    
    # Validate subject if provided
    if 'subject' in data and data['subject']:
        if len(data['subject']) > 1000:
            raise ValueError("Subject too long (max 1000 characters)")
    
    # Validate body if provided
    if 'body' in data and data['body']:
        if len(data['body']) > 10 * 1024 * 1024:  # 10MB
            raise ValueError("Body too large (max 10MB)")
    
    # Validate sender if provided
    if 'sender' in data and data['sender']:
        if '@' not in data['sender']:
            raise ValueError("Invalid sender email format")
    
    # Validate recipients if provided
    if 'recipients' in data and data['recipients']:
        for recipient in data['recipients']:
            if '@' not in recipient:
                raise ValueError(f"Invalid recipient email: {recipient}")
    
    return True

def validate_url(url: str) -> bool:
    """Validate URL format."""
    url_pattern = r'^https?://[^\s<>"\'(){}|\\^`\[\]]+$'
    return bool(re.match(url_pattern, url))
