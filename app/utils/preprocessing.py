from typing import Dict
import re
import email

class EmailPreprocessor:
    """Preprocesses email data for analysis."""
    
    def process(self, email_data: Dict) -> Dict:
        """Process and clean email data."""
        processed = email_data.copy()
        
        # Clean body
        if 'body' in processed and processed['body']:
            processed['body'] = self._clean_text(processed['body'])
        
        # Clean subject
        if 'subject' in processed and processed['subject']:
            processed['subject'] = self._clean_text(processed['subject'])
        
        # Extract sender domain
        if 'sender' in processed and processed['sender']:
            if '@' in processed['sender']:
                processed['sender_domain'] = processed['sender'].split('@')[1]
        
        return processed
    
    def _clean_text(self, text: str) -> str:
        """Clean and normalize text."""
        # Remove HTML tags
        text = re.sub(r'<[^>]+>', '', text)
        
        # Remove excessive whitespace
        text = ' '.join(text.split())
        
        # Remove email addresses (privacy)
        text = re.sub(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', '[EMAIL]', text)
        
        # Remove phone numbers
        text = re.sub(r'\b\d{3}[-.]?\d{3}[-.]?\d{4}\b', '[PHONE]', text)
        
        return text
