import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.model_selection import train_test_split
import re
from typing import Dict, List, Tuple
import os
import json
from nltk.corpus import stopwords
import nltk

# Download NLTK stopwords if not available
try:
    nltk.data.find('tokenizers/punkt')
except LookupError:
    nltk.download('punkt')
    nltk.download('stopwords')

class MLPhishingDetector:
    """Machine Learning-based phishing detector."""
    
    def __init__(self):
        self.model_path = "app/models/phishing_model.pkl"
        self.vectorizer = TfidfVectorizer(
            max_features=5000,
            ngram_range=(1, 3),
            stop_words=stopwords.words('english')
        )
        
        self.rf_model = RandomForestClassifier(
            n_estimators=300,
            max_depth=20,
            random_state=42
        )
        self.gb_model = GradientBoostingClassifier(
            n_estimators=200,
            learning_rate=0.1,
            random_state=42
        )
        
        self._load_model()
    
    def _load_model(self):
        """Load pre-trained models."""
        try:
            if os.path.exists(self.model_path):
                model_data = joblib.load(self.model_path)
                self.rf_model = model_data['rf_model']
                self.gb_model = model_data['gb_model']
                self.vectorizer = model_data['vectorizer']
                print("✅ Loaded pre-trained ML models")
            else:
                print("ℹ️ No pre-trained model found. Using default configuration.")
        except Exception as e:
            print(f"⚠️ Error loading model: {e}")
    
    def predict(self, email_data: Dict) -> Dict:
        """Predict phishing probability."""
        text = self._prepare_text(email_data)
        
        # If model is not trained, return default score
        if not hasattr(self.vectorizer, 'vocabulary_'):
            return {
                'score': 50.0,
                'is_phishing': False,
                'confidence': 0,
                'flags': ['Model not trained - using default'],
                'rf_score': 50.0,
                'gb_score': 50.0
            }
        
        try:
            text_vector = self.vectorizer.transform([text])
            rf_pred = self.rf_model.predict_proba(text_vector)[0][1]
            gb_pred = self.gb_model.predict_proba(text_vector)[0][1]
            
            base_score = (rf_pred + gb_pred) / 2
            flags = self._extract_flags(email_data)
            
            return {
                'score': round(base_score * 100, 2),
                'is_phishing': base_score > 0.5,
                'confidence': round(max(rf_pred, gb_pred) * 100, 2),
                'flags': flags,
                'rf_score': round(rf_pred * 100, 2),
                'gb_score': round(gb_pred * 100, 2)
            }
        except Exception as e:
            return {
                'score': 50.0,
                'is_phishing': False,
                'confidence': 0,
                'flags': [f'Prediction error: {str(e)}'],
                'rf_score': 50.0,
                'gb_score': 50.0
            }
    
    def _prepare_text(self, email_data: Dict) -> str:
        """Prepare email text for vectorization."""
        text_parts = []
        
        if 'subject' in email_data and email_data['subject']:
            text_parts.append(email_data['subject'])
        
        if 'body' in email_data and email_data['body']:
            text_parts.append(email_data['body'])
        
        if 'sender' in email_data and email_data['sender']:
            text_parts.append(email_data['sender'])
        
        return ' '.join(text_parts)
    
    def _extract_flags(self, email_data: Dict) -> List[str]:
        """Extract detection flags."""
        flags = []
        body = email_data.get('body', '').lower()
        subject = email_data.get('subject', '').lower()
        
        # Urgency keywords
        urgency_keywords = ['urgent', 'immediate', 'asap', 'limited', 'expire', 'deadline']
        if any(kw in body or kw in subject for kw in urgency_keywords):
            flags.append("Urgency language detected")
        
        # Suspicious keywords
        suspicious_keywords = ['verify', 'confirm', 'update', 'validate', 'authenticate']
        if any(kw in body or kw in subject for kw in suspicious_keywords):
            flags.append("Suspicious keywords detected")
        
        # URL detection
        if 'http://' in body:
            flags.append("HTTP (non-HTTPS) URL detected")
        
        return flags
