"""
Advanced Phishing Email Detector
Allben Rakgoale - Phishing-Email-Detector Project

Auto-trains a starter model on first run if no model file exists.
Returns structured AnalysisResult objects with prediction, confidence,
and reasoning.
"""

import os
import re
import pickle
from dataclasses import dataclass, asdict
from typing import Dict, List, Optional

from loguru import logger
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier
from sklearn.pipeline import Pipeline


# =========================================================
# Data Class: Analysis Result
# =========================================================
@dataclass
class AnalysisResult:
    """Structured result returned from the phishing detector."""
    is_phishing: bool
    label: str
    confidence: float
    matched_keywords: List[str]
    reasoning: str

    def to_dict(self) -> Dict:
        """Convert to dictionary for JSON responses."""
        return asdict(self)


# =========================================================
# Main Detector Class
# =========================================================
class AdvancedPhishingDetector:
    """
    ML-powered phishing email detector with auto-training fallback.

    On first run, if `model.pkl` does not exist, the detector trains
    a simple starter model using a small built-in dataset, saves it,
    and uses it for predictions.
    """

    # Suspicious keywords used for reasoning and starter training
    PHISHING_KEYWORDS = [
        "click here", "verify", "urgent", "prize", "won", "suspended",
        "confirm", "account", "password", "bank", "login", "update",
        "immediately", "limited time", "act now", "congratulations",
        "free gift", "claim", "unusual activity", "security alert",
    ]

    def __init__(self, model_path: str = "model.pkl"):
        self.model_path = model_path
        self.model: Optional[Pipeline] = None
        self._load_or_train()

    # -----------------------------------------------------
    # Model Loading / Training
    # -----------------------------------------------------
    def _load_or_train(self) -> None:
        """Load existing model or train a starter model if none exists."""
        if os.path.exists(self.model_path):
            try:
                with open(self.model_path, "rb") as f:
                    self.model = pickle.load(f)
                logger.info(f"✅ Loaded existing model from {self.model_path}")
                return
            except Exception as e:
                logger.warning(f"⚠️ Failed to load model: {e}. Retraining...")

        logger.info("⚠️ No model found. Training a starter model...")
        self.model = self._train_starter_model()

        try:
            with open(self.model_path, "wb") as f:
                pickle.dump(self.model, f)
            logger.info(f"✅ Starter model trained and saved to {self.model_path}")
        except Exception as e:
            logger.warning(f"⚠️ Could not save model: {e}")

    def _train_starter_model(self) -> Pipeline:
        """Train a starter model on a small built-in dataset."""
        # Label 1 = phishing, 0 = legitimate
        samples = [
            # Phishing
            ("Click here to claim your prize now", 1),
            ("Your account is suspended, verify immediately", 1),
            ("Congratulations you won $1,000,000", 1),
            ("Urgent: verify your banking details", 1),
            ("You have won a free iPhone, click now", 1),
            ("Your PayPal account needs verification", 1),
            ("Security alert: unusual activity detected", 1),
            ("Confirm your password immediately", 1),
            ("Limited time offer, act now", 1),
            ("Your bank account has been locked", 1),
            # Legitimate
            ("Hi, let's schedule the meeting for Tuesday", 0),
            ("Please find the attached report for review", 0),
            ("Thanks for your email, I'll get back to you", 0),
            ("Your order has been shipped, tracking below", 0),
            ("The project deadline is next week", 0),
            ("Meeting notes from today's call", 0),
            ("Can you review this document when you have time", 0),
            ("Lunch tomorrow at 12?", 0),
            ("I've updated the spreadsheet as requested", 0),
            ("Looking forward to hearing from you", 0),
        ]

        texts = [s[0] for s in samples]
        labels = [s[1] for s in samples]

        pipeline = Pipeline([
            ("tfidf", TfidfVectorizer(ngram_range=(1, 2), lowercase=True)),
            ("clf", RandomForestClassifier(n_estimators=50, random_state=42)),
        ])
        pipeline.fit(texts, labels)
        return pipeline

    # -----------------------------------------------------
    # Prediction
    # -----------------------------------------------------
    def _find_keywords(self, text: str) -> List[str]:
        """Find suspicious keywords in the text."""
        text_lower = text.lower()
        return [kw for kw in self.PHISHING_KEYWORDS if kw in text_lower]

    def _build_reasoning(self, matched: List[str], is_phishing: bool) -> str:
        """Build a human-readable reasoning string."""
        if is_phishing and matched:
            return f"Detected {len(matched)} suspicious keyword(s): {', '.join(matched[:5])}"
        if is_phishing:
            return "ML model classified this email as phishing based on learned patterns."
        return "No suspicious patterns detected. Email appears legitimate."

    def analyze(self, text: str) -> AnalysisResult:
        """Analyze an email text and return an AnalysisResult."""
        if not text or not text.strip():
            return AnalysisResult(
                is_phishing=False,
                label="unknown",
                confidence=0.0,
                matched_keywords=[],
                reasoning="Empty email text provided.",
            )

        matched = self._find_keywords(text)

        try:
            prediction = int(self.model.predict([text])[0])
            proba = self.model.predict_proba([text])[0]
            confidence = float(max(proba))
        except Exception as e:
            logger.error(f"Prediction failed: {e}. Falling back to keyword rule.")
            prediction = 1 if len(matched) >= 2 else 0
            confidence = 0.75 if prediction == 1 else 0.80

        is_phishing = prediction == 1
        label = "phishing" if is_phishing else "legitimate"
        reasoning = self._build_reasoning(matched, is_phishing)

        return AnalysisResult(
            is_phishing=is_phishing,
            label=label,
            confidence=round(confidence, 4),
            matched_keywords=matched,
            reasoning=reasoning,
        )

    def predict(self, text: str) -> Dict:
        """Convenience method returning a plain dict (used by API routes)."""
        return self.analyze(text).to_dict()
