import os
import pickle
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier
from sklearn.pipeline import Pipeline

class AdvancedPhishingDetector:
    def __init__(self, model_path="model.pkl"):
        self.model_path = model_path
        if os.path.exists(model_path):
            # Load existing model
            with open(model_path, "rb") as f:
                self.model = pickle.load(f)
            print("✅ Loaded existing model")
        else:
            # Train a simple model on first run
            print("⚠️ No model found. Training a starter model...")
            self.model = self._train_starter_model()
            with open(model_path, "wb") as f:
                pickle.dump(self.model, f)
            print("✅ Starter model trained and saved")

    def _train_starter_model(self):
        """Train a quick model with sample data."""
        texts = [
            # Phishing examples
            "Click here to claim your prize now",
            "Your account is suspended, verify immediately",
            "Congratulations you won $1,000,000",
            "Urgent: verify your banking details",
            "You have won a free iPhone, click now",
            "Your PayPal account needs verification",
            # Legitimate examples
            "Hi, let's schedule the meeting for Tuesday",
            "Please find the attached report for review",
            "Thanks for your email, I'll get back to you",
            "Your order has been shipped, tracking below",
            "The project deadline is next week",
            "Meeting notes from today's call",
        ]
        labels = [1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0]  # 1=phishing, 0=legit

        pipeline = Pipeline([
            ("tfidf", TfidfVectorizer(ngram_range=(1, 2))),
            ("clf", RandomForestClassifier(n_estimators=50, random_state=42)),
        ])
        pipeline.fit(texts, labels)
        return pipeline

    def predict(self, text):
        """Predict if the text is phishing."""
        prediction = self.model.predict([text])[0]
        proba = self.model.predict_proba([text])[0]
        confidence = float(max(proba))
        return {
            "is_phishing": bool(prediction == 1),
            "confidence": confidence,
            "label": "phishing" if prediction == 1 else "legitimate",
        import os
import pickle
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier
from sklearn.pipeline import Pipeline

class AdvancedPhishingDetector:
    def __init__(self, model_path="model.pkl"):
        self.model_path = model_path
        if os.path.exists(model_path):
            # Load existing model
            with open(model_path, "rb") as f:
                self.model = pickle.load(f)
            print("✅ Loaded existing model")
        else:
            # Train a simple model on first run
            print("⚠️ No model found. Training a starter model...")
            self.model = self._train_starter_model()
            with open(model_path, "wb") as f:
                pickle.dump(self.model, f)
            print("✅ Starter model trained and saved")

    def _train_starter_model(self):
        """Train a quick model with sample data."""
        texts = [
            # Phishing examples
            "Click here to claim your prize now",
            "Your account is suspended, verify immediately",
            "Congratulations you won $1,000,000",
            "Urgent: verify your banking details",
            "You have won a free iPhone, click now",
            "Your PayPal account needs verification",
            # Legitimate examples
            "Hi, let's schedule the meeting for Tuesday",
            "Please find the attached report for review",
            "Thanks for your email, I'll get back to you",
            "Your order has been shipped, tracking below",
            "The project deadline is next week",
            "Meeting notes from today's call",
        ]
        labels = [1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0]  # 1=phishing, 0=legit

        pipeline = Pipeline([
            ("tfidf", TfidfVectorizer(ngram_range=(1, 2))),
            ("clf", RandomForestClassifier(n_estimators=50, random_state=42)),
        ])
        pipeline.fit(texts, labels)
        return pipeline

    def predict(self, text):
        """Predict if the text is phishing."""
        prediction = self.model.predict([text])[0]
        proba = self.model.predict_proba([text])[0]
        confidence = float(max(proba))
        return {
            "is_phishing": bool(prediction == 1),
            "confidence": confidence,
            "label": "phishing" if prediction == 1 else "legitimate",
        }import os
import pickle
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier
from sklearn.pipeline import Pipeline

class AdvancedPhishingDetector:
    def __init__(self, model_path="model.pkl"):
        self.model_path = model_path
        if os.path.exists(model_path):
            # Load existing model
            with open(model_path, "rb") as f:
                self.model = pickle.load(f)
            print("✅ Loaded existing model")
        else:
            # Train a simple model on first run
            print("⚠️ No model found. Training a starter model...")
            self.model = self._train_starter_model()
            with open(model_path, "wb") as f:
                pickle.dump(self.model, f)
            print("✅ Starter model trained and saved")

    def _train_starter_model(self):
        """Train a quick model with sample data."""
        texts = [
            # Phishing examples
            "Click here to claim your prize now",
            "Your account is suspended, verify immediately",
            "Congratulations you won $1,000,000",
            "Urgent: verify your banking details",
            "You have won a free iPhone, click now",
            "Your PayPal account needs verification",
            # Legitimate examples
            "Hi, let's schedule the meeting for Tuesday",
            "Please find the attached report for review",
            "Thanks for your email, I'll get back to you",
            "Your order has been shipped, tracking below",
            "The project deadline is next week",
            "Meeting notes from today's call",
        ]
        labels = [1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0]  # 1=phishing, 0=legit

        pipeline = Pipeline([
            ("tfidf", TfidfVectorizer(ngram_range=(1, 2))),
            ("clf", RandomForestClassifier(n_estimators=50, random_state=42)),
        ])
        pipeline.fit(texts, labels)
        return pipeline

    def predict(self, text):
        """Predict if the text is phishing."""
        prediction = self.model.predict([text])[0]
        proba = self.model.predict_proba([text])[0]
        confidence = float(max(proba))
        return {
            "is_phishing": bool(prediction == 1),
            "confidence": confidence,
            "label": "phishing" if prediction == 1 else "legitimate",
        }