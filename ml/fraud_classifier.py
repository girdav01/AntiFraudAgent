"""
ML-Based Fraud Classification Module

Uses machine learning for advanced fraud pattern classification.
"""

import logging
from typing import Dict, List, Optional, Any, Tuple
from datetime import datetime
import structlog
import numpy as np
from pathlib import Path
import pickle
import json

# ML libraries
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import Pipeline
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix
import joblib

logger = structlog.get_logger(__name__)


class FraudClassifier:
    """
    Machine learning-based fraud classifier.

    Features:
    - Multi-class fraud type classification
    - Confidence scoring
    - Feature extraction from text content
    - Model training and persistence
    - Real-time inference
    """

    FRAUD_TYPES = [
        "phishing",
        "scam",
        "malware",
        "social_engineering",
        "credential_harvesting",
        "fake_shop",
        "investment_fraud",
        "ransomware",
        "legitimate"
    ]

    def __init__(
        self,
        model_path: Optional[str] = None,
        model_type: str = "random_forest"
    ):
        """
        Initialize fraud classifier.

        Args:
            model_path: Path to saved model (optional)
            model_type: Type of model ("random_forest", "gradient_boosting")
        """
        self.model_path = model_path
        self.model_type = model_type
        self.model = None
        self.vectorizer = None
        self.scaler = None
        self.feature_names = []

        if model_path and Path(model_path).exists():
            self.load_model(model_path)
        else:
            self._initialize_model()

        logger.info("fraud_classifier_initialized", model_type=model_type)

    def _initialize_model(self):
        """Initialize new model."""
        # Text vectorizer
        self.vectorizer = TfidfVectorizer(
            max_features=1000,
            ngram_range=(1, 3),
            stop_words='english',
            min_df=2
        )

        # Feature scaler
        self.scaler = StandardScaler()

        # Classifier
        if self.model_type == "random_forest":
            classifier = RandomForestClassifier(
                n_estimators=100,
                max_depth=20,
                min_samples_split=5,
                random_state=42,
                n_jobs=-1
            )
        elif self.model_type == "gradient_boosting":
            classifier = GradientBoostingClassifier(
                n_estimators=100,
                max_depth=10,
                learning_rate=0.1,
                random_state=42
            )
        else:
            raise ValueError(f"Unsupported model type: {self.model_type}")

        self.model = classifier

        logger.info("model_initialized", type=self.model_type)

    def extract_features(self, content: Dict[str, Any]) -> np.ndarray:
        """
        Extract features from content.

        Args:
            content: Content dictionary with text and metadata

        Returns:
            Feature vector
        """
        features = []

        # Text content
        text = content.get("text", "")

        # Numerical features
        url = content.get("url", "")
        features.extend([
            len(text),  # Text length
            len(url),  # URL length
            url.count("."),  # Number of dots in URL
            url.count("-"),  # Number of hyphens
            url.count("@"),  # Number of @ symbols
            int("https" in url.lower()),  # Has HTTPS
            int(any(char.isdigit() for char in url)),  # Has digits in URL
            len(content.get("suspicious_patterns", [])),  # Number of suspicious patterns
            len(content.get("iocs", [])),  # Number of IOCs
        ])

        # Keyword presence features
        fraud_keywords = [
            "urgent", "verify", "suspended", "click", "password",
            "prize", "winner", "congratulations", "limited", "act now",
            "confirm", "account", "security", "update", "download"
        ]

        for keyword in fraud_keywords:
            features.append(int(keyword in text.lower()))

        return np.array(features).reshape(1, -1)

    def extract_text_features(self, text: str) -> np.ndarray:
        """
        Extract TF-IDF features from text.

        Args:
            text: Text content

        Returns:
            TF-IDF feature vector
        """
        if self.vectorizer is None:
            raise ValueError("Vectorizer not initialized. Train model first.")

        return self.vectorizer.transform([text])

    def train(
        self,
        training_data: List[Dict[str, Any]],
        labels: List[str],
        test_size: float = 0.2
    ) -> Dict[str, Any]:
        """
        Train the fraud classifier.

        Args:
            training_data: List of content dictionaries
            labels: List of fraud type labels
            test_size: Proportion of test set

        Returns:
            Training results and metrics
        """
        logger.info("training_started", samples=len(training_data))

        # Extract text for vectorization
        texts = [item.get("text", "") for item in training_data]

        # Fit and transform text features
        text_features = self.vectorizer.fit_transform(texts)

        # Extract numerical features
        numerical_features = np.vstack([
            self.extract_features(item) for item in training_data
        ])

        # Scale numerical features
        numerical_features = self.scaler.fit_transform(numerical_features)

        # Combine features
        X = np.hstack([text_features.toarray(), numerical_features])

        # Convert labels to indices
        y = np.array([self.FRAUD_TYPES.index(label) for label in labels])

        # Split data
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=test_size, random_state=42, stratify=y
        )

        # Train model
        self.model.fit(X_train, y_train)

        # Evaluate
        y_pred = self.model.predict(X_test)

        results = {
            "accuracy": float(np.mean(y_pred == y_test)),
            "classification_report": classification_report(
                y_test,
                y_pred,
                target_names=self.FRAUD_TYPES,
                output_dict=True
            ),
            "confusion_matrix": confusion_matrix(y_test, y_pred).tolist(),
            "training_samples": len(X_train),
            "test_samples": len(X_test),
            "timestamp": datetime.utcnow().isoformat()
        }

        logger.info("training_completed", accuracy=results["accuracy"])

        return results

    def predict(self, content: Dict[str, Any]) -> Dict[str, Any]:
        """
        Predict fraud type for content.

        Args:
            content: Content dictionary

        Returns:
            Prediction with confidence scores
        """
        if self.model is None:
            raise ValueError("Model not trained. Train or load model first.")

        # Extract features
        text = content.get("text", "")
        text_features = self.extract_text_features(text)
        numerical_features = self.extract_features(content)
        numerical_features = self.scaler.transform(numerical_features)

        # Combine features
        X = np.hstack([text_features.toarray(), numerical_features])

        # Predict
        prediction = self.model.predict(X)[0]
        probabilities = self.model.predict_proba(X)[0]

        fraud_type = self.FRAUD_TYPES[prediction]
        confidence = float(probabilities[prediction]) * 100

        # Get top 3 predictions
        top_indices = np.argsort(probabilities)[-3:][::-1]
        top_predictions = [
            {
                "fraud_type": self.FRAUD_TYPES[idx],
                "confidence": float(probabilities[idx]) * 100
            }
            for idx in top_indices
        ]

        result = {
            "fraud_type": fraud_type,
            "confidence": confidence,
            "is_fraud": fraud_type != "legitimate",
            "top_predictions": top_predictions,
            "timestamp": datetime.utcnow().isoformat()
        }

        logger.info(
            "prediction_made",
            fraud_type=fraud_type,
            confidence=confidence,
            is_fraud=result["is_fraud"]
        )

        return result

    def predict_batch(
        self,
        contents: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """
        Predict fraud types for multiple contents.

        Args:
            contents: List of content dictionaries

        Returns:
            List of predictions
        """
        return [self.predict(content) for content in contents]

    def save_model(self, path: str):
        """
        Save model to disk.

        Args:
            path: Path to save model
        """
        model_data = {
            "model": self.model,
            "vectorizer": self.vectorizer,
            "scaler": self.scaler,
            "model_type": self.model_type,
            "fraud_types": self.FRAUD_TYPES,
            "timestamp": datetime.utcnow().isoformat()
        }

        Path(path).parent.mkdir(parents=True, exist_ok=True)

        with open(path, "wb") as f:
            joblib.dump(model_data, f)

        logger.info("model_saved", path=path)

    def load_model(self, path: str):
        """
        Load model from disk.

        Args:
            path: Path to model file
        """
        with open(path, "rb") as f:
            model_data = joblib.load(f)

        self.model = model_data["model"]
        self.vectorizer = model_data["vectorizer"]
        self.scaler = model_data["scaler"]
        self.model_type = model_data.get("model_type", "random_forest")

        logger.info("model_loaded", path=path)

    def get_feature_importance(self) -> List[Tuple[str, float]]:
        """
        Get feature importance scores.

        Returns:
            List of (feature_name, importance) tuples
        """
        if not hasattr(self.model, "feature_importances_"):
            return []

        importances = self.model.feature_importances_

        # Get feature names from vectorizer
        vocab = self.vectorizer.get_feature_names_out()
        numerical_features = [
            "text_length", "url_length", "dots_in_url", "hyphens_in_url",
            "at_symbols", "has_https", "has_digits", "suspicious_patterns", "iocs_count"
        ]

        all_features = list(vocab) + numerical_features

        feature_importance = sorted(
            zip(all_features, importances),
            key=lambda x: x[1],
            reverse=True
        )

        return feature_importance[:20]  # Top 20

    def explain_prediction(
        self,
        content: Dict[str, Any],
        prediction: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Explain why a prediction was made.

        Args:
            content: Content dictionary
            prediction: Prediction result

        Returns:
            Explanation dictionary
        """
        explanation = {
            "fraud_type": prediction["fraud_type"],
            "confidence": prediction["confidence"],
            "reasons": []
        }

        text = content.get("text", "").lower()
        url = content.get("url", "").lower()

        # Check for fraud indicators
        if prediction["fraud_type"] == "phishing":
            if any(word in text for word in ["verify", "suspended", "account"]):
                explanation["reasons"].append("Contains credential harvesting language")
            if "login" in text or "password" in text:
                explanation["reasons"].append("Requests login credentials")

        elif prediction["fraud_type"] == "scam":
            if any(word in text for word in ["prize", "winner", "congratulations"]):
                explanation["reasons"].append("Contains prize/winner language")
            if "urgent" in text or "act now" in text:
                explanation["reasons"].append("Uses urgency tactics")

        elif prediction["fraud_type"] == "malware":
            if "download" in text or "install" in text:
                explanation["reasons"].append("Prompts for software installation")

        # URL features
        if len(url) > 100:
            explanation["reasons"].append("Unusually long URL")
        if url.count("-") > 3:
            explanation["reasons"].append("Excessive hyphens in URL")

        # Suspicious patterns
        if content.get("suspicious_patterns"):
            explanation["reasons"].append(f"Found {len(content['suspicious_patterns'])} suspicious patterns")

        return explanation


def create_synthetic_training_data() -> Tuple[List[Dict[str, Any]], List[str]]:
    """
    Create synthetic training data for initial model.

    Returns:
        Tuple of (training_data, labels)
    """
    training_data = []
    labels = []

    # Phishing examples
    phishing_samples = [
        {"text": "Your account has been suspended. Click here to verify your identity and password.", "url": "http://suspicious-bank-verify.com"},
        {"text": "Urgent: Confirm your login credentials to avoid account closure.", "url": "http://paypal-security-check.net"},
        {"text": "Your email account will be closed. Update your password now.", "url": "http://gmail-account-verify.com"},
    ]

    for sample in phishing_samples:
        sample["suspicious_patterns"] = [{"type": "credential_request"}]
        sample["iocs"] = [sample["url"]]
        training_data.append(sample)
        labels.append("phishing")

    # Scam examples
    scam_samples = [
        {"text": "Congratulations! You've won $1,000,000. Click to claim your prize now!", "url": "http://prize-winner-2024.com"},
        {"text": "You are the lucky winner of our iPhone giveaway. Act now to receive your reward!", "url": "http://free-iphone-winner.net"},
    ]

    for sample in scam_samples:
        sample["suspicious_patterns"] = [{"type": "reward_lure"}]
        sample["iocs"] = [sample["url"]]
        training_data.append(sample)
        labels.append("scam")

    # Legitimate examples
    legit_samples = [
        {"text": "Welcome to our newsletter. Read about industry trends and insights.", "url": "https://legitcompany.com/newsletter"},
        {"text": "Thank you for your purchase. Your order will ship within 2-3 business days.", "url": "https://store.example.com/order"},
    ]

    for sample in legit_samples:
        sample["suspicious_patterns"] = []
        sample["iocs"] = []
        training_data.append(sample)
        labels.append("legitimate")

    return training_data, labels
