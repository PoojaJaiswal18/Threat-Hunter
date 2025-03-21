"""Anomaly detection module for network traffic."""

import os
import pickle
import logging
import numpy as np
from typing import Dict, List, Tuple, Optional, Union, Any

from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.decomposition import PCA

logger = logging.getLogger(__name__)


class AnomalyDetector:
    """Detect network traffic anomalies using an ensemble approach."""

    def __init__(self,
                 model_path: Optional[str] = None,
                 contamination: float = 0.05,
                 n_estimators: int = 100,
                 use_pca: bool = True,
                 n_components: int = 10):
        """
        Initialize the anomaly detector.

        Args:
            model_path: Path to saved model (if None, a new model will be initialized)
            contamination: Expected proportion of outliers in the data
            n_estimators: Number of base estimators in the ensemble
            use_pca: Whether to use PCA for dimensionality reduction
            n_components: Number of components to keep when using PCA
        """
        self.use_pca = use_pca
        self.n_components = n_components
        self.contamination = contamination
        self.n_estimators = n_estimators

        # Initialize the scaler
        self.scaler = StandardScaler()

        # Initialize PCA if enabled
        self.pca = PCA(n_components=n_components) if use_pca else None

        # Initialize the model
        self.model = IsolationForest(
            n_estimators=n_estimators,
            contamination=contamination,
            random_state=42,
            bootstrap=True,
            n_jobs=-1
        )

        # Load pre-trained model if available
        if model_path and os.path.exists(model_path):
            self.load_model(model_path)
            logger.info(f"Loaded pre-trained model from {model_path}")
        else:
            logger.info("Initialized new model. Training required.")

        # Store feature names for future reference
        self.feature_names = []
        self.is_trained = False

        # Statistical baseline values
        self.baseline_stats = {}

    # Rest of the implementation as in the original code
    def preprocess_features(self, features: Dict[str, Any]) -> np.ndarray:
        """
        Convert feature dictionary to a model-compatible numpy array.

        Args:
            features: Dictionary of extracted features

        Returns:
            Numpy array of preprocessed features
        """
        # Select numerical features and convert to a flat structure
        feature_dict = {}

        # Extract protocol counts into separate features
        if 'protocol_counts' in features:
            for proto, count in features['protocol_counts'].items():
                feature_dict[f'protocol_{proto}'] = count

        # Add all other numerical features
        for key, value in features.items():
            if key != 'protocol_counts' and key != 'timestamp' and isinstance(value, (int, float)):
                feature_dict[key] = value

        # Update or initialize feature names
        if not self.feature_names:
            self.feature_names = list(feature_dict.keys())

        # Convert to numpy array
        if self.feature_names:
            X = np.array([feature_dict.get(f, 0) for f in self.feature_names]).reshape(1, -1)
            return X

        # Fallback if feature_names not yet initialized
        return np.array(list(feature_dict.values())).reshape(1, -1)

    def update_baseline(self, features: Dict[str, Any]):
        """
        Update the statistical baseline with new data.

        Args:
            features: Dictionary of extracted features
        """
        # Initialize baseline if empty
        if not self.baseline_stats:
            for key, value in features.items():
                if key != 'timestamp' and isinstance(value, (int, float)):
                    self.baseline_stats[key] = {
                        'min': value,
                        'max': value,
                        'sum': value,
                        'count': 1,
                        'mean': value,
                        'values': [value]
                    }
        else:
            # Update existing baseline
            for key, value in features.items():
                if key in self.baseline_stats and isinstance(value, (int, float)):
                    stats = self.baseline_stats[key]
                    stats['min'] = min(stats['min'], value)
                    stats['max'] = max(stats['max'], value)
                    stats['sum'] += value
                    stats['count'] += 1
                    stats['mean'] = stats['sum'] / stats['count']
                    stats['values'].append(value)

                    # Limit the number of stored values to 1000
                    if len(stats['values']) > 1000:
                        stats['values'].pop(0)

    def train(self, X_train: np.ndarray):
        """
        Train the anomaly detection model.

        Args:
            X_train: Training data as a numpy array
        """
        logger.info(f"Training model with {X_train.shape[0]} samples...")

        # Fit the scaler
        X_scaled = self.scaler.fit_transform(X_train)

        # Apply PCA if enabled
        if self.use_pca and self.pca:
            X_processed = self.pca.fit_transform(X_scaled)
            logger.info(f"Applied PCA, reduced dimensions from {X_scaled.shape[1]} to {X_processed.shape[1]}")
        else:
            X_processed = X_scaled

        # Fit the model
        self.model.fit(X_processed)
        self.is_trained = True
        logger.info("Model training complete")

    def predict(self, features: Dict[str, Any]) -> Tuple[int, float]:
        """
        Predict anomaly score for a set of features.

        Args:
            features: Dictionary of extracted features

        Returns:
            Tuple of (prediction, confidence score)
            prediction: 1 for normal, -1 for anomaly
            confidence: 0-1 score where higher means more confident
        """
        if not self.is_trained:
            # Use simple statistical approach if model not trained
            return self._statistical_anomaly_score(features)

        # Preprocess features
        X = self.preprocess_features(features)

        # Apply scaling
        X_scaled = self.scaler.transform(X)

        # Apply PCA if enabled
        if self.use_pca and self.pca:
            X_processed = self.pca.transform(X_scaled)
        else:
            X_processed = X_scaled

        # Get model's decision function (negative=anomaly, positive=normal)
        raw_score = self.model.decision_function(X_processed)[0]

        # Convert to prediction (-1=anomaly, 1=normal)
        prediction = self.model.predict(X_processed)[0]

        # Calculate confidence score (0-1)
        # Higher absolute value of raw_score means more confidence
        confidence = 1.0 - np.exp(-np.abs(raw_score))

        # Combine with statistical approach for ensemble decision
        stat_prediction, stat_confidence = self._statistical_anomaly_score(features)

        # Use ensemble approach: weighted average of ML and statistical methods
        ml_weight = 0.7  # Give more weight to the ML model
        stat_weight = 0.3

        # If predictions disagree, use the one with higher confidence
        if prediction != stat_prediction:
            if confidence > stat_confidence:
                final_prediction = prediction
                final_confidence = confidence
            else:
                final_prediction = stat_prediction
                final_confidence = stat_confidence
        else:
            # If predictions agree, combine confidences
            final_prediction = prediction
            final_confidence = (ml_weight * confidence + stat_weight * stat_confidence) / (ml_weight + stat_weight)

        return final_prediction, final_confidence

    def _statistical_anomaly_score(self, features: Dict[str, Any]) -> Tuple[int, float]:
        """
        Calculate anomaly score using statistical methods.

        Args:
            features: Dictionary of extracted features

        Returns:
            Tuple of (prediction, confidence score)
        """
        if not self.baseline_stats:
            # No baseline yet, can't detect anomalies
            return 1, 1.0

        anomaly_scores = []

        for key, value in features.items():
            if key in self.baseline_stats and isinstance(value, (int, float)):
                stats = self.baseline_stats[key]

                # Skip if we don't have enough data
                if stats['count'] < 10:
                    continue

                # Calculate z-score if we have enough samples
                if len(stats['values']) > 5:
                    std = np.std(stats['values'])
                    if std > 0:
                        z_score = abs((value - stats['mean']) / std)
                        # Z-score > 3 is generally considered an outlier
                        if z_score > 3:
                            anomaly_scores.append(min(z_score / 10, 1.0))  # Cap at 1.0

                # Also check if value is outside min-max range
                if value < stats['min'] or value > stats['max']:
                    # How far outside the range?
                    range_size = max(stats['max'] - stats['min'], 1e-10)  # Avoid division by zero
                    distance = min(value, stats['min']) if value < stats['min'] else max(value, stats['max'])
                    normalized_distance = abs(distance - stats['mean']) / range_size
                    anomaly_scores.append(min(normalized_distance, 1.0))  # Cap at 1.0

        # If we have anomaly scores, use their average
        if anomaly_scores:
            avg_score = np.mean(anomaly_scores)
            # Consider anomaly if average score is above threshold
            if avg_score > 0.5:
                return -1, avg_score
            else:
                return 1, 1.0 - avg_score

        # Default to normal
        return 1, 1.0

    def save_model(self, model_path: str):
        """
        Save the trained model to a file.

        Args:
            model_path: Path to save the model
        """
        if not self.is_trained:
            logger.warning("Cannot save untrained model")
            return

        model_data = {
            'model': self.model,
            'scaler': self.scaler,
            'pca': self.pca,
            'feature_names': self.feature_names,
            'use_pca': self.use_pca,
            'baseline_stats': self.baseline_stats
        }

        with open(model_path, 'wb') as f:
            pickle.dump(model_data, f)

        logger.info(f"Model saved to {model_path}")

    def load_model(self, model_path: str):
        """
        Load a trained model from a file.

        Args:
            model_path: Path to the saved model
        """
        with open(model_path, 'rb') as f:
            model_data = pickle.load(f)

        self.model = model_data.get('model')
        self.scaler = model_data.get('scaler')
        self.pca = model_data.get('pca')
        self.feature_names = model_data.get('feature_names', [])
        self.use_pca = model_data.get('use_pca', self.use_pca)
        self.baseline_stats = model_data.get('baseline_stats', {})
        self.is_trained = True

        logger.info(f"Model loaded from {model_path}")