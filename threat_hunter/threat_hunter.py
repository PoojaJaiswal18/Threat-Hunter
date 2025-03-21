"""
Main module for the Proactive Threat Hunter system.
Implements network packet capture, feature extraction, and anomaly detection.
"""

import os
import json
import logging
import numpy as np
import pandas as pd
from datetime import datetime
from typing import Dict, Optional, Any

from scapy.all import sniff

from .feature_extraction import PacketFeatureExtractor
from .anomaly_detection import AnomalyDetector

logger = logging.getLogger(__name__)


class ThreatHunter:
    """Main class for the Proactive Threat Hunter system."""

    def __init__(self,
                 interface: str = 'eth0',
                 model_path: Optional[str] = None,
                 window_size: int = 100,
                 training_mode: bool = False,
                 training_file: Optional[str] = None):
        """
        Initialize the Threat Hunter.

        Args:
            interface: Network interface to capture packets from
            model_path: Path to load/save anomaly detection model
            window_size: Number of packets to process in each window
            training_mode: Whether to train the model or use it for detection
            training_file: Path to training dataset file (if training_mode is True)
        """
        self.interface = interface
        self.model_path = model_path
        self.training_mode = training_mode
        self.training_file = training_file

        # Initialize components
        self.feature_extractor = PacketFeatureExtractor(window_size=window_size)
        self.anomaly_detector = AnomalyDetector(model_path=model_path)

        # Training data container
        self.training_data = []

    def packet_handler(self, packet):
        """
        Process captured packets for feature extraction and anomaly detection.

        Args:
            packet: Scapy packet object
        """
        # Extract features from the packet
        features = self.feature_extractor.process_packet(packet)

        if features:
            if self.training_mode:
                # In training mode, collect extracted features
                X = self.anomaly_detector.preprocess_features(features)
                self.training_data.append(X[0])
                logger.info(f"Collected training sample: {len(self.training_data)} samples so far")
            else:
                # In detection mode, update baseline stats
                self.anomaly_detector.update_baseline(features)

                # Detect anomalies
                prediction, confidence = self.anomaly_detector.predict(features)

                # Log the prediction
                result = "NORMAL" if prediction == 1 else "ANOMALY"
                logger.info(f"Prediction: {result} (confidence: {confidence:.2f})")

                # If anomaly detected with high confidence, trigger alert
                if prediction == -1 and confidence > 0.8:
                    self._trigger_alert(features, confidence)

    def _trigger_alert(self, features: Dict[str, Any], confidence: float):
        """
        Trigger an alert for detected anomalies.

        Args:
            features: Dictionary of extracted features
            confidence: Confidence score of the prediction
        """
        alert = {
            'timestamp': datetime.now().isoformat(),
            'confidence': confidence,
            'features': features,
            'alert_type': 'NETWORK ANOMALY',
            'severity': 'HIGH' if confidence > 0.9 else 'MEDIUM'
        }

        logger.warning(f"ALERT: Network anomaly detected with {confidence:.2f} confidence!")

        # Here you would integrate with your response system
        # For now, we'll just save the alert to a file
        with open('logs/threat_alerts.json', 'a') as f:
            f.write(json.dumps(alert) + '\n')

    def start_capture(self, count: Optional[int] = None):
        """
        Start capturing packets from the network.

        Args:
            count: Number of packets to capture (None for unlimited)
        """
        logger.info(f"Starting packet capture on interface {self.interface}")

        try:
            # Start packet capture
            sniff(iface=self.interface, prn=self.packet_handler, count=count, store=0)
        except KeyboardInterrupt:
            logger.info("Packet capture stopped by user")
        except Exception as e:
            logger.error(f"Error during packet capture: {e}")

    def train_model(self):
        """Train the anomaly detection model with collected data."""
        if not self.training_data:
            if self.training_file and os.path.exists(self.training_file):
                # Load training data from file
                logger.info(f"Loading training data from {self.training_file}")
                df = pd.read_csv(self.training_file)
                # Convert dataframe to numpy array
                X_train = df.values
                logger.info(f"Loaded {X_train.shape[0]} training samples")
            else:
                logger.error("No training data available")
                return
        else:
            # Use collected training data
            X_train = np.array(self.training_data)
            logger.info(f"Using {X_train.shape[0]} collected training samples")

        # Train the model
        self.anomaly_detector.train(X_train)

        # Save the trained model
        if self.model_path:
            os.makedirs(os.path.dirname(self.model_path), exist_ok=True)
            self.anomaly_detector.save_model(self.model_path)

    def run(self):
        """Run the Threat Hunter in the configured mode."""
        if self.training_mode:
            logger.info("Running in training mode")
            # Capture packets for training
            self.start_capture(count=10000)  # Capture a limited number of packets
            # Train the model
            self.train_model()
        else:
            logger.info("Running in detection mode")
            # Continuous packet capture and anomaly detection
            self.start_capture()