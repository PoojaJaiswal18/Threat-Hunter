#!/usr/bin/env python3
"""
Unit tests for the Proactive Threat Hunter system.
"""

import unittest
import os
import sys
import pandas as pd
import numpy as np
from unittest.mock import MagicMock, patch

# Add the parent directory to the sys.path to import the modules
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from threat_hunter.feature_extraction import PacketFeatureExtractor
from threat_hunter.anomaly_detection import AnomalyDetector
from threat_hunter.threat_hunter import ThreatHunter


class TestPacketFeatureExtractor(unittest.TestCase):
    """Test cases for the PacketFeatureExtractor class."""

    def setUp(self):
        """Set up test fixtures."""
        self.extractor = PacketFeatureExtractor(window_size=10, window_timeout=5)

    def test_init(self):
        """Test initialization of the feature extractor."""
        self.assertEqual(self.extractor.window_size, 10)
        self.assertEqual(self.extractor.window_timeout, 5)
        self.assertEqual(len(self.extractor.packet_buffer), 0)

    @patch('scapy.all.IP')
    def test_process_packet_no_ip(self, mock_ip):
        """Test processing a packet without IP layer."""
        mock_packet = MagicMock()
        mock_packet.haslayer.return_value = False

        result = self.extractor.process_packet(mock_packet)
        self.assertIsNone(result)
        self.assertEqual(len(self.extractor.packet_buffer), 0)

    @patch('scapy.all.IP')
    def test_extract_features_empty_buffer(self, mock_ip):
        """Test feature extraction with an empty buffer."""
        features = self.extractor.extract_features()
        self.assertEqual(features, {})


class TestAnomalyDetector(unittest.TestCase):
    """Test cases for the AnomalyDetector class."""

    def setUp(self):
        """Set up test fixtures."""
        self.detector = AnomalyDetector()

    def test_init(self):
        """Test initialization of the anomaly detector."""
        self.assertFalse(self.detector.is_trained)
        self.assertEqual(self.detector.feature_names, [])

    def test_preprocess_features(self):
        """Test preprocessing of features."""
        features = {
            'timestamp': '2023-01-01T12:00:00',
            'window_size': 100,
            'unique_src_ips': 5,
            'protocol_counts': {'TCP': 80, 'UDP': 20}
        }

        X = self.detector.preprocess_features(features)
        self.assertIsInstance(X, np.ndarray)

    def test_statistical_anomaly_score_no_baseline(self):
        """Test statistical anomaly detection with no baseline."""
        features = {
            'window_size': 100,
            'unique_src_ips': 5
        }

        prediction, confidence = self.detector._statistical_anomaly_score(features)
        self.assertEqual(prediction, 1)  # Normal by default
        self.assertEqual(confidence, 1.0)


class TestThreatHunter(unittest.TestCase):
    """Test cases for the ThreatHunter class."""

    def setUp(self):
        """Set up test fixtures."""
        self.hunter = ThreatHunter(interface='eth0', training_mode=True)

    def test_init(self):
        """Test initialization of the threat hunter."""
        self.assertEqual(self.hunter.interface, 'eth0')
        self.assertTrue(self.hunter.training_mode)
        self.assertIsInstance(self.hunter.feature_extractor, PacketFeatureExtractor)
        self.assertIsInstance(self.hunter.anomaly_detector, AnomalyDetector)

    @patch('threat_hunter.threat_hunter.ThreatHunter.packet_handler')
    def test_trigger_alert(self, mock_handler):
        """Test alert triggering."""
        features = {
            'timestamp': '2023-01-01T12:00:00',
            'window_size': 100,
            'unique_src_ips': 5
        }

        # Use a temporary file for testing alerts
        with patch('builtins.open') as mock_open:
            self.hunter._trigger_alert(features, 0.95)
            mock_open.assert_called_once()


if __name__ == '__main__':
    unittest.main()