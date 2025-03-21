"""Configuration settings for the Proactive Threat Hunter."""

import os
import json
import logging

# Default configuration
DEFAULT_CONFIG = {
    'network': {
        'interface': 'eth0'
    },
    'model': {
        'filename': 'threat_model.pkl',
        'contamination': 0.05,
        'n_estimators': 100,
        'use_pca': True,
        'n_components': 10
    },
    'feature_extraction': {
        'window_size': 100,
        'window_timeout': 30
    },
    'alerts': {
        'high_confidence_threshold': 0.9,
        'alert_confidence_threshold': 0.8,
        'alert_file': 'threat_alerts.json'
    },
    'paths': {
        'output_dir': 'data',
        'models_dir': 'models',
        'logs_dir': 'logs'
    },
    'logging': {
        'level': 'INFO',
        'format': '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    }
}


def load_config(config_path=None):
    """
    Load configuration from file and merge with defaults.

    Args:
        config_path: Path to configuration file (JSON)

    Returns:
        Dictionary containing configuration settings
    """
    config = DEFAULT_CONFIG.copy()

    # If a config file is specified, load and merge it
    if config_path and os.path.exists(config_path):
        try:
            with open(config_path, 'r') as f:
                user_config = json.load(f)

            # Deep merge the user config with defaults
            _deep_update(config, user_config)
            logging.info(f"Loaded configuration from {config_path}")
        except Exception as e:
            logging.warning(f"Failed to load config from {config_path}: {e}")
            logging.warning("Using default configuration")

    return config


def _deep_update(original, update):
    """
    Recursively update a dictionary.

    Args:
        original: Original dictionary to update
        update: Dictionary with updates to apply
    """
    for key, value in update.items():
        if key in original and isinstance(original[key], dict) and isinstance(value, dict):
            _deep_update(original[key], value)
        else:
            original[key] = value