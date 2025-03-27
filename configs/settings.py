import os
import json
import logging


def load_config(config_path=None):
    """
    Load and merge configuration with defaults

    Args:
        config_path (str, optional): Path to JSON configuration file

    Returns:
        dict: Merged configuration dictionary
    """
    # Default configuration with comprehensive settings
    default_config = {
        'network': {
            'interface': 'eth0'
        },
        'model': {
            'contamination': 0.05,  # Expected anomaly rate
            'n_estimators': 100,
            'filename': 'anomaly_detection_model.pkl',
            'path': None
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

    # If no config path is provided, return default configuration
    if not config_path or not os.path.exists(config_path):
        if config_path:
            logging.warning(f"Config file not found: {config_path}. Using default configuration.")
        return default_config

    # Load user configuration
    try:
        with open(config_path, 'r') as f:
            user_config = json.load(f)

        # Deep update function to merge configurations
        def deep_update(original, update):
            for key, value in update.items():
                if isinstance(value, dict):
                    original[key] = deep_update(original.get(key, {}), value)
                else:
                    original[key] = value
            return original

        # Merge user config with default config
        merged_config = deep_update(default_config.copy(), user_config)
        return merged_config

    except Exception as e:
        logging.error(f"Error loading configuration file: {e}")
        logging.warning("Falling back to default configuration.")
        return default_config