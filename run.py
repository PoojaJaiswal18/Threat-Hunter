#!/usr/bin/env python3
"""
Proactive Threat Hunter - Main Entry Point

This script initializes and runs the Proactive Threat Hunter system for
network traffic analysis and anomaly detection.
"""

import os
import argparse
import logging
from threat_hunter.threat_hunter import ThreatHunter
from utils.logging_utils import setup_logging
from configs.settings import load_config


def parse_arguments():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description='Proactive Threat Hunter - Network Traffic Analysis and Anomaly Detection')

    parser.add_argument('-i', '--interface',
                        help='Network interface to capture packets from')

    parser.add_argument('-m', '--model',
                        help='Path to anomaly detection model file')

    parser.add_argument('-w', '--window', type=int,
                        help='Window size for feature extraction')

    parser.add_argument('-t', '--train', action='store_true',
                        help='Run in training mode')

    parser.add_argument('-f', '--training-file',
                        help='Path to training data file')

    parser.add_argument('-c', '--config',
                        help='Path to configuration file')

    parser.add_argument('-l', '--log-level', choices=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'],
                        help='Set the logging level')

    parser.add_argument('-o', '--output-dir',
                        help='Directory to save output files and logs')

    return parser.parse_args()


def main():
    """Main entry point for the Proactive Threat Hunter application."""
    # Parse command line arguments
    args = parse_arguments()

    # Load configuration (with command line overrides)
    config = load_config(args.config)

    # Override config with command line arguments if provided
    if args.interface:
        config['network']['interface'] = args.interface
    if args.model:
        config['model']['path'] = args.model
    if args.window:
        config['feature_extraction']['window_size'] = args.window
    if args.log_level:
        config['logging']['level'] = args.log_level
    if args.output_dir:
        config['paths']['output_dir'] = args.output_dir

    # Ensure output directories exist
    os.makedirs(config['paths']['output_dir'], exist_ok=True)
    os.makedirs(config['paths']['models_dir'], exist_ok=True)
    os.makedirs(config['paths']['logs_dir'], exist_ok=True)

    # Setup logging
    setup_logging(
        log_level=config['logging']['level'],
        log_dir=config['paths']['logs_dir']
    )

    logger = logging.getLogger(__name__)
    logger.info("Starting Proactive Threat Hunter")

    # Determine model path
    model_path = os.path.join(config['paths']['models_dir'], config['model']['filename'])

    # Initialize the Threat Hunter
    hunter = ThreatHunter(
        interface=config['network']['interface'],
        model_path=model_path,
        window_size=config['feature_extraction']['window_size'],
        training_mode=args.train,
        training_file=args.training_file
    )

    # Display configuration summary
    logger.info(f"Network Interface: {config['network']['interface']}")
    logger.info(f"Model Path: {model_path}")
    logger.info(f"Window Size: {config['feature_extraction']['window_size']}")
    logger.info(f"Mode: {'Training' if args.train else 'Detection'}")

    # Run the Threat Hunter
    try:
        hunter.run()
    except KeyboardInterrupt:
        logger.info("Application terminated by user")
    except Exception as e:
        logger.error(f"Error running Threat Hunter: {e}", exc_info=True)
    finally:
        logger.info("Shutting down Proactive Threat Hunter")


if __name__ == "__main__":
    main()