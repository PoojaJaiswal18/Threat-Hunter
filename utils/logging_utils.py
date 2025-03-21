#!/usr/bin/env python3
"""
Logging utilities for the Proactive Threat Hunter system.
"""

import os
import logging
from logging.handlers import RotatingFileHandler
from datetime import datetime


def setup_logging(log_level=logging.INFO, log_dir='logs'):
    """
    Set up logging configuration for the application.

    Args:
        log_level: Logging level (default: INFO)
        log_dir: Directory to store log files

    Returns:
        Logger object configured with file and console handlers
    """
    # Ensure the log directory exists
    os.makedirs(log_dir, exist_ok=True)

    # Create a timestamped log file name
    timestamp = datetime.now().strftime('%Y%m%d-%H%M%S')
    log_file = os.path.join(log_dir, f'threat_hunter_{timestamp}.log')

    # Configure the logger
    logger = logging.getLogger('threat_hunter')
    logger.setLevel(log_level)

    # Create console handler
    console_handler = logging.StreamHandler()
    console_handler.setLevel(log_level)

    # Create file handler with rotating logs (10MB max size, 5 backup files)
    file_handler = RotatingFileHandler(
        log_file, maxBytes=10 * 1024 * 1024, backupCount=5
    )
    file_handler.setLevel(log_level)

    # Create formatter and add to handlers
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    console_handler.setFormatter(formatter)
    file_handler.setFormatter(formatter)

    # Add handlers to logger
    logger.addHandler(console_handler)
    logger.addHandler(file_handler)

    # Add a simple log message to indicate logger initialization
    logger.info(f"Logging initialized. Log file: {log_file}")

    return logger


def log_system_info():
    """
    Log information about the system environment.
    """
    logger = logging.getLogger('threat_hunter')

    try:
        import platform
        import psutil

        # Log system information
        logger.info(f"System: {platform.system()} {platform.release()}")
        logger.info(f"Python version: {platform.python_version()}")

        # Log CPU and memory information
        logger.info(f"CPU cores: {psutil.cpu_count(logical=False)} physical, {psutil.cpu_count()} logical")
        memory = psutil.virtual_memory()
        logger.info(f"Memory: {memory.total / (1024 ** 3):.2f} GB total, {memory.percent}% used")

        # Log network interfaces
        network_interfaces = psutil.net_if_addrs()
        logger.info(f"Network interfaces: {', '.join(network_interfaces.keys())}")

    except ImportError:
        logger.warning("psutil module not installed. Limited system information available.")
        logger.info(f"System: {platform.system()} {platform.release()}")
        logger.info(f"Python version: {platform.python_version()}")