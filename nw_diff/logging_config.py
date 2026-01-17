"""
Copyright 2025 NW-Diff Contributors
SPDX-License-Identifier: Apache-2.0

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

This file was created or modified with the assistance of an AI (Large Language Model).
Review required for correctness, security, and licensing.
"""

import logging
import logging.handlers
import os

# Configure logging
LOGS_DIR = "logs"
os.makedirs(LOGS_DIR, exist_ok=True)

# Create logger
logger = logging.getLogger("nw-diff")
logger.setLevel(logging.DEBUG)

# Create rotating file handler (10MB max, keep 5 backup files)
log_file = os.path.join(LOGS_DIR, "nw-diff.log")
file_handler = logging.handlers.RotatingFileHandler(
    log_file, maxBytes=10 * 1024 * 1024, backupCount=5
)
file_handler.setLevel(logging.DEBUG)

# Create console handler for development
console_handler = logging.StreamHandler()
console_handler.setLevel(logging.INFO)

# Create formatter using lazy % formatting
formatter = logging.Formatter(
    "%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
file_handler.setFormatter(formatter)
console_handler.setFormatter(formatter)

# Add handlers to logger (only if not already added to prevent duplicates)
if not logger.handlers:
    logger.addHandler(file_handler)
    logger.addHandler(console_handler)

logger.info("NW-Diff application starting")
