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
import re

logger = logging.getLogger("nw-diff")


def validate_hostname(hostname):
    """
    Validates hostname to prevent path traversal attacks.
    Only allows alphanumeric characters, hyphens, underscores, and dots.
    Blocks path separators, parent directory references, and absolute paths.

    Args:
        hostname: The hostname string to validate

    Returns:
        True if valid, False otherwise
    """
    if not hostname:
        return False
    # Block common path traversal patterns
    if ".." in hostname or "/" in hostname or "\\" in hostname:
        logger.warning("Rejected hostname with traversal pattern: %s", hostname)
        return False
    # Only allow safe characters: alphanumeric, hyphen, underscore, dot
    if not re.match(r"^[a-zA-Z0-9._-]+$", hostname):
        logger.warning("Rejected hostname with invalid characters: %s", hostname)
        return False
    return True


def validate_command(command):
    """
    Validates command string to prevent path traversal attacks.
    Only allows alphanumeric characters, spaces, hyphens, underscores.
    Blocks path separators and parent directory references.

    Args:
        command: The command string to validate

    Returns:
        True if valid, False otherwise
    """
    if not command:
        return False
    # Block common path traversal patterns
    if ".." in command or "/" in command or "\\" in command:
        logger.warning("Rejected command with traversal pattern: %s", command)
        return False
    # Only allow safe characters: alphanumeric, space, hyphen, underscore
    if not re.match(r"^[a-zA-Z0-9 _-]+$", command):
        logger.warning("Rejected command with invalid characters: %s", command)
        return False
    return True


def validate_base_directory(base):
    """
    Validates that base is one of the allowed directory names.

    Args:
        base: The base directory name

    Returns:
        True if valid, False otherwise
    """
    return base in ["origin", "dest"]
