#!/usr/bin/env python3
"""
Copyright 2025 NW-Diff Contributors
SPDX-License-Identifier: Apache-2.0

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

This file was created or modified with the assistance of an AI (Large Language Model).
Review required for correctness, security, and licensing.

Simple wrapper script to run the NW-Diff application.
"""

import sys
from pathlib import Path

# Add src directory to path so nw_diff module can be imported
src_dir = Path(__file__).parent / "src"
sys.path.insert(0, str(src_dir))

# Import and run the app
from nw_diff import app

if __name__ == "__main__":
    app.app.run(
        host="0.0.0.0",
        port=5000,
        debug=app.os.environ.get("APP_DEBUG", "").lower() == "true",
    )
