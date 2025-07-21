#!/usr/bin/env python3
"""
VSX-Bastion Configuration Constants
Centralized configuration for paths, files, and default values.
"""

import os

# Base directories
EXTENSIONS_DIR = "extensions-list"
REPORTS_DIR = "reports"
LOGS_DIR = "logs"
THREAT_DATA_DIR = "threat_data"

# Configuration file names
WHITELIST_FILENAME = "whitelist.yaml"
BLACKLIST_FILENAME = "blacklist.yaml"
EXTENSIONS_TO_INSTALL_FILENAME = "extensions-to-install"

# Default file paths
DEFAULT_WHITELIST_PATH = os.path.join(EXTENSIONS_DIR, WHITELIST_FILENAME)
DEFAULT_BLACKLIST_PATH = os.path.join(EXTENSIONS_DIR, BLACKLIST_FILENAME)

# Supported editors
SUPPORTED_EDITORS = [
    "cursor",
    "windsurf",
    "vscodium",
    "vscode",
    "code-oss"
]

# Required directories for setup
REQUIRED_DIRECTORIES = [
    EXTENSIONS_DIR,
    REPORTS_DIR,
    LOGS_DIR,
    THREAT_DATA_DIR
]

# Configuration files to check during setup
CONFIG_FILES = [
    DEFAULT_WHITELIST_PATH,
    DEFAULT_BLACKLIST_PATH,
    EXTENSIONS_TO_INSTALL_FILENAME
]
