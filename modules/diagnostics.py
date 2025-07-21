"""
Diagnostics Module
Handles extension diagnostics and health checks.
"""

import os
import json
from typing import Dict


class ExtensionDiagnostics:
    """Quick diagnostic checks for extension consistency"""

    def __init__(self, extensions_path: str):
        self.extensions_path = extensions_path
        self.extensions_json_path = os.path.join(extensions_path, "extensions.json")

    def check_consistency(self) -> Dict[str, int]:
        """Quick consistency check"""
        if not os.path.exists(self.extensions_json_path):
            return {"orphaned_entries": 0, "total_directories": 0}

        try:
            with open(self.extensions_json_path, 'r') as f:
                metadata = json.load(f)
                if not isinstance(metadata, list):
                    metadata = []
        except (json.JSONDecodeError, IOError):
            metadata = []

        # Count metadata entries
        metadata_dirs = set()
        for entry in metadata:
            if 'relativeLocation' in entry:
                metadata_dirs.add(entry['relativeLocation'])

        # Count actual directories
        actual_dirs = set()
        if os.path.exists(self.extensions_path):
            try:
                for item in os.listdir(self.extensions_path):
                    item_path = os.path.join(self.extensions_path, item)
                    if os.path.isdir(item_path) and not item.startswith('.'):
                        actual_dirs.add(item)
            except OSError:
                pass

        orphaned = len(metadata_dirs - actual_dirs)
        return {
            "orphaned_entries": orphaned,
            "total_directories": len(actual_dirs),
            "total_metadata": len(metadata_dirs)
        }
