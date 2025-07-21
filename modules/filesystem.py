"""
Filesystem Module
Handles local file system operations.
"""

import os
import subprocess
from typing import List


class LocalFileSystemManager:
    """Manages local file system operations"""

    def clean_directory(self, path: str) -> bool:
        """Remove all contents from directory"""
        if not self.directory_exists(path):
            return True

        try:
            items = self.list_directory(path)
            for item in items:
                item_path = os.path.join(path, item)
                subprocess.run(["rm", "-rf", item_path], check=True)
            return True
        except (subprocess.CalledProcessError, OSError):
            return False

    def directory_exists(self, path: str) -> bool:
        """Check if directory exists"""
        return os.path.exists(path) and os.path.isdir(path)

    def list_directory(self, path: str) -> List[str]:
        """List directory contents"""
        if not self.directory_exists(path):
            return []
        return [f for f in os.listdir(path)
                if os.path.isdir(os.path.join(path, f))]
