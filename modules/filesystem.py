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
            print(f"🧹 Cleaning {len(items)} items from {path}")
            for item in items:
                item_path = os.path.join(path, item)
                subprocess.run(["rm", "-rf", item_path], check=True)

            # Also clean any hidden files and extensions.json
            hidden_files = ['.obsolete', 'extensions.json']
            for hidden_file in hidden_files:
                hidden_path = os.path.join(path, hidden_file)
                if os.path.exists(hidden_path):
                    os.remove(hidden_path)
                    print(f"🧹 Removed {hidden_file}")

            return True
        except (subprocess.CalledProcessError, OSError) as e:
            print(f"❌ Failed to clean directory {path}: {e}")
            return False

    def directory_exists(self, path: str) -> bool:
        """Check if directory exists"""
        return os.path.exists(path) and os.path.isdir(path)

    def list_directory(self, path: str) -> List[str]:
        """List directory contents"""
        if not self.directory_exists(path):
            return []
        return [f for f in os.listdir(path)
                if os.path.isdir(os.path.join(path, f)) and not f.startswith('.')]

    def force_clean_extensions(self, path: str) -> bool:
        """Force clean all extensions including hidden files"""
        if not self.directory_exists(path):
            print(f"🧹 Directory {path} doesn't exist, nothing to clean")
            return True

        try:
            # Remove all contents including hidden files
            for item in os.listdir(path):
                item_path = os.path.join(path, item)
                if os.path.isfile(item_path):
                    os.remove(item_path)
                    print(f"🧹 Removed file: {item}")
                elif os.path.isdir(item_path):
                    subprocess.run(["rm", "-rf", item_path], check=True)
                    print(f"🧹 Removed directory: {item}")

            print(f"✅ Successfully cleaned all contents from {path}")
            return True
        except (subprocess.CalledProcessError, OSError) as e:
            print(f"❌ Failed to force clean directory {path}: {e}")
            return False
