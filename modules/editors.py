"""
Editors Module
Handles editor detection and management.
"""

import os
import platform
from typing import List, Dict, Optional


class EditorDetector:
    """Detects installed VS Code-based editors and their extension paths"""

    def __init__(self):
        self.system = platform.system().lower()
        self.editors = self._get_editor_definitions()

    def _get_editor_definitions(self) -> Dict[str, Dict[str, str]]:
        """Define editor configurations for different platforms"""
        if self.system == "darwin":  # macOS
            return {
                "cursor": {
                    "name": "Cursor AI",
                    "path": "~/.cursor/extensions",
                    "executable": "/Applications/Cursor.app"
                },
                "windsurf": {
                    "name": "Windsurf",
                    "path": "~/.windsurf/extensions",
                    "executable": "/Applications/Windsurf.app"
                },
                "vscodium": {
                    "name": "VSCodium",
                    "path": "~/.vscode-oss/extensions",
                    "executable": "/Applications/VSCodium.app"
                },
                "vscode": {
                    "name": "VS Code",
                    "path": "~/.vscode/extensions",
                    "executable": "/Applications/Visual Studio Code.app"
                },
                "code-oss": {
                    "name": "Code-OSS",
                    "path": "~/.vscode-oss/extensions",
                    "executable": "/usr/local/bin/code-oss"
                }
            }
        elif self.system == "linux":
            return {
                "cursor": {
                    "name": "Cursor AI",
                    "path": "~/.cursor/extensions",
                    "executable": "/usr/bin/cursor"
                },
                "windsurf": {
                    "name": "Windsurf",
                    "path": "~/.windsurf/extensions",
                    "executable": "/usr/bin/windsurf"
                },
                "vscodium": {
                    "name": "VSCodium",
                    "path": "~/.vscode-oss/extensions",
                    "executable": "/usr/bin/codium"
                },
                "vscode": {
                    "name": "VS Code",
                    "path": "~/.vscode/extensions",
                    "executable": "/usr/bin/code"
                },
                "code-oss": {
                    "name": "Code-OSS",
                    "path": "~/.vscode-oss/extensions",
                    "executable": "/usr/bin/code-oss"
                }
            }
        else:  # Windows
            return {
                "cursor": {
                    "name": "Cursor AI",
                    "path": "~/.cursor/extensions",
                    "executable": "C:/Users/{}/AppData/Local/Programs/cursor/Cursor.exe"
                },
                "windsurf": {
                    "name": "Windsurf",
                    "path": "~/.windsurf/extensions",
                    "executable": "C:/Users/{}/AppData/Local/Programs/Windsurf/Windsurf.exe"
                },
                "vscodium": {
                    "name": "VSCodium",
                    "path": "~/.vscode-oss/extensions",
                    "executable": "C:/Users/{}/AppData/Local/Programs/VSCodium/VSCodium.exe"
                },
                "vscode": {
                    "name": "VS Code",
                    "path": "~/.vscode/extensions",
                    "executable": "C:/Users/{}/AppData/Local/Programs/Microsoft VS Code/Code.exe"
                },
                "code-oss": {
                    "name": "Code-OSS",
                    "path": "~/.vscode-oss/extensions",
                    "executable": "C:/Program Files/Code - OSS/Code - OSS.exe"
                }
            }

    def detect_installed_editors(self) -> List[Dict[str, str]]:
        """Detect which editors are actually installed"""
        installed = []

        for editor_id, config in self.editors.items():
            # Check if extension directory exists
            ext_path = os.path.expanduser(config["path"])
            if os.path.exists(ext_path):
                installed.append({
                    "id": editor_id,
                    "name": config["name"],
                    "path": ext_path,
                    "extensions_path": config["path"]
                })

        return installed

    def get_editor_path(self, editor_id: str) -> Optional[str]:
        """Get extension path for specific editor"""
        if editor_id in self.editors:
            return os.path.expanduser(self.editors[editor_id]["path"])
        return None

    def get_default_editor(self) -> Optional[Dict[str, str]]:
        """Get the first available editor as default"""
        installed = self.detect_installed_editors()
        return installed[0] if installed else None
