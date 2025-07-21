#!/usr/bin/env python3
"""
Simple VS Code Version Detector
Dynamically detects VS Code engine version from editor product.json files.
"""

import subprocess
import os
import json
import platform
import re
from typing import Optional, Dict


class VSCodeVersionDetector:
    """Dynamic detector for VS Code engine versions using product.json"""

    def __init__(self):
        self.system = platform.system().lower()

    def get_editor_version(self, editor_id: str) -> Optional[str]:
        """Get VS Code engine version for a specific editor"""

        # Try dynamic detection from product.json first
        version = self._get_version_from_product_json(editor_id)
        if version:
            return version

        # Fallback to command line detection
        version = self._get_version_from_command(editor_id)
        if version:
            return version

        # Final fallback to safe defaults
        return self._get_safe_default(editor_id)

    def _get_version_from_product_json(self, editor_id: str) -> Optional[str]:
        """Extract VS Code version from editor's product.json file"""

        # Define application paths for different platforms
        app_paths = self._get_app_paths(editor_id)

        for app_path in app_paths:
            if os.path.exists(app_path):
                product_json_path = os.path.join(app_path, "Contents/Resources/app/product.json")
                if self.system != "darwin":  # Linux/Windows
                    product_json_path = os.path.join(app_path, "resources/app/product.json")

                try:
                    with open(product_json_path, 'r') as f:
                        data = json.load(f)

                    # Check for vscodeVersion field (used by forks like Cursor)
                    if 'vscodeVersion' in data:
                        return data['vscodeVersion']

                    # For VS Code itself and VSCodium, use the version field
                    if editor_id in ['code', 'codium'] and 'version' in data:
                        return data['version']

                except (json.JSONDecodeError, IOError, OSError):
                    continue

        return None

    def _get_app_paths(self, editor_id: str) -> list:
        """Get possible application paths for different editors and platforms"""

        if self.system == "darwin":  # macOS
            paths = {
                'cursor': ['/Applications/Cursor.app'],
                'windsurf': ['/Applications/Windsurf.app'],
                'code': ['/Applications/Visual Studio Code.app'],
                'codium': ['/Applications/VSCodium.app'],
            }
        elif self.system == "linux":
            paths = {
                'cursor': ['/opt/cursor', '/usr/share/cursor', '~/.local/share/cursor'],
                'windsurf': ['/opt/windsurf', '/usr/share/windsurf'],
                'code': ['/opt/visual-studio-code', '/usr/share/code'],
                'codium': ['/opt/vscodium', '/usr/share/vscodium'],
            }
        else:  # Windows
            username = os.environ.get('USERNAME', 'User')
            paths = {
                'cursor': [f'C:/Users/{username}/AppData/Local/Programs/cursor'],
                'windsurf': [f'C:/Users/{username}/AppData/Local/Programs/Windsurf'],
                'code': [f'C:/Users/{username}/AppData/Local/Programs/Microsoft VS Code'],
                'codium': [f'C:/Users/{username}/AppData/Local/Programs/VSCodium'],
            }

        return [os.path.expanduser(path) for path in paths.get(editor_id, [])]

    def _get_version_from_command(self, editor_id: str) -> Optional[str]:
        """Try to get version from command line as fallback"""
        commands = {
            'cursor': ['cursor', '--version'],
            'code': ['code', '--version'],
            'codium': ['codium', '--version'],
            'windsurf': ['windsurf', '--version']
        }

        if editor_id not in commands:
            return None

        try:
            result = subprocess.run(
                commands[editor_id],
                capture_output=True,
                text=True,
                timeout=10
            )

            if result.returncode == 0:
                lines = result.stdout.strip().split('\n')
                if lines:
                    # Extract version from first line
                    version_line = lines[0].strip()
                    version_match = re.search(r'(\d+\.\d+\.\d+)', version_line)
                    if version_match:
                        version = version_match.group(1)
                        # For VS Code itself, return as-is
                        if editor_id in ['code', 'codium']:
                            return version

        except (subprocess.SubprocessError, FileNotFoundError, subprocess.TimeoutExpired):
            pass

        return None

    def _get_safe_default(self, editor_id: str) -> Optional[str]:
        """Provide safe default versions as last resort"""
        defaults = {
            'cursor': '1.99.3',      # Conservative default
            'windsurf': '1.102.0',   # Recent stable version
            'code': '1.102.1',       # Latest stable
            'codium': '1.102.0'      # Usually close to VS Code
        }
        return defaults.get(editor_id)

    def check_vscode_version_available(self, version: str) -> bool:
        """Check if specific VS Code version is available in apt repository"""
        try:
            # Quick check using docker
            result = subprocess.run([
                'docker', 'run', '--rm',
                'mcr.microsoft.com/devcontainers/base:ubuntu',
                'bash', '-c',
                f'''
                apt-get update -qq 2>/dev/null &&
                wget -qO- https://packages.microsoft.com/keys/microsoft.asc | gpg --dearmor > packages.microsoft.gpg 2>/dev/null &&
                install -D -o root -g root -m 644 packages.microsoft.gpg /etc/apt/keyrings/packages.microsoft.gpg &&
                echo "deb [arch=amd64,arm64,armhf signed-by=/etc/apt/keyrings/packages.microsoft.gpg] https://packages.microsoft.com/repos/code stable main" | tee /etc/apt/sources.list.d/vscode.list > /dev/null &&
                apt-get update -qq 2>/dev/null &&
                apt-cache policy code | grep -q "{version}"
                '''
            ], capture_output=True, timeout=60)

            return result.returncode == 0

        except (subprocess.SubprocessError, subprocess.TimeoutExpired):
            return False


def list_available_versions():
    """List all available VS Code versions in repository"""
    try:
        result = subprocess.run([
            'docker', 'run', '--rm',
            'mcr.microsoft.com/devcontainers/base:ubuntu',
            'bash', '-c',
            '''
            apt-get update -qq 2>/dev/null &&
            wget -qO- https://packages.microsoft.com/keys/microsoft.asc | gpg --dearmor > packages.microsoft.gpg 2>/dev/null &&
            install -D -o root -g root -m 644 packages.microsoft.gpg /etc/apt/keyrings/packages.microsoft.gpg &&
            echo "deb [arch=amd64,arm64,armhf signed-by=/etc/apt/keyrings/packages.microsoft.gpg] https://packages.microsoft.com/repos/code stable main" | tee /etc/apt/sources.list.d/vscode.list > /dev/null &&
            apt-get update -qq 2>/dev/null &&
            apt-cache policy code | grep -E "^\\s+[0-9]" | head -15
            '''
        ], capture_output=True, text=True, timeout=120)

        if result.returncode == 0:
            print("📋 Available VS Code versions in repository:")
            lines = result.stdout.strip().split('\n')
            versions = []
            for line in lines:
                if line.strip() and not line.strip().startswith('500'):
                    # Extract version number like "1.102.1-1752598707"
                    version_match = re.search(r'(\d+\.\d+\.\d+)', line)
                    if version_match:
                        versions.append(version_match.group(1))

            # Remove duplicates and sort
            unique_versions = sorted(set(versions), reverse=True)
            for i, version in enumerate(unique_versions[:10], 1):
                print(f"   {i:2d}. {version}")

            if len(unique_versions) > 10:
                print(f"   ... and {len(unique_versions) - 10} more versions")
        else:
            print("❌ Failed to fetch available versions")
            return False

    except (subprocess.SubprocessError, subprocess.TimeoutExpired):
        print("❌ Error: Could not check available versions (Docker required)")
        return False

    return True


def main():
    """CLI interface for testing"""
    import argparse

    parser = argparse.ArgumentParser(description="VS Code Version Detector")
    parser.add_argument("editor", nargs='?', choices=['cursor', 'windsurf', 'code', 'codium'],
                       help="Editor to check")
    parser.add_argument("--check-available", action="store_true",
                       help="Check if detected version is available in repository")
    parser.add_argument("--list-versions", action="store_true",
                       help="List all available VS Code versions in repository")
    parser.add_argument("--summary", action="store_true",
                       help="Show simple summary of version matching")

    args = parser.parse_args()

    # Handle list-versions command
    if args.list_versions:
        return 0 if list_available_versions() else 1

    # Require editor if not listing versions
    if not args.editor:
        parser.error("Editor argument is required unless using --list-versions")

    detector = VSCodeVersionDetector()
    version = detector.get_editor_version(args.editor)

    if version:
        if args.summary:
            # Simple summary format
            available = detector.check_vscode_version_available(version)
            print(f"{args.editor.upper()} → VS Code {version} → Container: {'✓' if available else '✗'}")
        else:
            print(f"Editor: {args.editor}")
            print(f"VS Code engine version: {version}")

            if args.check_available:
                print("Checking availability in repository...")
                available = detector.check_vscode_version_available(version)
                print(f"Available in apt repo: {'Yes' if available else 'No'}")

                if not available:
                    print(f"Note: Will fallback to latest available version")
    else:
        if args.summary:
            print(f"{args.editor.upper()} → Unknown version → Container: ✗")
        else:
            print(f"Could not detect version for {args.editor}")
        return 1

    return 0


if __name__ == "__main__":
    exit(main())
