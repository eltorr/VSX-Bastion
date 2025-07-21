#!/usr/bin/env python3
"""
Extension Diagnostics and Repair Utility
Fixes inconsistent extension states in VS Code-based editors.
"""

import json
import os
import platform
import sys
from pathlib import Path
from typing import Dict, List, Optional, Set


class ExtensionDiagnostics:
    """Diagnose and repair extension installation issues"""

    def __init__(self, extensions_path: str = None):
        self.system = platform.system().lower()
        self.extensions_path = extensions_path or self._detect_extensions_path()
        self.extensions_json_path = os.path.join(self.extensions_path, "extensions.json")

    def _detect_extensions_path(self) -> str:
        """Auto-detect extensions directory"""
        possible_paths = [
            "~/.cursor/extensions",
            "~/.windsurf/extensions",
            "~/.vscode/extensions",
            "~/.vscode-oss/extensions"
        ]

        for path in possible_paths:
            expanded_path = os.path.expanduser(path)
            if os.path.exists(expanded_path):
                return expanded_path

        # Default to cursor if nothing found
        return os.path.expanduser("~/.cursor/extensions")

    def load_extensions_metadata(self) -> List[Dict]:
        """Load extensions.json metadata"""
        if not os.path.exists(self.extensions_json_path):
            return []

        try:
            with open(self.extensions_json_path, 'r') as f:
                data = json.load(f)
                return data if isinstance(data, list) else []
        except (json.JSONDecodeError, IOError):
            return []

    def get_installed_directories(self) -> Set[str]:
        """Get actual extension directories"""
        if not os.path.exists(self.extensions_path):
            return set()

        directories = set()
        try:
            for item in os.listdir(self.extensions_path):
                item_path = os.path.join(self.extensions_path, item)
                if os.path.isdir(item_path) and not item.startswith('.'):
                    directories.add(item)
        except OSError:
            pass

        return directories

    def get_metadata_entries(self) -> Dict[str, Dict]:
        """Get extensions from metadata with their directory names"""
        metadata = self.load_extensions_metadata()
        entries = {}

        for entry in metadata:
            if 'relativeLocation' in entry:
                dir_name = entry['relativeLocation']
                entries[dir_name] = entry

        return entries

    def diagnose(self) -> Dict[str, List[str]]:
        """Diagnose extension installation issues"""
        metadata_entries = self.get_metadata_entries()
        installed_dirs = self.get_installed_directories()

        # Find orphaned entries (in metadata but directory missing)
        orphaned = []
        for dir_name in metadata_entries.keys():
            if dir_name not in installed_dirs:
                orphaned.append(dir_name)

        # Find ghost directories (directory exists but not in metadata)
        ghost_dirs = []
        for dir_name in installed_dirs:
            if dir_name not in metadata_entries and not dir_name.startswith('.'):
                ghost_dirs.append(dir_name)

        # Find extensions with missing package.json
        missing_package_json = []
        for dir_name in installed_dirs:
            package_json_path = os.path.join(self.extensions_path, dir_name, "package.json")
            if not os.path.exists(package_json_path):
                missing_package_json.append(dir_name)

        return {
            'orphaned_entries': orphaned,
            'ghost_directories': ghost_dirs,
            'missing_package_json': missing_package_json,
            'total_metadata_entries': len(metadata_entries),
            'total_directories': len(installed_dirs)
        }

    def clean_orphaned_entries(self, orphaned_entries: List[str]) -> bool:
        """Remove orphaned entries from extensions.json"""
        if not orphaned_entries:
            return True

        metadata = self.load_extensions_metadata()
        if not metadata:
            return True

        # Filter out orphaned entries
        cleaned_metadata = []
        for entry in metadata:
            if 'relativeLocation' in entry:
                if entry['relativeLocation'] not in orphaned_entries:
                    cleaned_metadata.append(entry)
            else:
                cleaned_metadata.append(entry)

        # Write back cleaned metadata
        try:
            # Backup original
            backup_path = self.extensions_json_path + ".backup"
            if os.path.exists(self.extensions_json_path):
                os.rename(self.extensions_json_path, backup_path)

            with open(self.extensions_json_path, 'w') as f:
                json.dump(cleaned_metadata, f, indent=2)
            return True
        except (IOError, OSError):
            # Restore backup if write failed
            if os.path.exists(backup_path):
                os.rename(backup_path, self.extensions_json_path)
            return False

    def remove_ghost_directories(self, ghost_dirs: List[str]) -> bool:
        """Remove ghost extension directories"""
        import shutil

        success = True
        for dir_name in ghost_dirs:
            dir_path = os.path.join(self.extensions_path, dir_name)
            try:
                shutil.rmtree(dir_path)
            except (OSError, IOError):
                success = False

        return success

    def print_report(self, diagnosis: Dict[str, List[str]]) -> None:
        """Print diagnostic report"""
        print(f"\n{'='*60}")
        print(f"🔍 Extension Diagnostics Report")
        print(f"{'='*60}")
        print(f"📁 Extensions path: {self.extensions_path}")
        print(f"📊 Total metadata entries: {diagnosis['total_metadata_entries']}")
        print(f"📊 Total directories: {diagnosis['total_directories']}")

        if diagnosis['orphaned_entries']:
            print(f"\n❌ Orphaned entries ({len(diagnosis['orphaned_entries'])}):")
            print("   (Listed in metadata but directory missing)")
            for entry in diagnosis['orphaned_entries']:
                print(f"   • {entry}")

        if diagnosis['ghost_directories']:
            print(f"\n👻 Ghost directories ({len(diagnosis['ghost_directories'])}):")
            print("   (Directory exists but not in metadata)")
            for dir_name in diagnosis['ghost_directories']:
                print(f"   • {dir_name}")

        if diagnosis['missing_package_json']:
            print(f"\n📦 Missing package.json ({len(diagnosis['missing_package_json'])}):")
            print("   (Extension directory exists but package.json missing)")
            for dir_name in diagnosis['missing_package_json']:
                print(f"   • {dir_name}")

        if not any([diagnosis['orphaned_entries'], diagnosis['ghost_directories'], diagnosis['missing_package_json']]):
            print(f"\n✅ No issues found! Extensions are in consistent state.")


def main():
    """Main entry point"""
    import argparse

    parser = argparse.ArgumentParser(
        description="Extension Diagnostics and Repair Utility",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 extension_diagnostics.py --diagnose
  python3 extension_diagnostics.py --diagnose --extensions-path ~/.windsurf/extensions
  python3 extension_diagnostics.py --diagnose --fix-orphaned
  python3 extension_diagnostics.py --diagnose --fix-all
        """
    )

    parser.add_argument(
        "--diagnose", "-d",
        action="store_true",
        help="Run diagnostic scan"
    )

    parser.add_argument(
        "--extensions-path", "-p",
        help="Path to extensions directory (auto-detected if not specified)"
    )

    parser.add_argument(
        "--fix-orphaned",
        action="store_true",
        help="Fix orphaned entries in extensions.json"
    )

    parser.add_argument(
        "--fix-ghosts",
        action="store_true",
        help="Remove ghost directories"
    )

    parser.add_argument(
        "--fix-all",
        action="store_true",
        help="Fix all detected issues"
    )

    parser.add_argument(
        "--backup",
        action="store_true",
        default=True,
        help="Create backup before making changes (default: True)"
    )

    args = parser.parse_args()

    if not any([args.diagnose, args.fix_orphaned, args.fix_ghosts, args.fix_all]):
        parser.print_help()
        return

    try:
        diagnostics = ExtensionDiagnostics(args.extensions_path)
        print(f"🔍 Scanning extensions at: {diagnostics.extensions_path}")

        diagnosis = diagnostics.diagnose()
        diagnostics.print_report(diagnosis)

        # Apply fixes if requested
        if args.fix_orphaned or args.fix_all:
            if diagnosis['orphaned_entries']:
                print(f"\n🔧 Fixing orphaned entries...")
                if diagnostics.clean_orphaned_entries(diagnosis['orphaned_entries']):
                    print(f"✅ Successfully cleaned {len(diagnosis['orphaned_entries'])} orphaned entries")
                else:
                    print(f"❌ Failed to clean orphaned entries")

        if args.fix_ghosts or args.fix_all:
            if diagnosis['ghost_directories']:
                print(f"\n🔧 Removing ghost directories...")
                if diagnostics.remove_ghost_directories(diagnosis['ghost_directories']):
                    print(f"✅ Successfully removed {len(diagnosis['ghost_directories'])} ghost directories")
                else:
                    print(f"❌ Failed to remove some ghost directories")

        if args.fix_all or args.fix_orphaned or args.fix_ghosts:
            print(f"\n💡 Restart your editor to apply changes")

    except Exception as e:
        print(f"❌ Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
