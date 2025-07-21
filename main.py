#!/usr/bin/env python3
"""
VSX-Bastion Main Entry Point
YAML-based VS Code extension installer with security-first design.
"""

import sys
import argparse
from modules.app import SecureExtensionInstallerApp
from modules.config import DEFAULT_WHITELIST_PATH, DEFAULT_BLACKLIST_PATH, SUPPORTED_EDITORS


def main():
    """Entry point with command line argument support for YAML-based configuration"""
    parser = argparse.ArgumentParser(
        description="VSX-Bastion: Secure VS Code Extension Installer",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""
Examples:
  python3 main.py --config {DEFAULT_WHITELIST_PATH}
  python3 main.py --config {DEFAULT_WHITELIST_PATH} --editor windsurf
  python3 main.py --config {DEFAULT_WHITELIST_PATH} --scan-new
  python3 main.py --config {DEFAULT_WHITELIST_PATH} --scan-only
  python3 main.py --config {DEFAULT_WHITELIST_PATH} --install-all
        """
    )

    parser.add_argument(
        "--config", "-c",
        default=DEFAULT_WHITELIST_PATH,
        help=f"Path to YAML configuration file (default: {DEFAULT_WHITELIST_PATH})"
    )

    parser.add_argument(
        "--blacklist", "-b",
        default=DEFAULT_BLACKLIST_PATH,
        help=f"Path to security blacklist YAML file (default: {DEFAULT_BLACKLIST_PATH})"
    )

    parser.add_argument(
        "--editor", "-e",
        choices=SUPPORTED_EDITORS,
        help="Specify which editor to install extensions for"
    )

    parser.add_argument(
        "--target-path", "-t",
        help="Custom extension directory path"
    )

    parser.add_argument(
        "--install-all",
        action="store_true",
        help="Install all whitelisted extensions (ignore install flags in YAML)"
    )

    parser.add_argument(
        "--scan-new",
        action="store_true",
        help="Security scan extensions not previously verified"
    )

    parser.add_argument(
        "--scan-only", "-s",
        action="store_true",
        help="Security scan only - analyze extensions without installing them"
    )

    parser.add_argument(
        "--no-scan",
        action="store_true",
        help="Skip security scanning entirely"
    )

    parser.add_argument(
        "--force",
        action="store_true",
        help="Force installation even for extensions under review"
    )

    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable verbose output"
    )

    parser.add_argument(
        "--list-all",
        action="store_true",
        help="List all whitelisted extensions and exit"
    )

    parser.add_argument(
        "--list-installable",
        action="store_true",
        help="List extensions marked for installation and exit"
    )

    parser.add_argument(
        "--status",
        metavar="EXTENSION_ID",
        help="Show status of specific extension and exit"
    )

    args = parser.parse_args()

    try:
        # Handle utility commands first
        if args.list_all or args.list_installable or args.status:
            from modules.file_io import YAMLFileReader
            from modules.validation import YAMLWhitelistValidator, BlacklistValidator

            yaml_reader = YAMLFileReader()
            whitelist_validator = YAMLWhitelistValidator(yaml_reader, args.config)
            blacklist_validator = BlacklistValidator(yaml_reader, args.blacklist)

            if args.list_installable:
                installable = whitelist_validator.get_installable_extensions()
                print(f"📋 Extensions marked for installation ({len(installable)}):")
                for ext_id in installable:
                    if not blacklist_validator.is_blocked(ext_id):
                        print(f"   ✅ {ext_id}")
                    else:
                        reason = blacklist_validator.get_block_reason(ext_id)
                        print(f"   🚫 {ext_id} - BLOCKED: {reason}")
                sys.exit(0)

            if args.list_all:
                all_extensions = whitelist_validator.extensions_metadata
                print(f"📋 All whitelisted extensions ({len(all_extensions)}):")
                for ext_id, metadata in all_extensions.items():
                    install_flag = "✅" if metadata.get('install', False) else "⏸️ "
                    if blacklist_validator.is_blocked(ext_id):
                        install_flag = "🚫"
                    print(f"   {install_flag} {ext_id} (by {metadata.get('author', 'Unknown')})")
                sys.exit(0)

            if args.status:
                from modules.validation import ExtensionFilter
                filter_obj = ExtensionFilter(whitelist_validator, blacklist_validator)
                status = filter_obj.get_extension_status(args.status)

                print(f"📊 Status for {args.status}:")
                print(f"   Whitelisted: {'✅' if status['whitelisted'] else '❌'}")
                print(f"   Installable: {'✅' if status['installable'] else '❌'}")
                print(f"   Blocked: {'🚫' if status['blocked'] else '✅'}")
                print(f"   Status: {status['status']}")
                if status['reason']:
                    print(f"   Reason: {status['reason']}")
                if status['metadata'].get('author'):
                    print(f"   Author: {status['metadata']['author']}")
                sys.exit(0)

        app = SecureExtensionInstallerApp(
            config_path=args.config,
            blacklist_path=args.blacklist,
            target_path=args.target_path,
            editor_id=args.editor,
            install_all=args.install_all,
            scan_new=args.scan_new,
            security_scan=not args.no_scan,
            force_install=args.force,
            scan_only=args.scan_only,
            verbose=args.verbose
        )

        success = app.run()
        sys.exit(0 if success else 1)

    except KeyboardInterrupt:
        print("\n❌ Operation cancelled by user")
        sys.exit(1)
    except FileNotFoundError as e:
        print(f"❌ Configuration file error: {e}")
        sys.exit(1)
    except Exception as e:
        if args.verbose:
            import traceback
            traceback.print_exc()
        print(f"❌ Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
