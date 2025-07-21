"""
App Module
Main application orchestrating the YAML-based installation process with security features.
"""

import os
import sys
from typing import List, Dict, Optional, Tuple
from .config import DEFAULT_WHITELIST_PATH, DEFAULT_BLACKLIST_PATH, SUPPORTED_EDITORS, REPORTS_DIR
from .file_io import YAMLFileReader
from .validation import YAMLWhitelistValidator, BlacklistValidator, ExtensionFilter
from .editors import EditorDetector
from .containers import DockerVSCodeContainer
from .filesystem import LocalFileSystemManager
from .installation import ExtensionInstaller
from .diagnostics import ExtensionDiagnostics


class SecureExtensionInstallerApp:
    """Main application orchestrating the YAML-based installation process"""

    def __init__(self,
                 config_path: str = DEFAULT_WHITELIST_PATH,
                 blacklist_path: str = DEFAULT_BLACKLIST_PATH,
                 target_path: Optional[str] = None,
                 editor_id: Optional[str] = None,
                 install_all: bool = False,
                 scan_new: bool = False,
                 security_scan: bool = True,
                 force_install: bool = False,
                 scan_only: bool = False,
                 verbose: bool = False):

        # Configuration
        self.config_path = config_path
        self.blacklist_path = blacklist_path
        self.target_path = target_path
        self.editor_id = editor_id
        self.install_all = install_all
        self.scan_new = scan_new
        self.security_scan = security_scan
        self.force_install = force_install
        self.scan_only = scan_only
        self.verbose = verbose

        # Initialize components
        self.file_reader = YAMLFileReader()
        self.yaml_validator = YAMLWhitelistValidator(self.file_reader, self.config_path)
        self.blacklist_validator = BlacklistValidator(self.file_reader, self.blacklist_path)
        self.filter = ExtensionFilter(self.yaml_validator, self.blacklist_validator)
        self.editor_detector = EditorDetector()
        self.filesystem_manager = LocalFileSystemManager()
        self.diagnostics = None  # Will be initialized after target_path is determined

        # Version detector (optional import)
        try:
            from .version_detector import VSCodeVersionDetector
            self.version_detector = VSCodeVersionDetector()
        except ImportError:
            self.version_detector = None

        # Docker container manager
        self.container_manager = None
        try:
            self.container_manager = DockerVSCodeContainer()
        except Exception as e:
            if verbose:
                print(f"⚠️  Docker container manager not available: {e}")

        # Initialize installer after container manager is ready
        self.installer = ExtensionInstaller(self.container_manager, self.filesystem_manager, self.filter)

        # Editor selection logic
        if self.editor_id:
            if self.editor_id not in SUPPORTED_EDITORS:
                raise ValueError(f"Unsupported editor: {self.editor_id}. Supported: {SUPPORTED_EDITORS}")
            self.target_editor = self.editor_id
        else:
            detected = self.editor_detector.detect_installed_editors()
            if not detected:
                raise RuntimeError("No supported VS Code editors found. Install one of: " +
                                 ", ".join(SUPPORTED_EDITORS))
            self.target_editor = detected[0]["id"]  # Use first detected editor ID
            if verbose:
                print(f"🎯 Auto-detected editor: {self.target_editor}")

        # Target path resolution
        if not self.target_path:
            self.target_path = self.editor_detector.get_editor_path(self.target_editor)

        # Initialize diagnostics now that we have target_path
        self.diagnostics = ExtensionDiagnostics(self.target_path)

        if verbose:
            print(f"📂 Target extensions path: {self.target_path}")
            print(f"📄 Configuration: {self.config_path}")
            print(f"🚫 Blacklist: {self.blacklist_path}")

        # Security scanner (optional import)
        self.security_scanner = None
        if self.security_scan:
            try:
                from scanner import EnhancedProductionScanner
                self.security_scanner = EnhancedProductionScanner()
                if verbose:
                    print("🔒 Security scanner enabled for new extensions")
            except ImportError as e:
                if verbose:
                    print(f"⚠️  Security scanner not available: {e}")
                self.security_scan = False

    def get_extensions_to_process(self) -> List[str]:
        """Get list of extension IDs to process based on configuration"""
        if self.install_all:
            # Install all whitelisted extensions regardless of install flag
            return list(self.yaml_validator.extensions_metadata.keys())
        else:
            # Only install extensions marked with install: true
            return self.yaml_validator.get_installable_extensions()

    def apply_security_filters(self, extension_ids: List[str]) -> Tuple[List[str], List[str], List[str]]:
        """Apply security filters and return categorized lists"""
        return self.filter.filter_extensions(extension_ids)

    def security_scan_extensions(self, extension_ids: List[str]) -> Dict:
        """Perform security scanning on extensions"""
        if not self.security_scanner or not extension_ids:
            return {}

        scan_results = {}
        for ext_id in extension_ids:
            if self.verbose:
                print(f"🔍 Scanning {ext_id}...")

            try:
                result = self.security_scanner.scan_extension(ext_id)
                scan_results[ext_id] = result

                if result.get('threats_found', 0) > 0:
                    print(f"⚠️  Security issues found in {ext_id}")
                    if self.verbose:
                        threats = result.get('threats', [])
                        for threat in threats[:3]:  # Show first 3 threats
                            print(f"   - {threat.get('type', 'Unknown')}: {threat.get('description', 'No description')}")

            except Exception as e:
                if self.verbose:
                    print(f"❌ Scan failed for {ext_id}: {e}")
                scan_results[ext_id] = {'error': str(e), 'threats_found': 0}

        return scan_results

    def should_skip_extension(self, ext_id: str, scan_result: Dict) -> bool:
        """Determine if extension should be skipped based on scan results"""
        if not scan_result:
            return False

        threats_found = scan_result.get('threats_found', 0)

        # Skip if threats found and not force installing
        if threats_found > 0 and not self.force_install:
            return True

        # Skip if scan error and being cautious
        if 'error' in scan_result and not self.force_install:
            return True

        return False

    def install_extensions(self, extension_ids: List[str]) -> Dict[str, bool]:
        """Install multiple extensions and return results"""
        try:
            if self.verbose:
                print(f"📦 Installing {len(extension_ids)} extensions...")

            # Use the ExtensionInstaller's install_extensions method
            result = self.installer.install_extensions(extension_ids, self.target_path)

            # Convert the result format to our expected format
            results = {}
            for ext_id in extension_ids:
                if ext_id in result.get('installed', []):
                    results[ext_id] = True
                    if self.verbose:
                        print(f"✅ Successfully installed {ext_id}")
                else:
                    results[ext_id] = False
                    if ext_id in result.get('failed', []):
                        print(f"❌ Failed to install {ext_id}")
                    elif ext_id in result.get('blocked', []):
                        print(f"🚫 Blocked: {ext_id}")
                    else:
                        print(f"⚠️  Skipped: {ext_id}")

            return results

        except Exception as e:
            print(f"❌ Installation error: {e}")
            if self.verbose:
                import traceback
                traceback.print_exc()
            # Return all failed
            return {ext_id: False for ext_id in extension_ids}

    def update_installation_status(self, results: Dict[str, bool]):
        """Update diagnostics with installation results"""
        for ext_id, success in results.items():
            if success:
                self.diagnostics.mark_installed(ext_id)
            else:
                self.diagnostics.mark_failed(ext_id)

    def print_summary(self, installable: List[str], blocked: List[str],
                     not_whitelisted: List[str], install_results: Dict[str, bool],
                     scan_results: Dict = None):
        """Print installation summary"""
        print("\n" + "="*60)
        print("📊 INSTALLATION SUMMARY")
        print("="*60)

        if install_results:
            successful = [ext_id for ext_id, success in install_results.items() if success]
            failed = [ext_id for ext_id, success in install_results.items() if not success]

            print(f"✅ Successfully installed: {len(successful)}")
            if self.verbose and successful:
                for ext_id in successful:
                    print(f"   • {ext_id}")

            if failed:
                print(f"❌ Failed to install: {len(failed)}")
                for ext_id in failed:
                    print(f"   • {ext_id}")

        if blocked:
            print(f"🚫 Blocked by security: {len(blocked)}")
            if self.verbose:
                for ext_id in blocked:
                    reason = self.blacklist_validator.get_block_reason(ext_id)
                    print(f"   • {ext_id} - {reason}")

        if not_whitelisted:
            print(f"❓ Not whitelisted: {len(not_whitelisted)}")
            if self.verbose:
                for ext_id in not_whitelisted[:5]:  # Show first 5
                    print(f"   • {ext_id}")

        if scan_results:
            threats_found = sum(1 for result in scan_results.values()
                              if result.get('threats_found', 0) > 0)
            if threats_found > 0:
                print(f"⚠️  Extensions with security concerns: {threats_found}")

    def save_scan_report(self, scan_results: Dict):
        """Save detailed scan report"""
        if not scan_results:
            return

        import json
        from datetime import datetime

        os.makedirs(REPORTS_DIR, exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_file = f"{REPORTS_DIR}/security_scan_{timestamp}.json"

        try:
            with open(report_file, 'w') as f:
                json.dump(scan_results, f, indent=2, default=str)
            if self.verbose:
                print(f"📄 Scan report saved to {report_file}")
        except Exception as e:
            if self.verbose:
                print(f"⚠️  Failed to save scan report: {e}")

    def run(self) -> bool:
        """Main execution logic"""
        try:
            if self.verbose:
                print(f"🚀 VSX-Bastion starting for {self.target_editor}")
                print(f"📋 Processing configuration: {self.config_path}")

            # Get extensions to process
            extensions_to_process = self.get_extensions_to_process()

            if not extensions_to_process:
                print("ℹ️  No extensions marked for installation")
                return True

            if self.verbose:
                print(f"📝 Found {len(extensions_to_process)} extensions to process")

            # Apply security filters
            installable, blocked, not_whitelisted = self.apply_security_filters(extensions_to_process)

            # Display filter summary
            self.filter.print_filter_summary(installable, blocked, not_whitelisted)

            if not installable:
                print("ℹ️  No installable extensions after security filtering")
                return True

            # Security scanning for new extensions
            scan_results = {}
            if self.scan_new and self.security_scanner:
                print(f"\n🔍 Security scanning {len(installable)} extensions...")
                scan_results = self.security_scan_extensions(installable)

                # Filter out extensions with security issues
                safe_extensions = []
                for ext_id in installable:
                    if not self.should_skip_extension(ext_id, scan_results.get(ext_id, {})):
                        safe_extensions.append(ext_id)
                    elif self.verbose:
                        print(f"⏭️  Skipping {ext_id} due to security concerns")

                installable = safe_extensions

            # Save scan report if we performed scanning
            if scan_results:
                self.save_scan_report(scan_results)

            # Scan-only mode
            if self.scan_only:
                print("\n🔍 Scan-only mode: No installations performed")
                self.print_summary(installable, blocked, not_whitelisted, {}, scan_results)
                return True

            # Install extensions
            if installable:
                print(f"\n📦 Installing {len(installable)} extensions...")
                install_results = self.install_extensions(installable)
                self.update_installation_status(install_results)
            else:
                install_results = {}

            # Print summary
            self.print_summary(installable, blocked, not_whitelisted, install_results, scan_results)

            # Run diagnostics
            if install_results:
                print(f"\n🔧 Running post-installation diagnostics...")
                diagnostic_results = self.diagnostics.run_diagnostics(
                    list(install_results.keys()),
                    self.target_path
                )

                if self.verbose:
                    self.diagnostics.print_diagnostic_summary(diagnostic_results)

            return len([r for r in install_results.values() if r]) > 0

        except KeyboardInterrupt:
            print("\n❌ Installation cancelled by user")
            return False
        except Exception as e:
            print(f"❌ Application error: {e}")
            if self.verbose:
                import traceback
                traceback.print_exc()
            return False
