"""
Validation Module
Handles extension validation and filtering with YAML-based whitelist and blacklist support.
"""

import os
from typing import List, Set, Optional, Dict, Any, Tuple
from .file_io import YAMLFileReader


class YAMLWhitelistValidator:
    """Validates extensions against a YAML-based whitelist with metadata"""

    def __init__(self, yaml_reader: YAMLFileReader, whitelist_path: str):
        self.yaml_reader = yaml_reader
        self.whitelist_path = whitelist_path
        self._whitelist_data: Optional[Dict[str, Any]] = None
        self._extensions_metadata: Optional[Dict[str, Dict[str, Any]]] = None

    @property
    def whitelist_data(self) -> Dict[str, Any]:
        """Lazy load whitelist YAML data"""
        if self._whitelist_data is None:
            try:
                self._whitelist_data = self.yaml_reader.read_yaml(self.whitelist_path)
            except FileNotFoundError:
                print(f"⚠️  Whitelist file not found: {self.whitelist_path}")
                self._whitelist_data = {}
            except Exception as e:
                print(f"⚠️  Error loading whitelist: {e}")
                self._whitelist_data = {}
        return self._whitelist_data

    @property
    def extensions_metadata(self) -> Dict[str, Dict[str, Any]]:
        """Lazy load extensions metadata"""
        if self._extensions_metadata is None:
            self._extensions_metadata = self.yaml_reader.extract_extensions_with_metadata(self.whitelist_data)
        return self._extensions_metadata

    def is_whitelisted(self, extension_id: str) -> bool:
        """Check if extension is in whitelist (regardless of install flag)"""
        return extension_id in self.extensions_metadata

    def should_install(self, extension_id: str) -> bool:
        """Check if extension is marked for installation"""
        metadata = self.extensions_metadata.get(extension_id, {})
        return metadata.get('install', False)

    def get_extension_metadata(self, extension_id: str) -> Dict[str, Any]:
        """Get extension metadata"""
        return self.extensions_metadata.get(extension_id, {})

    def get_installable_extensions(self) -> List[str]:
        """Get all extensions marked for installation"""
        return self.yaml_reader.get_installable_extensions(self.whitelist_data)

    def count_whitelisted(self) -> int:
        """Get count of whitelisted extensions"""
        return len(self.extensions_metadata)

    def count_installable(self) -> int:
        """Get count of extensions marked for installation"""
        return len(self.get_installable_extensions())


class BlacklistValidator:
    """Validates extensions against a YAML-based security blacklist"""

    def __init__(self, yaml_reader: YAMLFileReader, blacklist_path: str):
        self.yaml_reader = yaml_reader
        self.blacklist_path = blacklist_path
        self._blacklist_data: Optional[Dict[str, Any]] = None

    @property
    def blacklist_data(self) -> Dict[str, Any]:
        """Lazy load blacklist YAML data"""
        if self._blacklist_data is None:
            try:
                self._blacklist_data = self.yaml_reader.read_yaml(self.blacklist_path)
            except FileNotFoundError:
                # Blacklist file may not exist initially
                self._blacklist_data = {
                    'blocked_extensions': {},
                    'review_queue': {},
                    'metadata': {
                        'last_updated': '',
                        'scanner_version': '2.0',
                        'total_blocked': 0
                    }
                }
            except Exception as e:
                print(f"⚠️  Error loading blacklist: {e}")
                self._blacklist_data = {
                    'blocked_extensions': {},
                    'review_queue': {},
                    'metadata': {
                        'last_updated': '',
                        'scanner_version': '2.0',
                        'total_blocked': 0
                    }
                }
        return self._blacklist_data

    def is_blocked(self, extension_id: str) -> bool:
        """Check if extension is in blacklist"""
        blocked_extensions = self.blacklist_data.get('blocked_extensions', {})
        return extension_id in blocked_extensions

    def is_under_review(self, extension_id: str) -> bool:
        """Check if extension is under security review"""
        review_queue = self.blacklist_data.get('review_queue', {})
        return extension_id in review_queue

    def get_block_reason(self, extension_id: str) -> str:
        """Get reason why extension is blocked"""
        blocked_extensions = self.blacklist_data.get('blocked_extensions', {})
        if extension_id in blocked_extensions:
            block_info = blocked_extensions[extension_id]
            return f"{block_info.get('reason', 'UNKNOWN')}: {block_info.get('details', 'No details')}"
        return ""

    def get_review_reason(self, extension_id: str) -> str:
        """Get reason why extension is under review"""
        review_queue = self.blacklist_data.get('review_queue', {})
        if extension_id in review_queue:
            review_info = review_queue[extension_id]
            return f"{review_info.get('reason', 'UNKNOWN')}: {review_info.get('details', 'No details')}"
        return ""

    def add_blocked_extension(self, extension_id: str, reason: str, details: str) -> None:
        """Add extension to blacklist"""
        from datetime import datetime

        blocked_extensions = self.blacklist_data.get('blocked_extensions', {})
        blocked_extensions[extension_id] = {
            'reason': reason,
            'blocked_date': datetime.now().strftime('%Y-%m-%d'),
            'details': details
        }

        # Update metadata
        metadata = self.blacklist_data.get('metadata', {})
        metadata['last_updated'] = datetime.now().strftime('%Y-%m-%d')
        metadata['total_blocked'] = len(blocked_extensions)

        self.blacklist_data['blocked_extensions'] = blocked_extensions
        self.blacklist_data['metadata'] = metadata

    def save_blacklist(self) -> None:
        """Save blacklist changes to file"""
        try:
            self.yaml_reader.write_yaml(self.blacklist_path, self.blacklist_data)
        except Exception as e:
            print(f"⚠️  Error saving blacklist: {e}")

    def count_blocked(self) -> int:
        """Get count of blocked extensions"""
        return len(self.blacklist_data.get('blocked_extensions', {}))

    def count_under_review(self) -> int:
        """Get count of extensions under review"""
        return len(self.blacklist_data.get('review_queue', {}))


class ExtensionFilter:
    """Filters extensions based on whitelist and blacklist validation rules"""

    def __init__(self, whitelist_validator: YAMLWhitelistValidator, blacklist_validator: BlacklistValidator):
        self.whitelist_validator = whitelist_validator
        self.blacklist_validator = blacklist_validator

    def filter_extensions(self, requested: List[str]) -> Tuple[List[str], List[str], List[str]]:
        """
        Separate extensions into allowed, blocked, and not whitelisted
        Returns: (allowed, blocked_by_blacklist, not_whitelisted)
        """
        allowed = []
        blocked_by_blacklist = []
        not_whitelisted = []

        for ext_id in requested:
            # First check if extension is blocked by security blacklist
            if self.blacklist_validator.is_blocked(ext_id):
                blocked_by_blacklist.append(ext_id)
                continue

            # Check if extension is under review (treat as blocked for now)
            if self.blacklist_validator.is_under_review(ext_id):
                blocked_by_blacklist.append(ext_id)
                continue

            # Check if extension is whitelisted
            if not self.whitelist_validator.is_whitelisted(ext_id):
                not_whitelisted.append(ext_id)
                continue

            # Extension is whitelisted and not blocked
            allowed.append(ext_id)

        return allowed, blocked_by_blacklist, not_whitelisted

    def filter_installable_extensions(self) -> Tuple[List[str], List[str]]:
        """
        Get extensions marked for installation, filtered by blacklist
        Returns: (installable, blocked_installable)
        """
        installable_extensions = self.whitelist_validator.get_installable_extensions()
        allowed, blocked, _ = self.filter_extensions(installable_extensions)

        return allowed, blocked

    def get_extension_status(self, extension_id: str) -> Dict[str, Any]:
        """Get comprehensive status information for an extension"""
        status = {
            'extension_id': extension_id,
            'whitelisted': False,
            'installable': False,
            'blocked': False,
            'under_review': False,
            'status': 'UNKNOWN',
            'reason': '',
            'metadata': {}
        }

        # Check whitelist status
        if self.whitelist_validator.is_whitelisted(extension_id):
            status['whitelisted'] = True
            status['installable'] = self.whitelist_validator.should_install(extension_id)
            status['metadata'] = self.whitelist_validator.get_extension_metadata(extension_id)

        # Check blacklist status
        if self.blacklist_validator.is_blocked(extension_id):
            status['blocked'] = True
            status['status'] = 'BLOCKED'
            status['reason'] = self.blacklist_validator.get_block_reason(extension_id)
        elif self.blacklist_validator.is_under_review(extension_id):
            status['under_review'] = True
            status['status'] = 'UNDER_REVIEW'
            status['reason'] = self.blacklist_validator.get_review_reason(extension_id)
        elif status['whitelisted']:
            if status['installable']:
                status['status'] = 'INSTALLABLE'
            else:
                status['status'] = 'WHITELISTED'
        else:
            status['status'] = 'NOT_WHITELISTED'

        return status

    def print_filter_summary(self, allowed: List[str], blocked: List[str], not_whitelisted: List[str]) -> None:
        """Print a summary of the filtering results"""
        total = len(allowed) + len(blocked) + len(not_whitelisted)

        print(f"\n{'='*60}")
        print(f"🔍 EXTENSION FILTERING SUMMARY")
        print(f"{'='*60}")
        print(f"📊 Total requested: {total}")
        print(f"✅ Allowed: {len(allowed)}")
        print(f"🚫 Blocked by security: {len(blocked)}")
        print(f"❓ Not whitelisted: {len(not_whitelisted)}")

        if blocked:
            print(f"\n🚫 BLOCKED EXTENSIONS:")
            for ext_id in blocked:
                if self.blacklist_validator.is_blocked(ext_id):
                    reason = self.blacklist_validator.get_block_reason(ext_id)
                    print(f"   • {ext_id} - {reason}")
                elif self.blacklist_validator.is_under_review(ext_id):
                    reason = self.blacklist_validator.get_review_reason(ext_id)
                    print(f"   • {ext_id} - UNDER REVIEW: {reason}")

        if not_whitelisted:
            print(f"\n❓ NOT WHITELISTED:")
            for ext_id in not_whitelisted:
                print(f"   • {ext_id}")
            print(f"💡 Add these to whitelist.yaml to enable installation")
