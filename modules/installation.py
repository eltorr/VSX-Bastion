"""
Installation Module
Handles extension installation orchestration.
"""

from typing import List, Dict


class ExtensionInstaller:
    """Orchestrates extension installation process"""

    def __init__(self, container, filesystem, filter):
        self.container = container
        self.filesystem = filesystem
        self.filter = filter

    def install_extensions(self, requested: List[str], target_path: str) -> dict:
        """Install filtered extensions to target path"""
        # Filter extensions
        allowed, blocked_by_security, not_whitelisted = self.filter.filter_extensions(requested)
        blocked = blocked_by_security + not_whitelisted

        if not allowed:
            return {
                'success': False,
                'message': 'No allowed extensions to install',
                'allowed': allowed,
                'blocked': blocked,
                'installed': [],
                'failed': []
            }

        # Clean target directory
        if not self.filesystem.clean_directory(target_path):
            return {
                'success': False,
                'message': 'Failed to clean target directory',
                'allowed': allowed,
                'blocked': blocked,
                'installed': [],
                'failed': []
            }

        # Build and start container
        if not self.container.build_image():
            return {
                'success': False,
                'message': 'Failed to build container image',
                'allowed': allowed,
                'blocked': blocked,
                'installed': [],
                'failed': []
            }

        if not self.container.start_container(target_path):
            return {
                'success': False,
                'message': 'Failed to start container',
                'allowed': allowed,
                'blocked': blocked,
                'installed': [],
                'failed': []
            }

        # Install extensions
        installed = []
        failed = []

        try:
            for ext in allowed:
                if self.container.install_extension(ext):
                    installed.append(ext)
                else:
                    failed.append(ext)
        finally:
            # Always cleanup container to maintain temporary container approach
            self.container.cleanup()

        return {
            'success': len(installed) > 0,
            'message': f'Installed {len(installed)}/{len(allowed)} extensions',
            'allowed': allowed,
            'blocked': blocked,
            'installed': installed,
            'failed': failed
        }

    def cleanup(self) -> None:
        """Clean up resources"""
        self.container.cleanup()
