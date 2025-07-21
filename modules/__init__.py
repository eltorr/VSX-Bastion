"""
VSX-Bastion Modules Package

A modular VS Code extension manager with clean separation of concerns.
Each module handles a specific responsibility.

Modules:
- file_io: File reading operations
- validation: Extension validation and filtering
- containers: Docker container management
- editors: Editor detection and management
- diagnostics: Extension diagnostics
- filesystem: File system operations
- installation: Extension installation orchestration
- app: Main application logic
- version_detector: VS Code version detection
"""

from .file_io import PlainTextFileReader, YAMLFileReader
from .validation import YAMLWhitelistValidator, BlacklistValidator, ExtensionFilter
from .containers import DockerVSCodeContainer
from .editors import EditorDetector
from .diagnostics import ExtensionDiagnostics
from .filesystem import LocalFileSystemManager
from .installation import ExtensionInstaller
from .app import SecureExtensionInstallerApp

__all__ = [
    'PlainTextFileReader',
    'YAMLFileReader',
    'YAMLWhitelistValidator',
    'BlacklistValidator',
    'ExtensionFilter',
    'DockerVSCodeContainer',
    'EditorDetector',
    'ExtensionDiagnostics',
    'LocalFileSystemManager',
    'ExtensionInstaller',
    'SecureExtensionInstallerApp'
]
