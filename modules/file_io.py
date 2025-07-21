"""
File I/O Module
Handles file reading operations for both plain text and YAML files.
"""

import os
import yaml
from typing import List, Dict, Any


class PlainTextFileReader:
    """Reads plain text files line by line"""

    def read_lines(self, filepath: str) -> List[str]:
        """Read non-empty, non-comment lines from file"""
        if not os.path.exists(filepath):
            raise FileNotFoundError(f"File not found: {filepath}")

        lines = []
        with open(filepath, 'r') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    lines.append(line)
        return lines


class YAMLFileReader:
    """Reads and parses YAML configuration files"""

    def read_yaml(self, filepath: str) -> Dict[str, Any]:
        """Read and parse YAML file"""
        if not os.path.exists(filepath):
            raise FileNotFoundError(f"YAML file not found: {filepath}")

        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                data = yaml.safe_load(f)
                return data if data is not None else {}
        except yaml.YAMLError as e:
            raise ValueError(f"Invalid YAML format in {filepath}: {e}")
        except Exception as e:
            raise IOError(f"Error reading YAML file {filepath}: {e}")

    def write_yaml(self, filepath: str, data: Dict[str, Any]) -> None:
        """Write data to YAML file"""
        try:
            os.makedirs(os.path.dirname(filepath), exist_ok=True)
            with open(filepath, 'w', encoding='utf-8') as f:
                yaml.safe_dump(data, f, default_flow_style=False, sort_keys=False, indent=2)
        except Exception as e:
            raise IOError(f"Error writing YAML file {filepath}: {e}")

    def extract_extensions_with_metadata(self, whitelist_data: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
        """Extract extensions with their metadata from whitelist YAML structure"""
        extensions = {}

        authors = whitelist_data.get('authors', {})
        for author, author_extensions in authors.items():
            if isinstance(author_extensions, list):
                for ext_data in author_extensions:
                    if isinstance(ext_data, dict) and 'id' in ext_data:
                        ext_id = ext_data['id']
                        extensions[ext_id] = {
                            'author': author,
                            'install': ext_data.get('install', False),
                            'url': ext_data.get('url', ''),
                            'metadata': ext_data
                        }

        return extensions

    def get_installable_extensions(self, whitelist_data: Dict[str, Any]) -> List[str]:
        """Get list of extensions marked for installation"""
        extensions_metadata = self.extract_extensions_with_metadata(whitelist_data)
        return [ext_id for ext_id, data in extensions_metadata.items() if data.get('install', False)]

    def get_all_whitelisted_extensions(self, whitelist_data: Dict[str, Any]) -> List[str]:
        """Get list of all whitelisted extensions regardless of install flag"""
        extensions_metadata = self.extract_extensions_with_metadata(whitelist_data)
        return list(extensions_metadata.keys())
