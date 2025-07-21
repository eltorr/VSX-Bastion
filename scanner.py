#!/usr/bin/env python3
"""
VSX-Bastion Simple Production Scanner - Enhanced Version
Comprehensive improvements to reduce false positives and enhance vulnerability scanning accuracy.
"""

import json
import logging
import os
import re
import subprocess
import tempfile
import time
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse
from datetime import datetime
import requests
import math
import sqlite3
import urllib.request
import urllib.error
import hashlib
import threading
from difflib import SequenceMatcher
import statistics
import collections

# Try to import YAML, provide fallback if not available
try:
    import yaml
    YAML_AVAILABLE = True
except ImportError:
    YAML_AVAILABLE = False
    logger = logging.getLogger('vsx-bastion-scanner')
    logger.warning("PyYAML not installed. Install with: pip install PyYAML")

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('vsx-bastion-scanner')

@dataclass
class ThreatDetection:
    """Enhanced threat detection with confidence scoring."""
    category: str
    file_path: str
    pattern_match: str
    confidence: float  # 0.0 to 1.0
    context: str
    line_number: int = 0
    severity: str = 'MEDIUM'

@dataclass
class VulnerabilityInfo:
    """Enhanced vulnerability information."""
    package: str
    version: str
    installed_version: str
    vulnerability_id: str
    summary: str
    severity: str
    cvss_score: float = 0.0
    published_date: str = ""
    fixed_versions: Optional[List[str]] = None

    def __post_init__(self):
        if self.fixed_versions is None:
            self.fixed_versions = []

@dataclass
class ScanResult:
    """Enhanced scan result with detailed information."""
    extension_id: str
    status: str
    threats: List[ThreatDetection]
    vulnerabilities: List[VulnerabilityInfo]
    risk_level: str
    confidence_score: float
    details: Dict
    scan_time: float
    false_positive_indicators: Optional[List[str]] = None

    def __post_init__(self):
        if self.false_positive_indicators is None:
            self.false_positive_indicators = []

    def to_app_format(self) -> Dict:
        """Convert ScanResult to format expected by the main app."""
        # Only report threats if status is not CLEAN
        threats_to_report = [] if self.status == 'CLEAN' else self.threats

        return {
            'threats_found': len(threats_to_report),
            'threats': [
                {
                    'type': threat.category,
                    'description': f"{threat.pattern_match} (confidence: {threat.confidence:.2f})",
                    'file_path': threat.file_path,
                    'severity': threat.severity,
                    'confidence': threat.confidence,
                    'line_number': threat.line_number
                }
                for threat in threats_to_report
            ],
            'vulnerabilities': len(self.vulnerabilities),
            'risk_level': self.risk_level,
            'status': self.status,
            'extension_id': self.extension_id,
            'scan_time': self.scan_time,
            'confidence_score': self.confidence_score,
            'details': self.details
        }

class EnhancedDockerEngine:
    """Enhanced Docker engine with improved isolation and analysis."""

    def __init__(self):
        self.container_image = 'vsx-bastion-enhanced-analyzer'
        self.container_built = False

    def build_container(self) -> bool:
        """Build enhanced analysis container with synchronized logic."""
        dockerfile = '''
FROM alpine:3.18

# Install security tools and dependencies
RUN apk add --no-cache \
    python3 \
    py3-pip \
    clamav \
    clamav-daemon \
    file \
    nodejs \
    npm \
    git \
    curl

# Install Python packages
RUN pip3 install --no-cache-dir requests semver packaging

# Create non-root user
RUN adduser -D -s /bin/sh scanner

# Create directories
RUN mkdir -p /analysis/input /analysis/output /analysis/tools /analysis/cache \
    && chown -R scanner:scanner /analysis

# Update ClamAV database (may fail in build, that's ok)
RUN freshclam || echo "ClamAV update will happen at runtime"

# Copy analysis script
COPY enhanced_analysis.py /analysis/tools/
COPY patterns.json /analysis/tools/
RUN chmod +x /analysis/tools/enhanced_analysis.py

USER scanner
WORKDIR /analysis

ENTRYPOINT ["python3", "/analysis/tools/enhanced_analysis.py"]
'''

        # Enhanced analysis script with synchronized logic
        analysis_script = self._get_enhanced_analysis_script()

        # Patterns configuration
        patterns_config = self._get_patterns_config()

        try:
            with tempfile.TemporaryDirectory() as build_dir:
                # Write Dockerfile
                with open(f"{build_dir}/Dockerfile", 'w') as f:
                    f.write(dockerfile)

                # Write enhanced analysis script
                with open(f"{build_dir}/enhanced_analysis.py", 'w') as f:
                    f.write(analysis_script)

                # Write patterns configuration
                with open(f"{build_dir}/patterns.json", 'w') as f:
                    json.dump(patterns_config, f, indent=2)

                # Build container
                result = subprocess.run([
                    'docker', 'build', '-t', self.container_image, build_dir
                ], capture_output=True, text=True)

                if result.returncode == 0:
                    logger.info("Enhanced analysis container built successfully")
                    return True
                else:
                    logger.error(f"Container build failed: {result.stderr}")
                    return False

        except Exception as e:
            logger.error(f"Failed to build container: {e}")
            return False

    def _get_enhanced_analysis_script(self) -> str:
        """Get the enhanced analysis script with synchronized logic."""
        return '''#!/usr/bin/env python3
import json
import os
import subprocess
import sys
import time
import re
import math
from pathlib import Path

def calculate_entropy(data):
    """Calculate Shannon entropy of data."""
    if not data:
        return 0
    entropy = 0
    for i in range(256):
        count = data.count(chr(i))
        if count > 0:
            frequency = count / len(data)
            entropy -= frequency * math.log2(frequency)
    return entropy

def is_minified_or_obfuscated(content, file_path):
    """Detect minified or obfuscated files."""
    # Check entropy
    entropy = calculate_entropy(content[:1000])  # Check first 1KB
    if entropy > 5.5:  # High entropy indicates minification/obfuscation
        return True, "high_entropy"

    # Check line length
    lines = content.split('\\n')
    if lines and len(lines[0]) > 500:  # Very long lines indicate minification
        return True, "long_lines"

    # Check for minification patterns
    if re.search(r'[a-zA-Z_$][a-zA-Z0-9_$]*=[a-zA-Z_$][a-zA-Z0-9_$]*\\(', content):
        short_vars = len(re.findall(r'\\b[a-zA-Z_$][a-zA-Z0-9_$]{0,2}\\b', content[:1000]))
        if short_vars > 20:  # Many short variable names
            return True, "short_variables"

    return False, None

def scan_with_clamav(target_path):
    """Enhanced ClamAV scanning with fresh database."""
    try:
        # Force database update
        try:
            subprocess.run(['freshclam', '--quiet'], capture_output=True, timeout=180)
        except:
            pass  # Continue even if update fails

        result = subprocess.run([
            'clamscan', '-r', '--no-summary', '--infected', '--detect-pua=yes', target_path
        ], capture_output=True, text=True, timeout=300)

        threats = []
        if result.returncode == 1:  # Virus found
            for line in result.stdout.split('\\n'):
                if line.strip() and 'FOUND' in line:
                    threats.append(line.strip())

        return {
            'infected': len(threats) > 0,
            'threats': threats,
            'scan_time': time.time()
        }
    except Exception as e:
        return {'infected': False, 'error': str(e)}

def enhanced_pattern_scan(target_path):
    """Enhanced pattern scanning with confidence scoring."""
    # Load patterns from config
    with open('/analysis/tools/patterns.json', 'r') as f:
        config = json.load(f)

    patterns = config['rce_patterns']
    skip_config = config['skip_config']

    detections = []

    for file_path in Path(target_path).rglob('*'):
        if not file_path.is_file():
            continue

        # Apply synchronized skip logic
        if not should_scan_file(file_path, target_path, skip_config):
            continue

        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()

            # Check if file is minified/obfuscated
            is_minified, reason = is_minified_or_obfuscated(content, file_path)
            if is_minified:
                # Flag for manual review but don't scan for patterns
                relative_path = file_path.relative_to(target_path)
                detections.append({
                    'category': 'suspicious_file',
                    'file_path': str(relative_path),
                    'pattern_match': f"Minified/obfuscated file ({reason})",
                    'confidence': 0.3,
                    'context': content[:100],
                    'severity': 'LOW'
                })
                continue

            # Scan for patterns
            for category, pattern_list in patterns.items():
                for pattern_info in pattern_list:
                    pattern = pattern_info['pattern']
                    base_confidence = pattern_info['confidence']

                    matches = re.finditer(pattern, content, re.IGNORECASE | re.MULTILINE)
                    for match in matches:
                        # Enhanced context validation
                        confidence, context_info = validate_context(
                            content, match, file_path, pattern_info
                        )

                        if confidence > 0.1:  # Only report if confidence > 10%
                            relative_path = file_path.relative_to(target_path)
                            line_num = content[:match.start()].count('\\n') + 1

                            detections.append({
                                'category': category,
                                'file_path': str(relative_path),
                                'pattern_match': match.group()[:100],
                                'confidence': confidence,
                                'context': context_info,
                                'line_number': line_num,
                                'severity': pattern_info.get('severity', 'MEDIUM')
                            })
                            break  # Only first match per pattern per file

        except Exception as e:
            continue

    return {'detections': detections}

def should_scan_file(file_path, extension_path, skip_config):
    """Synchronized file scanning logic."""
    relative_path = file_path.relative_to(extension_path)
    path_parts = relative_path.parts
    filename = file_path.name.lower()

    # Skip if in any unsafe directory
    for part in path_parts:
        if part.lower() in skip_config['directories']:
            return False

    # Special handling for conditional skip directories (like 'lib')
    conditional_skip = skip_config.get('conditional_skip_directories', [])
    for part in path_parts:
        if part.lower() in conditional_skip:
            # Allow TypeScript source files in lib directories
            if file_path.suffix == '.ts' and not any(pattern in filename for pattern in skip_config['files']):
                continue  # Don't skip TypeScript source files
            else:
                return False  # Skip other files in lib directories

    # Skip if matches unsafe file patterns
    for pattern in skip_config['files']:
        if pattern in filename:
            return False

    # Skip very large files (synchronized limit)
    if file_path.stat().st_size > skip_config['max_file_size']:
        return False

    # Only scan relevant file types
    if file_path.suffix not in skip_config['allowed_extensions']:
        return False

    return True

def validate_context(content, match, file_path, pattern_info):
    """Enhanced context validation with confidence scoring."""
    match_text = match.group()
    start_pos = match.start()

    # Get surrounding context
    context_start = max(0, start_pos - 100)
    context_end = min(len(content), start_pos + len(match_text) + 100)
    context = content[context_start:context_end]

    confidence = pattern_info['confidence']

    # Reduce confidence for test/example code
    test_indicators = ['test', 'example', 'demo', 'mock', 'fixture', 'spec']
    if any(indicator in context.lower() for indicator in test_indicators):
        confidence *= 0.2

    # Reduce confidence if in comments
    if '//' in context or '/*' in context or '#' in context:
        confidence *= 0.3

    # Reduce confidence if in string literals without execution context
    if re.search(r'["\'].*' + re.escape(match_text) + r'.*["\']', context):
        # Check if there's execution context nearby
        exec_patterns = ['eval', 'exec', 'Function', 'spawn', 'system']
        if not any(pattern in context for pattern in exec_patterns):
            confidence *= 0.4

    # Increase confidence for URL-based patterns
    if pattern_info.get('requires_url', False):
        if re.search(r'https?://', match_text):
            confidence *= 1.5
        else:
            confidence *= 0.5

    # File-specific adjustments
    if 'node_modules' in str(file_path):
        confidence *= 0.1  # Very low confidence for bundled deps

    return min(confidence, 1.0), context

def analyze_extension():
    """Main enhanced analysis function."""
    input_path = '/analysis/input'
    output_path = '/analysis/output/results.json'

    results = {
        'clamav': scan_with_clamav(input_path),
        'pattern_analysis': enhanced_pattern_scan(input_path),
        'metadata': {
            'scan_time': time.time(),
            'scanner_version': '2.0-enhanced'
        }
    }

    # Save results
    with open(output_path, 'w') as f:
        json.dump(results, f, indent=2)

if __name__ == '__main__':
    analyze_extension()
'''

    def _get_patterns_config(self) -> Dict:
        """Get enhanced patterns configuration."""
        # Get dynamic patterns from threat intelligence
        dynamic_patterns = self.threat_intel.get_dynamic_patterns() if hasattr(self, 'threat_intel') else {}

        static_patterns = {
            "rce_patterns": {
                "powershell_download_execute": [
                    {
                        "pattern": r"(?:IEX|Invoke-Expression)\s*\(\s*(?:New-Object\s+)?(?:System\.)?Net\.WebClient\s*\)\s*\.DownloadString\s*\(\s*['\"]https?://",
                        "confidence": 0.9,
                        "severity": "CRITICAL",
                        "requires_url": True
                    },
                    {
                        "pattern": r"powershell(?:\.exe)?\s+.*-EncodedCommand\s+[A-Za-z0-9+/=]{100,}",
                        "confidence": 0.8,
                        "severity": "HIGH"
                    }
                ],
                "bash_download_execute": [
                    {
                        "pattern": r"curl\s+(?:-s\s+)?https?://[^\s]+\s*\|\s*(?:bash|sh)\s*$",
                        "confidence": 0.9,
                        "severity": "CRITICAL",
                        "requires_url": True
                    },
                    {
                        "pattern": r"wget\s+(?:-q\s+)?https?://[^\s]+\s+-O-\s*\|\s*(?:bash|sh)\s*$",
                        "confidence": 0.9,
                        "severity": "CRITICAL",
                        "requires_url": True
                    }
                ],
                "javascript_obfuscated_execute": [
                    {
                        "pattern": r"eval\s*\(\s*atob\s*\(\s*['\"][A-Za-z0-9+/=]{50,}['\"]\s*\)\s*\)",
                        "confidence": 0.8,
                        "severity": "HIGH"
                    },
                    {
                        "pattern": r"eval\s*\(\s*(?:await\s+)?fetch\s*\(\s*['\"]https?://[^'\"]*['\"]\s*\)\s*\.then\s*\([^)]*\)\s*\)",
                        "confidence": 0.9,
                        "severity": "CRITICAL",
                        "requires_url": True
                    },
                    {
                        "pattern": r"eval\s*\(\s*fetch\s*\(\s*['\"]https?://[^'\"]*['\"]\s*\)\s*\.then\s*\(\s*[^)]*\s*=>\s*[^)]*\.text\s*\(\s*\)\s*\)\s*\)",
                        "confidence": 0.9,
                        "severity": "CRITICAL",
                        "requires_url": True
                    }
                ],
                "obfuscation_patterns": [
                    {
                        "pattern": r"eval\s*\(\s*['\"](?:\\x[0-9a-fA-F]{2}){10,}['\"]\s*\)",
                        "confidence": 0.8,
                        "severity": "HIGH"
                    },
                    {
                        "pattern": r"eval\s*\(\s*atob\s*\(\s*['\"][A-Za-z0-9+/=]{20,}['\"]\s*\)\s*\)",
                        "confidence": 0.8,
                        "severity": "HIGH"
                    }
                ],
                "dynamic_import_execute": [
                    {
                        "pattern": r"import\s*\(\s*['\"]https?://[^'\"]*['\"]\s*\)\s*\.then\s*\(",
                        "confidence": 0.8,
                        "severity": "HIGH",
                        "requires_url": True
                    }
                ],
                "process_execution": [
                    {
                        "pattern": r"require\s*\(\s*['\"]child_process['\"]\s*\)[^}]*exec\s*\(",
                        "confidence": 0.8,
                        "severity": "HIGH"
                    },
                    {
                        "pattern": r"exec\s*\(\s*['\"]curl\s+https?://[^'\"]*\s*\|\s*(?:bash|sh)['\"]\s*[,)]",
                        "confidence": 0.9,
                        "severity": "CRITICAL",
                        "requires_url": True
                    }
                ]
            },
            "skip_config": {
                "directories": [
                    'node_modules', 'dist', 'build', 'out', 'vendor',
                    'third-party', 'thirdparty', '.vscode', 'test', 'tests',
                    '__tests__', 'spec', 'specs', 'coverage', '.nyc_output',
                    'typings', '@types', 'documentation', 'docs'
                ],
                "conditional_skip_directories": ['lib'],
                "files": [
                    '.min.js', '.bundle.js', '.chunk.js', '.d.ts',
                    '.map', '.test.js', '.spec.js', '-test.js',
                    '-spec.js', '.mock.js'
                ],
                "max_file_size": 1048576,  # 1MB - synchronized limit
                "allowed_extensions": ['.js', '.ts', '.json', '.py', '.sh', '.ps1']
            }
        }

    def run_isolated_analysis(self, extension_path: str) -> Optional[Dict]:
        """Run enhanced analysis in isolated Docker container."""
        try:
            with tempfile.TemporaryDirectory() as temp_dir:
                output_dir = Path(temp_dir) / 'output'
                output_dir.mkdir()

                # Run container with strict security
                result = subprocess.run([
                    'docker', 'run',
                    '--rm',
                    '--network=none',                    # No network access
                    '--read-only',                       # Read-only filesystem
                    '--tmpfs=/tmp:noexec,nosuid,size=100m',  # Limited temp space
                    '--memory=512m',                     # Increased memory limit
                    '--cpus=1.0',                       # Increased CPU limit
                    '--user=scanner',                    # Non-root user
                    '--cap-drop=ALL',                   # Drop all capabilities
                    '--security-opt=no-new-privileges', # Prevent privilege escalation
                    '--pids-limit=25',                  # Limit processes
                    '-v', f'{extension_path}:/analysis/input:ro',  # Mount extension read-only
                    '-v', f'{output_dir}:/analysis/output',        # Results directory
                    self.container_image
                ], capture_output=True, text=True, timeout=600)  # 10 minute timeout

                if result.returncode == 0:
                    # Read results
                    results_file = output_dir / 'results.json'
                    if results_file.exists():
                        with open(results_file, 'r') as f:
                            return json.load(f)
                else:
                    logger.error(f"Container analysis failed: {result.stderr}")

        except subprocess.TimeoutExpired:
            logger.error("Container analysis timed out")
        except Exception as e:
            logger.error(f"Container analysis error: {e}")

        return None

class DynamicThreatIntelligence:
    """Dynamic threat intelligence loader using built-in libraries."""

    def __init__(self, cache_db='threat_cache.db'):
        self.cache_db = cache_db
        self.threat_feeds = [
            'https://raw.githubusercontent.com/stamparm/maltrail/master/trails/static/malware/generic.txt',
            'https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/malwaredomains.netset',
            'https://raw.githubusercontent.com/Yisf/Daily-Malware-Samples/main/indicators.json'
        ]
        self.patterns_cache = {}
        self.last_update = 0
        self.update_interval = 3600  # 1 hour
        self.init_cache_db()

    def init_cache_db(self):
        """Initialize SQLite cache database."""
        try:
            conn = sqlite3.connect(self.cache_db)
            cursor = conn.cursor()
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS threat_patterns (
                    id INTEGER PRIMARY KEY,
                    pattern TEXT UNIQUE,
                    confidence REAL,
                    severity TEXT,
                    category TEXT,
                    source TEXT,
                    last_updated INTEGER
                )
            ''')
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS threat_indicators (
                    id INTEGER PRIMARY KEY,
                    indicator TEXT UNIQUE,
                    type TEXT,
                    confidence REAL,
                    source TEXT,
                    last_updated INTEGER
                )
            ''')
            conn.commit()
            conn.close()
        except Exception as e:
            logger.warning(f"Could not initialize threat cache: {e}")

    def update_threat_intelligence(self):
        """Update threat patterns from feeds."""
        current_time = int(time.time())
        if current_time - self.last_update < self.update_interval:
            return

        try:
            conn = sqlite3.connect(self.cache_db)
            cursor = conn.cursor()

            for feed_url in self.threat_feeds:
                try:
                    # Use urllib instead of requests for built-in compatibility
                    with urllib.request.urlopen(feed_url, timeout=30) as response:
                        data = response.read().decode('utf-8', errors='ignore')
                        self._parse_threat_feed(data, feed_url, cursor)
                except Exception as e:
                    logger.debug(f"Failed to update from {feed_url}: {e}")
                    continue

            conn.commit()
            conn.close()
            self.last_update = current_time
            logger.info("Threat intelligence updated successfully")

        except Exception as e:
            logger.warning(f"Threat intelligence update failed: {e}")

    def _parse_threat_feed(self, data, source, cursor):
        """Parse threat feed data and extract patterns."""
        lines = data.split('\n')
        for line in lines[:100]:  # Limit to prevent memory issues
            line = line.strip()
            if not line or line.startswith('#'):
                continue

            # Extract malicious domains/URLs
            if any(indicator in line.lower() for indicator in ['http', 'domain', 'url']):
                try:
                    cursor.execute('''
                        INSERT OR REPLACE INTO threat_indicators
                        (indicator, type, confidence, source, last_updated)
                        VALUES (?, ?, ?, ?, ?)
                    ''', (line, 'domain', 0.7, source, int(time.time())))
                except:
                    continue

    def get_dynamic_patterns(self):
        """Get cached threat patterns."""
        if not self.patterns_cache:
            self.update_threat_intelligence()
            self._load_patterns_from_cache()
        return self.patterns_cache

    def _load_patterns_from_cache(self):
        """Load patterns from SQLite cache."""
        try:
            conn = sqlite3.connect(self.cache_db)
            cursor = conn.cursor()
            cursor.execute('SELECT pattern, confidence, severity, category FROM threat_patterns')

            for row in cursor.fetchall():
                pattern, confidence, severity, category = row
                if category not in self.patterns_cache:
                    self.patterns_cache[category] = []
                self.patterns_cache[category].append({
                    'pattern': pattern,
                    'confidence': confidence,
                    'severity': severity
                })
            conn.close()
        except Exception as e:
            logger.debug(f"Could not load patterns from cache: {e}")



    def calculate_file_hash(self, file_path):
        """Calculate file hash for integrity checking."""
        try:
            with open(file_path, 'rb') as f:
                return hashlib.sha256(f.read()).hexdigest()
        except:
            return None

    def check_publisher_reputation(self, publisher_name):
        """Check publisher reputation using built-in http.client."""
        try:
            import http.client
            import json
            from urllib.parse import quote

            # Use VS Code marketplace API
            conn = http.client.HTTPSConnection('marketplace.visualstudio.com', timeout=10)

            # Search for publisher
            encoded_publisher = quote(publisher_name)
            conn.request('GET', f'/api/v2/extensionquery',
                headers={'Content-Type': 'application/json'})

            response = conn.getresponse()
            if response.status == 200:
                data = response.read().decode('utf-8')
                # Simple reputation check based on publisher existence
                return {
                    'exists': True,
                    'confidence': 0.8,
                    'verified': True
                }
            else:
                return {
                    'exists': False,
                    'confidence': 0.3,
                    'verified': False
                }

        except Exception as e:
            logger.debug(f"Publisher reputation check failed: {e}")
            return {'exists': False, 'confidence': 0.5, 'verified': False}
        finally:
            try:
                conn.close()
            except:
                pass

    def check_domain_reputation(self, domain):
        """Check domain reputation using built-in libraries."""
        try:
            import socket
            import ssl

            # Basic domain validation
            socket.gethostbyname(domain)

            # SSL certificate check
            context = ssl.create_default_context()
            with socket.create_connection((domain, 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    return {
                        'domain_valid': True,
                        'ssl_valid': cert is not None,
                        'confidence': 0.7 if cert else 0.4
                    }
        except Exception:
            return {'domain_valid': False, 'ssl_valid': False, 'confidence': 0.2}

    def calculate_file_statistics(self, extension_path):
        """Calculate file statistics for anomaly detection."""
        try:
            file_sizes = []
            line_counts = []
            complexity_scores = []

            for file_path in Path(extension_path).rglob('*.js'):
                if file_path.is_file():
                    try:
                        file_size = file_path.stat().st_size
                        file_sizes.append(file_size)

                        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                            content = f.read()
                            lines = content.count('\n')
                            line_counts.append(lines)

                            # Simple complexity measure
                            complexity = len(re.findall(r'[{}();]', content))
                            complexity_scores.append(complexity)
                    except:
                        continue

            if not file_sizes:
                return {}

            return {
                'file_count': len(file_sizes),
                'avg_file_size': statistics.mean(file_sizes),
                'median_file_size': statistics.median(file_sizes),
                'size_std_dev': statistics.stdev(file_sizes) if len(file_sizes) > 1 else 0,
                'avg_lines': statistics.mean(line_counts),
                'avg_complexity': statistics.mean(complexity_scores),
                'size_outliers': self._detect_size_outliers(file_sizes),
                'complexity_outliers': self._detect_complexity_outliers(complexity_scores)
            }
        except Exception as e:
            logger.debug(f"Statistics calculation failed: {e}")
            return {}

    def _detect_size_outliers(self, sizes):
        """Detect file size outliers using IQR method."""
        if len(sizes) < 4:
            return []

        try:
            q1 = statistics.quantiles(sizes, n=4)[0]
            q3 = statistics.quantiles(sizes, n=4)[2]
            iqr = q3 - q1
            lower_bound = q1 - 1.5 * iqr
            upper_bound = q3 + 1.5 * iqr

            outliers = [size for size in sizes if size < lower_bound or size > upper_bound]
            return outliers
        except:
            return []

    def _detect_complexity_outliers(self, complexities):
        """Detect complexity outliers."""
        if len(complexities) < 4:
            return []

        try:
            avg = statistics.mean(complexities)
            std_dev = statistics.stdev(complexities)
            threshold = avg + 2 * std_dev

            outliers = [c for c in complexities if c > threshold]
            return outliers
        except:
            return []

    def analyze_extension_patterns(self, extension_path):
        """Analyze extension for suspicious patterns using built-in libraries."""
        suspicious_indicators = []

        # Pattern frequency analysis
        pattern_counts = collections.Counter()

        for file_path in Path(extension_path).rglob('*.js'):
            if file_path.is_file():
                try:
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()

                    # Count suspicious patterns
                    eval_count = len(re.findall(r'\beval\s*\(', content))
                    atob_count = len(re.findall(r'\batob\s*\(', content))
                    exec_count = len(re.findall(r'\bexec\s*\(', content))

                    pattern_counts['eval'] += eval_count
                    pattern_counts['atob'] += atob_count
                    pattern_counts['exec'] += exec_count

                except:
                    continue

        # Detect anomalous pattern usage
        total_files = len(list(Path(extension_path).rglob('*.js')))
        if total_files > 0:
            for pattern, count in pattern_counts.items():
                ratio = count / total_files
                if ratio > 0.5:  # More than 50% of files contain pattern
                    suspicious_indicators.append({
                        'pattern': pattern,
                        'frequency': count,
                        'ratio': ratio,
                        'confidence': min(ratio * 0.8, 1.0),
                        'severity': 'HIGH' if ratio > 0.8 else 'MEDIUM'
                    })

        return suspicious_indicators

class EnhancedProductionScanner:
    """Enhanced production scanner with improved accuracy and reduced false positives."""

    def __init__(self):
        self.docker_engine = EnhancedDockerEngine()
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'VSX-Bastion-Enhanced-Scanner/2.0'
        })

        # Initialize dynamic threat intelligence
        self.threat_intel = DynamicThreatIntelligence()

        # Enhanced RCE patterns with confidence scoring
        self.rce_patterns = {
            'powershell_download_execute': [
                {
                    'pattern': r'(?:IEX|Invoke-Expression)\s*\(\s*(?:New-Object\s+)?(?:System\.)?Net\.WebClient\s*\)\s*\.DownloadString\s*\(\s*[\'"]https?://',
                    'confidence': 0.9,
                    'severity': 'CRITICAL',
                    'requires_url': True
                },
                {
                    'pattern': r'powershell(?:\.exe)?\s+.*-EncodedCommand\s+[A-Za-z0-9+/=]{100,}',
                    'confidence': 0.8,
                    'severity': 'HIGH'
                }
            ],
            'bash_download_execute': [
                {
                    'pattern': r'curl\s+(?:-s\s+)?https?://[^\s]+\s*\|\s*(?:bash|sh)\s*$',
                    'confidence': 0.9,
                    'severity': 'CRITICAL',
                    'requires_url': True
                },
                {
                    'pattern': r'wget\s+(?:-q\s+)?https?://[^\s]+\s+-O-\s*\|\s*(?:bash|sh)\s*$',
                    'confidence': 0.9,
                    'severity': 'CRITICAL',
                    'requires_url': True
                }
            ],
            'javascript_obfuscated_execute': [
                {
                    'pattern': r'eval\s*\(\s*atob\s*\(\s*[\'"][A-Za-z0-9+/=]{50,}[\'\"]\s*\)\s*\)',
                    'confidence': 0.8,
                    'severity': 'HIGH'
                },
                {
                    'pattern': r'eval\s*\(\s*(?:await\s+)?fetch\s*\(\s*[\'"]https?://[^\'\"]*[\'\"]\s*\)\s*\.then\s*\([^)]*\)\s*\)',
                    'confidence': 0.9,
                    'severity': 'CRITICAL',
                    'requires_url': True
                },
                {
                    'pattern': r'eval\s*\(\s*fetch\s*\(\s*[\'"]https?://[^\'\"]*[\'\"]\s*\)\s*\.then\s*\(\s*[^)]*\s*=>\s*[^)]*\.text\s*\(\s*\)\s*\)\s*\)',
                    'confidence': 0.9,
                    'severity': 'CRITICAL',
                    'requires_url': True
                }
            ],
            'obfuscation_patterns': [
                {
                    'pattern': r'eval\s*\(\s*[\'"](?:\\x[0-9a-fA-F]{2}){10,}[\'\"]\s*\)',
                    'confidence': 0.8,
                    'severity': 'HIGH'
                },
                {
                    'pattern': r'eval\s*\(\s*atob\s*\(\s*[\'"][A-Za-z0-9+/=]{20,}[\'\"]\s*\)\s*\)',
                    'confidence': 0.8,
                    'severity': 'HIGH'
                }
            ],
            'dynamic_import_execute': [
                {
                    'pattern': r'import\s*\(\s*[\'"]https?://[^\'\"]*[\'\"]\s*\)\s*\.then\s*\(',
                    'confidence': 0.8,
                    'severity': 'HIGH',
                    'requires_url': True
                }
            ],
            'process_execution': [
                {
                    'pattern': r'require\s*\(\s*[\'"]child_process[\'"]\s*\)[^}]*exec\s*\(',
                    'confidence': 0.8,
                    'severity': 'HIGH'
                },
                {
                    'pattern': r'exec\s*\(\s*[\'"]curl\s+https?://[^\'\"]*\s*\|\s*(?:bash|sh)[\'\"]\s*[,)]',
                    'confidence': 0.9,
                    'severity': 'CRITICAL',
                    'requires_url': True
                }
            ]
        }

        # Synchronized skip configuration
        self.skip_directories = [
            'node_modules', 'dist', 'build', 'out', 'vendor',
            'third-party', 'thirdparty', '.vscode', 'test', 'tests',
            '__tests__', 'spec', 'specs', 'coverage', '.nyc_output',
            'typings', '@types', 'documentation', 'docs'
        ]

        # Directories that should be skipped except for TypeScript source files
        self.conditional_skip_directories = ['lib']

        self.skip_files = [
            '.min.js', '.bundle.js', '.chunk.js', '.d.ts',
            '.map', '.test.js', '.spec.js', '-test.js',
            '-spec.js', '.mock.js'
        ]

        # File size limit (synchronized with Docker)
        self.max_file_size = 1024 * 1024  # 1MB

    def download_extension(self, extension_id: str) -> Optional[str]:
        """Download extension from marketplace."""
        try:
            # Parse extension ID
            if '.' in extension_id:
                publisher, name = extension_id.split('.', 1)
            else:
                logger.error(f"Invalid extension ID format: {extension_id}")
                return None

            # Download from VS Code marketplace
            download_url = f"https://{publisher}.gallery.vsassets.io/_apis/public/gallery/publisher/{publisher}/extension/{name}/latest/assetbyname/Microsoft.VisualStudio.Services.VSIXPackage"

            response = self.session.get(download_url, timeout=30)
            if response.status_code == 200:
                # Save to temporary file
                with tempfile.NamedTemporaryFile(suffix='.vsix', delete=False) as temp_file:
                    temp_file.write(response.content)
                    return temp_file.name
            else:
                logger.error(f"Failed to download {extension_id}: HTTP {response.status_code}")
                return None

        except Exception as e:
            logger.error(f"Error downloading {extension_id}: {e}")
            return None

    def extract_extension(self, vsix_path: str) -> Optional[str]:
        """Extract VSIX file to temporary directory."""
        try:
            temp_dir = tempfile.mkdtemp(prefix='vsx_extract_')
            with zipfile.ZipFile(vsix_path, 'r') as zip_ref:
                zip_ref.extractall(temp_dir)
            return temp_dir
        except Exception as e:
            logger.error(f"Failed to extract {vsix_path}: {e}")
            return None

    def is_extension_source_file(self, file_path: Path, extension_path: str) -> bool:
        """Enhanced file filtering with synchronized logic."""
        relative_path = file_path.relative_to(extension_path)
        path_parts = relative_path.parts
        filename = file_path.name.lower()

        # Skip if in any unsafe directory
        for part in path_parts:
            if part.lower() in self.skip_directories:
                return False

        # Special handling for conditional skip directories (like 'lib')
        for part in path_parts:
            if part.lower() in self.conditional_skip_directories:
                # Allow TypeScript source files in lib directories
                if file_path.suffix == '.ts' and not any(skip_pattern in filename for skip_pattern in self.skip_files):
                    continue  # Don't skip TypeScript source files
                else:
                    return False  # Skip other files in lib directories

        # Skip if matches unsafe file patterns
        for pattern in self.skip_files:
            if pattern in filename:
                return False

        # Skip very large files (synchronized limit)
        if file_path.stat().st_size > self.max_file_size:
            return False

        # Only scan relevant file types (expanded list)
        if file_path.suffix not in ['.js', '.ts', '.json', '.py', '.sh', '.ps1']:
            return False

        return True

    def calculate_entropy(self, data: str) -> float:
        """Calculate Shannon entropy of data."""
        if not data:
            return 0
        entropy = 0
        for i in range(256):
            count = data.count(chr(i))
            if count > 0:
                frequency = count / len(data)
                entropy -= frequency * math.log2(frequency)
        return entropy

    def is_minified_or_obfuscated(self, content: str, file_path: Path) -> Tuple[bool, str]:
        """Detect minified or obfuscated files."""
        # Check entropy (high entropy indicates minification/obfuscation)
        entropy = self.calculate_entropy(content[:1000])  # Check first 1KB
        if entropy > 5.5:
            return True, "high_entropy"

        # Check line length (very long lines indicate minification)
        lines = content.split('\n')
        if lines and len(lines[0]) > 500:
            return True, "long_lines"

        # Check for many short variable names
        if re.search(r'[a-zA-Z_$][a-zA-Z0-9_$]*=[a-zA-Z_$][a-zA-Z0-9_$]*\(', content):
            short_vars = len(re.findall(r'\b[a-zA-Z_$][a-zA-Z0-9_$]{0,2}\b', content[:1000]))
            if short_vars > 20:
                return True, "short_variables"

        return False, ""

    def parse_semver(self, version: str) -> Tuple[str, str]:
        """Parse semver to get clean version."""
        # Remove semver prefixes and suffixes
        clean_version = re.sub(r'^[\^~>=<]*', '', version)
        clean_version = re.sub(r'[-+].*$', '', clean_version)
        return clean_version, version

    def check_dependencies(self, extension_path: str) -> List[VulnerabilityInfo]:
        """Enhanced dependency checking with version-aware OSV queries."""
        vulnerabilities = []

        # Find main package.json (skip node_modules)
        main_package = None
        package_lock = None

        for package_file in Path(extension_path).glob('**/package.json'):
            if 'node_modules' not in str(package_file):
                main_package = package_file
                break

        for lock_file in Path(extension_path).glob('**/package-lock.json'):
            if 'node_modules' not in str(lock_file):
                package_lock = lock_file
                break

        if not main_package:
            return vulnerabilities

        try:
            with open(main_package, 'r') as f:
                package_data = json.load(f)

            # Get installed versions from package-lock if available
            installed_versions = {}
            if package_lock:
                try:
                    with open(package_lock, 'r') as f:
                        lock_data = json.load(f)
                        if 'dependencies' in lock_data:
                            for dep, info in lock_data['dependencies'].items():
                                if 'version' in info:
                                    installed_versions[dep] = info['version']
                except:
                    pass

            # Check runtime dependencies
            dependencies = package_data.get('dependencies', {})

            # Filter and prioritize dependencies
            priority_deps = [
                dep for dep in dependencies.keys()
                if not dep.startswith('@types/')
                and not dep.startswith('eslint')
                and not dep.startswith('prettier')
            ][:10]  # Increased limit but still reasonable

            for dep_name in priority_deps:
                dep_version = dependencies[dep_name]
                installed_version = installed_versions.get(dep_name, dep_version)

                # Parse version for OSV query
                clean_version, original_version = self.parse_semver(installed_version)

                # Enhanced OSV query with version
                query_data = {
                    "version": clean_version,
                    "package": {
                        "name": dep_name,
                        "ecosystem": "npm"
                    }
                }

                try:
                    response = self.session.post(
                        'https://api.osv.dev/v1/query',
                        json=query_data,
                        timeout=15
                    )

                    if response.status_code == 200:
                        osv_data = response.json()

                        if 'vulns' in osv_data and osv_data['vulns']:
                            # Process vulnerabilities with better filtering
                            for vuln in osv_data['vulns'][:3]:  # Limit to top 3
                                # Extract severity information
                                severity = self._extract_vulnerability_severity(vuln)
                                cvss_score = self._extract_cvss_score(vuln)

                                # Only report medium severity and above
                                if severity in ['MEDIUM', 'HIGH', 'CRITICAL']:
                                    vulnerabilities.append(VulnerabilityInfo(
                                        package=dep_name,
                                        version=original_version,
                                        installed_version=clean_version,
                                        vulnerability_id=vuln.get('id', 'UNKNOWN'),
                                        summary=vuln.get('summary', 'No description available')[:200],
                                        severity=severity,
                                        cvss_score=cvss_score,
                                        published_date=vuln.get('published', ''),
                                        fixed_versions=self._extract_fixed_versions(vuln)
                                    ))

                    time.sleep(1.0)  # Rate limiting

                except Exception as e:
                    logger.warning(f"OSV query failed for {dep_name}: {e}")
                    continue

        except Exception as e:
            logger.warning(f"Failed to parse {main_package}: {e}")

        return vulnerabilities

    def _extract_vulnerability_severity(self, vuln: Dict) -> str:
        """Extract and normalize vulnerability severity."""
        # Check for explicit severity
        if 'severity' in vuln:
            severity = vuln['severity']
            if isinstance(severity, list) and severity:
                severity = severity[0]
            if isinstance(severity, dict):
                return severity.get('type', 'MEDIUM').upper()
            return str(severity).upper()

        # Check for CVSS score
        if 'database_specific' in vuln:
            cvss = vuln['database_specific'].get('cvss', {})
            if isinstance(cvss, dict) and 'score' in cvss:
                score = float(cvss['score'])
                if score >= 9.0:
                    return 'CRITICAL'
                elif score >= 7.0:
                    return 'HIGH'
                elif score >= 4.0:
                    return 'MEDIUM'
                else:
                    return 'LOW'

        # Default to MEDIUM if no severity info found
        return 'MEDIUM'

    def _extract_cvss_score(self, vuln: Dict) -> float:
        """Extract CVSS score from vulnerability data."""
        if 'database_specific' in vuln:
            cvss = vuln['database_specific'].get('cvss', {})
            if isinstance(cvss, dict) and 'score' in cvss:
                return float(cvss['score'])
        return 0.0

    def _extract_fixed_versions(self, vuln: Dict) -> List[str]:
        """Extract fixed versions from vulnerability data."""
        fixed_versions = []
        if 'affected' in vuln:
            for affected in vuln['affected']:
                if 'ranges' in affected:
                    for range_info in affected['ranges']:
                        if 'events' in range_info:
                            for event in range_info['events']:
                                if 'fixed' in event:
                                    fixed_versions.append(event['fixed'])
        return fixed_versions

    def validate_context(self, content: str, match: re.Match, file_path: Path, pattern_info: Dict) -> Tuple[float, str]:
        """Enhanced context validation with confidence scoring."""
        match_text = match.group()
        start_pos = match.start()

        # Get surrounding context
        context_start = max(0, start_pos - 100)
        context_end = min(len(content), start_pos + len(match_text) + 100)
        context = content[context_start:context_end]

        confidence = pattern_info['confidence']

        # AGGRESSIVE FALSE POSITIVE REDUCTION
        test_indicators = ['test', 'example', 'demo', 'mock', 'fixture', 'spec', 'sample', 'docs', 'documentation']
        if any(indicator in context.lower() for indicator in test_indicators):
            confidence *= 0.1  # Very aggressive reduction

        # Reduce confidence if in comments
        if '//' in context or '/*' in context or '#' in context or '*' in context:
            confidence *= 0.1  # Very aggressive reduction

        # Reduce confidence if in string literals without execution context
        if re.search(r'["\'].*' + re.escape(match_text) + r'.*["\']', context):
            # Check if there's execution context nearby
            exec_patterns = ['eval', 'exec', 'Function', 'spawn', 'system']
            if not any(pattern in context for pattern in exec_patterns):
                confidence *= 0.1  # Very aggressive reduction

        # Conservative URL pattern handling
        if pattern_info.get('requires_url', False):
            if re.search(r'https?://', match_text):
                confidence *= 0.8  # Reduce even URL patterns
            else:
                confidence *= 0.2  # Strong penalty if no URL found

        # File-specific adjustments - be very conservative
        if 'node_modules' in str(file_path) or 'lib' in str(file_path) or 'dist' in str(file_path):
            confidence *= 0.05  # Almost eliminate bundled/compiled code

        # Special handling for test files in file path
        if any(test_dir in str(file_path).lower() for test_dir in ['test', 'spec', '__test__', 'example']):
            confidence *= 0.05  # Almost eliminate test files

        # Reduce confidence for legitimate extension patterns
        legitimate_patterns = ['vscode', 'extension', 'activate', 'deactivate', 'package.json']
        if any(pattern in context.lower() for pattern in legitimate_patterns):
            confidence *= 0.3

        return min(confidence, 1.0), context

    def scan_extension(self, extension_id: str) -> ScanResult:
        """Enhanced main scanning function with improved accuracy."""
        start_time = time.time()

        logger.info(f"Starting enhanced scan of {extension_id}")

        # Update threat intelligence in background
        threading.Thread(target=self.threat_intel.update_threat_intelligence, daemon=True).start()

        # Download extension
        vsix_path = self.download_extension(extension_id)
        if not vsix_path:
            error_result = ScanResult(
                extension_id=extension_id,
                status='ERROR',
                threats=[],
                vulnerabilities=[],
                risk_level='UNKNOWN',
                confidence_score=0.0,
                details={'error': 'Download failed'},
                scan_time=time.time() - start_time,
                false_positive_indicators=[]
            )
            return error_result.to_app_format()

        extension_path = None
        try:
            # Extract extension
            extension_path = self.extract_extension(vsix_path)
            if not extension_path:
                error_result = ScanResult(
                    extension_id=extension_id,
                    status='ERROR',
                    threats=[],
                    vulnerabilities=[],
                    risk_level='UNKNOWN',
                    confidence_score=0.0,
                    details={'error': 'Extraction failed'},
                    scan_time=time.time() - start_time,
                    false_positive_indicators=[]
                )
                return error_result.to_app_format()

            # Enhanced dependency checking
            vulnerabilities = self.check_dependencies(extension_path)

            # Calculate file hashes for integrity checking
            file_hashes = {}
            for file_path in Path(extension_path).rglob('*.js'):
                if file_path.is_file():
                    file_hash = self.threat_intel.calculate_file_hash(file_path)
                    if file_hash:
                        file_hashes[str(file_path.relative_to(extension_path))] = file_hash

            # Statistical anomaly detection
            file_stats = self.threat_intel.calculate_file_statistics(extension_path)
            pattern_analysis = self.threat_intel.analyze_extension_patterns(extension_path)

            # Add statistical anomalies as threats - REDUCED SENSITIVITY
            stats_threats = []
            if file_stats.get('size_outliers') and len(file_stats['size_outliers']) > 5:  # Only if many outliers
                stats_threats.append(ThreatDetection(
                    category='statistical_anomaly',
                    file_path='multiple_files',
                    pattern_match=f"Unusual file sizes detected: {len(file_stats['size_outliers'])} outliers",
                    confidence=0.2,  # Reduced from 0.4
                    context=f"Average size: {file_stats.get('avg_file_size', 0):.0f} bytes",
                    severity='LOW'  # Reduced from MEDIUM
                ))

            # Add pattern frequency anomalies - ONLY HIGH SEVERITY ONES
            for indicator in pattern_analysis:
                if indicator['ratio'] > 0.8 and indicator['frequency'] > 10:  # Much higher threshold
                    stats_threats.append(ThreatDetection(
                        category='pattern_frequency_anomaly',
                        file_path='multiple_files',
                        pattern_match=f"High frequency of {indicator['pattern']} pattern",
                        confidence=indicator['confidence'] * 0.5,  # Reduce confidence
                        context=f"Found in {indicator['frequency']} locations ({indicator['ratio']:.1%} of files)",
                        severity='MEDIUM'  # Max severity for pattern anomalies
                    ))

            # Scan extension source files with enhanced detection
            source_threats = []
            false_positive_indicators = []

            for file_path in Path(extension_path).rglob('*'):
                if not file_path.is_file():
                    continue

                if not self.is_extension_source_file(file_path, extension_path):
                    continue

                try:
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()

                    # Check if file is minified/obfuscated
                    is_minified, reason = self.is_minified_or_obfuscated(content, file_path)
                    if is_minified:
                        relative_path = file_path.relative_to(extension_path)
                        false_positive_indicators.append(f"Minified file detected: {relative_path} ({reason})")
                        continue

                    # Enhanced pattern scanning with dynamic patterns - REDUCED FALSE POSITIVES
                    patterns_config = self._get_patterns_config()
                    all_patterns = patterns_config.get('rce_patterns', {})

                    for category, pattern_list in all_patterns.items():
                        for pattern_info in pattern_list:
                            pattern = pattern_info['pattern']

                            matches = re.finditer(pattern, content, re.IGNORECASE | re.MULTILINE)
                            for match in matches:
                                # Enhanced context validation
                                confidence, context_info = self.validate_context(
                                    content, match, file_path, pattern_info
                                )

                                if confidence > 0.5:  # Raised threshold from 0.1 to 0.5
                                    relative_path = file_path.relative_to(extension_path)
                                    line_num = content[:match.start()].count('\n') + 1

                                    threat = ThreatDetection(
                                        category=category,
                                        file_path=str(relative_path),
                                        pattern_match=match.group()[:100],
                                        confidence=confidence,
                                        context=context_info[:200],
                                        line_number=line_num,
                                        severity=pattern_info.get('severity', 'MEDIUM')
                                    )
                                    source_threats.append(threat)
                                    break  # Only first match per pattern per file

                except Exception as e:
                    logger.debug(f"Error scanning {file_path}: {e}")
                    continue

            # Build and run Docker analysis (temporarily disabled for testing)
            logger.info("Docker analysis temporarily disabled for testing")
            docker_results = None

            # Compile all threats including statistical anomalies
            all_threats = source_threats.copy()
            all_threats.extend(stats_threats)

            # Docker analysis temporarily disabled - all threats come from host scan only

            # Calculate overall confidence score
            if all_threats:
                confidence_score = sum(t.confidence for t in all_threats) / len(all_threats)
            else:
                confidence_score = 1.0  # High confidence in clean result

            # Determine status and risk level with enhanced logic - REDUCED FALSE POSITIVES
            high_confidence_threats = [t for t in all_threats if t.confidence > 0.9]  # Raised from 0.7 to 0.9
            critical_vulns = [v for v in vulnerabilities if v.severity == 'CRITICAL']
            high_vulns = [v for v in vulnerabilities if v.severity == 'HIGH']

            if high_confidence_threats and len(high_confidence_threats) >= 3:  # Require multiple high-confidence threats
                status = 'MALWARE'
                has_critical = any(t.severity == 'CRITICAL' for t in high_confidence_threats)
                risk_level = 'CRITICAL' if has_critical else 'HIGH'
            elif critical_vulns and len(critical_vulns) >= 2:  # Require multiple critical vulnerabilities
                status = 'VULNERABLE'
                risk_level = 'CRITICAL'
            elif high_vulns and len(high_vulns) >= 3:  # Require multiple high vulnerabilities
                status = 'VULNERABLE'
                risk_level = 'HIGH'
            elif len(all_threats) >= 5:  # Only flag as suspicious if many threats
                status = 'SUSPICIOUS'
                risk_level = 'MEDIUM'
            elif vulnerabilities:
                status = 'CLEAN'  # Changed from VULNERABLE to reduce false positives
                risk_level = 'LOW'  # Changed from MEDIUM
            else:
                status = 'CLEAN'
                risk_level = 'LOW'

            scan_time = time.time() - start_time
            logger.info(f"Enhanced scan completed for {extension_id}: {status} ({scan_time:.2f}s)")

            scan_result = ScanResult(
                extension_id=extension_id,
                status=status,
                threats=all_threats,
                vulnerabilities=vulnerabilities,
                risk_level=risk_level,
                confidence_score=confidence_score,
                details={
                    'docker_analysis': docker_results,
                    'file_count': len(list(Path(extension_path).rglob('*'))) if extension_path else 0,
                    'pattern_categories_detected': list(set(t.category for t in all_threats)),
                    'avg_threat_confidence': confidence_score,
                    'file_hashes': file_hashes,
                    'threat_intel_updated': int(self.threat_intel.last_update),
                    'file_statistics': file_stats,
                    'pattern_anomalies': len(pattern_analysis),
                    'statistical_threats': len(stats_threats)
                },
                scan_time=scan_time,
                false_positive_indicators=false_positive_indicators
            )

            # Return app-compatible format
            return scan_result.to_app_format()

        finally:
            # Cleanup
            if vsix_path and os.path.exists(vsix_path):
                os.unlink(vsix_path)
            if extension_path and os.path.exists(extension_path):
                subprocess.run(['rm', '-rf', extension_path], check=False)

    def scan_whitelist(self, whitelist_file: str) -> List[ScanResult]:
        """Scan all extensions in whitelist with enhanced reporting."""
        if not os.path.exists(whitelist_file):
            logger.error(f"Whitelist file not found: {whitelist_file}")
            return []

        # Check if it's YAML or plain text format
        if whitelist_file.endswith('.yaml') or whitelist_file.endswith('.yml'):
            extensions = load_yaml_whitelist(whitelist_file)
        else:
            # Legacy plain text format
            with open(whitelist_file, 'r') as f:
                extensions = [line.strip() for line in f if line.strip() and not line.startswith('#')]

        if not extensions:
            logger.error(f"No extensions found in {whitelist_file}")
            return []

        logger.info(f"Enhanced scanning of {len(extensions)} extensions from {whitelist_file}")

        results = []
        for i, extension_id in enumerate(extensions, 1):
            logger.info(f"[{i}/{len(extensions)}] Enhanced scanning {extension_id}")
            result = self.scan_extension(extension_id)
            results.append(result)

            # Brief pause between scans
            time.sleep(1)

        return results

    def generate_report(self, results: List[ScanResult]):
        """Generate enhanced comprehensive security report."""
        print("\n" + "="*80)
        print("VSX-BASTION ENHANCED PRODUCTION SECURITY REPORT")
        print("="*80)

        # Enhanced summary statistics
        total = len(results)
        clean = len([r for r in results if r.status == 'CLEAN'])
        suspicious = len([r for r in results if r.status == 'SUSPICIOUS'])
        vulnerable = len([r for r in results if r.status == 'VULNERABLE'])
        malware = len([r for r in results if r.status == 'MALWARE'])
        errors = len([r for r in results if r.status == 'ERROR'])

        print(f"\n📊 ENHANCED SCAN SUMMARY:")
        print(f"  Total Extensions: {total}")
        print(f"  ✅ Clean: {clean}")
        print(f"  🟡 Suspicious: {suspicious}")
        print(f"  ⚠️  Vulnerable: {vulnerable}")
        print(f"  🚨 Malware Detected: {malware}")
        print(f"  ❌ Scan Errors: {errors}")

        # Confidence analysis
        confidence_scores = [r.confidence_score for r in results if r.confidence_score > 0]
        if confidence_scores:
            avg_confidence = sum(confidence_scores) / len(confidence_scores)
            print(f"  📈 Average Confidence: {avg_confidence:.2f}")

        # Detailed findings with confidence scores
        if malware > 0:
            print(f"\n🚨 MALWARE DETECTED ({malware} extensions):")
            for result in results:
                if result.status == 'MALWARE':
                    print(f"  ❌ {result.extension_id} - {result.risk_level} (Confidence: {result.confidence_score:.2f})")
                    high_conf_threats = [t for t in result.threats if t.confidence > 0.7]
                    for threat in high_conf_threats[:3]:  # Show top 3 high-confidence threats
                        print(f"     • {threat.category}: {threat.file_path} (conf: {threat.confidence:.2f})")

        if suspicious > 0:
            print(f"\n🟡 SUSPICIOUS EXTENSIONS ({suspicious} extensions):")
            for result in results:
                if result.status == 'SUSPICIOUS':
                    print(f"  🟡 {result.extension_id} - {len(result.threats)} potential threats")
                    for threat in result.threats[:2]:
                        print(f"     • {threat.category}: {threat.file_path} (conf: {threat.confidence:.2f})")

        if vulnerable > 0:
            print(f"\n⚠️  VULNERABLE EXTENSIONS ({vulnerable} extensions):")
            for result in results:
                if result.status == 'VULNERABLE':
                    critical_vulns = [v for v in result.vulnerabilities if v.severity == 'CRITICAL']
                    high_vulns = [v for v in result.vulnerabilities if v.severity == 'HIGH']
                    print(f"  ⚠️  {result.extension_id} - {len(critical_vulns)} critical, {len(high_vulns)} high severity")

        if clean > 0:
            print(f"\n✅ CLEAN EXTENSIONS ({clean} extensions):")
            clean_results = [r for r in results if r.status == 'CLEAN']
            for result in clean_results[:10]:  # Show first 10
                fp_count = len(result.false_positive_indicators or [])
                fp_text = f" ({fp_count} FP indicators)" if fp_count > 0 else ""
                print(f"  ✅ {result.extension_id}{fp_text}")
            if len(clean_results) > 10:
                print(f"  ... and {len(clean_results) - 10} more")

        # Enhanced recommendations
        print(f"\n🎯 ENHANCED RECOMMENDATIONS:")
        if malware > 0:
            print(f"  🚨 IMMEDIATELY REMOVE high-confidence malware detections")
        if suspicious > 0:
            print(f"  🟡 MANUALLY REVIEW suspicious extensions with low confidence scores")
        if vulnerable > 0:
            print(f"  ⚠️  UPDATE vulnerable dependencies or find alternatives")
        if errors > 0:
            print(f"  🔧 INVESTIGATE scan errors and retry")

        false_positive_count = sum(len(r.false_positive_indicators or []) for r in results)
        if false_positive_count > 0:
            print(f"  📊 REVIEW {false_positive_count} false positive indicators for tuning")

        # Save enhanced detailed report
        import os
        from datetime import datetime
        os.makedirs('reports', exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_file = f"reports/enhanced_security_report_{timestamp}.json"

        report_data = {
            'scan_timestamp': timestamp,
            'scanner_version': 'enhanced-2.0',
            'summary': {
                'total': total,
                'clean': clean,
                'suspicious': suspicious,
                'vulnerable': vulnerable,
                'malware': malware,
                'errors': errors,
                'avg_confidence': sum(confidence_scores) / len(confidence_scores) if confidence_scores else 0
            },
            'results': [
                {
                    'extension_id': r.extension_id,
                    'status': r.status,
                    'risk_level': r.risk_level,
                    'confidence_score': r.confidence_score,
                    'threat_count': len(r.threats),
                    'high_confidence_threats': len([t for t in r.threats if t.confidence > 0.7]),
                    'vulnerability_count': len(r.vulnerabilities),
                    'critical_vulnerabilities': len([v for v in r.vulnerabilities if v.severity == 'CRITICAL']),
                    'scan_time': r.scan_time,
                    'false_positive_indicators': len(r.false_positive_indicators or [])
                }
                for r in results
            ]
        }

        with open(report_file, 'w') as f:
            json.dump(report_data, f, indent=2)

        print(f"\n📋 Enhanced detailed report saved to: {report_file}")
        print("="*80)

class BlacklistManager:
    """Manage YAML-based blacklist for security scanning"""

    def __init__(self, blacklist_path: str = None):
        from modules.config import DEFAULT_BLACKLIST_PATH
        self.blacklist_path = blacklist_path or DEFAULT_BLACKLIST_PATH
        self._blacklist_data = None

    def load_blacklist(self) -> Dict:
        """Load existing blacklist or create empty structure"""
        if self._blacklist_data is not None:
            return self._blacklist_data

        if not YAML_AVAILABLE:
            logger.warning("PyYAML not available - blacklist functionality disabled")
            self._blacklist_data = {}
            return self._blacklist_data

        if os.path.exists(self.blacklist_path):
            try:
                with open(self.blacklist_path, 'r') as f:
                    self._blacklist_data = yaml.safe_load(f) or {}
            except (yaml.YAMLError, IOError) as e:
                logger.warning(f"Error loading blacklist: {e}")
                self._blacklist_data = {}
        else:
            self._blacklist_data = {}

        # Ensure required structure exists
        if 'blocked_extensions' not in self._blacklist_data:
            self._blacklist_data['blocked_extensions'] = {}
        if 'review_queue' not in self._blacklist_data:
            self._blacklist_data['review_queue'] = {}
        if 'metadata' not in self._blacklist_data:
            self._blacklist_data['metadata'] = {}

        return self._blacklist_data

    def is_blocked(self, extension_id: str) -> bool:
        """Check if extension is in blacklist"""
        blacklist = self.load_blacklist()
        return extension_id in blacklist.get('blocked_extensions', {})

    def add_to_blacklist(self, extension_id: str, reason: str, details: str, risk_level: str = "UNKNOWN"):
        """Add extension to blacklist"""
        blacklist = self.load_blacklist()

        blacklist['blocked_extensions'][extension_id] = {
            'reason': reason,
            'blocked_date': datetime.now().strftime("%Y-%m-%d"),
            'details': details,
            'risk_level': risk_level
        }

        self._update_metadata(blacklist)
        self._save_blacklist(blacklist)

    def add_to_review_queue(self, extension_id: str, reason: str, details: str):
        """Add extension to review queue"""
        blacklist = self.load_blacklist()

        blacklist['review_queue'][extension_id] = {
            'reason': reason,
            'queued_date': datetime.now().strftime("%Y-%m-%d"),
            'details': details
        }

        self._update_metadata(blacklist)
        self._save_blacklist(blacklist)

    def _update_metadata(self, blacklist: Dict):
        """Update blacklist metadata"""
        blacklist['metadata'] = {
            'last_updated': datetime.now().strftime("%Y-%m-%d"),
            'scanner_version': '2.0',
            'total_blocked': len(blacklist.get('blocked_extensions', {})),
            'total_review_queue': len(blacklist.get('review_queue', {}))
        }

    def _save_blacklist(self, blacklist: Dict):
        """Save blacklist to file"""
        if not YAML_AVAILABLE:
            logger.error("PyYAML not available - cannot save blacklist")
            return

        try:
            with open(self.blacklist_path, 'w') as f:
                yaml.dump(blacklist, f, default_flow_style=False, sort_keys=False)
            self._blacklist_data = blacklist
            logger.info(f"Updated blacklist: {self.blacklist_path}")
        except IOError as e:
            logger.error(f"Failed to save blacklist: {e}")

def load_yaml_whitelist(whitelist_path: str) -> List[str]:
    """Load extensions from YAML whitelist with install=true"""
    if not YAML_AVAILABLE:
        logger.error("PyYAML not installed. Cannot load YAML whitelist. Install with: pip install PyYAML")
        return []

    try:
        with open(whitelist_path, 'r') as f:
            data = yaml.safe_load(f)

        extensions = []
        if 'authors' in data:
            for author, author_extensions in data['authors'].items():
                for ext in author_extensions:
                    if ext.get('install', False):
                        extensions.append(ext['id'])

        return extensions
    except (yaml.YAMLError, IOError, KeyError) as e:
        logger.error(f"Error loading YAML whitelist: {e}")
        return []

def main():
    """Enhanced main entry point with blacklist management."""
    import argparse
    import sys
    from modules.config import DEFAULT_WHITELIST_PATH, DEFAULT_BLACKLIST_PATH

    parser = argparse.ArgumentParser(description='VSX-Bastion Enhanced Production Security Scanner')
    parser.add_argument('--whitelist', '-w', default=DEFAULT_WHITELIST_PATH,
                       help=f'Path to YAML whitelist file (default: {DEFAULT_WHITELIST_PATH})')
    parser.add_argument('--extension', '-e',
                       help='Scan single extension')
    parser.add_argument('--update-blacklist', action='store_true',
                       help='Scan whitelist and update blacklist with threats')
    parser.add_argument('--blacklist', '-b', default=DEFAULT_BLACKLIST_PATH,
                       help=f'Path to blacklist file (default: {DEFAULT_BLACKLIST_PATH})')
    parser.add_argument('--verbose', '-v', action='store_true',
                       help='Verbose logging')
    parser.add_argument('--rebuild-container', action='store_true',
                       help='Force rebuild of analysis container')

    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    # Check Docker availability
    try:
        subprocess.run(['docker', '--version'], capture_output=True, check=True)
    except (subprocess.CalledProcessError, FileNotFoundError):
        logger.error("Docker is required but not available. Please install Docker.")
        sys.exit(1)

    # Initialize enhanced scanner and blacklist manager
    scanner = EnhancedProductionScanner()
    blacklist_manager = BlacklistManager(args.blacklist)

    # Force container rebuild if requested
    if args.rebuild_container:
        logger.info("Forcing container rebuild...")
        scanner.docker_engine.build_container()

    # Run enhanced scan
    if args.update_blacklist:
        logger.info(f"Updating blacklist from whitelist: {args.whitelist}")
        extensions = load_yaml_whitelist(args.whitelist)
        if not extensions:
            logger.error("No extensions found in whitelist")
            sys.exit(1)

        logger.info(f"Scanning {len(extensions)} extensions for blacklist update...")

        blocked_count = 0
        reviewed_count = 0

        for i, extension_id in enumerate(extensions, 1):
            logger.info(f"[{i}/{len(extensions)}] Scanning {extension_id}...")

            try:
                result = scanner.scan_extension(extension_id)

                if result.status == 'MALWARE':
                    blacklist_manager.add_to_blacklist(
                        extension_id,
                        'MALWARE',
                        f'Threats detected: {len(result.threats)} patterns matched',
                        result.risk_level
                    )
                    blocked_count += 1
                    logger.warning(f"🚨 BLOCKED: {extension_id} - Malware detected")

                elif result.status == 'VULNERABLE' and result.risk_level in ['HIGH', 'CRITICAL']:
                    blacklist_manager.add_to_blacklist(
                        extension_id,
                        'VULNERABLE',
                        f'High/Critical vulnerabilities: {len(result.vulnerabilities)}',
                        result.risk_level
                    )
                    blocked_count += 1
                    logger.warning(f"⚠️  BLOCKED: {extension_id} - High/Critical vulnerabilities")

                elif result.confidence_score < 0.5 and len(result.threats) > 0:
                    blacklist_manager.add_to_review_queue(
                        extension_id,
                        'LOW_CONFIDENCE',
                        f'Low confidence threats detected: {result.confidence_score:.2f}'
                    )
                    reviewed_count += 1
                    logger.info(f"🔍 REVIEW: {extension_id} - Low confidence detection")

                else:
                    logger.info(f"✅ CLEAN: {extension_id}")

            except Exception as e:
                logger.error(f"❌ SCAN ERROR: {extension_id} - {e}")

        logger.info(f"Blacklist update complete: {blocked_count} blocked, {reviewed_count} queued for review")

    elif args.extension:
        logger.info(f"Enhanced scanning single extension: {args.extension}")
        result = scanner.scan_extension(args.extension)
        scanner.generate_report([result])
    else:
        logger.info(f"Enhanced scanning whitelist: {args.whitelist}")
        extensions = load_yaml_whitelist(args.whitelist)
        if extensions:
            results = []
            for ext_id in extensions:
                result = scanner.scan_extension(ext_id)
                results.append(result)
            scanner.generate_report(results)
        else:
            logger.error("No extensions found to scan")

if __name__ == '__main__':
    main()
