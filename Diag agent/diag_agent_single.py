#!/usr/bin/env python3
"""
diag_agent_single.py - Cybershield Solutions 2025 Professional Edition

Features:
 - Dashboard with clear cards for: vulnerabilities, packages, SSH fails, CPU, memory, disk.
 - Separate tabs: Vulns, Packages, Services, Logs, SSH Logs, Nmap, Report.
 - Modern Bootstrap dark UI + spinner while generating reports.
 - Footer watermark: Vitaliy 2025.
 - APIs: /api/status, /api/run_trivy_filtered, /api/nmap_scan, /api/run_cmd.
 - Fixed: Suspicious Processes table with wrapping/clipping and modal for full text.
 - Improved: Whitelisted common system paths, configurable whitelist, tooltips for clipped text.
 - New: PDF export option for professional reports.

 - REPORT page (/report):
   * Section A: On-page "Visual Report" (renders selected sections inline).
   * Section B: CSV Export (checkboxes to pick sections; returns downloadable CSV).
   * Section C: PDF Export (checkboxes to pick sections; returns downloadable PDF).
   * Sections available: Trivy, Nmap, System Logs, SSH Fails, Processes, Services,
                        Upgradable Packages, Suspicious Processes.
"""

import argparse, shlex, io, csv, time, os, sys, json, datetime, subprocess, shutil, psutil, ipaddress, socket, collections, re, threading, uuid, requests
from flask import Flask, jsonify, request, abort, render_template_string, Response, send_file
from weasyprint import HTML
from typing import Dict, List, Tuple
from dataclasses import dataclass, field

# --- Config globals ---
NMAP_BIN = shutil.which("nmap")   # ruta a nmap o None si no està instal·lat
NMAP_TIMEOUT = 120                # segons per a nmap per defecte
NMAP_MAX_CHARS = 250_000          # límit de retorn per evitar pantalles quilomètriques


# ==================== SSH AUDIT PARSER ====================
# Professional SSH audit parser integrated into Diag Agent
# Parses raw ssh-audit output and generates clean, structured security reports.

@dataclass
class SSHAlgorithm:
    """Represents an SSH algorithm with its security classification."""
    name: str
    key_size: str = ""
    security_level: str = "unknown"  # secure, weak, fail
    notes: List[str] = field(default_factory=list)
    available_since: str = ""


@dataclass
class SSHAuditReport:
    """Structured SSH audit report."""
    # Banner info
    banner: str = ""
    software: str = ""
    protocol_version: str = ""
    compression: str = ""
    
    # Algorithms by category
    kex_secure: List[SSHAlgorithm] = field(default_factory=list)
    kex_weak: List[SSHAlgorithm] = field(default_factory=list)
    kex_fail: List[SSHAlgorithm] = field(default_factory=list)
    
    hostkey_secure: List[SSHAlgorithm] = field(default_factory=list)
    hostkey_weak: List[SSHAlgorithm] = field(default_factory=list)
    hostkey_fail: List[SSHAlgorithm] = field(default_factory=list)
    
    encryption_preferred: List[SSHAlgorithm] = field(default_factory=list)
    encryption_secure: List[SSHAlgorithm] = field(default_factory=list)
    encryption_weak: List[SSHAlgorithm] = field(default_factory=list)
    
    mac_secure: List[SSHAlgorithm] = field(default_factory=list)
    mac_weak: List[SSHAlgorithm] = field(default_factory=list)
    mac_fail: List[SSHAlgorithm] = field(default_factory=list)
    
    # Fingerprints
    fingerprints: Dict[str, str] = field(default_factory=dict)
    
    # Recommendations
    recommendations: List[str] = field(default_factory=list)
    
    # Critical findings
    critical_issues: List[str] = field(default_factory=list)
    hardening_actions: List[str] = field(default_factory=list)


class SSHAuditParser:
    """Parses raw ssh-audit output into structured security reports."""
    
    # Security classification patterns
    FAIL_PATTERNS = [
        r'\(fail\)',
        r'weak\s+\(',
        r'broken',
        r'vulnerable',
        r'deprecated',
        r'SHA-?1',
        r'MD5',
        r'RC4',
        r'3DES',
        r'CBC',  # CBC mode ciphers are generally weak
    ]
    
    WEAK_PATTERNS = [
    ]
    
    WEAK_PATTERNS = [
        r'\(warn\)',
        r'warning',
        r'small\s+modulus',
        r'short\s+key',
    ]
    
    SECURE_PATTERNS = [
        r'ed25519',
        r'ecdsa-sha2-nistp521',
        r'ecdsa-sha2-nistp384',
        r'rsa-sha2-512',
        r'rsa-sha2-256',
        r'chacha20-poly1305',
        r'aes256-gcm',
        r'aes128-gcm',
        r'curve25519',
        r'diffie-hellman-group-exchange-sha256',
    ]
    
    def __init__(self):
        self.report = SSHAuditReport()
    
    def clean_ansi(self, text: str) -> str:
        """Remove ANSI color codes and control characters."""
        ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
        return ansi_escape.sub('', text)
    
    def extract_banner(self, lines: List[str]) -> None:
        """Extract SSH banner and software information."""
        for line in lines:
            clean_line = self.clean_ansi(line).strip()
            
            if 'banner:' in clean_line.lower():
                match = re.search(r'banner:\s*(.+)', clean_line, re.IGNORECASE)
                if match:
                    self.report.banner = match.group(1).strip()
            
            if 'SSH-' in clean_line and not 'banner:' in clean_line.lower():
                if not self.report.software:
                    self.report.software = clean_line.strip()
            
            # Auto-extract from banner if missing
            if self.report.banner and not self.report.protocol_version:
                if 'SSH-2.0' in self.report.banner: self.report.protocol_version = '2.0'
                elif 'SSH-1.99' in self.report.banner: self.report.protocol_version = '1.99/2.0'
                elif 'SSH-1.' in self.report.banner: self.report.protocol_version = '1.x'
            
            if self.report.banner and not self.report.software:
                if 'OpenSSH' in self.report.banner: self.report.software = 'OpenSSH'
                elif 'Dropbear' in self.report.banner: self.report.software = 'Dropbear'
            
            if 'protocol version' in clean_line.lower():
                match = re.search(r'(\d+\.\d+)', clean_line)
                if match:
                    self.report.protocol_version = match.group(1)
            
            if 'compression:' in clean_line.lower():
                match = re.search(r'compression:\s*(.+)', clean_line, re.IGNORECASE)
                if match:
                    self.report.compression = match.group(1).strip()
    
    def classify_algorithm(self, algo_text: str) -> str:
        """Classify algorithm as secure, weak, or fail based on patterns."""
        algo_lower = algo_text.lower()
        
        for pattern in self.FAIL_PATTERNS:
            if re.search(pattern, algo_lower, re.IGNORECASE):
                return "fail"
        
        for pattern in self.WEAK_PATTERNS:
            if re.search(pattern, algo_lower, re.IGNORECASE):
                return "weak"
        
        for pattern in self.SECURE_PATTERNS:
            if re.search(pattern, algo_lower, re.IGNORECASE):
                return "secure"
        
        return "weak"
    
    def parse_algorithm_line(self, line: str) -> Tuple[SSHAlgorithm, str]:
        """Parse a single algorithm line and return algorithm object and classification."""
        clean_line = self.clean_ansi(line).strip()
        
        # Handle lines like "(kex) curve25519-sha256@libssh.org" or just "curve25519-sha256@libssh.org"
        # Skip optional prefixes like (kex), (key), (enc), (mac)
        algo_match = re.search(r'^(?:\([a-z]+\)\s+)?\s*[-*]?\s*([a-zA-Z0-9_@.-]+)', clean_line)
        if not algo_match:
            return None, "unknown"
        
        algo_name = algo_match.group(1)
        
        key_size = ""
        size_match = re.search(r'(\d+\s*bit)', clean_line, re.IGNORECASE)
        if size_match:
            key_size = size_match.group(1)
        
        notes = []
        note_matches = re.findall(r'\(([^)]+)\)', clean_line)
        notes.extend(note_matches)
        
        available_since = ""
        since_match = re.search(r'available\s+since\s+(.+?)(?:\s|$)', clean_line, re.IGNORECASE)
        if since_match:
            available_since = since_match.group(1).strip()
        
        security_level = self.classify_algorithm(clean_line)
        
        algo = SSHAlgorithm(
            name=algo_name,
            key_size=key_size,
            security_level=security_level,
            notes=notes,
            available_since=available_since
        )
        
        return algo, security_level
    
    def parse_kex_algorithms(self, lines: List[str]) -> None:
        """Parse key exchange algorithms section."""
        in_kex_section = False
        
        for line in lines:
            clean_line = self.clean_ansi(line).strip().lower()
            
            if any(x in clean_line for x in ['key exchange', 'kex algorithms', '(kex)']):
                in_kex_section = True
                continue
            
            if in_kex_section:
                if clean_line.startswith('host-key algorithms') or clean_line.startswith('encryption algorithms'):
                    break
                
                if not clean_line or clean_line.startswith('(') or clean_line.startswith('#'):
                    continue
                
                algo, classification = self.parse_algorithm_line(line)
                if algo:
                    if not self.report.kex_preferred and (classification == "secure" or "default" in clean_line):
                        self.report.kex_preferred.append(algo)
                        
                    if classification == "secure":
                        self.report.kex_secure.append(algo)
                    elif classification == "weak":
                        self.report.kex_weak.append(algo)
                    else:
                        self.report.kex_fail.append(algo)
    
    def parse_hostkey_algorithms(self, lines: List[str]) -> None:
        """Parse host-key algorithms section."""
        in_hostkey_section = False
        
        for line in lines:
            clean_line = self.clean_ansi(line).strip().lower()
            
            if any(x in clean_line for x in ['host-key algorithms', 'host key algorithms', '(key)']):
                in_hostkey_section = True
                continue
            
            if in_hostkey_section:
                if clean_line.startswith('encryption algorithms') or clean_line.startswith('mac algorithms'):
                    break
                
                if not clean_line or clean_line.startswith('(') or clean_line.startswith('#'):
                    continue
                
                algo, classification = self.parse_algorithm_line(line)
                if algo:
                    if not self.report.hostkey_preferred and (classification == "secure" or "default" in clean_line):
                        self.report.hostkey_preferred.append(algo)
                        
                    if classification == "secure":
                        self.report.hostkey_secure.append(algo)
                    elif classification == "weak":
                        self.report.hostkey_weak.append(algo)
                    else:
                        self.report.hostkey_fail.append(algo)
    
    def parse_encryption_algorithms(self, lines: List[str]) -> None:
        """Parse encryption cipher algorithms section."""
        in_encryption_section = False
        
        for line in lines:
            clean_line = self.clean_ansi(line).strip().lower()
            
            if any(x in clean_line for x in ['encryption algorithms', '(enc)']):
                in_encryption_section = True
                continue
            
            if in_encryption_section:
                if clean_line.startswith('mac algorithms') or clean_line.startswith('fingerprints'):
                    break
                
                if not clean_line or clean_line.startswith('(') or clean_line.startswith('#'):
                    continue
                
                algo, classification = self.parse_algorithm_line(line)
                if algo:
                    if not self.report.encryption_preferred:
                        self.report.encryption_preferred.append(algo)
                    
                    if classification == "secure":
                        self.report.encryption_secure.append(algo)
                    elif classification == "weak" or classification == "fail":
                        self.report.encryption_weak.append(algo)
    
    def parse_mac_algorithms(self, lines: List[str]) -> None:
        """Parse MAC algorithms section."""
        in_mac_section = False
        
        for line in lines:
            clean_line = self.clean_ansi(line).strip().lower()
            
            if any(x in clean_line for x in ['mac algorithms', '(mac)']):
                in_mac_section = True
                continue
            
            if in_mac_section:
                if clean_line.startswith('fingerprints') or clean_line.startswith('recommendations'):
                    break
                
                if not clean_line or clean_line.startswith('(') or clean_line.startswith('#'):
                    continue
                
                algo, classification = self.parse_algorithm_line(line)
                if algo:
                    if classification == "secure":
                        self.report.mac_secure.append(algo)
                    elif classification == "weak":
                        self.report.mac_weak.append(algo)
                    else:
                        self.report.mac_fail.append(algo)
    
    def parse_fingerprints(self, lines: List[str]) -> None:
        """Extract SSH fingerprints."""
        in_fingerprint_section = False
        
        for line in lines:
            clean_line = self.clean_ansi(line).strip().lower()
            
            if any(x in clean_line for x in ['fingerprints', 'fingerprint', '(fp)']):
                in_fingerprint_section = True
                continue
            
            if in_fingerprint_section:
                if clean_line.startswith('recommendations') or clean_line.startswith('algorithm'):
                    break
                
                fp_match = re.search(r'(rsa|ed25519|ecdsa|dsa)[\s:-]+(sha256:[a-zA-Z0-9+/=]+)', clean_line, re.IGNORECASE)
                if fp_match:
                    key_type = fp_match.group(1)
                    fingerprint = fp_match.group(2)
                    self.report.fingerprints[key_type] = fingerprint
    
    def parse_recommendations(self, lines: List[str]) -> None:
        """Extract algorithm removal recommendations."""
        in_rec_section = False
        
        for line in lines:
            clean_line = self.clean_ansi(line).strip()
            clean_lower = clean_line.lower()
            
            if 'recommendations' in clean_lower or 'remove' in clean_lower:
                in_rec_section = True
                continue
            
            if in_rec_section:
                if not clean_line:
                    continue
                
                if any(keyword in clean_lower for keyword in ['remove', 'disable', 'avoid']):
                    self.report.recommendations.append(clean_line)
    
    def generate_critical_issues(self) -> None:
        """Generate a list of critical security issues found."""
        issues = []
        
        if self.report.kex_fail:
            issues.append(f"❌ {len(self.report.kex_fail)} dangerous Key Exchange algorithms detected: {', '.join([a.name for a in self.report.kex_fail[:3]])}")
        
        if self.report.hostkey_fail:
            issues.append(f"❌ {len(self.report.hostkey_fail)} insecure Host Key algorithms found: {', '.join([a.name for a in self.report.hostkey_fail[:3]])}")
        
        if self.report.encryption_weak:
            weak_ciphers = [a.name for a in self.report.encryption_weak if 'cbc' in a.name.lower() or '3des' in a.name.lower()]
            if weak_ciphers:
                issues.append(f"⚠️ Weak encryption ciphers enabled: {', '.join(weak_ciphers[:3])}")
        
        if self.report.mac_fail:
            issues.append(f"❌ {len(self.report.mac_fail)} broken MAC algorithms (SHA-1/MD5): {', '.join([a.name for a in self.report.mac_fail[:3]])}")
        
        if self.report.protocol_version and self.report.protocol_version.startswith('1'):
            issues.append("🚨 SSH Protocol 1.x detected - CRITICAL: Upgrade to SSH 2.0 immediately")
        
        if not issues:
            issues.append("✅ No critical security vulnerabilities detected")
        
        self.report.critical_issues = issues[:5]
    
    def generate_hardening_recommendations(self) -> None:
        """Generate actionable hardening recommendations."""
        actions = []
        
        if self.report.kex_fail or self.report.kex_weak:
            actions.append("Configure KexAlgorithms to use only: curve25519-sha256, diffie-hellman-group-exchange-sha256")
        
        if self.report.hostkey_fail or self.report.hostkey_weak:
            actions.append("Configure HostKeyAlgorithms to prefer: ssh-ed25519, rsa-sha2-512, rsa-sha2-256")
        
        if self.report.encryption_weak:
            actions.append("Configure Ciphers to use: chacha20-poly1305@openssh.com, aes256-gcm@openssh.com, aes128-gcm@openssh.com")
        
        if self.report.mac_fail or self.report.mac_weak:
            actions.append("Configure MACs to use: hmac-sha2-512-etm@openssh.com, hmac-sha2-256-etm@openssh.com")
        
        actions.append("Disable SSH Protocol 1 completely (Protocol 2 only)")
        actions.append("Regenerate SSH host keys with stronger algorithms (ed25519, RSA 4096-bit)")
        actions.append("Enable StrictHostKeyChecking on clients")
        actions.append("Review and apply all removal recommendations from ssh-audit")
        
        self.report.hardening_actions = actions
    
    def parse(self, raw_output: str) -> SSHAuditReport:
        """Parse raw ssh-audit output and return structured report."""
        lines = raw_output.split('\n')
        
        self.extract_banner(lines)
        self.parse_kex_algorithms(lines)
        self.parse_hostkey_algorithms(lines)
        self.parse_encryption_algorithms(lines)
        self.parse_mac_algorithms(lines)
        self.parse_fingerprints(lines)
        self.parse_recommendations(lines)
        
        self.generate_critical_issues()
        self.generate_hardening_recommendations()
        
        return self.report
    
    def to_html(self, report: SSHAuditReport = None, for_pdf=False) -> str:
        """Generate HTML - icons for web, clean compact summary for PDF"""
        if report is None:
            report = self.report
        
        # PDF MODE: Compact horizontal summary table
        if for_pdf:
            html = f"""
<div class="ssh-report">
    <h2>SSH Audit Summary</h2>
    
    <table>
        <tr><th>Banner</th><td>{report.banner or 'N/A'}</td></tr>
        <tr><th>Software</th><td>{report.software or 'N/A'}</td></tr>
        <tr><th>Protocol</th><td>{report.protocol_version or 'N/A'}</td></tr>
    </table>
    
    <h3>Algorithm Security Summary</h3>
    <table>
        <tr>
            <th>Category</th>
            <th>Secure</th>
            <th>Weak</th>
            <th>Unsafe</th>
        </tr>
        <tr>
            <td><strong>Key Exchange (KEX)</strong></td>
            <td>{len(report.kex_secure)}</td>
            <td>{len(report.kex_weak)}</td>
            <td>{len(report.kex_fail)}</td>
        </tr>
        <tr>
            <td><strong>Host Key</strong></td>
            <td>{len(report.hostkey_secure)}</td>
            <td>{len(report.hostkey_weak)}</td>
            <td>{len(report.hostkey_fail)}</td>
        </tr>
        <tr>
            <td><strong>Encryption</strong></td>
            <td>{len(report.encryption_secure)}</td>
            <td>{len(report.encryption_weak)}</td>
            <td>-</td>
        </tr>
        <tr>
            <td><strong>MAC</strong></td>
            <td>{len(report.mac_secure)}</td>
            <td>{len(report.mac_weak)}</td>
            <td>{len(report.mac_fail)}</td>
        </tr>
    </table>
"""
            
            if report.critical_issues:
                html += "<h3>CRITICAL: Security Issues</h3><ul>\n"
                for issue in report.critical_issues:
                    html += f"<li>{issue}</li>\n"
                html += "</ul>\n"
            
            if report.hardening_actions:
                html += "<h3>Security Recommendations</h3><ol>\n"
                for action in report.hardening_actions[:10]:
                    html += f"<li>{action}</li>\n"
                html += "</ol>\n"
            
            html += "</div>"
            return html
        
        # WEB MODE: Full details with icons
        html = f"""
<div class="ssh-audit-report">
    <h2>SSH Audit Summary</h2>
    
    <div class="section">
        <h3>🔍 Banner Information</h3>
        <table>
            <tr><th>Banner</th><td>{report.banner or 'N/A'}</td></tr>
            <tr><th>Software</th><td>{report.software or 'N/A'}</td></tr>
            <tr><th>Protocol</th><td>{report.protocol_version or 'N/A'}</td></tr>
            <tr><th>Compression</th><td>{report.compression or 'N/A'}</td></tr>
        </table>
    </div>
    
    <div class="section">
        <h3>🔐 Key Exchange (KEX) Algorithms</h3>
        <div class="algo-group">
            <h4 class="secure">✅ Secure ({len(report.kex_secure)})</h4>
            <ul>
                {''.join([f'<li>{a.name} {a.key_size}</li>' for a in report.kex_secure]) or '<li>None</li>'}
            </ul>
        </div>
        <div class="algo-group">
            <h4 class="weak">⚠️ Weak ({len(report.kex_weak)})</h4>
            <ul>
                {''.join([f'<li>{a.name} {a.key_size}</li>' for a in report.kex_weak]) or '<li>None</li>'}
            </ul>
        </div>
        <div class="algo-group">
            <h4 class="fail">❌ Dangerous ({len(report.kex_fail)})</h4>
            <ul>
                {''.join([f'<li>{a.name} {a.key_size}</li>' for a in report.kex_fail]) or '<li>None</li>'}
            </ul>
        </div>
    </div>
    
    <div class="section">
        <h3>🔑 Host Key Algorithms</h3>
        <div class="algo-group">
            <h4 class="secure">✅ Secure ({len(report.hostkey_secure)})</h4>
            <ul>
                {''.join([f'<li>{a.name} {a.key_size}</li>' for a in report.hostkey_secure]) or '<li>None</li>'}
            </ul>
        </div>
        <div class="algo-group">
            <h4 class="weak">⚠️ Weak ({len(report.hostkey_weak)})</h4>
            <ul>
                {''.join([f'<li>{a.name} {a.key_size}</li>' for a in report.hostkey_weak]) or '<li>None</li>'}
            </ul>
        </div>
        <div class="algo-group">
            <h4 class="fail">❌ Insecure ({len(report.hostkey_fail)})</h4>
            <ul>
                {''.join([f'<li>{a.name} {a.key_size}</li>' for a in report.hostkey_fail]) or '<li>None</li>'}
            </ul>
        </div>
    </div>
    
    <div class="section">
        <h3>🛡️ Encryption Ciphers</h3>
        <div class="algo-group">
            <h4>Preferred/Default</h4>
            <ul>
                {''.join([f'<li>{a.name}</li>' for a in report.encryption_preferred]) or '<li>None</li>'}
            </ul>
        </div>
        <div class="algo-group">
            <h4 class="secure">✅ Secure ({len(report.encryption_secure)})</h4>
            <ul>
                {''.join([f'<li>{a.name}</li>' for a in report.encryption_secure]) or '<li>None</li>'}
            </ul>
        </div>
        <div class="algo-group">
            <h4 class="weak">⚠️ Weak/Deprecated ({len(report.encryption_weak)})</h4>
            <ul>
                {''.join([f'<li>{a.name}</li>' for a in report.encryption_weak]) or '<li>None</li>'}
            </ul>
        </div>
    </div>
    
    <div class="section">
        <h3>🛡️ MAC Algorithms</h3>
        <div class="algo-group">
            <h4 class="secure">✅ Secure ({len(report.mac_secure)})</h4>
            <ul>
                {''.join([f'<li>{a.name}</li>' for a in report.mac_secure]) or '<li>None</li>'}
            </ul>
        </div>
        <div class="algo-group">
            <h4 class="weak">⚠️ Weak ({len(report.mac_weak)})</h4>
            <ul>
                {''.join([f'<li>{a.name}</li>' for a in report.mac_weak]) or '<li>None</li>'}
            </ul>
        </div>
        <div class="algo-group">
            <h4 class="fail">❌ Broken ({len(report.mac_fail)})</h4>
            <ul>
                {''.join([f'<li>{a.name}</li>' for a in report.mac_fail]) or '<li>None</li>'}
            </ul>
        </div>
    </div>
    
    <div class="section">
        <h3>🔐 Fingerprints</h3>
        <table>
            {''.join([f'<tr><th>{k.upper()}</th><td><code>{v}</code></td></tr>' for k, v in report.fingerprints.items()]) or '<tr><td>No fingerprints extracted</td></tr>'}
        </table>
    </div>
    
    <div class="section">
        <h3>📋 Recommended Removals</h3>
        <ul>
            {''.join([f'<li>{rec}</li>' for rec in report.recommendations]) or '<li>No specific recommendations</li>'}
        </ul>
    </div>
    
    <div class="section critical">
        <h3>🚨 CRITICAL: Security Issues</h3>
        <ul>
            {''.join([f'<li>{issue}</li>' for issue in report.critical_issues])}
        </ul>
    </div>
    
    <div class="section recommendations">
        <h3>✅ Security Recommendations</h3>
        <ol>
            {''.join([f'<li>{action}</li>' for action in report.hardening_actions])}
        </ol>
    </div>
</div>
"""
        return html

# ==================== END SSH AUDIT PARSER ====================


# ==================== NMAP PARSER ====================
# Professional Nmap output parser integrated into Diag Agent
# Parses network scan results and generates structured security reports.

@dataclass
class NmapPort:
    """Represents a scanned port with service information."""
    port: int
    protocol: str = "tcp"  # tcp/udp
    state: str = ""  # open/closed/filtered
    service: str = ""
    version: str = ""
    security_level: str = "unknown"  # safe/attention/dangerous
    notes: List[str] = field(default_factory=list)


@dataclass
class NmapHost:
    """Represents a scanned host with its ports."""
    ip: str
    hostname: str = ""
    status: str = ""  # up/down
    os: str = ""
    latency: str = ""
    ports: List[NmapPort] = field(default_factory=list)


@dataclass  
class NmapReport:
    """Structured Nmap scan report."""
    scan_time: str = ""
    command: str = ""
    hosts_up: int = 0
    hosts_down: int = 0
    total_ports_found: int = 0
    hosts: List[NmapHost] = field(default_factory=list)
    critical_findings: List[str] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)


class NmapParser:
    """Parses raw Nmap output into structured security reports."""
    
    # Dangerous ports that should not be exposed
    DANGEROUS_PORTS = {
        21: "FTP - Unencrypted file transfer protocol",
        23: "Telnet - Unencrypted remote access (use SSH)",
        69: "TFTP - Trivial FTP with no authentication",
        135: "MS-RPC - Should not be internet-facing",
        139: "NetBIOS - Should not be internet-facing",
        445: "SMB - Should not be internet-facing",
        1433: "MSSQL - Database should not be exposed",
        3306: "MySQL - Database should not be exposed",
        5432: "PostgreSQL - Database should not be exposed",
        6379: "Redis - Should not be exposed without auth",
        27017: "MongoDB - Should not be exposed",
        3389: "RDP - Remote Desktop (high risk)",
    }
    
    # Safe/common ports
    SAFE_PORTS = {
        53: "DNS - Domain Name System",
        80: "HTTP - Web traffic (use HTTPS when possible)",
        443: "HTTPS - Secure web traffic",
        22: "SSH - Secure shell (ensure key-based auth)",
        25: "SMTP - Email (ensure TLS)",
        465: "SMTPS - Secure email",
        587: "SMTP - Email submission (TLS)",
        993: "IMAPS - Secure email retrieval",
        995: "POP3S - Secure email retrieval",
    }
    
    # Ports that need attention
    ATTENTION_PORTS = {
        8080: "HTTP Proxy/Alt - Review configuration",
        8443: "HTTPS Alt - Review configuration",
        3000: "Development server - Should not be production",
        5000: "Development server - Should not be production",
        8000: "Development server - Should not be production",
    }
    
    def __init__(self):
        self.report = NmapReport()
    
    def classify_port(self, port: int, service: str = "") -> str:
        """Classify port as safe, attention, or dangerous."""
        if port in self.DANGEROUS_PORTS:
            return "dangerous"
        elif port in self.ATTENTION_PORTS:
            return "attention"
        elif port in self.SAFE_PORTS:
            return "safe"
        elif port > 49152:  # Dynamic/private ports
            return "attention"
        else:
            return "safe"
    
    def get_port_description(self, port: int) -> str:
        """Get description for a known port."""
        if port in self.DANGEROUS_PORTS:
            return self.DANGEROUS_PORTS[port]
        elif port in self.SAFE_PORTS:
            return self.SAFE_PORTS[port]
        elif port in self.ATTENTION_PORTS:
            return self.ATTENTION_PORTS[port]
        return ""
    
    def parse_host_header(self, line: str) -> NmapHost:
        """Parse 'Nmap scan report for...' line."""
        # Format: "Nmap scan report for hostname (ip)" or "Nmap scan report for ip"
        match = re.search(r'Nmap scan report for (.+?)(?:\s+\((.+?)\))?$', line)
        if match:
            first = match.group(1).strip()
            second = match.group(2)
            
            # Check if first part is an IP
            if re.match(r'^\d+\.\d+\.\d+\.\d+$', first):
                return NmapHost(ip=first, hostname=second or "")
            else:
                return NmapHost(ip=second or first, hostname=first if second else "")
        
        return NmapHost(ip="unknown")
    
    def parse_port_line(self, line: str) -> NmapPort:
        """Parse a port line like '22/tcp   open  ssh     OpenSSH 7.4'."""
        parts = line.split()
        if len(parts) < 2:
            return None
        
        # Parse port/protocol
        port_proto = parts[0].split('/')
        if len(port_proto) != 2:
            return None
        
        try:
            port_num = int(port_proto[0])
        except ValueError:
            return None
        
        protocol = port_proto[1]
        state = parts[1] if len(parts) > 1 else ""
        service = parts[2] if len(parts) > 2 else ""
        version = " ".join(parts[3:]) if len(parts) > 3 else ""
        
        security_level = self.classify_port(port_num, service)
        
        port_obj = NmapPort(
            port=port_num,
            protocol=protocol,
            state=state,
            service=service,
            version=version,
            security_level=security_level
        )
        
        # Add notes for dangerous/attention ports
        desc = self.get_port_description(port_num)
        if desc:
            port_obj.notes.append(desc)
        
        return port_obj
    
    def parse(self, raw_output: str) -> NmapReport:
        """Parse raw Nmap output and return structured report."""
        lines = raw_output.split('\n')
        
        current_host = None
        in_port_section = False
        
        for line in lines:
            line_stripped = line.strip()
            
            # Extract scan command
            if line_stripped.startswith('Starting Nmap') or 'nmap' in line_stripped.lower():
                if not self.report.command:
                    self.report.command = line_stripped
            
            # Extract scan time
            if 'at' in line_stripped and not self.report.scan_time:
                time_match = re.search(r'at (.+)$', line_stripped)
                if time_match:
                    self.report.scan_time = time_match.group(1)
            
            # Host header
            if line_stripped.startswith('Nmap scan report for'):
                # Save previous host
                if current_host:
                    self.report.hosts.append(current_host)
                
                current_host = self.parse_host_header(line_stripped)
                in_port_section = False
            
            # Host status
            elif current_host and 'Host is' in line_stripped:
                if 'up' in line_stripped.lower():
                    current_host.status = "up"
                    self.report.hosts_up += 1
                    
                    # Extract latency
                    latency_match = re.search(r'\((.+?latency)\)', line_stripped)
                    if latency_match:
                        current_host.latency = latency_match.group(1)
                elif 'down' in line_stripped.lower():
                    current_host.status = "down"
                    self.report.hosts_down += 1
            
            # Port section header
            elif 'PORT' in line_stripped and 'STATE' in line_stripped:
                in_port_section = True
            
            # Parse port lines
            elif in_port_section and current_host and '/' in line_stripped:
                port = self.parse_port_line(line_stripped)
                if port:
                    current_host.ports.append(port)
                    self.report.total_ports_found += 1
            
            # OS detection
            elif current_host and ('OS:' in line_stripped or 'Running:' in line_stripped):
                os_match = re.search(r'(?:OS:|Running:)\s*(.+)', line_stripped)
                if os_match and not current_host.os:
                    current_host.os = os_match.group(1).strip()
        
        # Don't forget the last host
        if current_host:
            self.report.hosts.append(current_host)
        
        # Generate insights
        self.generate_critical_findings()
        self.generate_recommendations()
        
        return self.report
    
    def generate_critical_findings(self) -> None:
        """Generate critical security findings from scan results."""
        findings = []
        
        # Count dangerous ports
        dangerous_count = 0
        dangerous_hosts = []
        
        for host in self.report.hosts:
            host_dangerous = []
            for port in host.ports:
                if port.security_level == "dangerous" and port.state == "open":
                    dangerous_count += 1
                    host_dangerous.append(f"{port.port}/{port.protocol} ({port.service})")
            
            if host_dangerous:
                dangerous_hosts.append(f"{host.ip}: {', '.join(host_dangerous)}")
        
        if dangerous_count > 0:
            findings.append(f"🚨 {dangerous_count} dangerous port(s) found open across network")
            for host_info in dangerous_hosts[:3]:  # Limit to top 3
                findings.append(f"  ❌ {host_info}")
        
        # Check for common attacks vectors
        telnet_hosts = []
        ftp_hosts = []
        db_exposed = []
        
        for host in self.report.hosts:
            for port in host.ports:
                if port.port == 23 and port.state == "open":
                    telnet_hosts.append(host.ip)
                elif port.port == 21 and port.state == "open":
                    ftp_hosts.append(host.ip)
                elif port.port in [3306, 5432, 1433, 27017] and port.state == "open":
                    db_exposed.append(f"{host.ip}:{port.port} ({port.service})")
        
        if telnet_hosts:
            findings.append(f"⚠️ Telnet detected on {len(telnet_hosts)} host(s) - Use SSH instead!")
        
        if ftp_hosts:
            findings.append(f"⚠️ FTP detected on {len(ftp_hosts)} host(s) - Use SFTP/FTPS instead!")
        
        if db_exposed:
            findings.append(f"⚠️ Database ports exposed: {', '.join(db_exposed[:3])}")
        
        # Positive findings
        if dangerous_count == 0 and self.report.hosts_up > 0:
            findings.append("✅ No dangerous ports detected")
        
        self.report.critical_findings = findings[:5]  # Limit to 5
    
    def generate_recommendations(self) -> None:
        """Generate hardening recommendations based on findings."""
        recommendations = []
        
        # Check what issues we found
        has_telnet = any(p.port == 23 and p.state == "open" for h in self.report.hosts for p in h.ports)
        has_ftp = any(p.port == 21 and p.state == "open" for h in self.report.hosts for p in h.ports)
        has_db = any(p.port in [3306, 5432, 1433, 27017] and p.state == "open" for h in self.report.hosts for p in h.ports)
        has_smb = any(p.port in [139, 445] and p.state == "open" for h in self.report.hosts for p in h.ports)
        has_rdp = any(p.port == 3389 and p.state == "open" for h in self.report.hosts for p in h.ports)
        
        if has_telnet:
            recommendations.append("Disable Telnet service and use SSH for secure remote access")
        
        if has_ftp:
            recommendations.append("Replace FTP with SFTP or FTPS for encrypted file transfer")
        
        if has_db:
            recommendations.append("Firewall database ports - only allow from trusted application servers")
        
        if has_smb:
            recommendations.append("Restrict SMB/NetBIOS to internal network only - disable on internet-facing interfaces")
        
        if has_rdp:
            recommendations.append("Secure RDP: Use VPN, enable NLA, change default port, use strong passwords")
        
        # General recommendations
        recommendations.append("Implement firewall rules to restrict unnecessary port exposure")
        recommendations.append("Regularly scan network for unauthorized services")
        recommendations.append("Use intrusion detection/prevention systems (IDS/IPS)")
        recommendations.append("Keep all services updated with latest security patches")
        
        self.report.recommendations = recommendations
    
    def to_html(self, report: NmapReport = None) -> str:
        """Generate clean HTML output for web/PDF display."""
        if report is None:
            report = self.report
        
        # Proper singular/plural grammar
        hosts_label = "Host" if report.hosts_up == 1 else "Hosts"
        ports_label = "Port" if report.total_ports_found == 1 else "Ports"
        dangerous_count = sum(1 for h in report.hosts for p in h.ports if p.security_level == 'dangerous')
        dangerous_label = "Issue" if dangerous_count == 1 else "Issues"
        
        # Summary cards with better styling
        summary_html = f"""
<div class="nmap-summary-cards">
    <div class="summary-card">
        <div class="card-icon">🖥️</div>
        <div class="card-value">{report.hosts_up}</div>
        <div class="card-label">{hosts_label} Up</div>
    </div>
    <div class="summary-card">
        <div class="card-icon">🔌</div>
        <div class="card-value">{report.total_ports_found}</div>
        <div class="card-label">Open {ports_label}</div>
    </div>
    <div class="summary-card {'card-danger' if dangerous_count > 0 else ''}">
        <div class="card-icon">⚠️</div>
        <div class="card-value">{dangerous_count}</div>
        <div class="card-label">Critical {dangerous_label}</div>
    </div>
</div>
"""
        
        # Hosts detail
        hosts_html = ""
        for host in report.hosts:
            if host.status != "up":
                continue
            
            ports_rows = ""
            for port in host.ports:
                security_class = f"port-{port.security_level}"
                security_icon = "✅" if port.security_level == "safe" else ("⚠️" if port.security_level == "attention" else "❌")
                
                ports_rows += f"""
                <tr class="{security_class}">
                    <td>{port.port}/{port.protocol}</td>
                    <td>{port.state}</td>
                    <td>{port.service}</td>
                    <td>{port.version}</td>
                    <td>{security_icon} {port.security_level.title()}</td>
                </tr>
                """
            
            host_display = f"{host.hostname} ({host.ip})" if host.hostname else host.ip
            
            hosts_html += f"""
            <div class="nmap-host-section">
                <h3>🖥️ {host_display}</h3>
                {f'<p class="host-meta">OS: {host.os}</p>' if host.os else ''}
                <div class="table-wrap">
                    <table>
                        <thead>
                            <tr>
                                <th>Port</th>
                                <th>State</th>
                                <th>Service</th>
                                <th>Version</th>
                                <th>Security</th>
                            </tr>
                        </thead>
                        <tbody>
                            {ports_rows if ports_rows else '<tr><td colspan="5">No open ports</td></tr>'}
                        </tbody>
                    </table>
                </div>
            </div>
            """
        
        html = f"""
<div class="nmap-report">
    <h2>🔍 Network Scan Results</h2>
    
    <div class="scan-info">
        <p><strong>Scan Time:</strong> {report.scan_time or 'N/A'}</p>
        <p><strong>Hosts Scanned:</strong> {report.hosts_up} up, {report.hosts_down} down</p>
    </div>
    
    {summary_html}
    
    {hosts_html}
    
    <div class="section critical">
        <h3>🚨 Critical Findings</h3>
        <ul>
            {''.join([f'<li>{finding}</li>' for finding in report.critical_findings]) or '<li>No critical issues detected</li>'}
        </ul>
    </div>
    
    <div class="section recommendations">
        <h3>✅ Security Recommendations</h3>
        <ol>
            {''.join([f'<li>{rec}</li>' for rec in report.recommendations])}
        </ol>
    </div>
</div>
"""
        return html

# ==================== END NMAP PARSER ====================


app = Flask(__name__)
ALLOWED_NETWORKS = []
WHITELIST_FILE = os.path.join(os.path.dirname(__file__), "whitelist.json")

# ==================== PENTEST AGENT INTEGRATION ====================
# Import pentest agent for web vulnerability scanning
try:
    from pentest_agent import PentestAgent, Finding, ScanStatistics, MitigationDatabase
    PENTEST_AVAILABLE = True
except ImportError:
    PENTEST_AVAILABLE = False
    print("[WARNING] pentest_agent.py not found - Pentest features disabled")

# Thread-safe storage for background pentest scans
# Format: {scan_id: {"status": str, "agent": PentestAgent|None, "error": str|None, "target": str}}
pentest_scans = {}
pentest_scans_lock = threading.Lock()

# ==================== TELEGRAM INTEGRATION ====================
# Configure these with your Telegram bot token and chat ID
TELEGRAM_BOT_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN", "8297536398:AAE-peeeFX7QFB92Hvs3rmwoffHrs1u16nw")  # Set via env or edit here
TELEGRAM_CHAT_ID = os.environ.get("TELEGRAM_CHAT_ID", "")      # Set via env or edit here

def send_pdf_to_telegram(pdf_bytes: bytes, filename: str, caption: str = "", chat_id: str = "") -> dict:
    """
    Send a PDF file to Telegram.
    
    Args:
        pdf_bytes: The PDF content
        filename: Filename for the document
        caption: Optional caption (max 1024 chars)
        chat_id: User's chat ID (uses default TELEGRAM_CHAT_ID if empty)
    
    Returns:
        dict: {"success": bool, "message": str}
    """
    if not TELEGRAM_BOT_TOKEN:
        return {"success": False, "message": "Telegram bot token not configured. Set TELEGRAM_BOT_TOKEN."}
    
    # Use provided chat_id or fall back to global default
    target_chat_id = chat_id.strip() if chat_id else TELEGRAM_CHAT_ID
    
    if not target_chat_id:
        return {"success": False, "message": "No Chat ID provided. Get yours from @userinfobot on Telegram."}
    
    try:
        url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendDocument"
        
        files = {
            "document": (filename, io.BytesIO(pdf_bytes), "application/pdf")
        }
        data = {
            "chat_id": target_chat_id,
            "caption": caption[:1024] if caption else f"📄 {filename}"  # Telegram caption limit
        }
        
        response = requests.post(url, files=files, data=data, timeout=30)
        result = response.json()
        
        if result.get("ok"):
            return {"success": True, "message": "PDF sent to Telegram successfully!"}
        else:
            return {"success": False, "message": f"Telegram API error: {result.get('description', 'Unknown error')}"}
            
    except Exception as e:
        return {"success": False, "message": f"Failed to send to Telegram: {str(e)}"}

# ==================== END TELEGRAM INTEGRATION ====================

# ---------------- Helpers ----------------


def run_cmd(cmd: str, timeout: int = 30) -> str:
    try:
        return subprocess.check_output(cmd, stderr=subprocess.STDOUT, shell=True, timeout=timeout).decode(errors='ignore')
    except Exception as e:
        return f"ERR: {e}"

def get_local_ips():
    ips = {"127.0.0.1","localhost"}
    try:
        out = run_cmd("hostname -I").strip().split()
        ips.update(out)
    except: pass
    try:
        hn = socket.gethostname()
        for r in socket.getaddrinfo(hn, None):
            ips.add(r[4][0])
    except: pass
    return ips

def is_allowed_target(t: str) -> bool:
    if t in ("localhost","127.0.0.1"): return True
    return t in get_local_ips()

def load_whitelist():
    """Load custom whitelist from JSON file, create if missing."""
    try:
        if not os.path.exists(WHITELIST_FILE):
            with open(WHITELIST_FILE, 'w') as f:
                json.dump({"paths": ["/usr/local/bin", "/opt/myapp"]}, f, indent=4)
            os.chmod(WHITELIST_FILE, 0o644)
        with open(WHITELIST_FILE, 'r') as f:
            return json.load(f).get("paths", [])
    except Exception as e:
        print(f"Error loading whitelist: {e}")
        return ["/usr/local/bin", "/opt/myapp"]  # Fallback to default paths

@app.before_request
def restrict_client_ip():
    if not ALLOWED_NETWORKS: return
    addr = request.remote_addr or ""
    try:
        ip = ipaddress.ip_address(addr)
        if not any(ip in net for net in ALLOWED_NETWORKS):
            abort(403)
    except: abort(403)

# ---------------- UI ----------------
BASE_HTML = """
<!doctype html>
<html lang="en" data-theme="dark">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Cybershield Solutions — {{hostname}}</title>
  
  <!-- Favicon -->
  <link rel="icon" type="image/png" href="/static/cshield.png">

  <!-- Bootstrap -->
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
  <!-- Bootstrap Icons -->
  <link href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.3/font/bootstrap-icons.css" rel="stylesheet">
  <!-- Google Fonts -->
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">

<style>
  /* ===== PROFESSIONAL THEME SYSTEM ===== */
  :root {
    /* Dark Theme (Default) */
    --bg-primary: #0a0e1a;
    --bg-secondary: #111827;
    --bg-tertiary: #1a202e;
    --bg-card: linear-gradient(135deg, #1a202e 0%, #151b28 100%);
    --text-primary: #f8fafc;
    --text-secondary: #cbd5e1;
    --text-muted: #94a3b8;
    --border-color: #2d3748;
    --accent-primary: #3b82f6;
    --accent-secondary: #60a5fa;
    --success: #10b981;
    --warning: #f59e0b;
    --danger: #ef4444;
    --info: #06b6d4;
    --shadow-sm: 0 2px 8px rgba(0, 0, 0, 0.4);
    --shadow-md: 0 4px 16px rgba(0, 0, 0, 0.5);
    --shadow-lg: 0 8px 32px rgba(0, 0, 0, 0.6);
    --radius-sm: 8px;
    --radius-md: 12px;
    --radius-lg: 16px;
  }

  html[data-theme="light"] {
    /* Light Theme - High Contrast */
    --bg-primary: #f8fafc;
    --bg-secondary: #ffffff;
    --bg-tertiary: #f1f5f9;
    --bg-card: linear-gradient(135deg, #ffffff 0%, #f8fafc 100%);
    --text-primary: #0f172a;
    --text-secondary: #334155;
    --text-muted: #64748b;
    --border-color: #e2e8f0;
    --accent-primary: #2563eb;
    --accent-secondary: #3b82f6;
    --success: #059669;
    --warning: #d97706;
    --danger: #dc2626;
    --info: #0891b2;
    --shadow-sm: 0 2px 8px rgba(15, 23, 42, 0.08);
    --shadow-md: 0 4px 16px rgba(15, 23, 42, 0.12);
    --shadow-lg: 0 8px 32px rgba(15, 23, 42, 0.16);
  }

  /* ===== GLOBAL STYLES ===== */
  * { box-sizing: border-box; }
  
  body {
    background: var(--bg-primary);
    color: var(--text-primary);
    font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
    font-size: 15px;
    line-height: 1.6;
    margin: 0;
    padding: 0;
    transition: background-color 0.3s ease, color 0.3s ease;
  }

  /* ===== HEADER ===== */
  header {
    position: sticky;
    top: 0;
    z-index: 1000;
    background: var(--bg-secondary);
    border-bottom: 1px solid var(--border-color);
    box-shadow: var(--shadow-sm);
    backdrop-filter: blur(10px);
  }

  .brand {
    display: flex;
    align-items: center;
    gap: 12px;
    color: var(--text-primary);
    text-decoration: none;
    font-weight: 600;
    transition: opacity 0.2s ease;
  }

  .brand:hover { opacity: 0.8; }

  .brand .logo {
    width: 40px;
    height: 40px;
    border-radius: 10px;
    background: linear-gradient(135deg, var(--accent-primary), var(--accent-secondary));
    box-shadow: 0 4px 12px rgba(59, 130, 246, 0.3);
    display: flex;
    align-items: center;
    justify-content: center;
    font-weight: 700;
    color: white;
    font-size: 18px;
  }

  /* ===== NAVIGATION ===== */
  nav.site-nav {
    display: flex;
    gap: 4px;
    flex-wrap: wrap;
  }

  nav.site-nav a {
    color: var(--text-secondary);
    text-decoration: none;
    padding: 8px 14px;
    border-radius: var(--radius-sm);
    font-weight: 500;
    font-size: 14px;
    transition: all 0.2s ease;
    display: inline-flex;
    align-items: center;
    gap: 6px;
  }

  nav.site-nav a:hover {
    background: var(--bg-tertiary);
    color: var(--text-primary);
  }

  nav.site-nav a.active {
    background: var(--accent-primary);
    color: white;
    box-shadow: 0 2px 8px rgba(59, 130, 246, 0.3);
  }

  /* ===== MAIN CONTAINER (FULL WIDTH) ===== */
  .container-main {
    max-width: 100% !important;  /* Full screen width */
    width: 100%;
    margin: 0;
    padding: 20px 40px;  /* Side padding for breathing room */
  }

  /* Header alignment */
  header .container-main {
    padding-left: 40px;
    padding-right: 40px;
  }

  /* ===== CARDS ===== */
  .card {
    background: var(--bg-card);
    border: 1px solid var(--border-color);
    border-radius: var(--radius-md);
    box-shadow: var(--shadow-md);
    padding: 20px;
    margin-bottom: 20px;
    transition: box-shadow 0.3s ease, transform 0.2s ease;
  }

  .card:hover {
    box-shadow: var(--shadow-lg);
    transform: translateY(-2px);
  }

  .card-title {
    font-size: 18px;
    font-weight: 700;
    color: var(--text-primary);
    margin-bottom: 12px;
  }

  /* ===== KPI CARDS ===== */
  .kpi {
    display: flex;
    align-items: center;
    gap: 12px;
    font-weight: 600;
    color: var(--text-primary);
  }

  .kpi i {
    font-size: 24px;
  }

  .badge-soft {
    background: rgba(59, 130, 246, 0.15);
    border: 1px solid rgba(59, 130, 246, 0.3);
    color: var(--accent-secondary);
    border-radius: 20px;
    padding: 4px 12px;
    font-size: 12px;
    font-weight: 600;
  }

  /* ===== TABLES ===== */
  .table-wrap {
    overflow-x: auto;
    border-radius: var(--radius-sm);
    margin-top: 12px;
  }

  table {
    width: 100%;
    border-collapse: collapse;
    font-size: 14px;
    background: var(--bg-secondary);
  }

  thead th {
    background: var(--bg-tertiary);
    color: var(--text-primary);
    font-weight: 600;
    text-align: left;
    padding: 12px 16px;
    border-bottom: 2px solid var(--border-color);
    font-size: 13px;
    text-transform: uppercase;
    letter-spacing: 0.5px;
  }

  tbody td {
    padding: 12px 16px;
    border-bottom: 1px solid var(--border-color);
    color: var(--text-secondary);
  }

  tbody tr {
    transition: background-color 0.2s ease;
  }

  tbody tr:nth-child(even) {
    background: var(--bg-tertiary);
  }

  tbody tr:hover {
    background: rgba(59, 130, 246, 0.08);
  }

  /* ===== CODE BLOCKS ===== */
  pre {
    background: var(--bg-tertiary);
    color: var(--text-secondary);
    padding: 16px;
    border-radius: var(--radius-sm);
    border: 1px solid var(--border-color);
    font-family: 'Courier New', monospace;
    font-size: 13px;
    line-height: 1.5;
    overflow-x: auto;
    margin: 12px 0;
  }

  code {
    background: var(--bg-tertiary);
    color: var(--accent-secondary);
    padding: 2px 6px;
    border-radius: 4px;
    font-size: 13px;
  }

  /* ===== BADGES ===== */
  .sev-crit {
    background: var(--danger);
    color: white;
    padding: 4px 10px;
    border-radius: 6px;
    font-weight: 600;
    font-size: 12px;
  }

  .sev-high {
    background: var(--warning);
    color: white;
    padding: 4px 10px;
    border-radius: 6px;
    font-weight: 600;
    font-size: 12px;
  }

  /* ===== BUTTONS ===== */
  .btn-pill {
    border-radius: 20px;
    padding: 10px 20px;
    font-weight: 600;
    transition: all 0.2s ease;
  }

  .btn-primary {
    background: linear-gradient(135deg, var(--accent-primary), var(--accent-secondary));
    border: none;
    box-shadow: 0 4px 12px rgba(59, 130, 246, 0.3);
  }

  .btn-primary:hover {
    transform: translateY(-2px);
    box-shadow: 0 6px 16px rgba(59, 130, 246, 0.4);
  }

  /* ===== FORMS ===== */
  .form-control {
    background: var(--bg-tertiary);
    border: 1px solid var(--border-color);
    color: var(--text-primary);
    border-radius: var(--radius-sm);
    padding: 10px 14px;
    transition: all 0.2s ease;
  }

  .form-control:focus {
    background: var(--bg-secondary);
    border-color: var(--accent-primary);
    box-shadow: 0 0 0 3px rgba(59, 130, 246, 0.1);
    outline: none;
  }

  .form-label {
    color: var(--text-primary);
    font-weight: 600;
    margin-bottom: 8px;
    font-size: 14px;
  }

  /* ===== ALERTS ===== */
  .alert {
    border-radius: var(--radius-sm);
    padding: 14px 18px;
    margin: 12px 0;
    border-left: 4px solid;
  }

  .alert-danger {
    background: rgba(239, 68, 68, 0.1);
    border-left-color: var(--danger);
    color: var(--text-primary);
  }

  .alert-warning {
    background: rgba(245, 158, 11, 0.1);
    border-left-color: var(--warning);
    color: var(--text-primary);
  }

  .alert-success {
    background: rgba(16, 185, 129, 0.1);
    border-left-color: var(--success);
    color: var(--text-primary);
  }

  /* ===== FOOTER ===== */
  footer {
    text-align: center;
    padding: 24px 0;
    color: var(--text-muted);
    font-size: 13px;
    border-top: 1px solid var(--border-color);
    margin-top: 40px;
  }

  /* ===== THEME TOGGLE ===== */
  #themeToggle {
    background: var(--bg-tertiary);
    border: 1px solid var(--border-color);
    color: var(--text-primary);
    padding: 8px 16px;
    border-radius: 20px;
    font-size: 14px;
    display: flex;
    align-items: center;
    gap: 8px;
    transition: all 0.2s ease;
  }

  #themeToggle:hover {
    background: var(--bg-primary);
    border-color: var(--accent-primary);
  }

  /* ===== DARK MODE FORCED VISIBILITY FIX ===== */
  
  /* Force White Text on ALL main elements when in Dark Mode */
  html[data-theme="dark"] body,
  html[data-theme="dark"] .card,
  html[data-theme="dark"] .card-title,
  html[data-theme="dark"] table,
  html[data-theme="dark"] th,
  html[data-theme="dark"] td,
  html[data-theme="dark"] pre,
  html[data-theme="dark"] code,
  html[data-theme="dark"] h1, 
  html[data-theme="dark"] h2, 
  html[data-theme="dark"] h3, 
  html[data-theme="dark"] h4, 
  html[data-theme="dark"] h5, 
  html[data-theme="dark"] h6,
  html[data-theme="dark"] p,
  html[data-theme="dark"] label,
  html[data-theme="dark"] li,
  html[data-theme="dark"] a:not(.btn) {
      color: #ffffff !important;
  }

  /* Make sure "muted" text is light grey, not dark grey */
  html[data-theme="dark"] .text-muted,
  html[data-theme="dark"] .small {
      color: #cbd5e1 !important;
  }

  /* Fix Input fields: Dark background, White text */
  html[data-theme="dark"] .form-control, 
  html[data-theme="dark"] input,
  html[data-theme="dark"] select,
  html[data-theme="dark"] textarea {
      background-color: var(--bg-tertiary) !important;
      color: #ffffff !important;
      border-color: var(--border-color) !important;
  }

  /* Fix Input Placeholder text to be visible */
  html[data-theme="dark"] .form-control::placeholder {
      color: #94a3b8 !important;
      opacity: 1;
  }

  /* ===== RESPONSIVE ===== */
  @media (max-width: 768px) {
    .container-main { padding: 16px; }
    .card { padding: 16px; }
    nav.site-nav a { font-size: 13px; padding: 6px 10px; }
  }

  
  /* ===== NMAP SUMMARY CARDS (INLINE DISPLAY) ===== */
  .nmap-summary-cards {
    display: flex;
    justify-content: space-between;
    margin: 15px 0;
    gap: 10px;
    flex-wrap: wrap;
  }
  
  .summary-card {
    flex: 1;
    display: flex;
    align-items: center;
    justify-content: center;
    gap: 8px;
    padding: 12px 15px;
    border-radius: 8px;
    border: 2px solid var(--border-color);
    background: var(--bg-tertiary);
    min-width: 200px;
  }
  
  .summary-card.card-danger {
    background: rgba(239, 68, 68, 0.1);
    border-color: rgba(239, 68, 68, 0.3);
  }
  
  .card-icon {
    font-size: 24px;
  }
  
  .card-value {
    font-size: 24px;
    font-weight: bold;
    color: var(--primary);
  }
  
  .card-danger .card-value {
    color: #ef4444;
  }
  
  /* ===== CRITICAL VISIBILITY FIXES ===== */
  
  /* 1. Fix Cards ignoring utility colors (Light/Dark Mode) */
  .card.bg-danger {
      background: var(--danger) !important; /* Use 'background' to override gradient image */
      color: white !important;
  }
  .card.bg-warning {
      background: var(--warning) !important; /* Use 'background' to override gradient image */
      color: white !important;
  }
  .card.text-white h3, .card.text-white div {
      color: white !important;
  }
  
  /* Missing Badge Classes for Vulnerabilities Table */
  .badge-crit { background-color: var(--danger); color: white; }
  .badge-high { background-color: var(--warning); color: white; }
  .badge-med { background-color: var(--info); color: white; }

  /* 2. Fix Dark Mode Table Backgrounds (Prevent White-on-White) */
  [data-theme="dark"] table,
  [data-theme="dark"] .table {
      background-color: var(--bg-tertiary) !important;
      color: white !important;
      --bs-table-bg: var(--bg-tertiary);
      --bs-table-striped-bg: var(--bg-secondary);
      --bs-table-hover-bg: var(--bg-secondary);
  }
  
  [data-theme="dark"] table th {
      background-color: var(--bg-secondary) !important;
      color: white !important;
      border-color: var(--border-color) !important;
  }
  
  [data-theme="dark"] table td {
      background-color: inherit;
      color: white !important;
      border-color: var(--border-color) !important;
  }
  
  /* Fix 'table-danger' rows in Dark Mode (make them dark red, not pink) */
  [data-theme="dark"] .table-danger,
  [data-theme="dark"] .table-danger > th,
  [data-theme="dark"] .table-danger > td {
      background-color: rgba(220, 38, 38, 0.2) !important;
      color: #fca5a5 !important;
      --bs-table-bg: rgba(220, 38, 38, 0.2);
  }

  /* 3. Global Dark Mode Text Override (Safety Net) */
  
  .card-label {
    font-size: 12px;
    color: var(--text-secondary);
    font-weight: 600;
  }
  
  /* Nmap report styling */
  .nmap-report h2 {
    color: var(--primary);
    margin-bottom: 20px;
  }
  
  .nmap-host-section {
    background: var(--bg-tertiary);
    border-radius: 8px;
    padding: 15px;
    margin: 15px 0;
    border: 1px solid var(--border-color);
  }
  
  .nmap-host-section h3 {
    color: var(--primary);
    margin-top: 0;
  }
  
  .port-safe {
    background: rgba(16, 185, 129, 0.1) !important;
  }
  
  .port-attention {
    background: rgba(245, 158, 11, 0.1) !important;
  }
  
  .port-dangerous {
    background: rgba(239, 68, 68, 0.15) !important;
    font-weight: 600;
  }
  
  .scan-info {
    background: var(--bg-tertiary);
    padding: 12px;
    border-radius: 6px;
    margin: 10px 0;
    border-left: 4px solid var(--primary);
  }
  
  .section.critical {
    background: rgba(239, 68, 68, 0.1);
    border: 2px solid rgba(239, 68, 68, 0.3);
    border-radius: 8px;
    padding: 12px;
    margin: 15px 0;
  }
  
  .section.recommendations {
    background: rgba(59, 130, 246, 0.1);
    border: 2px solid rgba(59, 130, 246, 0.3);
    border-radius: 8px;
    padding: 12px;
    margin: 15px 0;
  }
</style>
</head>
<body>
  <header class="py-3">
    <div class="container container-main d-flex align-items-center justify-content-between">
      <a class="brand" href="/">
        <img src="/static/cshield.png" alt="CS" style="width:48px; height:48px; border-radius:8px; margin-right:12px;">
        <div>
          <div class="fw-bold">Cybershield Solutions</div>
          <div class="small" style="opacity: 0.7; color: var(--text-muted)">Professional Security Diagnostics Platform</div>
        </div>
      </a>
      <button id="themeToggle">
        <i class="bi bi-moon-stars"></i> <span>Theme</span>
      </button>
    </div>
    <div class="container container-main pb-2">
      <nav class="site-nav">
        <a href="/" class="{% if request.path=='/' %}active{% endif %}"><i class="bi bi-grid"></i> Overview</a>
        <a href="/vulns" class="{% if request.path.startswith('/vulns') %}active{% endif %}"><i class="bi bi-bug"></i> Vulnerabilities</a>
        <a href="/packages" class="{% if request.path.startswith('/packages') %}active{% endif %}"><i class="bi bi-box-seam"></i> Packages</a>
        <a href="/services" class="{% if request.path.startswith('/services') %}active{% endif %}"><i class="bi bi-hdd-network"></i> Services</a>
        <a href="/logs" class="{% if request.path.startswith('/logs') %}active{% endif %}"><i class="bi bi-journal-text"></i> Logs</a>
        <a href="/sshlogs" class="{% if request.path.startswith('/sshlogs') %}active{% endif %}"><i class="bi bi-shield-lock"></i> SSH</a>
        <a href="/nmap" class="{% if request.path.startswith('/nmap') %}active{% endif %}"><i class="bi bi-radar"></i> Nmap</a>
        <a href="/sshaudit" class="{% if request.path.startswith('/sshaudit') %}active{% endif %}"><i class="bi bi-terminal"></i> SSH-Audit</a>
        <a href="/enum4linux" class="{% if request.path.startswith('/enum4linux') %}active{% endif %}"><i class="bi bi-hdd-network-fill"></i> Enumeration</a>
        <a href="/soc" class="{% if request.path.startswith('/soc') %}active{% endif %}"><i class="bi bi-activity"></i> SOC Dashboard</a>
        <a href="/pentest" class="{% if request.path.startswith('/pentest') %}active{% endif %}"><i class="bi bi-bug-fill"></i> Pentest</a>
        <a href="/report" class="{% if request.path.startswith('/report') %}active{% endif %}"><i class="bi bi-filetype-pdf"></i> Report</a>
      </nav>
    </div>
  </header>

  <main class="container container-main mt-3">
    {{content|safe}}
  </main>

  <footer>
    <div>Cybershield Solutions © 2025 — Professional Security Diagnostics</div>
    <div class="small mt-1" style="opacity: 0.6;">Created by Vitaliy</div>
  </footer>

  <script>
    // Theme toggle with smooth transition
    (function() {
      const key = 'diag.theme';
      const root = document.documentElement;
      const btn = document.getElementById('themeToggle');
      const icon = btn.querySelector('i');
      const text = btn.querySelector('span');
      
      const saved = localStorage.getItem(key) || 'dark';
      root.setAttribute('data-theme', saved);
      updateButton(saved);
      
      btn.addEventListener('click', () => {
        const current = root.getAttribute('data-theme') || 'dark';
        const next = current === 'dark' ? 'light' : 'dark';
        root.setAttribute('data-theme', next);
        localStorage.setItem(key, next);
        updateButton(next);
      });
      
      function updateButton(theme) {
        if (theme === 'dark') {
          icon.className = 'bi bi-sun-fill';
          text.textContent = 'Light';
        } else {
          icon.className = 'bi bi-moon-stars';
          text.textContent = 'Dark';
        }
      }
      
      // Global HTML Escaper
      window.esc = function(str) {
        if (!str) return '';
        return String(str)
          .replace(/&/g, '&amp;')
          .replace(/</g, '&lt;')
          .replace(/>/g, '&gt;')
          .replace(/"/g, '&quot;')
          .replace(/'/g, '&#039;');
      };
    })();
  </script>

  <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>
"""


# ================== SOC DASHBOARD METRICS ==================
# Real-time monitoring: System health, Network, Security events, Logs

from collections import deque

# Store metric history (last 60 data points for graphs)
soc_metric_history = {
    "cpu": deque(maxlen=60),
    "memory": deque(maxlen=60),
    "network_sent": deque(maxlen=60),
    "network_recv": deque(maxlen=60),
    "timestamps": deque(maxlen=60)
}

# Track previous network counters for rate calculation
soc_prev_net = {"bytes_sent": 0, "bytes_recv": 0, "timestamp": time.time()}


def soc_get_system_metrics():
    """Collect system health: CPU, Memory, Disk, Uptime with alert thresholds"""
    cpu_pct = psutil.cpu_percent(interval=1)  # 1 second interval for accurate reading
    cpu_alert = "critical" if cpu_pct > 95 else ("warning" if cpu_pct > 80 else "normal")
    
    mem = psutil.virtual_memory()
    mem_alert = "critical" if mem.percent > 95 else ("warning" if mem.percent > 85 else "normal")
    
    disk = psutil.disk_usage('/')
    disk_alert = "critical" if disk.percent > 98 else ("warning" if disk.percent > 90 else "normal")
    
    try:
        load1, load5, load15 = psutil.getloadavg()
    except (AttributeError, OSError):
        load1, load5, load15 = 0, 0, 0
    
    boot_time = psutil.boot_time()
    uptime_sec = int(time.time() - boot_time)
    uptime_hrs = uptime_sec // 3600
    uptime_days = uptime_hrs // 24
    
    # Store in history for graphs
    now = datetime.datetime.now().strftime("%H:%M:%S")
    soc_metric_history["cpu"].append(cpu_pct)
    soc_metric_history["memory"].append(mem.percent)
    soc_metric_history["timestamps"].append(now)
    
    return {
        "cpu": {"percent": round(cpu_pct, 1), "alert": cpu_alert, "history": list(soc_metric_history["cpu"])},
        "memory": {
            "percent": round(mem.percent, 1),
            "used_gb": round(mem.used / (1024**3), 2),
            "total_gb": round(mem.total / (1024**3), 2),
            "alert": mem_alert,
            "history": list(soc_metric_history["memory"])
        },
        "disk": {
            "percent": round(disk.percent, 1),
            "used_gb": round(disk.used / (1024**3), 1),
            "total_gb": round(disk.total / (1024**3), 1),
            "alert": disk_alert
        },
        "load": {"load1": round(load1, 2), "load5": round(load5, 2), "load15": round(load15, 2)},
        "uptime": {"days": uptime_days, "hours": uptime_hrs % 24},
        "timestamps": list(soc_metric_history["timestamps"])
    }


def soc_get_network_metrics():
    """Collect network traffic rates, active connections"""
    global soc_prev_net
    
    net_io = psutil.net_io_counters()
    current_time = time.time()
    time_delta = current_time - soc_prev_net["timestamp"]
    
    if time_delta > 0:
        sent_per_sec = (net_io.bytes_sent - soc_prev_net["bytes_sent"]) / time_delta
        recv_per_sec = (net_io.bytes_recv - soc_prev_net["bytes_recv"]) / time_delta
    else:
        sent_per_sec = recv_per_sec = 0
    
    soc_prev_net = {"bytes_sent": net_io.bytes_sent, "bytes_recv": net_io.bytes_recv, "timestamp": current_time}
    
    soc_metric_history["network_sent"].append(sent_per_sec / 1024)  # KB/s
    soc_metric_history["network_recv"].append(recv_per_sec / 1024)
    
    try:
        connections = psutil.net_connections(kind='inet')
        active = len([c for c in connections if c.status == 'ESTABLISHED'])
        top_conns = []
        for c in connections[:10]:
            if c.raddr:
                top_conns.append({
                    "local": f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else "N/A",
                    "remote": f"{c.raddr.ip}:{c.raddr.port}",
                    "status": c.status
                })
    except (psutil.AccessDenied, Exception):
        active = 0
        top_conns = []
    
    return {
        "traffic": {
            "sent_kbps": round(sent_per_sec / 1024, 2),
            "recv_kbps": round(recv_per_sec / 1024, 2),
            "sent_total_gb": round(net_io.bytes_sent / (1024**3), 2),
            "recv_total_gb": round(net_io.bytes_recv / (1024**3), 2),
            "sent_history": list(soc_metric_history["network_sent"]),
            "recv_history": list(soc_metric_history["network_recv"])
        },
        "connections": {"active": active, "top": top_conns}
    }


def soc_get_security_events():
    """Collect SSH fails, suspicious processes"""
    events = {"ssh_fails": {"count": 0, "recent": [], "alert": "normal"}, "suspicious_procs": []}
    
    # SSH Failed Attempts - Parse auth.log with better format handling
    try:
        result = subprocess.run(
            ["grep", "-i", "Failed password", "/var/log/auth.log"],
            capture_output=True, text=True, timeout=2, check=False
        )
        if result.returncode == 0:
            lines = result.stdout.strip().splitlines()
            recent = lines[-10:]
            events["ssh_fails"]["count"] = len(lines)
            
            for line in recent:
                try:
                    # Handle two formats:
                    # 1. Standard: "Dec  1 19:11:13 hostname sshd[1883]: Failed password for..."
                    # 2. ISO: "2025-12-01T18:56:52.143081+00:00 hostname sshd[1682]: Failed password for..."
                    
                    time_str = "Unknown"
                    user = "unknown"
                    ip = "unknown"
                    
                    # Detect format and extract time
                    if line[0].isdigit() and 'T' in line[:20]:  # ISO format
                        # Extract ISO timestamp and convert to short format
                        iso_match = re.match(r'(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):\d{2}', line)
                        if iso_match:
                            year, month, day, hour, minute = iso_match.groups()
                            months = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec']
                            time_str = f"{months[int(month)-1]} {int(day)} {hour}:{minute}"
                    else:  # Standard syslog format
                        parts = line.split()
                        if len(parts) >= 3:
                            # "Dec 1 19:11:13" -> "Dec 1 19:11"
                            time_str = f"{parts[0]} {parts[1]} {parts[2][:5]}"
                    
                    # Extract username - handle both "for user" and "for invalid user"
                    if "for invalid user" in line:
                        match = re.search(r'for invalid user (\S+)', line)
                        if match:
                            user = match.group(1)
                    elif "Failed password for" in line:
                        match = re.search(r'Failed password for (\S+)', line)
                        if match:
                            user = match.group(1)
                            # Clean up if it's followed by "from"
                            if " from " in user:
                                user = user.split()[0]
                    
                    # Extract IP address
                    ip_match = re.search(r'from ([\d\.]+)', line)
                    if ip_match:
                        ip = ip_match.group(1)
                    
                    # Only add if we successfully parsed
                    if time_str != "Unknown" or user != "unknown" or ip != "unknown":
                        events["ssh_fails"]["recent"].append({
                            "time": time_str,
                            "user": user,
                            "ip": ip
                        })
                except Exception as e:
                    # Debug: skip malformed lines silently
                    continue
            
            # Alert thresholds
            if len(lines) > 10:
                events["ssh_fails"]["alert"] = "warning"
            if len(lines) > 50:
                events["ssh_fails"]["alert"] = "critical"
    except Exception:
        pass
    
    # Suspicious Processes (high CPU/Memory)
    try:
        for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent', 'username']):
            try:
                pinfo = proc.info
                if pinfo['cpu_percent'] > 50 or pinfo['memory_percent'] > 30:
                    events["suspicious_procs"].append({
                        "pid": pinfo['pid'],
                        "name": pinfo['name'],
                        "cpu": round(pinfo['cpu_percent'], 1),
                        "mem": round(pinfo['memory_percent'], 1),
                        "user": pinfo['username']
                    })
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        events["suspicious_procs"] = sorted(events["suspicious_procs"], key=lambda x: x['cpu'] + x['mem'], reverse=True)[:5]
    except Exception:
        pass
    
    return events


def soc_get_critical_logs(lines=15):
    """Get critical system logs with clean formatting"""
    logs = []
    try:
        # Get errors from journalctl
        result = subprocess.run(
            ["journalctl", "-p", "err", "-n", str(lines), "--no-pager", "-o", "short"],
            capture_output=True, text=True, timeout=3, check=False
        )
        if result.returncode == 0:
            for line in result.stdout.strip().splitlines():
                if line.strip():
                    try:
                        # Parse: Dec 01 19:11:13 hostname service[pid]: message
                        parts = line.split(None, 5)
                        if len(parts) >= 6:
                            # Clean time: "Dec 01 19:11"
                            time_clean = f"{parts[0]} {parts[1]} {parts[2][:5]}"
                            # Clean service: remove [pid]
                            service = parts[4].rstrip(':').split('[')[0]
                            # Truncate message to 100 chars
                            message = parts[5][:100] + ("..." if len(parts[5]) > 100 else "")
                            
                            logs.append({
                                "time": time_clean,
                                "service": service,
                                "message": message,
                                "severity": "error" if "error" in line.lower() or "fail" in line.lower() else "warning"
                            })
                    except Exception:
                        continue
    except Exception:
        # Fallback to syslog
        try:
            result = subprocess.run(
                ["tail", "-n", str(lines), "/var/log/syslog"],
                capture_output=True, text=True, timeout=2, check=False
            )
            if result.returncode == 0:
                for line in result.stdout.strip().splitlines():
                    if line.strip():
                        parts = line.split(None, 4)
                        if len(parts) >= 5:
                            logs.append({
                                "time": f"{parts[0]} {parts[1]} {parts[2][:5]}",
                                "service": "syslog",
                                "message": parts[4][:100] + ("..." if len(parts[4]) > 100 else ""),
                                "severity": "info"
                            })
        except Exception:
            pass
    return logs


def soc_get_all_metrics():
    """Collect all SOC metrics in one call"""
    return {
        "timestamp": datetime.datetime.now().isoformat(),
        "system": soc_get_system_metrics(),
        "network": soc_get_network_metrics(),
        "security": soc_get_security_events(),
        "logs": soc_get_critical_logs(15)
    }

# ============================================================


# Regex helpers for validation
PORT_RANGE_RE = re.compile(r"^\d{1,5}(?:-\d{1,5})?(?:,\d{1,5}(?:-\d{1,5})?)*$")  # 80 or 1-1024 or 80,443,1000-2000
SINGLE_TOKEN_WHITELIST = {"-p-", "-Pn", "-sV", "-v", "-vv", "-A"}  # -A optional (aggressive)
T_TUNING_RE = re.compile(r"^-T[0-5]$")  # -T0 .. -T5

def validate_nmap_extra_args(tokens):
    """
    Validate a list of tokenized extra args for nmap.
    Returns (cleaned_list, None) if OK, or (None, error_msg) if invalid.
    Allowed forms (safe subset only):
      - -p-                         (all ports)
      - -p 80,443 or -p 1-60000     (lists/ranges)
      - -Pn, -sV, -v, -vv, -A
      - -T[0-5]
    Any --script* is rejected.
    Rejects any token containing shell metachars or suspicious chars.
    """
    if not tokens:
        return [], None

    cleaned = []
    i = 0
    forbidden_chars = set(";|&$><`\\")
    while i < len(tokens):
        tok = tokens[i]

        # quick reject of suspicious characters
        if any(c in tok for c in forbidden_chars):
            return None, f"Forbidden character in token: {tok}"

        # hard block any script usage
        if tok.startswith("--script"):
            return None, "NSE scripts are disabled in this UI"

        # exact tokens allowed
        if tok in SINGLE_TOKEN_WHITELIST:
            cleaned.append(tok)
            i += 1
            continue

        # -T[0-5]
        if T_TUNING_RE.match(tok):
            cleaned.append(tok)
            i += 1
            continue

        # -p-
        if tok == "-p-":
            cleaned.append("-p-")
            i += 1
            continue

        # -p <ports>
        if tok == "-p":
            if i + 1 >= len(tokens):
                return None, "Missing argument for -p"
            ports = tokens[i + 1]
            if not PORT_RANGE_RE.match(ports):
                return None, f"Invalid port spec: {ports}"
            # ensure numbers are within 1-65535
            for part in ports.split(","):
                if "-" in part:
                    a,b = part.split("-",1)
                    try:
                        ai,bi = int(a), int(b)
                    except:
                        return None, f"Invalid port numbers in range: {part}"
                    if not (1 <= ai <= 65535 and 1 <= bi <= 65535 and ai <= bi):
                        return None, f"Port range out of bounds: {part}"
                else:
                    try:
                        pi = int(part)
                    except:
                        return None, f"Invalid port number: {part}"
                    if not (1 <= pi <= 65535):
                        return None, f"Port out of bounds: {part}"
            cleaned.extend([tok, ports])
            i += 2
            continue

        # If we reach here token is not allowed
        return None, f"Token not allowed: {tok}"

    return cleaned, None

# nmap
def run_nmap_raw(target: str, extra_args=None, timeout=NMAP_TIMEOUT):
    """
    Execute nmap without shell. extra_args should be a list of tokens (validated).
    Returns (stdout_text, error_message_or_None).
    """
    if not NMAP_BIN:
        return None, "nmap not installed on server"
            
    args = [NMAP_BIN]

    if extra_args is not None:
        # /nmap page: only user-chosen safe args
        args.extend(extra_args)
    else:
        # /report default: fast discovery only, NO -sV, NO scripts
        args.extend(["-Pn", "-T4", "-n", "--max-retries", "1", "-p", "1-60000"])

    if target in args:
        args.remove(target)
    args.append(target)

    try:
        proc = subprocess.run(
            args,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=timeout,
            check=False
        )
    except subprocess.TimeoutExpired:
        return None, f"ERR: nmap timed out after {timeout} seconds"
    except Exception as e:
        return None, f"ERR: exception running nmap: {e}"

    stdout = proc.stdout or ""
    if not stdout:
        return None, "ERR: nmap produced no output"
    return stdout, None



# ---------------- Data collectors ----------------

def collect_nmap(target="localhost", extra_args_tokens=None):
    """
    Returns list of lines (like before). extra_args_tokens should be a list of validated tokens
    (e.g. ['-p','-'] or ['-p-'] or ['-p','1-65535']).
    """
    if not shutil.which("nmap"):
        return ["Nmap not installed on server"]

    out, err = run_nmap_raw(target, extra_args=extra_args_tokens)
    if err:
        return [err]

    lines = out.splitlines()
    return lines[:1000] if len(lines) > 1000 else lines

def build_host_summary():
    hn = os.uname().nodename if hasattr(os, "uname") else "host"
    plat = f"{os.uname().sysname} {os.uname().release}" if hasattr(os, "uname") else sys.platform
    uptime = run_cmd("uptime -p").strip()
    cpu_count = psutil.cpu_count()
    load1, load5, load15 = os.getloadavg()
    vm = psutil.virtual_memory()
    ip_list = ", ".join(sorted(get_local_ips()))
    return {
        "hostname": hn,
        "platform": plat,
        "uptime": uptime,
        "cpu_count": cpu_count,
        "load1": load1, "load5": load5, "load15": load15,
        "mem_used": human(vm.used), "mem_total": human(vm.total), "mem_percent": vm.percent,
        "ips": ip_list,
        "generated": now_utc_iso()
    }

    return summary

# --- TRIVY CACHING SYSTEM ---
TRIVY_CACHE = {
    "data": [],         # List of tuples (sev, pkg, inst, fixed, id, title)
    "raw_json": None,   # Keep raw json if needed for advanced parsing
    "timestamp": 0,
    "status": "idle",   # idle, scanning, error
    "error": None
}
TRIVY_LOCK = threading.Lock()

def refresh_trivy_cache():
    """Background worker to refresh trivy cache."""
    global TRIVY_CACHE
    
    with TRIVY_LOCK:
        if TRIVY_CACHE["status"] == "scanning":
            return
        TRIVY_CACHE["status"] = "scanning"
        TRIVY_CACHE["error"] = None
    
    TRIVY_BIN = shutil.which("trivy")
    if not TRIVY_BIN:
        with TRIVY_LOCK:
            TRIVY_CACHE["status"] = "error"
            TRIVY_CACHE["error"] = "Trivy not installed"
        return

    try:
        # 10x faster scan using rootfs + skip-dirs + vulns only
        result = subprocess.run(
            [
                TRIVY_BIN, "rootfs",
                "--scanners", "vuln",
                "--skip-dirs", "/tmp,/var/cache,/var/log,/proc,/sys,/dev,/run",
                "--quiet",
                "--format", "json",
                "--severity", "HIGH,CRITICAL",
                "/"
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=900,
            check=False
        )
        out = (result.stdout or "").strip()
        err = (result.stderr or "").strip()
        
        if not out:
            error_msg = f"No output. Stderr: {err[:200]}"
            if "lock" in err.lower(): error_msg = "Database locked, retrying..."
            with TRIVY_LOCK:
                TRIVY_CACHE["status"] = "error"
                TRIVY_CACHE["error"] = error_msg
            return

        try:
            data = json.loads(out)
            rows = []
            for res in data.get("Results", []):
                for v in res.get("Vulnerabilities", []) or []:
                    rows.append((
                        v.get("Severity"),
                        v.get("PkgName"),
                        v.get("InstalledVersion"),
                        v.get("FixedVersion") or "-",
                        v.get("VulnerabilityID"),
                        (v.get("Title") or "")[:200]
                    ))
            
            with TRIVY_LOCK:
                TRIVY_CACHE["data"] = rows
                TRIVY_CACHE["raw_json"] = data
                TRIVY_CACHE["timestamp"] = time.time()
                TRIVY_CACHE["status"] = "idle"
                TRIVY_CACHE["error"] = None
                
        except Exception as e:
            with TRIVY_LOCK:
                TRIVY_CACHE["status"] = "error"
                TRIVY_CACHE["error"] = f"JSON Parse Error: {str(e)}"

    except Exception as e:
        with TRIVY_LOCK:
            TRIVY_CACHE["status"] = "error"
            TRIVY_CACHE["error"] = f"Execution Error: {str(e)}"

def collect_trivy(limit=200, force=False):
    """Get trivy results from cache, or trigger clean refresh."""
    global TRIVY_CACHE
    
    # Trigger first run or forced run
    needs_start = False
    with TRIVY_LOCK:
        if force or (not TRIVY_CACHE["data"] and TRIVY_CACHE["status"] == "idle" and not TRIVY_CACHE["error"]):
             needs_start = True
             
    if needs_start:
        threading.Thread(target=refresh_trivy_cache).start()
        if force:
            return ["Scanning started in background... refresh in a minute."]
            
    with TRIVY_LOCK:
        if TRIVY_CACHE["status"] == "scanning" and not TRIVY_CACHE["data"]:
            return ["Scan in progress... please wait."]
        
        if TRIVY_CACHE["error"]:
             return [f"Scan Failed: {TRIVY_CACHE['error']}"]
             
        if not TRIVY_CACHE["data"]:
            # If idle and empty, likely 0 vulns found or not started
            if TRIVY_CACHE["timestamp"] > 0:
                 return ["No High/Critical vulnerabilities found (Clean)"]
            return ["Initializing scan..."]
            
        return TRIVY_CACHE["data"][:limit]


def collect_logs(limit_lines=500):
    logfile = "/var/log/syslog" if os.path.exists("/var/log/syslog") else None
    if os.path.exists("/var/log/auth.log"):
        logfile = "/var/log/auth.log"
    elif os.path.exists("/var/log/secure"):
        logfile = "/var/log/secure"
    if logfile:
        out = run_cmd(f"tail -n {limit_lines} {logfile}")
        return out.splitlines()
    out = run_cmd(f"journalctl -n {limit_lines} --no-pager")
    return out.splitlines()

def collect_ssh_fails(limit=500):
    logfile = "/var/log/auth.log" if os.path.exists("/var/log/auth.log") else "/var/log/secure" if os.path.exists("/var/log/secure") else None
    if not logfile:
        return ["No auth log found"]
    out = run_cmd(f"grep -i 'Failed password\\|Invalid user\\|authentication failure' {logfile} | tail -n {limit}")
    return out.splitlines() or ["No recent failed attempts"]

def collect_processes(limit=200):
    rows = []
    for p in psutil.process_iter(['pid','name','username','cpu_percent','memory_percent','cmdline']):
        try:
            info = p.info
            cmd = " ".join(info.get('cmdline') or [])[:200]
            rows.append((info.get('pid'), info.get('name'), info.get('username'),
                         info.get('cpu_percent'), round(info.get('memory_percent') or 0,2), cmd))
            if len(rows) >= limit:
                break
        except Exception:
            continue
    return rows

def collect_services(limit=300):
    """
    Recull els serveis i els analitza en tuples.
    Retorna llista de tuples: (UNIT, LOAD, ACTIVE, SUB, DESCRIPTION)
    """
    # Filtrem per estats rellevants
    out = run_cmd(f"systemctl list-units --type=service --no-pager --no-legend --state=running,failed,exited,loaded | head -n {limit}")
    rows = []
    
    if out.startswith("ERR:"):
        return [("Error", "Check logs", "Error", "Error", out)]

    lines = out.splitlines()
    if not lines:
        return [("No services found", "-", "-", "-", "-")]

    for line in lines:
        # Separem en 5 columnes: UNIT, LOAD, ACTIVE, SUB, DESCRIPTION
        parts = line.split(None, 4) 
        if len(parts) == 5:
            rows.append(tuple(parts))
        elif len(parts) == 4:
            # De vegades falta la columna SUB
            rows.append((parts[0], parts[1], parts[2], "-", parts[3]))
        elif parts:
            # Fallback per línies parcials
            rows.append((parts[0], "-", "-", "-", " ".join(parts[1:])))
            
    return rows
def collect_upgradable_packages(max_lines=500):
    out = run_cmd("apt list --upgradable 2>/dev/null | tail -n +2")
    if out.startswith("ERR:"):
        return [out]
    lines = out.splitlines()
    return lines[:max_lines] if lines else ["None"]

def collect_suspicious_processes(limit=200):
    """
    Heuristics:
      - Executable path not under standard system paths
      - Executable/command contains .tmp, .sh, .py, /tmp/, hidden names, or weird chars
      - Running as root from user dirs (/home, /tmp)
      - Listening network processes not from standard paths
    """
    std_paths = ('/usr/bin','/bin','/sbin','/usr/sbin','/usr/lib/systemd','/usr/libexec','/lib/systemd','/snap/bin','/usr/local/bin','/opt/myapp')
    all_std_paths = std_paths  # No custom_paths
    sus = []
    listeners = set()
    try:
        for c in psutil.net_connections(kind='inet'):
            if c.status == psutil.CONN_LISTEN and c.pid:
                listeners.add(c.pid)
    except Exception:
        pass

    pattern_weird = re.compile(r'(\.tmp|/tmp/|\.sh\b|\.py\b|\.\w|^\.+|\\x[0-9a-fA-F]{2})')

    for p in psutil.process_iter(['pid','name','username','exe','cmdline']):
        try:
            info = p.info
            exe = info.get('exe') or ''
            cmd = ' '.join(info.get('cmdline') or [])
            uid_root = (info.get('username') == 'root')
            flags = []

            if exe and not exe.startswith(all_std_paths):
                flags.append("non-standard exe path")
            if pattern_weird.search(exe) or pattern_weird.search(cmd):
                flags.append("suspicious name/cmd")
            if uid_root and (exe.startswith('/home/') or '/tmp/' in exe or '/home/' in cmd or '/tmp/' in cmd):
                flags.append("root from user/tmp path")
            if p.pid in listeners and (exe and not exe.startswith(all_std_paths)):
                flags.append("listening from non-standard path")

            if flags:
                sus.append((info['pid'], info['name'], info['username'], exe or '-', cmd or '-', "; ".join(flags)))
                if len(sus) >= limit:
                    break
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue
        except Exception:
            continue

    return sus or [("None","No suspicious processes found","","","","")]

def collect_sshaudit(target_str="localhost"):
    """
    Executa ssh-audit de manera segura i retorna les línies de sortida.
    Accepta "host" (default port 22) o "host:port".
    """
    SSHAUDIT_BIN = shutil.which("ssh-audit")
    if not SSHAUDIT_BIN:
        return ["ssh-audit not installed on server"]

    # Validació de caràcters (per seguretat)
    if not TARGET_RE.match(target_str) or len(target_str) > 255:
        return [f"ERR: Invalid target format for ssh-audit: {target_str}"]

    # ssh-audit accepta "host" o "host:port" directament
    args = [SSHAUDIT_BIN, target_str]

    try:
        # Fem servir subprocess.run amb check=False (igual que a l'API)
        result = subprocess.run(
            args,
            capture_output=True, 
            text=True, 
            timeout=60, # 60 segons de temps d'espera
            errors='ignore',
            check=False # No fallis si troba vulnerabilitats (codi 3)
        )
        
        output = result.stdout or ""
        if result.stderr:
            output += "\n" + result.stderr
        
        lines = output.strip().splitlines()
        return lines if lines else ["No output from ssh-audit"]
    
    except subprocess.TimeoutExpired:
        return [f"ERR: ssh-audit timed out after 60s for {target_str}"]
    except Exception as e:
        return [f"ERR: {e}"]

def collect_enum4linux(target_str="192.168.1.1", options=None):
    """
    Executes enum4linux/enum4linux-ng against a target (IP/hostname) for SMB/NetBIOS enumeration.
    Focus: Linux/Samba servers (Ubuntu, Debian, etc.)
    
    Args:
        target_str: IP address or hostname to enumerate
        options: dict with keys like 'users', 'shares', 'groups', 'policy', 'rid_cycling'
    
    Returns:
        Structured dict with parsed results or error message
    """
    # Try to find enum4linux-ng first (Python rewrite for Ubuntu 24.04+)
    ENUM4LINUX_BIN = None
    
    # Check for enum4linux-ng in the script directory (cloned from GitHub)
    script_dir = os.path.dirname(os.path.abspath(__file__))
    enum4linux_ng_path = os.path.join(script_dir, "enum4linux-ng", "enum4linux-ng.py")
    
    if os.path.exists(enum4linux_ng_path):
        ENUM4LINUX_BIN = enum4linux_ng_path
    else:
        # Try system-installed enum4linux-ng
        ENUM4LINUX_BIN = shutil.which("enum4linux-ng")
        if not ENUM4LINUX_BIN:
            # Fall back to classic enum4linux (Perl version)
            ENUM4LINUX_BIN = shutil.which("enum4linux")
    
    if not ENUM4LINUX_BIN:
        return {
            "error": "enum4linux/enum4linux-ng not installed on server", 
            "install_hint": "Clone enum4linux-ng: git clone https://github.com/cddmp/enum4linux-ng.git"
        }
    
    # Validation: IP or hostname only (no special chars to prevent injection)
    if not TARGET_RE.match(target_str) or len(target_str) > 255:
        return {"error": f"Invalid target format: {target_str}"}
    
    # Build safe command arguments
    # If it's a .py file (enum4linux-ng), run with the SAME Python that's running this script
    # This ensures it uses the venv where impacket is installed
    if ENUM4LINUX_BIN.endswith('.py'):
        args = [sys.executable, ENUM4LINUX_BIN]  # sys.executable = /path/to/venv/bin/python3
    else:
        args = [ENUM4LINUX_BIN]
    
    # Default: -a (all simple enumeration) if no options specified
    if not options or not any(options.values()):
        args.append("-a")
    else:
        if options.get("users"):
            args.append("-U")
        if options.get("shares"):
            args.append("-S")
        if options.get("groups"):
            args.append("-G")
        if options.get("policy"):
            args.append("-P")
    
    args.append(target_str)
    
    try:
        start_time = time.time()
        result = subprocess.run(
            args,
            capture_output=True,
            text=True,
            timeout=120,  # 2 minutes max
            errors='ignore',
            check=False  # enum4linux returns non-zero even on success sometimes
        )
        duration = round(time.time() - start_time, 2)
        
        raw_output = result.stdout or ""
        if result.stderr and "ERROR" in result.stderr.upper():
            raw_output += "\n" + result.stderr
        
        if not raw_output or len(raw_output) < 50:
            return {
                "error": "No output from enum4linux",
                "stderr": result.stderr,
                "hint": "Target might not have SMB/NetBIOS services running or is unreachable"
            }
        
        # Parse the output into structured data
        parsed = parse_enum4linux_output(raw_output, target_str, duration)
        return parsed
    
    except subprocess.TimeoutExpired:
        return {"error": f"enum4linux timed out after 120s for {target_str}"}
    except Exception as e:
        return {"error": f"Exception running enum4linux: {e}"}


def parse_enum4linux_output(raw_text, target, duration):
    """
    Parse enum4linux/enum4linux-ng text output into structured JSON.
    Handles both classic enum4linux (Perl) and enum4linux-ng (Python) formats.
    Extracts: users, shares, groups, OS info, password policy
    """
    result = {
        "target": target,
        "timestamp": now_utc_iso(),
        "scan_duration": duration,
        "raw_output": raw_text,  # Keep full output for debugging
        "summary": {
            "users_found": 0,
            "shares_found": 0,
            "groups_found": 0
        },
        "target_info": {},
        "users": [],
        "groups": [],
        "shares": [],
        "password_policy": {},
        "errors": []
    }
    
    # Remove ANSI color codes (enum4linux-ng uses them)
    ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
    clean_text = ansi_escape.sub('', raw_text)
    lines = clean_text.splitlines()
    
    # Extract Target Info - enum4linux-ng format
    for line in lines:
        # NetBIOS computer name
        if "NetBIOS computer name:" in line:
            result["target_info"]["netbios_name"] = line.split(":")[-1].strip()
        
        # NetBIOS domain name
        if "NetBIOS domain name:" in line:
            domain = line.split(":")[-1].strip().strip("'\"")
            if domain:
                result["target_info"]["netbios_domain"] = domain
        
        # DNS domain
        if "DNS domain:" in line:
            domain = line.split(":")[-1].strip().strip("'\"")
            if domain:
                result["target_info"]["dns_domain"] = domain
        
        # FQDN
        if "FQDN:" in line:
            result["target_info"]["fqdn"] = line.split(":")[-1].strip()
        
        # Domain (RPC)
        if line.strip().startswith("[+] Domain:") or line.strip().startswith("Domain:"):
            domain = line.split(":")[-1].strip()
            if domain and domain != "NULL SID":
                result["target_info"]["domain"] = domain
        
        # OS info (classic enum4linux)
        if "OS=" in line or "Server=" in line:
            if "OS=" in line:
                match = re.search(r'OS=([^,\]]+)', line)
                if match:
                    result["target_info"]["os"] = match.group(1).strip()
            if "Server=" in line:
                match = re.search(r'Server=([^,\]]+)', line)
                if match:
                    result["target_info"]["server"] = match.group(1).strip()
        
        # Domain Name (classic)
        if "Domain Name:" in line:
            result["target_info"]["domain"] = line.split("Domain Name:")[-1].strip()
        
        # Workgroup (classic)
        if "Workgroup" in line and ":" in line and "Member" not in line:
            result["target_info"]["workgroup"] = line.split(":")[-1].strip()
    
    # Extract Users - Classic enum4linux format
    # Pattern: user:[username] rid:[0xHEX]
    user_pattern1 = re.compile(r'user:\[([^\]]+)\]\s+rid:\[(0x[0-9a-fA-F]+)\]')
    for match in user_pattern1.finditer(raw_text):
        username = match.group(1)
        rid = match.group(2)
        if username and username not in [u["username"] for u in result["users"]]:
            result["users"].append({"username": username, "rid": rid})
    
    # Pattern 2: Simple user listing
    if not result["users"]:
        for line in lines:
            if line.strip().startswith("user:"):
                parts = line.split()
                if len(parts) >= 2:
                    result["users"].append({"username": parts[1], "rid": "N/A"})
    
    result["summary"]["users_found"] = len(result["users"])
    
    # Extract Shares - enum4linux-ng format
    # Pattern: "sharename:\n  comment: ...\n  type: ..."
    in_shares_section = False
    current_share = None
    
    for line in lines:
        # Detect start of shares section
        if "Found" in line and "share" in line.lower():
            in_shares_section = True
            continue
        
        # Detect end of shares section (next major section or testing shares)
        if in_shares_section and ("Testing share" in line or "Completed after" in line or "====" in line):
            if current_share:
                result["shares"].append(current_share)
                current_share = None
            in_shares_section = False
            continue
        
        if in_shares_section:
            # New share (line ends with :)
            if line.strip() and line.strip().endswith(':') and not line.strip().startswith('comment:') and not line.strip().startswith('type:'):
                # Save previous share
                if current_share:
                    result["shares"].append(current_share)
                # Start new share
                share_name = line.strip().rstrip(':')
                current_share = {"name": share_name, "comment": "", "type": "Unknown", "accessible": False}
            # Comment line
            elif current_share and "comment:" in line.lower():
                current_share["comment"] = line.split(":", 1)[-1].strip().strip("'\"")
            # Type line
            elif current_share and "type:" in line.lower():
                current_share["type"] = line.split(":", 1)[-1].strip()
        
        # Check for share accessibility (later in output)
        if "Mapping: OK" in line:
            # Find which share this refers to
            for s in result["shares"]:
                if s["name"] in line or line in raw_text[raw_text.find(s["name"]):raw_text.find(s["name"])+200]:
                    s["accessible"] = True
    
    # Add last share if exists
    if current_share:
        result["shares"].append(current_share)
    
    # Classic enum4linux share format
    if not result["shares"]:
        share_section = False
        for i, line in enumerate(lines):
            if "Sharename" in line and "Type" in line:
                share_section = True
                continue
            
            if share_section:
                if line.strip().startswith("-") or not line.strip():
                    continue
                if line.strip() and not line.startswith("[") and not line.startswith("="):
                    parts = line.split()
                    if len(parts) >= 2:
                        sharename = parts[0]
                        sharetype = parts[1] if len(parts) > 1 else "Unknown"
                        comment = " ".join(parts[2:]) if len(parts) > 2 else ""
                        
                        accessible = "Mapping: OK" in raw_text or "Access: " in raw_text
                        
                        result["shares"].append({
                            "name": sharename,
                            "type": sharetype,
                            "comment": comment,
                            "accessible": accessible
                        })
                
                # Stop at next section
                if "=" * 10 in line or "[+" in line:
                    share_section = False
    
    result["summary"]["shares_found"] = len(result["shares"])
    
    # Extract Groups - Classic format
    # Pattern: group:[groupname] rid:[0xHEX]
    group_pattern = re.compile(r'group:\[([^\]]+)\]\s+rid:\[(0x[0-9a-fA-F]+)\]')
    for match in group_pattern.finditer(raw_text):
        groupname = match.group(1)
        rid = match.group(2)
        if groupname and groupname not in [g["groupname"] for g in result["groups"]]:
            result["groups"].append({"groupname": groupname, "rid": rid})
    
    result["summary"]["groups_found"] = len(result["groups"])
    
    # Extract Password Policy
    for line in lines:
        if "Minimum password length:" in line:
            result["password_policy"]["min_length"] = line.split(":")[-1].strip()
        if "Password complexity:" in line or "Password Complexity:" in line:
            result["password_policy"]["complexity"] = line.split(":")[-1].strip()
        if "Lockout threshold:" in line:
            result["password_policy"]["lockout_threshold"] = line.split(":")[-1].strip()
    
    # Detect errors
    if "Access denied" in raw_text or "NT_STATUS_ACCESS_DENIED" in raw_text:
        result["errors"].append("Access denied - credentials may be required")
    if "Connection refused" in raw_text or "failed to connect" in raw_text.lower():
        result["errors"].append("Connection refused - SMB service may not be running")
    
    return result

# ---------------- Routes ----------------
@app.route("/")
def overview():
    hn = os.uname().nodename if hasattr(os, "uname") else "host"
    uptime = run_cmd("uptime -p")
    cpu_count, load1, _, _ = psutil.cpu_count(), *os.getloadavg()
    vm = psutil.virtual_memory()

    summary = {"CRITICAL": 0, "HIGH": 0}
    summary = {"CRITICAL": 0, "HIGH": 0}
    
    # Use Cached Collection
    t_rows = collect_trivy()
    if isinstance(t_rows, list) and t_rows and isinstance(t_rows[0], tuple):
        for row in t_rows:
            sev = row[0]
            if sev in summary:
                summary[sev] += 1

    upg_count_raw = run_cmd("apt list --upgradable 2>/dev/null | tail -n +2 | wc -l").strip()
    try:
        upg = int(upg_count_raw)
    except:
        upg = 0

    logfile = "/var/log/auth.log" if os.path.exists("/var/log/auth.log") else "/var/log/secure"
    sshfails, top = 0, []
    if os.path.exists(logfile):
        out = run_cmd(f"grep -i 'failed password' {logfile} | tail -n 500")
        ips = collections.Counter(p for line in out.splitlines() for p in line.split() if p.count(".") == 3)
        sshfails, top = sum(ips.values()), ips.most_common(5)

    disk_html = "<div class='table-wrap'><table><tr><th>Mount</th><th>Used</th><th>Total</th><th>%</th></tr>"
    for p in psutil.disk_partitions():
        if os.path.exists(p.mountpoint):
            du = psutil.disk_usage(p.mountpoint)
            disk_html += f"<tr><td>{p.mountpoint}</td><td>{human(du.used)}</td><td>{human(du.total)}</td><td>{du.percent}%</td></tr>"
    disk_html += "</table></div>"

    offenders = "<ul>" + "".join(f"<li>{ip}: {c}</li>" for ip, c in top) + "</ul>" if top else "<div>No recent fails</div>"

    content = f"""
    <div class="row g-3">
      <div class="col-md-3">
        <div class="card p-3">
          <div class="kpi"><i class="bi bi-x-octagon-fill text-danger"></i> CRITICAL Vulns</div>
          <div class="display-6 fw-bold mt-1">{summary['CRITICAL']}</div>
          <span class="badge-soft mt-2">Trivy</span>
        </div>
      </div>
      <div class="col-md-3">
        <div class="card p-3">
          <div class="kpi"><i class="bi bi-exclamation-triangle-fill text-warning"></i> HIGH Vulns</div>
          <div class="display-6 fw-bold mt-1">{summary['HIGH']}</div>
          <span class="badge-soft mt-2">Trivy</span>
        </div>
      </div>
      <div class="col-md-3">
        <div class="card p-3">
          <div class="kpi"><i class="bi bi-arrow-bar-up"></i> Upgradable Pkgs</div>
          <div class="display-6 fw-bold mt-1">{upg}</div>
          <span class="badge-soft mt-2">APT</span>
        </div>
      </div>
      <div class="col-md-3">
        <div class="card p-3">
          <div class="kpi"><i class="bi bi-shield-exclamation"></i> SSH fails</div>
          <div class="display-6 fw-bold mt-1">{sshfails}</div>
          <span class="badge-soft mt-2">Auth log</span>
        </div>
      </div>
    </div>
    <div class="card p-3"><b>CPU:</b> {load1:.2f} load • {cpu_count} cores</div>
    <div class="card p-3"><b>Memory:</b> {human(vm.used)} / {human(vm.total)} ({vm.percent}%)</div>
    <div class="card p-3"><h3 class="card-title">Disk Usage</h3>{disk_html}</div>
    <div class="card p-3"><h3 class="card-title">Top SSH offenders</h3>{offenders}</div>
    <div class="text-secondary small">Updated: {now_utc_iso()} UTC</div>
    <hr>
    <h3>Generate Report</h3>
    <form action="/report#csv" method="get">
      <button class="btn btn-primary btn-pill mt-2" type="submit"><i class="bi bi-file-earmark-text"></i> Go to Report page</button>
    </form>
    """

    return render_template_string(BASE_HTML, hostname=hn, content=content)


#ssh audit
# (Substitueix la teva funció @app.route("/sshaudit") per aquesta)

@app.route("/sshaudit", methods=["GET"])
def ui_sshaudit():
    # CORREGIT: Indentació de 4 espais
    hostname = os.uname().nodename if hasattr(os, "uname") else "host"

    # CORREGIT: Indentació de 4 espais
    content = """
    <h1>SSH Audit</h1>
    <p class="muted">
      Audit a host via <code>ssh-audit</code> (if installed). 
      You can specify any IP or hostname. 
      If you use the default port (22), it will run as <code>ssh-audit host</code>; 
      if you change the port, it will run as <code>ssh-audit host:port</code>.
    </p>

    <div class="card">
      <form id="sshAuditForm" onsubmit="return runSshAudit()">
        <label>Host/IP</label>
        <input type="text" class="form-control mb-2" id="saTarget" value="localhost" placeholder="ex: 192.168.1.93 or hostname" />

        <label>Port</label>
        <input type="number" class="form-control mb-2" id="saPort" value="22" min="1" max="65535" />

        <button class="btn btn-primary btn-pill" type="submit">Run ssh-audit</button>

        <div id="saLoading" style="display:none; text-align:center; margin-top:10px;">
          <div class="spinner-border text-info" role="status" style="width:2.5rem; height:2.5rem;"></div>
          <div class="mt-2">Auditing... (may take up to 60s)</div>
        </div>
      </form>
    </div>

    <div class="card">
      <h3>Result</h3>
      <div id="saOutput" style="min-height:140px;"></div>
    </div>

    <style>
      /* SSH Audit Report Styling */
      .ssh-audit-report h2,
      .ssh-audit-report h3,
      .ssh-audit-report h4 {
        color: var(--text-primary);
        margin-top: 20px;
        margin-bottom: 10px;
      }
      
      .ssh-audit-report .section {
        margin-bottom: 24px;
        padding: 16px;
        background: var(--bg-tertiary);
        border-radius: var(--radius-sm);
        border: 1px solid var(--border-color);
      }
      
      .ssh-audit-report .algo-group {
        margin-bottom: 16px;
      }
      
      .ssh-audit-report .algo-group h4 {
        margin-bottom: 8px;
        font-size: 14px;
        font-weight: 600;
      }
      
      .ssh-audit-report .algo-group h4.secure {
        color: var(--success);
      }
      
      .ssh-audit-report .algo-group h4.weak {
        color: var(--warning);
      }
      
      .ssh-audit-report .algo-group h4.fail {
        color: var(--danger);
      }
      
      .ssh-audit-report .algo-group ul {
        list-style: none;
        padding-left: 0;
        font-size: 13px;
      }
      
      .ssh-audit-report .algo-group ul li {
        padding: 4px 0;
        color: var(--text-secondary);
      }
      
      .ssh-audit-report table {
        width: 100%;
        margin-top: 8px;
      }
      
      .ssh-audit-report .section.critical {
        background: rgba(239, 68, 68, 0.1);
        border-color: var(--danger);
      }
      
      .ssh-audit-report .section.recommendations {
        background: rgba(16, 185, 129, 0.1);
        border-color: var(--success);
      }
      
      .ssh-audit-report code {
        background: var(--bg-secondary);
        padding: 2px 6px;
        border-radius: 4px;
        font-size: 12px;
      }
      
      .ssh-audit-report ol {
        padding-left: 20px;
      }
      
      .ssh-audit-report ol li {
        margin-bottom: 8px;
      }
    </style>

    <script>
      function runSshAudit() {
        const t = (document.getElementById('saTarget').value || '').trim() || 'localhost';
        const p = parseInt(document.getElementById('saPort').value, 10) || 22;

        const out = document.getElementById('saOutput');
        const spinner = document.getElementById('saLoading');

        if (!t) {
          out.innerHTML = "<div class='alert alert-danger'>Error: A host or IP is required.</div>";
          return false;
        }

        out.innerHTML = "";
        spinner.style.display = 'block';

        // Calls the secure endpoint /api/run_ssh_audit
        fetch('/api/run_ssh_audit', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ target: t, port: p })
        })
        .then(r => r.json())
        .then(d => {
          // Check if the API returned an error
          if (d && d.error) {
            out.innerHTML = `<div class="alert alert-danger">${esc(d.error)}</div>`;
          } else if (d && d.html) {
            // Display the structured HTML report
            out.innerHTML = d.html;
            
            // Add raw output section below (visible by default for technical users)
            if (d.output) {
              out.innerHTML += `
                <div class="mt-4">
                  <h3>Raw SSH Audit Output</h3>
                  <p class="text-muted small">Technical details for verification and debugging</p>
                  <pre style="max-height:400px; overflow-y:auto; background: var(--bg-tertiary); padding: 15px; border-radius: 6px; border: 1px solid var(--border-color);">${esc(d.output)}</pre>
                </div>
              `;
            }
          } else if (d && d.output !== undefined) {
            // Fallback to raw output if no HTML
            out.innerHTML = `<pre>${esc(d.output)}</pre>`;
          } else {
            out.innerHTML = `<pre>${esc(JSON.stringify(d, null, 2))}</pre>`;
          }
        })
        .catch(e => {
          out.innerHTML = `<div class="alert alert-danger">Error: ${esc(e)}</div>`;
        })
        .finally(() => {
          spinner.style.display = 'none';
        });

        return false; // prevents classic form submission
      }
    </script>
    """

    # CORREGIT: Indentació de 4 espais
    return render_template_string(BASE_HTML, hostname=hostname, content=content)

# CORREGIT: Sense indentació (nivell superior)
TARGET_RE = re.compile(r"^[a-zA-Z0-9\.\-_:]+$") 

@app.route("/api/run_ssh_audit", methods=["POST"])
def api_run_ssh_audit():
    # CORREGIT: Indentació de 4 espais
    SSHAUDIT_BIN = shutil.which("ssh-audit")
    if not SSHAUDIT_BIN:
        return jsonify({"error": "ssh-audit not installed on server"}), 400

    payload = request.get_json() or {}
    target = (payload.get("target") or "localhost").strip()
    port = int(payload.get("port") or 22)

    if not target:
        return jsonify({"error": "Target is required"}), 400
    
    # Basic character validation to avoid surprises
    if not TARGET_RE.match(target) or len(target) > 255:
        return jsonify({"error": "Invalid target format. Use hostname or IP."}), 400

    if not (1 <= port <= 65535):
        return jsonify({"error": "Invalid port number"}), 400

    # Build the argument list for shell=False (MUCH SAFER)
    args = [SSHAUDIT_BIN]
    target_str = target
    if port != 22:
        # ssh-audit accepts host:port syntax
        target_str = f"{target}:{port}"

    args.append(target_str)

    try:
        # Use subprocess.run with check=False
        # This is immune to command injection and captures the output
        # even if the exit code is 3 (vulnerabilities found)
        result = subprocess.run(
            args,
            capture_output=True, 
            text=True, 
            timeout=60, # 60 second timeout
            errors='ignore',
            check=False # <-- THE KEY: Don't raise exception if code is not 0
        )
        
        # Combine stdout and stderr for raw output
        raw_output = result.stdout or ""
        if result.stderr:
            raw_output += "\n" + result.stderr
        
        # Parse the output with the professional SSH audit parser
        try:
            parser = SSHAuditParser()
            report = parser.parse(raw_output)
            html_report = parser.to_html(report)
            
            # Return both structured HTML and raw output
            return jsonify({
                "target": target_str, 
                "output": raw_output.strip(),
                "html": html_report,
                "parsed": True
            })
        except Exception as parse_error:
            # If parsing fails, return raw output
            return jsonify({
                "target": target_str, 
                "output": raw_output.strip(),
                "html": f"<pre>{raw_output}</pre>",
                "parsed": False,
                "parse_error": str(parse_error)
            })
    
    except subprocess.TimeoutExpired:
        return jsonify({"error": f"ERR: Command timed out after 60s for {target_str}"}), 500
    except Exception as e:
        # Other errors (e.g., permission denied)
        return jsonify({"error": f"ERR: {e}"}), 500

# ---------------- enum4linux (SMB/NetBIOS Enumeration) ----------------

@app.route("/enum4linux", methods=["GET"])
def ui_enum4linux():
    """UI page for enum4linux SMB/NetBIOS enumeration"""
    hostname = os.uname().nodename if hasattr(os, "uname") else "host"
    
    content = f"""
    <h1>SMB/NetBIOS Enumeration (enum4linux)</h1>
    <p class="muted">
      Enumerate information from Linux/Samba servers via SMB/NetBIOS protocols.
      Discovers users, shares, groups, password policies, and system information.
      <br><strong>Focus:</strong> Ubuntu/Debian servers running Samba.
    </p>

    <div class="card">
      <form id="enumForm" onsubmit="return runEnum()">
        <label>Target IP/Hostname</label>
        <input type="text" class="form-control mb-2" id="enumTarget" value="192.168.1.1" placeholder="ex: 192.168.1.10 or server.local" />
        
        <label>Enumeration Options</label>
        <div class="row mb-2">
          <div class="col-6">
            <div class="form-check">
              <input class="form-check-input" type="checkbox" id="optUsers" checked />
              <label class="form-check-label" for="optUsers">Users (-U)</label>
            </div>
            <div class="form-check">
              <input class="form-check-input" type="checkbox" id="optShares" checked />
              <label class="form-check-label" for="optShares">Shares (-S)</label>
            </div>
            <div class="form-check">
              <input class="form-check-input" type="checkbox" id="optGroups" />
              <label class="form-check-label" for="optGroups">Groups (-G)</label>
            </div>
          </div>
          <div class="col-6">
            <div class="form-check">
              <input class="form-check-input" type="checkbox" id="optPolicy" />
              <label class="form-check-label" for="optPolicy">Password Policy (-P)</label>
            </div>
            <div class="form-check">
              <input class="form-check-input" type="checkbox" id="optRID" />
              <label class="form-check-label" for="optRID">RID Cycling (-r)</label>
            </div>
          </div>
        </div>

        <button class="btn btn-primary btn-pill" type="submit">Run Enumeration</button>

        <div id="enumLoading" style="display:none; text-align:center; margin-top:10px;">
          <div class="spinner-border text-info" role="status" style="width:2.5rem; height:2.5rem;"></div>
          <div class="mt-2">Enumerating... (may take up to 120s)</div>
        </div>
      </form>
    </div>

    <div class="card" id="resultsCard" style="display:none;">
      <h3>Enumeration Results</h3>
      <div id="enumSummary" class="mb-3"></div>
      <div id="enumResults"></div>
    </div>

    <div class="card" id="rawCard" style="display:none;">
      <h3>Raw Output</h3>
      <pre id="rawOutput" style="max-height:400px; overflow-y:auto;"></pre>
    </div>

    <script>
      function runEnum() {{
        const target = (document.getElementById('enumTarget').value || '').trim();
        const spinner = document.getElementById('enumLoading');
        const resultsCard = document.getElementById('resultsCard');
        const rawCard = document.getElementById('rawCard');
        const summaryDiv = document.getElementById('enumSummary');
        const resultsDiv = document.getElementById('enumResults');
        const rawOutput = document.getElementById('rawOutput');

        if (!target) {{
          alert('Please enter a target IP or hostname');
          return false;
        }}

        // Collect options
        const options = {{
          users: document.getElementById('optUsers').checked,
          shares: document.getElementById('optShares').checked,
          groups: document.getElementById('optGroups').checked,
          policy: document.getElementById('optPolicy').checked,
          rid_cycling: document.getElementById('optRID').checked
        }};

        resultsCard.style.display = 'none';
        rawCard.style.display = 'none';
        spinner.style.display = 'block';

        fetch('/api/run_enum4linux', {{
          method: 'POST',
          headers: {{ 'Content-Type': 'application/json' }},
          body: JSON.stringify({{ target: target, options: options }})
        }})
        .then(r => r.json())
        .then(data => {{
          spinner.style.display = 'none';
          
          if (data.error) {{
            resultsDiv.innerHTML = '<div class="alert alert-danger">' + esc(data.error) + (data.install_hint ? '<br><small>' + esc(data.install_hint) + '</small>' : '') + '</div>';
            resultsCard.style.display = 'block';
            return;
          }}

          // Display summary
          const summary = data.summary || {{}};
          summaryDiv.innerHTML = `
            <div class="row g-2">
              <div class="col-md-4">
                <div class="card p-2" style="background: rgba(34,197,94,0.1); border: 1px solid rgba(34,197,94,0.3); color: var(--text-primary);">
                  <div><i class="bi bi-people-fill"></i> <strong>${{summary.users_found || 0}}</strong> Users Found</div>
                </div>
              </div>
              <div class="col-md-4">
                <div class="card p-2" style="background: rgba(59,130,246,0.1); border: 1px solid rgba(59,130,246,0.3); color: var(--text-primary);">
                  <div><i class="bi bi-folder-fill"></i> <strong>${{summary.shares_found || 0}}</strong> Shares Found</div>
                </div>
              </div>
              <div class="col-md-4">
                <div class="card p-2" style="background: rgba(168,85,247,0.1); border: 1px solid rgba(168,85,247,0.3); color: var(--text-primary);">
                  <div><i class="bi bi-collection-fill"></i> <strong>${{summary.groups_found || 0}}</strong> Groups Found</div>
                </div>
              </div>
            </div>
          `;

          let html = '';

          // Target Info
          if (data.target_info && Object.keys(data.target_info).length > 0) {{
            html += '<h4>Target Information</h4><div class="table-wrap"><table>';
            html += '<tr><th>Property</th><th>Value</th></tr>';
            for (const [key, val] of Object.entries(data.target_info)) {{
              html += `<tr><td>${{key}}</td><td>${{val}}</td></tr>`;
            }}
            html += '</table></div>';
          }}

          // Users
          if (data.users && data.users.length > 0) {{
            html += '<h4 class="mt-3">Users</h4><div class="table-wrap"><table>';
            html += '<tr><th>Username</th><th>RID</th></tr>';
            data.users.forEach(u => {{
              html += `<tr><td>${{u.username}}</td><td><code>${{u.rid}}</code></td></tr>`;
            }});
            html += '</table></div>';
          }}

          // Shares
          if (data.shares && data.shares.length > 0) {{
            html += '<h4 class="mt-3">Shares</h4><div class="table-wrap"><table>';
            html += '<tr><th>Share Name</th><th>Type</th><th>Comment</th><th>Status</th></tr>';
            data.shares.forEach(s => {{
              const badge = s.accessible ? '<span class="badge bg-success">Accessible</span>' : '<span class="badge bg-secondary">Unknown</span>';
              html += `<tr><td><strong>${{s.name}}</strong></td><td>${{s.type}}</td><td>${{s.comment}}</td><td>${{badge}}</td></tr>`;
            }});
            html += '</table></div>';
          }}

          // Groups
          if (data.groups && data.groups.length > 0) {{
            html += '<h4 class="mt-3">Groups</h4><div class="table-wrap"><table>';
            html += '<tr><th>Group Name</th><th>RID</th></tr>';
            data.groups.forEach(g => {{
              html += `<tr><td>${{g.groupname}}</td><td><code>${{g.rid}}</code></td></tr>`;
            }});
            html += '</table></div>';
          }}

          // Password Policy
          if (data.password_policy && Object.keys(data.password_policy).length > 0) {{
            html += '<h4 class="mt-3">Password Policy</h4><div class="table-wrap"><table>';
            html += '<tr><th>Policy</th><th>Value</th></tr>';
            for (const [key, val] of Object.entries(data.password_policy)) {{
              html += `<tr><td>${{key.replace(/_/g, ' ')}}</td><td>${{val}}</td></tr>`;
            }}
            html += '</table></div>';
          }}

          // Errors/Warnings
          if (data.errors && data.errors.length > 0) {{
            html += '<div class="alert alert-warning mt-3"><strong>Warnings:</strong><ul>';
            data.errors.forEach(err => {{
              html += `<li>${{err}}</li>`;
            }});
            html += '</ul></div>';
          }}

          resultsDiv.innerHTML = html || '<p class="text-muted">No structured data found. See raw output below.</p>';
          resultsCard.style.display = 'block';

          // Show raw output
          if (data.raw_output) {{
            rawOutput.textContent = data.raw_output;
            rawCard.style.display = 'block';
          }}
        }})
        .catch(e => {{
          spinner.style.display = 'none';
          resultsDiv.innerHTML = '<div class="alert alert-danger">Error: ' + e + '</div>';
          resultsCard.style.display = 'block';
        }});

        return false;
      }}
    </script>
    """
    
    return render_template_string(BASE_HTML, hostname=hostname, content=content)


@app.route("/api/run_enum4linux", methods=["POST"])
def api_run_enum4linux():
    """API endpoint for enum4linux enumeration"""
    payload = request.get_json() or {}
    target = (payload.get("target") or "").strip()
    options = payload.get("options") or {}
    
    if not target:
        return jsonify({"error": "Target is required"}), 400
    
    # Run enumeration
    result = collect_enum4linux(target, options=options)
    
    # Check if error in result
    if "error" in result:
        return jsonify(result), 400
    
    return jsonify(result)

#vulnerab
@app.route("/vulns")
def ui_vulns():
    hostname = os.uname().nodename
    
    if request.args.get('refresh'):
        collect_trivy(force=True)
        return '<script>window.location.href="/vulns";</script>'

    if not shutil.which("trivy"):
        content = "<h1>Trivy not installed</h1><p>Install trivy to enable vulnerability scanning.</p>"
        return render_template_string(BASE_HTML, hostname=hostname, content=content)
    
    # Get Cached Data
    rows_data = collect_trivy(limit=5000)
    
    # Build Stats
    summary = {"CRITICAL": 0, "HIGH": 0}
    html_rows = ""
    
    status_msg = ""
    last_upd = ""
    with TRIVY_LOCK:
        if TRIVY_CACHE["status"] == "scanning":
            status_msg = "<div class='alert alert-info'>Background scan in progress... Refresh page in a few moments.</div>"
        if TRIVY_CACHE["timestamp"] > 0:
            last_upd = f"<small class='text-muted'>Last scan: {datetime.datetime.fromtimestamp(TRIVY_CACHE['timestamp']).strftime('%H:%M:%S')}</small>"

    if isinstance(rows_data, list) and rows_data and isinstance(rows_data[0], tuple):
        for r in rows_data:
            sev, pkg, inst, fixed, cve, title = r
            if sev in summary: summary[sev] += 1
            
            badge_cls = "badge-crit" if sev == "CRITICAL" else "badge-high"
            html_rows += f"""<tr class="{'table-danger' if sev=='CRITICAL' else ''}">
               <td><span class="badge {badge_cls}">{sev}</span></td>
               <td>{pkg}</td>
               <td>{inst}</td>
               <td>{fixed}</td>
               <td><a href="https://nvd.nist.gov/vuln/detail/{cve}" target="_blank">{cve}</a></td>
               <td>{title}</td>
            </tr>"""
    else:
        # It's an error message or list of strings
        msg = rows_data[0] if rows_data else "No data"
        html_rows = f"<tr><td colspan='6'>{msg}</td></tr>"

    content = f"""
    <div class="d-flex justify-content-between align-items-center mb-3">
        <h1>System Vulnerabilities ({summary['CRITICAL'] + summary['HIGH']})</h1>
        <div>
            {last_upd}
            <a href="/vulns?refresh=1" class="btn btn-primary ms-2"><i class="bi bi-arrow-clockwise"></i> Refresh Scan</a>
        </div>
    </div>
    
    {status_msg}
    
    <div class="row mb-3">
        <div class="col-md-3">
            <div class="card p-3 bg-danger text-white">
                <h3>{summary['CRITICAL']}</h3>
                <div>CRITICAL</div>
            </div>
        </div>
        <div class="col-md-3">
            <div class="card p-3 bg-warning">
                <h3>{summary['HIGH']}</h3>
                <div>HIGH</div>
            </div>
        </div>
    </div>

    <div class="card p-3">
        <div class="table-responsive">
            <table class="table table-hover" id="vulnsTable">
                <thead>
                    <tr>
                        <th>Severity</th><th>Package</th><th>Version</th><th>Fixed In</th><th>CVE</th><th>Title</th>
                    </tr>
                </thead>
                <tbody>
                    {html_rows}
                </tbody>
            </table>
        </div>
    </div>
    """
    return render_template_string(BASE_HTML, hostname=hostname, content=content)

@app.route("/packages")
def ui_packages():
    hostname = os.uname().nodename
    upg_raw = "\n".join(collect_upgradable_packages(200))
    sample = ""
    if shutil.which("dpkg"):
        sample = run_cmd("dpkg -l | awk 'NR>5 {print $2\" \"$3\" \"$4}' | head -n 200")
    content = f"<h1>Packages</h1><h3>Upgradable</h3><pre>{h_esc(upg_raw).strip() or 'None'}</pre><h3>Installed (sample)</h3><pre>{h_esc(sample)}</pre>"
    return render_template_string(BASE_HTML, hostname=hostname, content=content)

@app.route("/services")
def ui_services():
    hostname = os.uname().nodename
    out = run_cmd("systemctl list-units --type=service --no-pager --no-legend | head -n 200")
    content = f"<h1>Services</h1><pre>{out}</pre>"
    return render_template_string(BASE_HTML, hostname=hostname, content=content)

@app.route("/logs")
def ui_logs():
    hostname = os.uname().nodename
    out = run_cmd("journalctl -n 500 -p err --no-pager")
    if "ERR: Command" in out and "timed out" in out:
        if os.path.exists("/var/log/syslog"):
            out = run_cmd("tail -n 200 /var/log/syslog")
    content = f"<h1>System Logs — recent ERROR/CRITICAL</h1><pre>{out}</pre>"
    return render_template_string(BASE_HTML, hostname=hostname, content=content)

@app.route("/sshlogs")
def ui_sshlogs():
    hostname = os.uname().nodename
    logfile = "/var/log/auth.log" if os.path.exists("/var/log/auth.log") else "/var/log/secure"
    if not os.path.exists(logfile):
        content = "<h1>SSH Logs</h1><p>No auth log found on this distro.</p>"
        return render_template_string(BASE_HTML, hostname=hostname, content=content)
    out = run_cmd(f"grep -i 'Failed password\\|Invalid user\\|authentication failure' {logfile} | tail -n 500")
    ips = collections.Counter()
    for line in out.splitlines():
        for p in line.split():
            if p.count(".") == 3:
                ips[p] += 1
    top = ips.most_common(10)
    top_html = "<ul>" + "".join(f"<li>{ip}: {c} attempts</li>" for ip,c in top) + "</ul>" if top else "<div class='muted'>No recent failed attempts</div>"
    content = f"<h1>SSH Failed Logins (recent)</h1>{top_html}<h3>Raw lines</h3><pre>{out}</pre>"
    return render_template_string(BASE_HTML, hostname=hostname, content=content)

# ---------------- API endpoints ----------------

@app.route("/api/status")
def api_status():
    data = {
        "hostname": os.uname().nodename if hasattr(os, "uname") else "host",
        "platform": f"{os.uname().sysname} {os.uname().release}" if hasattr(os, "uname") else sys.platform,
        "python": run_cmd("python3 --version").strip(),
        "uptime": run_cmd("uptime -p").strip(),
        "cpu_percent": psutil.cpu_percent(interval=0.1),
        "cpu_count": psutil.cpu_count(),
        "memory": psutil.virtual_memory()._asdict(),
        "disk": {p.mountpoint: psutil.disk_usage(p.mountpoint)._asdict() for p in psutil.disk_partitions(all=False)}
    }
    return jsonify(data)

@app.route("/api/run_trivy_filtered")
def api_run_trivy_filtered():
    if not shutil.which("trivy"):
        return jsonify({"error": "trivy not installed"}), 400
    out = run_cmd("trivy fs --quiet --format json --severity HIGH,CRITICAL /", timeout=600)
    try:
        data = json.loads(out)
    except Exception:
        return jsonify({"error": "failed to parse trivy output", "raw": out}), 500
    vulns = []
    for res in data.get("Results", []):
        for v in res.get("Vulnerabilities", []):
            vulns.append(v)
    return jsonify({"count": len(vulns), "vulnerabilities": vulns})

@app.route("/api/nmap_scan")
def api_nmap_scan():
    """
    Query params:
      - target (default: localhost)
      - extra_args (optional) e.g. extra_args=-p-  or extra_args='-p 1-65535'
    """
    target = request.args.get("target", "localhost").strip()
    raw_args = (request.args.get("extra_args") or "").strip()
    if not is_allowed_target(target):
        return jsonify({"error": "target not allowed", "allowed": list(get_local_ips())}), 403
    if not NMAP_BIN:
        return jsonify({"error": "nmap not installed"}), 400
    if len(target) > 128:
        return jsonify({"error": "target too long"}), 400

    extra_tokens = None
    if raw_args:
        try:
            tokens = shlex.split(raw_args)
        except Exception as e:
            return jsonify({"error": f"invalid extra_args: {e}"}), 400
        cleaned, verr = validate_nmap_extra_args(tokens)
        if verr:
            return jsonify({"error": verr}), 400
        extra_tokens = cleaned

    raw, err = run_nmap_raw(target, extra_args=extra_tokens)
    if err:
        return jsonify({"error": err}), 500

    if len(raw) > NMAP_MAX_CHARS:
        raw = raw[:NMAP_MAX_CHARS] + "\n\n[...output truncated...]\n"

    # Return text in JSON field "scan" (keeps existing API shape)
    return jsonify({"target": target, "scan": raw})



# ---------------- Report builders ----------------
def generate_report_csv(selected_sections, nmap_target="localhost"):
    """Generates CSV bytes (utf-8) for the chosen sections, including a Host Summary header."""
    buf = io.StringIO()
    writer = csv.writer(buf)

    def section(title):
        writer.writerow([f"=== {title} ==="])
        writer.writerow([])

    section("Host Summary")
    hs = build_host_summary()
    writer.writerow(["Hostname", hs["hostname"]])
    writer.writerow(["Platform", hs["platform"]])
    writer.writerow(["IPs", hs["ips"]])
    writer.writerow(["Uptime", hs["uptime"]])
    writer.writerow(["CPU Cores", hs["cpu_count"]])
    writer.writerow(["Load (1/5/15)", f'{hs["load1"]:.2f}/{hs["load5"]:.2f}/{hs["load15"]:.2f}'])
    writer.writerow(["Memory", f'{hs["mem_used"]} / {hs["mem_total"]} ({hs["mem_percent"]}%)'])
    writer.writerow(["Generated (UTC)", hs["generated"]])
    writer.writerow([])

    if "trivy" in selected_sections:
        section("Trivy - Vulnerabilities (HIGH/CRITICAL)")
        start_t = time.time()
        trivy_data = collect_trivy()
        if isinstance(trivy_data, list) and trivy_data and isinstance(trivy_data[0], tuple):
            writer.writerow(["Severity", "Package", "Installed", "Fixed", "CVE", "Title"])
            for sev, pkg, inst, fixed, cve, title in trivy_data:
                writer.writerow([sev, pkg, inst, fixed, cve, title])
        else:
            for line in trivy_data:
                writer.writerow([line])
        writer.writerow([f"Trivy finished in {round(time.time() - start_t, 2)}s"])
        writer.writerow([])

    if "sshaudit" in selected_sections:
        section(f"SSH-Audit ({nmap_target})")
        start_ssh = time.time()
        ssh_audit_lines = collect_sshaudit(nmap_target)
        raw_output = "\n".join(ssh_audit_lines)
        
        # Parse with professional parser
        try:
            parser = SSHAuditParser()
            report = parser.parse(raw_output)
            
            # Write structured data
            writer.writerow(["SSH Banner", report.banner or "N/A"])
            writer.writerow(["SSH Software", report.software or "N/A"])
            writer.writerow(["Protocol Version", report.protocol_version or "N/A"])
            writer.writerow([])
            
            writer.writerow(["KEX Algorithms - Security Status"])
            writer.writerow(["Secure", len(report.kex_secure)])
            writer.writerow(["Weak", len(report.kex_weak)])
            writer.writerow(["Dangerous", len(report.kex_fail)])
            writer.writerow([])
            
            writer.writerow(["Host Key Algorithms - Security Status"])
            writer.writerow(["Secure", len(report.hostkey_secure)])
            writer.writerow(["Weak", len(report.hostkey_weak)])
            writer.writerow(["Dangerous", len(report.hostkey_fail)])
            writer.writerow([])
            
            writer.writerow(["Encryption Ciphers - Security Status"])
            writer.writerow(["Secure", len(report.encryption_secure)])
            writer.writerow(["Weak/Deprecated", len(report.encryption_weak)])
            writer.writerow([])
            
            writer.writerow(["MAC Algorithms - Security Status"])
            writer.writerow(["Secure", len(report.mac_secure)])
            writer.writerow(["Weak", len(report.mac_weak)])
            writer.writerow(["Broken", len(report.mac_fail)])
            writer.writerow([])
            
            # Critical Issues
            writer.writerow(["Critical Security Issues"])
            for issue in report.critical_issues:
                writer.writerow([issue])
            writer.writerow([])
            
            # Hardening Recommendations
            writer.writerow(["Hardening Recommendations"])
            for rec in report.hardening_actions[:5]:  # Top 5
                writer.writerow([rec])
        except Exception as e:
            writer.writerow(["Error parsing SSH audit output", str(e)])
            writer.writerow(["Raw Output"])
            for line in ssh_audit_lines:
                writer.writerow([line])
        
        writer.writerow([f"SSH-Audit finished in {round(time.time() - start_ssh, 2)}s"])
        writer.writerow([])
    
    if "enum4linux" in selected_sections:
        section(f"enum4linux SMB/NetBIOS Enumeration ({nmap_target})")
        start_enum = time.time()
        enum_result = collect_enum4linux(nmap_target, options={"users": True, "shares": True, "groups": True, "policy": True})
        
        if isinstance(enum_result, dict):
            if "error" in enum_result:
                writer.writerow(["Error", enum_result.get("error")])
                writer.writerow(["Hint", enum_result.get("hint", "N/A")])
            else:
                # Summary
                writer.writerow(["Summary"])
                writer.writerow(["Users Found", enum_result.get("summary", {}).get("users_found", 0)])
                writer.writerow(["Shares Found", enum_result.get("summary", {}).get("shares_found", 0)])
                writer.writerow(["Groups Found", enum_result.get("summary", {}).get("groups_found", 0)])
                writer.writerow([])
                
                # Target Info
                if enum_result.get("target_info"):
                    writer.writerow(["Target Information"])
                    for key, val in enum_result["target_info"].items():
                        writer.writerow([key, val])
                    writer.writerow([])
                
                # Users
                if enum_result.get("users"):
                    writer.writerow(["Users"])
                    writer.writerow(["Username", "RID"])
                    for user in enum_result["users"]:
                        writer.writerow([user.get("username"), user.get("rid")])
                    writer.writerow([])
                
                # Shares
                if enum_result.get("shares"):
                    writer.writerow(["Shares"])
                    writer.writerow(["Share Name", "Type", "Comment", "Accessible"])
                    for share in enum_result["shares"]:
                        writer.writerow([share.get("name"), share.get("type"), share.get("comment"), share.get("accessible")])
                    writer.writerow([])
                
                # Groups
                if enum_result.get("groups"):
                    writer.writerow(["Groups"])
                    writer.writerow(["Group Name", "RID"])
                    for group in enum_result["groups"]:
                        writer.writerow([group.get("groupname"), group.get("rid")])
                    writer.writerow([])
                
                # Password Policy
                if enum_result.get("password_policy"):
                    writer.writerow(["Password Policy"])
                    for key, val in enum_result["password_policy"].items():
                        writer.writerow([key.replace("_", " ").title(), val])
                    writer.writerow([])
        
        writer.writerow([f"enum4linux finished in {round(time.time() - start_enum, 2)}s"])
        writer.writerow([])

    if "nmap" in selected_sections:
        writer.writerow(["Waiting 3 seconds before running Nmap..."]); writer.writerow([]); time.sleep(3)
        section(f"Nmap scan ({nmap_target})")
        start_nmap = time.time()
        nmap_lines = collect_nmap(nmap_target)
        raw_output = "\n".join(nmap_lines)
        
        # Parse with professional parser
        try:
            parser = NmapParser()
            report = parser.parse(raw_output)
            
            # Write summary
            writer.writerow(["Scan Summary"])
            writer.writerow(["Hosts Up", report.hosts_up])
            writer.writerow(["Hosts Down", report.hosts_down])
            writer.writerow(["Total Open Ports", report.total_ports_found])
            writer.writerow([])
            
            # Write host details
            for host in report.hosts:
                if host.status != "up":
                    continue
                
                host_display = f"{host.hostname} ({host.ip})" if host.hostname else host.ip
                writer.writerow([f"Host: {host_display}"])
                if host.os:
                    writer.writerow(["OS", host.os])
                writer.writerow([])
                
                # Port table
                writer.writerow(["Port", "Protocol", "State", "Service", "Version", "Security"])
                for port in host.ports:
                    security = "Safe" if port.security_level == "safe" else ("Attention" if port.security_level == "attention" else "Dangerous")
                    writer.writerow([
                        port.port,
                        port.protocol,
                        port.state,
                        port.service,
                        port.version,
                        security
                    ])
                writer.writerow([])
            
            # Critical Findings
            writer.writerow(["Critical Security Findings"])
            for finding in report.critical_findings:
                writer.writerow([finding])
            writer.writerow([])
            
            # Recommendations
            writer.writerow(["Security Recommendations"])
            for rec in report.recommendations[:5]:  # Top 5
                writer.writerow([rec])
        except Exception as e:
            writer.writerow(["Error parsing Nmap output", str(e)])
            writer.writerow(["Raw Output"])
            for line in nmap_lines:
                writer.writerow([line])
        
        writer.writerow([f"Nmap finished in {round(time.time() - start_nmap, 2)}s"])
        writer.writerow([])

    if "logs" in selected_sections:
        section("System logs (tail 300)")
        writer.writerow(["Log line"])
        for line in collect_logs(300):
            writer.writerow([line])
        writer.writerow([])

    if "ssh" in selected_sections:
        section("SSH failed attempts summary + raw lines")
        writer.writerow(["SSH line"])
        for line in collect_ssh_fails(500):
            writer.writerow([line])
        writer.writerow([])

    if "procs" in selected_sections:
        section("Top processes (pid, name, user, cpu%, mem%, cmd)")
        writer.writerow(["PID","Name","User","CPU%","Mem%","Cmdline"])
        for pid,name,user,cpu,mem,cmd in collect_processes(300):
            writer.writerow([pid,name,user,cpu,mem,cmd])
        writer.writerow([])

    if "services" in selected_sections:
        section("Services (systemctl list-units --type=service)")
        # ARREGLAT: Ara escriu les columnes correctament
        writer.writerow(["Unit", "Load", "Active", "Sub", "Description"])
        services_data = collect_services(500)
        if services_data and isinstance(services_data[0], tuple):
            for s in services_data:
                writer.writerow(s)
        else:
            writer.writerow([services_data[0]]) # Escriu el missatge d'error
        writer.writerow([])

    if "packages" in selected_sections:
        section("Upgradable Packages (apt list --upgradable)")
        writer.writerow(["Line"])
        for line in collect_upgradable_packages(500):
            writer.writerow([line])
        writer.writerow([])

    if "suspicious" in selected_sections:
        section("Suspicious Processes (heuristic)")
        writer.writerow(["PID","Name","User","Exe","Cmd","Flags"])
        for pid,name,user,exe,cmd,flags in collect_suspicious_processes(300):
            writer.writerow([pid,name,user,exe,cmd,flags])
        writer.writerow([])

    return buf.getvalue().encode("utf-8")
## ---------------------------------
## --- Helper Functions ---
## ---------------------------------

def truncate(text, limit):
    """Truncate text to a specified length with ellipsis."""
    text = str(text) 
    return text[:limit] + "..." if len(text) > limit else text

def human(size):
    """Convert bytes to human readable format."""
    try:
        size = float(size)
        for unit in ['B','KB','MB','GB','TB']:
            if size < 1024.0: return f"{size:.1f} {unit}"
            size /= 1024.0
        return f"{size:.1f} PB"
    except: return str(size)

def now_utc_iso():
    """Return current time in ISO format."""
    return datetime.datetime.now().strftime('%Y-%m-%dT%H:%M:%S')

def h_esc(text):
    """HTML escaping for Python strings."""
    if text is None: return ""
    return str(text).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;").replace("'", "&#39;")


# (REPLACE the entire render_visual_report function in diag_agent_single.py)

def render_visual_report(selected_sections, nmap_target="localhost"):
    """Returns HTML for the selected sections, rendered inline on /report."""
    import datetime
    
    # DEBUG LOGGING
    debug_log = "/tmp/pdf_debug.log"
    try:
        with open(debug_log, 'a') as f:
            f.write(f"\n{'='*60}\n")
            f.write(f"[{datetime.datetime.now()}] render_visual_report called\n")
            f.write(f"Selected sections: {selected_sections}\n")
            f.write(f"Target: {nmap_target}\n")
    except:
        pass
    
    parts = []
    
    def block(title, body_html):
        # DEBUG: Log each section that's added
        try:
            with open(debug_log, 'a') as f:
                f.write(f"  ✓ Added section: {title} ({len(body_html)} bytes)\n")
        except:
            pass
        parts.append(f"<div class='card'><h4>{title}</h4>{body_html}</div>")

    # ------------------------------------------------
    # Host Summary
    # ------------------------------------------------
    hs = build_host_summary()
    if not isinstance(hs, dict) or not hs:
        parts.append("<div class='card'><h4 style='color:red;'>Host Summary Failed</h4><p>Unable to retrieve host details.</p></div>")
    else:
        parts.append(f"""
        <div class="card">
          <h4>Host Summary</h4>
          <div class='table-wrap'><table>
            <tr><th>Hostname</th><td>{hs.get('hostname', 'N/A')}</td></tr>
            <tr><th>Platform</th><td>{hs.get('platform', 'N/A')}</td></tr>
            <tr><th>IPs</th><td>{hs.get('ips', 'N/A')}</td></tr>
            <tr><th>Uptime</th><td>{hs.get('uptime', 'N/A')}</td></tr>
            <tr><th>CPU Cores</th><td>{hs.get('cpu_count', 'N/A')}</td></tr>
            <tr><th>Load (1/5/15)</th><td>{hs.get('load1', 0):.2f} / {hs.get('load5', 0):.2f} / {hs.get('load15', 0):.2f}</td></tr>
            <tr><th>Memory</th><td>{hs.get('mem_used', 'N/A')} / {hs.get('mem_total', 'N/A')} ({hs.get('mem_percent', 0)}%)</td></tr>
            <tr><th>Generated (UTC)</th><td>{hs.get('generated', 'N/A')}</td></tr>
          </table></div>
        </div>
        """)

    # ------------------------------------------------
    # Trivy
    # ------------------------------------------------
    if "trivy" in selected_sections:
        t = collect_trivy()
        if isinstance(t, list) and t and isinstance(t[0], tuple):
            rows = "".join(
                f"<tr><td><span class='badge {'badge-crit' if sev == 'CRITICAL' else 'badge-high'}'>{sev}</span></td>"
                f"<td class='package'>{pkg}</td><td class='installed'>{inst}</td><td class='fixed'>{fixed}</td>"
                f"<td class='cve'><a target='_blank' href='https://nvd.nist.gov/vuln/detail/{cve}'>{cve}</a></td><td class='title cell-clip' title='{title}'>{truncate(title, 60)}</td></tr>"
                for (sev,pkg,inst,fixed,cve,title) in t
            )
            html = f"<div class='table-wrap'><table><tr><th class='severity'>Severity</th><th class='package'>Package</th><th class='installed'>Installed</th><th class='fixed'>Fixed</th><th class='cve'>CVE</th><th class='title'>Title</th></tr>{rows}</table></div>"
        else:
            html = f"<pre>{truncate(str('\n'.join(t)), 600)}</pre>" if t else "<p>Trivy data not available.</p>"
        block("Trivy - Vulnerabilities (HIGH/CRITICAL)", html)

    # ------------------------------------------------------------------
    # --- SSH-AUDIT LOGIC ---
    # ------------------------------------------------------------------
    if "sshaudit" in selected_sections:
        ssh_audit_lines = collect_sshaudit(nmap_target)
        raw_output = "\n".join(ssh_audit_lines) if ssh_audit_lines and isinstance(ssh_audit_lines, list) else ""
        
        try:
            # Parse with professional parser
            parser = SSHAuditParser()
            report = parser.parse(raw_output)
            html = parser.to_html(report, for_pdf=True)
            block(f"SSH-Audit ({nmap_target})", html)
        except Exception as e:
            # Fallback to raw output on error
            if ssh_audit_lines and isinstance(ssh_audit_lines, list):
                safe_html_lines = [line.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;") for line in ssh_audit_lines]
                html = f"<pre>{'\n'.join(safe_html_lines)}</pre>"
            else:
                html = "<p>SSH-Audit scan failed or returned no data.</p>"
            block(f"SSH-Audit ({nmap_target}) - Parse Error", html)
    
    # ------------------------------------------------------------------
    # --- enum4linux SMB/NetBIOS Enumeration ---
    # ------------------------------------------------------------------
    if "enum4linux" in selected_sections:
        enum_result = collect_enum4linux(nmap_target, options={"users": True, "shares": True, "groups": True, "policy": True})
        
        if isinstance(enum_result, dict) and "error" not in enum_result:
            html = ""
            
            # Summary cards
            summary = enum_result.get("summary", {})
            html += f"""
            <div class="summary-cards">
                <div class="card-summary low">
                    <div class="num">{summary.get('users_found', 0)}</div>
                    <div class="label">Users</div>
                </div>
                <div class="card-summary low">
                    <div class="num">{summary.get('shares_found', 0)}</div>
                    <div class="label">Shares</div>
                </div>
                <div class="card-summary low">
                    <div class="num">{summary.get('groups_found', 0)}</div>
                    <div class="label">Groups</div>
                </div>
            </div>
            """
            
            # Target Info
            if enum_result.get("target_info"):
                html += "<h5>Target Information</h5><div class='table-wrap'><table><tr><th>Property</th><th>Value</th></tr>"
                for key, val in enum_result["target_info"].items():
                    html += f"<tr><td>{key.title()}</td><td>{val}</td></tr>"
                html += "</table></div>"
            
            # Users
            if enum_result.get("users"):
                html += "<h5 class='mt-3'>Users</h5><div class='table-wrap'><table><tr><th>Username</th><th>RID</th></tr>"
                for user in enum_result["users"][:50]:
                    html += f"<tr><td>{user.get('username')}</td><td><code>{user.get('rid')}</code></td></tr>"
                if len(enum_result["users"]) > 50:
                    html += f"<tr><td colspan='2' class='text-muted'>... and {len(enum_result['users']) - 50} more</td></tr>"
                html += "</table></div>"
            
            # Shares
            if enum_result.get("shares"):
                html += "<h5 class='mt-3'>Shares</h5><div class='table-wrap'><table><tr><th>Share Name</th><th>Type</th><th>Comment</th></tr>"
                for share in enum_result["shares"]:
                    html += f"<tr><td><strong>{share.get('name')}</strong></td><td>{share.get('type')}</td><td>{truncate(share.get('comment', ''), 40)}</td></tr>"
                html += "</table></div>"
            
            # Groups
            if enum_result.get("groups"):
                html += "<h5 class='mt-3'>Groups</h5><div class='table-wrap'><table><tr><th>Group Name</th><th>RID</th></tr>"
                for group in enum_result["groups"]:
                    html += f"<tr><td>{group.get('groupname')}</td><td><code>{group.get('rid')}</code></td></tr>"
                html += "</table></div>"
            
            # Password Policy
            if enum_result.get("password_policy"):
                html += "<h5 class='mt-3'>Password Policy</h5><div class='table-wrap'><table><tr><th>Policy</th><th>Value</th></tr>"
                for key, val in enum_result["password_policy"].items():
                    html += f"<tr><td>{key.replace('_', ' ').title()}</td><td>{val}</td></tr>"
                html += "</table></div>"
            
            # Warnings
            if enum_result.get("errors"):
                html += "<div class='alert alert-warning mt-3'><strong>Warnings:</strong><ul>"
                for err in enum_result["errors"]:
                    html += f"<li>{err}</li>"
                html += "</ul></div>"
            
            block(f"enum4linux SMB/NetBIOS Enumeration ({nmap_target})", html)
        else:
            error_msg = enum_result.get("error", "Unknown error") if isinstance(enum_result, dict) else "Enumeration failed"
            html = f"<p style='color:red;'>{error_msg}</p>"
            block(f"enum4linux SMB/NetBIOS Enumeration ({nmap_target})", html)

    # ------------------------------------------------------------------
    # --- NMAP LOGIC (now using professional parser) ---
    # ------------------------------------------------------------------
    if "nmap" in selected_sections:
        lines = collect_nmap(nmap_target)
        raw_output = "\n".join(lines) if lines and isinstance(lines, list) else ""
        
        try:
            # Parse with professional parser
            parser = NmapParser()
            report = parser.parse(raw_output)
            html = parser.to_html(report)
            # Remove title redundancy if the report already has one
            block(f"Network Scan Info ({nmap_target})", html)
        except Exception as e:
            # Fallback to raw output on error
            if not isinstance(lines, list) or not lines:
                block(f"Nmap Scan ({nmap_target})", "<p style='color:red;'>Nmap scan failed or returned no data.</p>")
            else:
                # Show only open ports lines in a clean list
                open_lines = []
                for  line in lines:
                    if "/tcp" in line and "open" in line and "Nmap scan report" not in line:
                        open_lines.append(line)

                if open_lines:
                    safe_lines = [line.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;") for line in open_lines]
                    html = "<p>Open Ports:</p><pre>" + "\n".join(safe_lines) + "</pre>"
                else:
                    html = "<p>No open ports found in scan output.</p>"
                block(f"Nmap Scan ({nmap_target}) - Parse Error", html)
    # ------------------------------------------------------------------

    # ------------------------------------------------
    # System Logs - Grouped and Summarized
    # ------------------------------------------------
    if "logs" in selected_sections:
        logs = collect_logs(300)
        if logs and len(logs) > 0:
            # Parse and group logs
            ssh_errors = []
            samba_sessions = 0
            cron_jobs = []
            sudo_commands = []
            other_logs = []
            
            for line in logs:
                line_lower = line.lower()
                if 'sshd' in line_lower and ('connection closed' in line_lower or 'dispatch_run_fatal' in line_lower):
                    ssh_errors.append(line)
                elif 'samba:session' in line_lower and 'session closed' in line_lower:
                    samba_sessions += 1
                elif 'cron' in line_lower:
                    cron_jobs.append(line)
                elif 'sudo' in line_lower:
                    sudo_commands.append(line)
                elif any(word in line_lower for word in ['error', 'fail', 'warn', 'critical']):
                    other_logs.append(line)
            
            # Build summary
            html = f"<p><strong>Log Summary</strong> ({len(logs)} entries)</p>"
            html += "<table><tr><th>Category</th><th>Count</th></tr>"
            html += f"<tr><td>SSH Connection Issues</td><td>{len(ssh_errors)}</td></tr>"
            html += f"<tr><td>Samba Sessions Closed</td><td>{samba_sessions}</td></tr>"
            html += f"<tr><td>Cron Jobs</td><td>{len(cron_jobs)}</td></tr>"
            html += f"<tr><td>Sudo Commands</td><td>{len(sudo_commands)}</td></tr>"
            html += f"<tr><td>Other Errors/Warnings</td><td>{len(other_logs)}</td></tr>"
            html += "</table>"
            
            if ssh_errors:
                html += f"<h4>SSH Issues (5 of {len(ssh_errors)})</h4>"
                html += f"<pre style='font-size:8pt;'>{'\n'.join(ssh_errors[:5])}</pre>"
            
            if sudo_commands:
                html += f"<h4>Recent Sudo (last 3)</h4>"
                html += f"<pre style='font-size:8pt;'>{'\n'.join(sudo_commands[-3:])}</pre>"
        else:
            html = "<p>No recent system logs found.</p>"
        block("System Logs (Grouped)", html)

    # ------------------------------------------------
    # SSH Failed Attempts - Enhanced Table
    # ------------------------------------------------
    if "ssh" in selected_sections:
        ssh_lines = collect_ssh_fails(300)
        if ssh_lines and len(ssh_lines) > 0:
            # Extract IPs and count attempts
            import re
            ip_counts = {}
            for line in ssh_lines:
                ip_match = re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', line)
                if ip_match:
                    ip = ip_match.group(0)
                    ip_counts[ip] = ip_counts.get(ip, 0) + 1
            
            total_attempts = len(ssh_lines)
            unique_ips = len(ip_counts)
            
            # Summary info
            summary = f"<p><strong>{total_attempts} failed login attempts</strong> from <strong>{unique_ips} unique IP addresses</strong></p>"
            
            # Top attackers table
            if ip_counts:
                top_ips = sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)[:15]
                rows = "".join(f"<tr><td>{idx+1}</td><td><code>{ip}</code></td><td><strong>{count}</strong></td></tr>" 
                               for idx, (ip, count) in enumerate(top_ips))
                table_html = f"""
                <div class='table-wrap'>
                    <table>
                        <tr><th>#</th><th>IP Address</th><th>Attempts</th></tr>
                        {rows}
                    </table>
                </div>
                """
                html = summary + table_html
            else:
                html = summary + "<p>No IP addresses found in logs.</p>"
        else:
            html = "<p>No recent SSH failed attempts found.</p>"
        block("SSH Failed Login Attempts", html)

    # ------------------------------------------------
    # Processes - SKIP for PDF, show for web only
    # ------------------------------------------------
    # Processes section is excluded from PDF generation
    # Available in CSV export instead

# (SUBSTITUEIX NOMÉS AQUEST BLOC DINS DE render_visual_report)

    # ------------------------------------------------
    # Services - ONLY RUNNING (active + running)
    # ------------------------------------------------
    if "services" in selected_sections:
        services = collect_services(150) 
        if services and isinstance(services, list) and services[0] and isinstance(services[0], tuple) and len(services[0]) >= 4:
            rows = ""
            running_count = 0
            # Filter to show ONLY running services
            for service_tuple in services: 
                unit = service_tuple[0]
                load = service_tuple[1] if len(service_tuple) > 1 else "N/A"
                active = service_tuple[2] if len(service_tuple) > 2 else "N/A"
                sub = service_tuple[3] if len(service_tuple) > 3 else "N/A"
                desc = service_tuple[4] if len(service_tuple) > 4 else "N/A"
                
                # ONLY show running services (active + running sub-state)
                if active == "active" and sub == "running":
                    running_count += 1
                    style = " style='color:#22c55e;'"
                    rows += f"""
                    <tr>
                        <td class='service-name' title='{unit}'>{truncate(unit, 40)}</td>
                        <td{style}>{active}</td>
                        <td{style}>{sub}</td>
                        <td class='cell-clip' title='{desc}'>{truncate(desc, 60)}</td>
                    </tr>
                    """
            
            if rows:
                summary = f"<p><strong>{running_count} running services</strong></p>"
                html = summary + f"<div class='table-wrap'><table><tr><th class='service-name'>Unit</th><th>Active</th><th>Sub</th><th>Description</th></tr>{rows}</table></div>"
            else:
                html = "<p>No running services found.</p>"
        else:
            html = f"<pre>{truncate(str('\\n'.join(map(str, services))), 600)}</pre>" if services else "<p>No services found or error fetching data.</p>"
        block("Running Services", html)
    # ------------------------------------------------
    # Upgradable Packages - Count Only (WeasyPrint limitation)
    # ------------------------------------------------
    if "packages" in selected_sections:
        packages = collect_upgradable_packages(500)
        if packages and len(packages) > 0:
            total = len(packages)
            html = f"<p style='font-size:14pt;'><strong>{total} packages need to be updated</strong></p>"
            html += "<div style='background:#fff3cd; border-left:4px solid #ffc107; padding:10px; margin:10px 0;'>"
            html += "<p style='margin:0; color:#856404;'><strong style='color:#d39e00;'>⚠ ACTION REQUIRED</strong></p>"
            html += "<p style='margin:5px 0 0 0;'>Run the following command to update all packages:</p>"
            html += "<p style='background:#f8f9fa; padding:8px; margin:5px 0; font-family:monospace; border:1px solid #dee2e6;'><strong>sudo apt update && sudo apt upgrade</strong></p>"
            html += "<p style='margin:5px 0 0 0; font-size:9pt; color:#6c757d;'>Outdated packages may contain security vulnerabilities or cause system errors.</p>"
            html += "</div>"
            html += "<p style='font-size:8pt; color:#6c757d;'>See CSV export for complete package list with versions</p>"
        else:
            html = "<div style='background:#d4edda; border-left:4px solid #28a745; padding:10px;'>"
            html += "<p style='margin:0; color:#155724;'><strong style='color:#28a745;'>✓ SYSTEM UP TO DATE</strong></p>"
            html += "<p style='margin:5px 0 0 0;'>No packages need upgrading</p>"
            html += "</div>"
        block("Upgradable Packages", html)

    # ------------------------------------------------
    # Suspicious Processes
    # ------------------------------------------------
    if "suspicious" in selected_sections:
        sus = collect_suspicious_processes(100)
        if sus and isinstance(sus, list) and sus[0] and isinstance(sus[0], tuple) and len(sus[0]) == 6:
            rows = ""
            for idx, (pid, name, user, exe, cmd, flags) in enumerate(sus):
                rows += f"""
                <tr>
                    <td class='pid'>{pid}</td>
                    <td class='name'>{name}</td>
                    <td class='user'>{user}</td>
                    <td class='exe cell-clip'>{truncate(exe, 40)}</td>
                    <td class='cmd cell-clip'>{truncate(cmd, 60)}</td>
                    <td class='flags'>{flags}</td>
                    <td class='details'>Details</td> 
                </tr>
                """
            # FIXED: Added missing '=' signs in table header
            html = f"""
            <div class='table-wrap'>
                <table>
                    <tr><th class='pid'>PID</th><th class='name'>Name</th><th class='user'>User</th><th class='exe'>Exe</th><th class='cmd'>Cmd</th><th class='flags'>Flags</th><th class='details'>Details</th></tr>
                    {rows}
                </table>
            </div>
            """
        else:
            html = f"<pre>{truncate(str('\n'.join(sus)), 600)}</pre>" if sus else "<p>No suspicious processes found.</p>"
        block("Suspicious Processes (heuristic)", html)

    # DEBUG: Log completion
    try:
        with open("/tmp/pdf_debug.log", 'a') as f:
            f.write(f"FINAL: Generated {len(parts)} sections total\n")
            f.write(f"{'='*60}\n")
    except:
        pass
    
    return "\n".join(parts)
## ---------------------------------
## --- PDF Digital Signature ---
## ---------------------------------

def sign_pdf_report(pdf_bytes):
    """
    Digitally sign a PDF report using pyhanko.
    Returns signed PDF bytes or original if signing fails.
    """
    try:
        from pyhanko.sign import signers
        from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
        import tempfile
        
        # Certificate paths (relative to script directory)
        script_dir = os.path.dirname(os.path.abspath(__file__))
        cert_path = os.path.join(script_dir, "certs", "cybershield.crt")
        key_path = os.path.join(script_dir, "certs", "cybershield.key")
        
        # Check if certificates exist
        if not os.path.exists(cert_path) or not os.path.exists(key_path):
            print(f"[WARNING] PDF signing certificates not found at {cert_path}")
            return pdf_bytes  # Return unsigned PDF
        
        # Create temporary file for processing
        with tempfile.NamedTemporaryFile(delete=False, suffix='.pdf') as tmp_in:
            tmp_in.write(pdf_bytes)
            tmp_in_path = tmp_in.name
        
        try:
            # Load signer
            signer = signers.SimpleSigner.load(
                cert_file=cert_path,
                key_file=key_path,
                key_passphrase=None
            )
            
            # Sign the PDF
            with open(tmp_in_path, 'rb') as inf:
                w = IncrementalPdfFileWriter(inf)
                out = signers.sign_pdf(
                    w,
                    signers.PdfSignatureMetadata(
                        field_name='CybershieldSignature',
                        name='Cybershield Solutions',
                        location='Security Audit Platform',
                        reason='Document Authenticity and Integrity',
                    ),
                    signer=signer
                )
                
                # Read signed PDF bytes
                signed_bytes = out.getvalue() if hasattr(out, 'getvalue') else out.read()
                
            print("[INFO] PDF successfully signed with Cybershield certificate")
            return signed_bytes
            
        finally:
            # Clean up temp file
            if os.path.exists(tmp_in_path):
                os.unlink(tmp_in_path)
                
    except ImportError:
        print("[WARNING] pyhanko not installed - PDF will not be signed")
        return pdf_bytes
    except Exception as e:
        print(f"[ERROR] PDF signing failed: {e}")
        return pdf_bytes  # Return unsigned PDF on error
        return pdf_bytes  # Return unsigned PDF on error

## ---------------------------------
## --- Main PDF Generator Function ---
## ---------------------------------

def generate_report_pdf(selected_sections, nmap_target="localhost"):
    """Generates PDF bytes for the chosen sections with professional branding."""
    from weasyprint import HTML
    import base64
    import os

    # Get host info
    hs = build_host_summary()
    hostname = hs.get("hostname", "N/A")
    ip_list = hs.get("ips", "N/A")
    platform = hs.get("platform", "N/A")
    generated = now_utc_iso()
    
    # Logo handling (embed as base64)
    logo_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "cshield.png")
    logo_img = ""
    if os.path.exists(logo_path):
        with open(logo_path, "rb") as f:
            encoded = base64.b64encode(f.read()).decode('utf-8')
            logo_img = f'<img src="data:image/png;base64,{encoded}" style="width:120px; margin-bottom:20px;">'

    # --- Cover Page ---
    cover_html = f"""
    <div class="cover-page">
        <div class="logo-container">{logo_img}</div>
        <h1 class="report-title">SECURITY AUDIT REPORT</h1>
        <div class="report-meta">
            <table class="meta-table">
                <tr><th>Target System</th><td>{hostname}</td></tr>
                <tr><th>Target IP(s)</th><td>{ip_list}</td></tr>
                <tr><th>Platform</th><td>{platform}</td></tr>
                <tr><th>Audit Date</th><td>{generated.split('T')[0]}</td></tr>
                <tr><th>Auditor</th><td><strong>Vitaliy</strong></td></tr>
                <tr><th>Report ID</th><td>CS-2025-{int(time.time())}</td></tr>
            </table>
        </div>
        <div class="confidential-badge">CONFIDENTIAL</div>
        <div class="footer-brand">
            <strong>Cybershield Solutions</strong><br>
            Professional Security Diagnostics Platform
        </div>
    </div>
    """

    # --- Executive Summary ---
    # Calculate summary stats
    vuln_count = 0
    crit_count = 0
    high_count = 0
    if "trivy" in selected_sections:
        trivy_data = collect_trivy()
        if isinstance(trivy_data, list) and trivy_data and isinstance(trivy_data[0], tuple):
            vuln_count = len(trivy_data)
            for v in trivy_data:
                if v[0] == "CRITICAL": crit_count += 1
                elif v[0] == "HIGH": high_count += 1

    exec_summary_html = f"""
    <div class="page-break"></div>
    <div class="header">Cybershield Solutions | Executive Summary</div>
    <h1>Executive Summary</h1>
    <p>This security audit was conducted by <strong>Vitaliy</strong> using the Cybershield Solutions diagnostic platform. The assessment focused on identifying vulnerabilities, misconfigurations, and security risks on the target system.</p>
    
    <div class="summary-cards">
        <div class="card-summary red">
            <div class="num">{crit_count}</div>
            <div class="label">Critical Issues</div>
        </div>
        <div class="card-summary orange">
            <div class="num">{high_count}</div>
            <div class="label">High Risks</div>
        </div>
        <div class="card-summary blue">
            <div class="num">{vuln_count}</div>
            <div class="label">Total Vulns</div>
        </div>
    </div>

    <h3>Risk Assessment</h3>
    <p>Based on the scan results, the system risk level is 
    <span class="badge {'badge-crit' if crit_count > 0 else 'badge-high' if high_count > 0 else 'badge-low'}">
    {'CRITICAL' if crit_count > 0 else 'HIGH' if high_count > 0 else 'LOW'}
    </span>. 
    Immediate attention is required for critical vulnerabilities to prevent potential exploitation.</p>

    <h3>Scope & Methodology</h3>
    <ul>
        <li><strong>Vulnerability Scanning:</strong> Detection of CVEs in system packages.</li>
        <li><strong>Network Security:</strong> Port scanning and service enumeration.</li>
        <li><strong>Configuration Audit:</strong> SSH, SMB, and system settings review.</li>
        <li><strong>Log Analysis:</strong> Review of system and authentication logs for suspicious activity.</li>
    </ul>
    """

    # --- Main Content ---
    main_content = render_visual_report(selected_sections, nmap_target)

    # --- CSS Styling ---
    css = """
    @page {
        size: A4 portrait;
        margin: 1.5cm;
        @bottom-center {
            content: "Page " counter(page) " | Cybershield Solutions | Confidential";
            font-size: 9pt;
            color: #64748b;
        }
    }
    body { font-family: 'Helvetica', 'Arial', sans-serif; color: #1e293b; font-size: 10pt; line-height: 1.5; }
    
    /* Cover Page */
    .cover-page { 
        text-align: center; 
        padding-top: 1.5cm; /* Reduced from 4cm to fit landscape */
        height: 17cm;       /* Fixed height to ensure single page */
        display: flex;
        flex-direction: column;
        justify-content: center;
        align-items: center;
        page-break-after: always; 
    }
    .report-title { 
        font-size: 24pt;    /* Slightly smaller for landscape */
        color: #0f172a; 
        margin: 15px 0 25px; 
        border-bottom: 3px solid #3b82f6; 
        display: inline-block; 
        padding-bottom: 8px; 
    }
    .meta-table { 
        margin: 0 auto; 
        text-align: left; 
        font-size: 11pt; 
        border-collapse: separate; 
        border-spacing: 0 6px; /* Tighter spacing */
    }
    .meta-table th { padding-right: 15px; color: #64748b; font-weight: normal; }
    .meta-table td { font-weight: bold; color: #0f172a; }
    .confidential-badge { 
        margin-top: 30px; 
        font-size: 12pt; 
        color: #ef4444; 
        font-weight: bold; 
        letter-spacing: 2px; 
        border: 2px solid #ef4444; 
        display: inline-block; 
        padding: 4px 15px; 
        border-radius: 4px; 
    }
    .footer-brand { margin-top: 40px; color: #3b82f6; font-size: 10pt; }

    /* Layout */
    .page-break { page-break-before: always; }
    .header { position: absolute; top: -1cm; left: 0; right: 0; color: #94a3b8; font-size: 9pt; border-bottom: 1px solid #e2e8f0; padding-bottom: 5px; }
    
    /* Typography */
    h1 { color: #1e3a8a; font-size: 18pt; margin-top: 30px; border-bottom: 2px solid #e2e8f0; padding-bottom: 5px; }
    h2 { color: #1e40af; font-size: 14pt; margin-top: 20px; }
    h3 { color: #334155; font-size: 12pt; margin-top: 15px; }
    h4 { color: #475569; font-size: 11pt; font-weight: bold; margin-top: 10px; }
    
    /* Summary Cards */
    .summary-cards { display: flex; justify-content: space-between; margin: 20px 0; }
    .card-summary { border: 1px solid #e2e8f0; border-radius: 8px; padding: 15px; text-align: center; width: 30%; }
    .card-summary .num { font-size: 24pt; font-weight: bold; }
    .card-summary .label { font-size: 10pt; color: #64748b; text-transform: uppercase; }
    .red { background: #fef2f2; color: #dc2626; border-color: #fecaca; }
    .orange { background: #fff7ed; color: #ea580c; border-color: #fed7aa; }
    .blue { background: #eff6ff; color: #3b82f6; border-color: #bfdbfe; }

    /* Tables */
    .table-wrap { width: 100%; margin-bottom: 15px; }
    table { width: 100%; border-collapse: collapse; font-size: 9pt; }
    th { background: #f1f5f9; color: #334155; font-weight: bold; text-align: left; padding: 8px; border-bottom: 2px solid #cbd5e1; }
    td { padding: 6px 8px; border-bottom: 1px solid #e2e8f0; vertical-align: top; }
    tr:nth-child(even) { background: #f8fafc; }

    /* Badges */
    .badge { padding: 2px 6px; border-radius: 4px; font-size: 8pt; font-weight: bold; color: white; }
    .badge-crit { background: #dc2626; }
    .badge-high { background: #ea580c; }
    .badge-med { background: #ca8a04; }
    .badge-low { background: #16a34a; }
    
    /* Specific Columns */
    .severity { font-weight: bold; }
    .package { font-family: monospace; }
    
    /* FORCE WRAPPING FOR LONG TEXT */
    pre {
        white-space: pre-wrap !important;      /* CSS3 - Text wraps when necessary */
        word-wrap: break-word !important;      /* Internet Explorer 5.5+ */
        overflow-wrap: break-word !important;  /* Chrome/Firefox/Opera */
        max-width: 100%;                       /* Ensure it doesn't exceed container */
        font-size: 8pt;                        /* Slightly smaller font for logs */
        border: 1px solid #e2e8f0;
        padding: 5px;
        background: #f8fafc;
        border-radius: 4px;
    }
    
    table {
        table-layout: fixed; /* Enforce strict column widths */
        width: 100%;
    }
    
    td {
        word-break: break-word; /* Break long words in tables */
        overflow-wrap: break-word;
        white-space: normal;    /* Allow wrapping */
    }
    
    /* ===== SSH AUDIT & NMAP PROFESSIONAL STYLING ===== */
    
    /* SSH Audit Report Styling */
    .ssh-report {
        background: #ffffff;
        border-radius: 8px;
        padding: 15px;
        margin: 15px 0;
        border: 1px solid #e2e8f0;
    }
    
    .ssh-report h2 {
        color: #1e3a8a;
        font-size: 16pt;
        margin-bottom: 15px;
        padding-bottom: 8px;
        border-bottom: 2px solid #3b82f6;
    }
    
    .ssh-report h3 {
        color: #334155;
        font-size: 13pt;
        margin-top: 18px;
        margin-bottom: 10px;
        padding-left: 10px;
        border-left: 4px solid #3b82f6;
    }
    
    .ssh-info {
        background: #f8fafc;
        padding: 12px;
        border-radius: 6px;
        margin: 10px 0;
        border-left: 4px solid #3b82f6;
    }
    
    .ssh-info p {
        margin: 5px 0;
        font-size: 10pt;
    }
    
    .ssh-info strong {
        color: #1e3a8a;
        font-weight: bold;
    }
    
    /* Algorithm Lists */
    .algorithm-section {
        margin: 15px 0;
    }
    
    .algorithm-list {
        list-style: none;
        padding-left: 0;
        margin: 8px 0;
    }
    
    .algorithm-list li {
        padding: 6px 10px;
        margin: 4px 0;
        border-radius: 4px;
        font-family: 'Courier New', monospace;
        font-size: 9pt;
    }
    
    /* Security Level Colors */
    .level-secure {
        background: #d1fae5;
        border-left: 4px solid #10b981;
        color: #065f46;
    }
    
    .level-weak {
        background: #fef3c7;
        border-left: 4px solid #f59e0b;
        color: #92400e;
    }
    
    .level-fail, .level-dangerous {
        background: #fee2e2;
        border-left: 4px solid #ef4444;
        color: #991b1b;
        font-weight: bold;
    }
    
    /* Critical Issues */
    .critical-issues {
        background: #fef2f2;
        border: 2px solid #ef4444;
        border-radius: 8px;
        padding: 12px;
        margin: 15px 0;
    }
    
    .critical-issues h3 {
        color: #dc2626;
        margin-top: 0;
        border-left-color: #ef4444;
    }
    
    .critical-issues ul {
        margin: 8px 0;
        padding-left: 20px;
    }
    
    .critical-issues li {
        color: #991b1b;
        margin: 5px 0;
        font-weight: 500;
    }
    
    /* Recommendations */
    .recommendations {
        background: #eff6ff;
        border: 2px solid #3b82f6;
        border-radius: 8px;
        padding: 12px;
        margin: 15px 0;
    }
    
    .recommendations h3 {
        color: #1e40af;
        margin-top: 0;
    }
    
    .recommendations ol {
        margin: 8px 0;
        padding-left: 25px;
    }
    
    .recommendations li {
        margin: 6px 0;
        color: #1e40af;
        font-weight: 500;
    }
    
    /* ===== NMAP REPORT STYLING ===== */
    
    .nmap-report {
        background: #ffffff;
        border-radius: 8px;
        padding: 15px;
        margin: 15px 0;
        border: 1px solid #e2e8f0;
    }
    
    .nmap-report h2 {
        color: #1e3a8a;
        font-size: 16pt;
        margin-bottom: 15px;
        padding-bottom: 8px;
        border-bottom: 2px solid #3b82f6;
    }
    
    .nmap-report h3 {
        color: #334155;
        font-size: 13pt;
        margin-top: 18px;
        margin-bottom: 10px;
        padding-left: 10px;
        border-left: 4px solid #10b981;
    }
    
    /* Scan Info */
    .scan-info {
        background: #f8fafc;
        padding: 12px;
        border-radius: 6px;
        margin: 10px 0;
        border-left: 4px solid #3b82f6;
    }
    
    .scan-info p {
        margin: 5px 0;
        font-size: 10pt;
    }
    
    .scan-info strong {
        color: #1e3a8a;
    }
    
    /* Nmap Summary Cards */
    .nmap-summary-cards {
        display: flex;
        justify-content: space-between;
        margin: 15px 0;
        gap: 10px;
    }
    
    .summary-card {
        flex: 1;
        display: flex;
        align-items: center;
        justify-content: center;
        gap: 8px;
        padding: 12px 15px;
        border-radius: 8px;
        border: 2px solid #e2e8f0;
        background: #f8fafc;
    }
    
    .summary-card.card-danger {
        background: #fef2f2;
        border-color: #fecaca;
    }
    
    .card-icon {
        font-size: 20pt;
    }
    
    .card-value {
        font-size: 20pt;
        font-weight: bold;
        color: #1e3a8a;
    }
    
    .card-danger .card-value {
        color: #dc2626;
    }
    
    .card-label {
        font-size: 10pt;
        color: #64748b;
        font-weight: 600;
    }
    
    /* Nmap Host Sections */
    .nmap-host-section {
        margin: 20px 0;
        padding: 15px;
        background: #f8fafc;
        border-radius: 8px;
        border: 1px solid #e2e8f0;
        page-break-inside: avoid;
    }
    
    .nmap-host-section h3 {
        color: #1e40af;
        font-size: 12pt;
        margin-top: 0;
        padding-bottom: 8px;
        border-bottom: 2px solid #cbd5e1;
    }
    
    .host-meta {
        font-size: 9pt;
        color: #475569;
        margin: 8px 0;
        font-style: italic;
    }
    
    /* Port Table Styling */
    .nmap-host-section table {
        width: 100%;
        margin-top: 10px;
        font-size: 9pt;
        border-collapse: collapse;
    }
    
    .nmap-host-section th {
        background: #1e3a8a;
        color: white;
        padding: 8px;
        text-align: left;
        font-weight: bold;
        font-size: 9pt;
    }
    
    .nmap-host-section td {
        padding: 6px 8px;
        border-bottom: 1px solid #e2e8f0;
    }
    
    /* Port Security Level Colors */
    .port-safe {
        background: #d1fae5 !important;
    }
    
    .port-safe td {
        color: #065f46;
    }
    
    .port-attention {
        background: #fef3c7 !important;
    }
    
    .port-attention td {
        color: #92400e;
    }
    
    .port-dangerous {
        background: #fee2e2 !important;
    }
    
    .port-dangerous td {
        color: #991b1b;
        font-weight: bold;
    }
    
    /* Section Styling */
    .section {
        margin: 15px 0;
        padding: 12px;
        border-radius: 8px;
    }
    
    .section.critical {
        background: #fef2f2;
        border: 2px solid #ef4444;
    }
    
    .section.critical h3 {
        color: #dc2626;
        border-left-color: #ef4444;
    }
    
    .section.critical ul {
        padding-left: 20px;
        margin: 8px 0;
    }
    
    .section.critical li {
        color: #991b1b;
        margin: 5px 0;
        font-weight: 500;
    }
    
    .section.recommendations {
        background: #eff6ff;
        border: 2px solid #3b82f6;
    }
    
    .section.recommendations h3 {
        color: #1e40af;
        border-left-color: #3b82f6;
    }
    
    .section.recommendations ol {
        padding-left: 25px;
        margin: 8px 0;
    }
    
    .section.recommendations li {
        color: #1e40af;
        margin: 6px 0;
        font-weight: 500;
    }
    
    /* Enhanced Visual Elements */
    .card {
        background: #ffffff;
        border: 1px solid #e2e8f0;
        border-radius: 8px;
        padding: 15px;
        margin: 10px 0;
        /* page-break-inside: avoid; */ /* Disabled per user request - allows large reports to split naturally */
    }
    
    .card h4 {
        color: #1e3a8a;
        font-size: 12pt;
        margin-top: 0;
        margin-bottom: 12px;
        padding-bottom: 8px;
        border-bottom: 2px solid #e2e8f0;
    }
    
    /* Emoji and Icons consistent display */
    span[role="img"] {
        font-family: 'Arial Unicode MS', 'Segoe UI Emoji', sans-serif;
    }
    """

    final_html = f"""
    <!doctype html>
    <html>
    <head>
        <meta charset="utf-8">
        <style>{css}</style>
    </head>
    <body>
        {cover_html}
        {exec_summary_html}
        <div class="page-break"></div>
        <div class="header">Cybershield Solutions | Detailed Findings</div>
        {main_content}
        
        <div style="margin-top: 50px; page-break-inside: avoid;">
            <div style="border-top: 2px solid #cbd5e1; padding-top: 20px; width: 100%;">
                <table style="width: 100%; border: none;">
                    <tr style="background: none;">
                        <td style="width: 60px; border: none; padding: 0; vertical-align: middle;">
                            {logo_img.replace('width:120px', 'width:50px')}
                        </td>
                        <td style="border: none; padding-left: 15px; vertical-align: middle;">
                            <div style="color: #1e3a8a; font-weight: bold; font-size: 11pt;">DIGITALLY SIGNED</div>
                            <div style="color: #64748b; font-size: 9pt;">Cybershield Solutions Security Audit</div>
                            <div style="color: #94a3b8; font-size: 8pt; font-family: monospace;">{generated.replace('T', ' ')} UTC</div>
                        </td>
                        <td style="text-align: right; border: none; vertical-align: middle;">
                            <div style="color: #10b981; font-weight: bold; font-size: 14pt; border: 2px solid #10b981; display: inline-block; padding: 5px 15px; border-radius: 4px; transform: rotate(-2deg);">
                                VERIFIED
                            </div>
                        </td>
                    </tr>
                </table>
            </div>
        </div>
    </body>
    </html>
    """

    # Generate PDF and sign it
    pdf_bytes = HTML(string=final_html).write_pdf()
    return sign_pdf_report(pdf_bytes)


# ---------------- REPORT PAGE (both sections) ----------------
# (SUBSTITUEIX la teva funció ui_report)

@app.route("/report", methods=["GET", "POST"])
def ui_report():
    hostname = os.uname().nodename

    if request.method == "POST":
        if request.form.get("action") == "download_csv":
            target = (request.form.get("target") or "localhost").strip()
            fname = (request.form.get("filename") or f"diag-report-{int(time.time())}.csv").strip()
            if "/" in fname or ".." in fname:
                fname = "diag-report.csv"
            selected = request.form.getlist("sections")
            csv_bytes = generate_report_csv(selected_sections=selected, nmap_target=target)
            resp = Response(csv_bytes, mimetype="text/csv; charset=utf-8")
            resp.headers["Content-Disposition"] = f"attachment; filename={fname}"
            return resp
        elif request.form.get("action") == "download_pdf":
            target = (request.form.get("target") or "localhost").strip()
            fname = (request.form.get("filename") or f"diag-report-{int(time.time())}.pdf").strip()
            if "/" in fname or ".." in fname:
                fname = "diag-report.pdf"
            selected = request.form.getlist("sections")
            try:
                pdf_bytes = generate_report_pdf(selected_sections=selected, nmap_target=target)
                resp = Response(pdf_bytes, mimetype="application/pdf")
                resp.headers["Content-Disposition"] = f"attachment; filename={fname}"
                return resp
            except Exception as e:
                return jsonify({"error": f"PDF generation failed: {str(e)}"}), 500

    visual_html = ""
    if request.args.get("view") == "interactive":
        # Afegim 'sshaudit' a la llista per defecte
        selected = request.args.getlist("sections") or ["trivy","packages","suspicious","logs","ssh","procs","services","sshaudit"]
        target = (request.args.get("target") or "localhost").strip()
        visual_html = render_visual_report(selected_sections=selected, nmap_target=target)

    allowed_ips = ", ".join(sorted(get_local_ips()))
    content = f"""
    <h1>Report</h1>
    <p class="muted">This page offers three ways to get diagnostics:</p>
    <div class="row">
      <div class="col-md-6">
        <div class="card" id="interactive">
          <h3>Section A — Visual Report (on this page)</h3>
          <p>Render selected sections below without downloading a file. Good for quick reviews.</p>
          <form id="visualForm" method="get" onsubmit="showVisualLoading()" action="/report#interactive">
            <input type="hidden" name="view" value="interactive">
            <div class="row">
              <div class="col-6">
                <div class="form-check"><input class="form-check-input" type="checkbox" name="sections" value="trivy" id="vTrivy" checked><label class="form-check-label" for="vTrivy">Trivy</label></div>
                <div class="form-check"><input class="form-check-input" type="checkbox" name="sections" value="packages" id="vPackages" checked><label class="form-check-label" for="vPackages">Upgradable Packages</label></div>
                <div class="form-check"><input class="form-check-input" type="checkbox" name="sections" value="suspicious" id="vSuspicious" checked><label class="form-check-label" for="vSuspicious">Suspicious Processes</label></div>
                <div class="form-check"><input class="form-check-input" type="checkbox" name="sections" value="logs" id="vLogs"><label class="form-check-label" for="vLogs">System Logs</label></div>
                <div class="form-check"><input class="form-check-input" type="checkbox" name="sections" value="nmap" id="vNmap"><label class="form-check-label" for="vNmap">Nmap</label></div>
              </div>
              <div class="col-6">
                <div class="form-check"><input class="form-check-input" type="checkbox" name="sections" value="ssh" id="vSSH"><label class="form-check-label" for="vSSH">SSH Fails</label></div>
                <div class="form-check"><input class="form-check-input" type="checkbox" name="sections" value="procs" id="vProcs"><label class="form-check-label" for="vProcs">Processes</label></div>
                <div class="form-check"><input class="form-check-input" type="checkbox" name="sections" value="services" id="vServices"><label class="form-check-label" for="vServices">Services</label></div>
                <div class="form-check"><input class="form-check-input" type="checkbox" name="sections" value="sshaudit" id="vSshAudit" checked><label class="form-check-label" for="vSshAudit">SSH-Audit</label></div>
                <div class="form-check"><input class="form-check-input" type="checkbox" name="sections" value="enum4linux" id="vEnum4linux"><label class="form-check-label" for="vEnum4linux">enum4linux</label></div>
              </div>
            </div>
            <label class="mt-2">Target (Nmap / SSH-Audit)</label>
            <div class="form-text">e.g., localhost, 192.168.1.1, or localhost:2222 (for SSH-Audit port)</div>
            <input type="text" name="target" value="localhost" class="form-control mb-2" />
            <button type="submit" class="btn btn-secondary btn-pill">Render Visual Report</button>
          </form>
          <div id="visualLoading" style="display:none; text-align:center; margin-top:20px;">
            <div class="spinner-border text-info" role="status" style="width:3rem; height:3rem;"></div>
            <div class="mt-2">Rendering sections...</div>
          </div>
          <div class="mt-3">{visual_html}</div>
        </div>
      </div>
      <div class="col-md-6">
        <div class="card" id="csv">
          <h3>Section B — CSV Export (download)</h3>
          <p>Generate a CSV file with the selected sections. Ideal for archiving or sharing.</p>
          <form id="csvForm" method="post" onsubmit="showCsvLoading()" action="/report#csv">
            <input type="hidden" name="action" value="download_csv">
            <div class="row">
              <div class="col-6">
                <div class="form-check"><input class="form-check-input" type="checkbox" name="sections" value="trivy" id="cTrivy" checked><label class="form-check-label" for="cTrivy">Trivy</label></div>
                <div class="form-check"><input class="form-check-input" type="checkbox" name="sections" value="packages" id="cPackages" checked><label class="form-check-label" for="cPackages">Upgradable Packages</label></div>
                <div class="form-check"><input class="form-check-input" type="checkbox" name="sections" value="suspicious" id="cSuspicious" checked><label class="form-check-label" for="cSuspicious">Suspicious Processes</label></div>
                <div class="form-check"><input class="form-check-input" type="checkbox" name="sections" value="logs" id="cLogs" checked><label class="form-check-label" for="cLogs">System Logs</label></div>
                <div class="form-check"><input class="form-check-input" type="checkbox" name="sections" value="nmap" id="cNmap" checked><label class="form-check-label" for="cNmap">Nmap</label></div>
              </div>
              <div class="col-6">
                <div class="form-check"><input class="form-check-input" type="checkbox" name="sections" value="ssh" id="cSSH" checked><label class="form-check-label" for="cSSH">SSH Fails</label></div>
                <div class="form-check"><input class="form-check-input" type="checkbox" name="sections" value="procs" id="cProcs" checked><label class="form-check-label" for="cProcs">Processes</label></div>
                <div class="form-check"><input class="form-check-input" type="checkbox" name="sections" value="services" id="cServices" checked><label class="form-check-label" for="cServices">Services</label></div>
                <div class="form-check"><input class="form-check-input" type="checkbox" name="sections" value="sshaudit" id="cSshAudit" checked><label class="form-check-label" for="cSshAudit">SSH-Audit</label></div>
                <div class="form-check"><input class="form-check-input" type="checkbox" name="sections" value="enum4linux" id="cEnum4linux"><label class="form-check-label" for="cEnum4linux">enum4linux</label></div>
              </div>
            </div>
            <label class="mt-2">Target (Nmap / SSH-Audit)</label>
            <div class="form-text">e.g., localhost, or localhost:2222</div>
            <input type="text" name="target" value="localhost" class="form-control mb-2" />
            <label>Output CSV filename</label>
            <input type="text" name="filename" value="diag-report.csv" class="form-control mb-3" />
            <button type="submit" class="btn btn-primary btn-pill">Generate & Download CSV</button>
          </form>
          <div id="csvLoading" style="display:none; text-align:center; margin-top:20px;">
            <div class="spinner-border text-info" role="status" style="width:3rem; height:3rem;"></div>
            <div class="mt-2">Generating CSV... (Trivy + optional Nmap)</div>
          </div>
        </div>
        <div class="card" id="pdf">
          <h3>Section C — PDF Export (download)</h3>
          <p>Generate a professional PDF report with the selected sections.</p>
          <form id="pdfForm" method="post" onsubmit="showPdfLoading()" action="/report#pdf">
            <input type="hidden" name="action" value="download_pdf">
            <div class="row">
              <div class="col-6">
                <div class="form-check"><input class="form-check-input" type="checkbox" name="sections" value="trivy" id="pTrivy" checked><label class="form-check-label" for="pTrivy">Trivy</label></div>
                <div class="form-check"><input class="form-check-input" type="checkbox" name="sections" value="packages" id="pPackages" checked><label class="form-check-label" for="pPackages">Upgradable Packages</label></div>
                <div class="form-check"><input class="form-check-input" type="checkbox" name="sections" value="suspicious" id="pSuspicious" checked><label class="form-check-label" for="pSuspicious">Suspicious Processes</label></div>
                <div class="form-check"><input class="form-check-input" type="checkbox" name="sections" value="logs" id="pLogs" checked><label class="form-check-label" for="pLogs">System Logs</label></div>
                <div class="form-check"><input class="form-check-input" type="checkbox" name="sections" value="nmap" id="pNmap" checked><label class="form-check-label" for="pNmap">Nmap</label></div>
              </div>
              <div class="col-6">
                <div class="form-check"><input class="form-check-input" type="checkbox" name="sections" value="ssh" id="pSSH" checked><label class="form-check-label" for="pSSH">SSH Fails</label></div>
                <div class="form-check"><input class="form-check-input" type="checkbox" name="sections" value="services" id="pServices" checked><label class="form-check-label" for="pServices">Services</label></div>
                <div class="form-check"><input class="form-check-input" type="checkbox" name="sections" value="sshaudit" id="pSshAudit" checked><label class="form-check-label" for="pSshAudit">SSH-Audit</label></div>
                <div class="form-check"><input class="form-check-input" type="checkbox" name="sections" value="enum4linux" id="pEnum4linux"><label class="form-check-label" for="pEnum4linux">enum4linux</label></div>
              </div>
            </div>
            <label class="mt-2">Target (Nmap / SSH-Audit)</label>
            <div class="form-text">e.g., localhost, or localhost:2222</div>
            <input type="text" name="target" value="localhost" class="form-control mb-2" />
            <label>Output PDF filename</label>
            <input type="text" name="filename" value="diag-report.pdf" class="form-control mb-3" />
            <button type="submit" class="btn btn-primary btn-pill">Generate & Download PDF</button>
          </form>
          <div id="pdfLoading" style="display:none; text-align:center; margin-top:20px;">
            <div class="spinner-border text-info" role="status" style="width:3rem; height:3rem;"></div>
            <div class="mt-2">Generating PDF...</div>
          </div>
        </div>
      </div>
    </div>
    <script>
      function showCsvLoading() {{ document.getElementById('csvLoading').style.display = 'block'; }}
      function showVisualLoading() {{ document.getElementById('visualLoading').style.display = 'block'; }}
      function showPdfLoading() {{ document.getElementById('pdfLoading').style.display = 'block'; }}
    </script>
    """
    return render_template_string(BASE_HTML, hostname=hostname, content=content)
# ---------------- Optional standalone Nmap page ----------------
@app.route("/nmap", methods=["GET","POST"])
def ui_nmap():
    hostname = os.uname().nodename
    note = "<p class='muted'>Server-side scan: only localhost or the host's IP addresses are allowed. This UI offers a safe subset of Nmap flags. NSE scripts are disabled.</p>"
    allowed_ips = ", ".join(sorted(get_local_ips()))
    form = f"""
      <h1>Nmap Network Scanner</h1>
      {note}
      <div class='small'>Allowed targets: {allowed_ips} (or 'localhost')</div>
      <form method='post' class='mt-2'>
        <label class="form-label">Target (default: localhost)</label>
        <input type='text' name='target' class="form-control mb-3" value='localhost' />

        <label class="form-label">Extra Nmap args (optional, safe subset)</label>
        <div class="card p-2">
          <div class="form-check">
            <input class="form-check-input" type="checkbox" id="arg_pall" name="arg_pall" value="1">
            <label class="form-check-label" for="arg_pall">-p- (scan all ports)</label>
          </div>

          <div class="row mt-2">
            <div class="col-6">
              <div class="form-check">
                <input class="form-check-input" type="checkbox" id="arg_prange_chk" name="arg_prange_chk" value="1">
                <label class="form-check-label" for="arg_prange_chk">-p &lt;range/list&gt;</label>
              </div>
            </div>
            <div class="col-6">
              <input type="text" class="form-control" name="arg_prange_val" placeholder="e.g. 1-60000 or 80,443,1000-2000" />
            </div>
          </div>

          <div class="row mt-2">
            <div class="col-6">
              <div class="form-check">
                <input class="form-check-input" type="checkbox" id="arg_T4" name="arg_T4" value="1">
                <label class="form-check-label" for="arg_T4">-T4 (faster timing)</label>
              </div>
              <div class="form-check">
                <input class="form-check-input" type="checkbox" id="arg_sV" name="arg_sV" value="1">
                <label class="form-check-label" for="arg_sV">-sV (service/version detection)</label>
              </div>
            </div>
            <div class="col-6">
              <div class="form-check">
                <input class="form-check-input" type="checkbox" id="arg_Pn" name="arg_Pn" value="1">
                <label class="form-check-label" for="arg_Pn">-Pn (treat hosts as online)</label>
              </div>
              <div class="form-check">
                <input class="form-check-input" type="checkbox" id="arg_A" name="arg_A" value="1">
                <label class="form-check-label" for="arg_A">-A (aggressive, no scripts here)</label>
              </div>
            </div>
          </div>
        </div>

        <button type='submit' class="btn btn-primary btn-pill mt-3">Run Nmap</button>
      </form>
    """
    scan_out = ""
    if request.method == "POST":
        target = (request.form.get("target") or "localhost").strip()
        if not is_allowed_target(target):
            scan_out = f"<div class='alert alert-danger'>ERROR: target not allowed: {target}</div>"
        elif not NMAP_BIN:
            scan_out = "<div class='alert alert-danger'>ERROR: nmap not installed on server</div>"
        else:
            # Build tokens from checkboxes
            tokens = []

            if request.form.get("arg_pall"):
                tokens.append("-p-")

            if request.form.get("arg_prange_chk"):
                pr = (request.form.get("arg_prange_val") or "").strip()
                if pr:
                    tokens.extend(["-p", pr])

            if request.form.get("arg_T4"):
                tokens.append("-T4")
            if request.form.get("arg_sV"):
                tokens.append("-sV")
            if request.form.get("arg_Pn"):
                tokens.append("-Pn")
            if request.form.get("arg_A"):
                tokens.append("-A")

            # Validate with safe whitelist (will also reject any --script)
            cleaned, verr = validate_nmap_extra_args(tokens)
            if verr:
                scan_out = f"<div class='alert alert-danger'>ERROR: {verr}</div>"
            else:
                raw, err = run_nmap_raw(target, extra_args=cleaned)
                if err:
                    scan_out = f"<div class='alert alert-danger'>{err}</div>"
                else:
                    # Parse with professional parser
                    try:
                        parser = NmapParser()
                        report = parser.parse(raw)
                        scan_out = parser.to_html(report)
                        
                        # Add raw output section (visible by default for technical users)
                        scan_out += f"""
                        <div class="mt-4">
                            <h3>Raw Nmap Output</h3>
                            <p class="text-muted small">Technical details for verification and debugging</p>
                            <pre style="max-height:400px; overflow-y:auto; background: var(--bg-tertiary); padding: 15px; border-radius: 6px; border: 1px solid var(--border-color);">{h_esc(raw[:NMAP_MAX_CHARS])}</pre>
                        </div>
                        """
                    except Exception as e:
                        # Fallback to raw output
                        safe = raw[:NMAP_MAX_CHARS]
                        if len(raw) > NMAP_MAX_CHARS:
                            safe += "\n\n[...output truncated...]\n"
                        safe = safe.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
                        scan_out = "<h2>Scan output (raw - parser error)</h2><pre>" + safe + "</pre>"

    content = form + (scan_out or "")
    return render_template_string(BASE_HTML, hostname=hostname, platform="", uptime="", content=content)


# ========== SOC DASHBOARD (Security Operations Center) ==========

@app.route("/static/cshield.png")
def serve_logo():
    """Serve the cshield.png logo from the script directory"""
    logo_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "cshield.png")
    if os.path.exists(logo_path):
        return send_file(logo_path, mimetype='image/png')
    else:
        return "", 404


@app.route("/soc")
def soc_dashboard():
    """SOC Dashboard - Real-time Security Monitoring"""
    hostname = os.uname().nodename if hasattr(os, "uname") else "host"
    
    content = """
    <h1><i class="bi bi-activity"></i> SOC Dashboard — Live Security Monitoring</h1>
    <p class="text-muted">Real-time system health, network activity, security events, and critical logs</p>
    
    <!-- Alert Summary Banner -->
    <div id="alertBanner" style="display:none; margin-bottom:20px;"></div>
    
    <!-- System Health Row -->
    <div class="row g-3 mb-3">
      <div class="col-md-4">
        <div class="card">
          <div class="card-title">CPU Usage</div>
          <div style="position: relative; height: 200px; width: 100%;">
            <canvas id="cpuChart"></canvas>
          </div>
          <div id="cpuInfo" class="small mt-2 text-center"></div>
        </div>
      </div>
      <div class="col-md-4">
        <div class="card">
          <div class="card-title">Memory Usage</div>
          <div style="position: relative; height: 200px; width: 100%;">
            <canvas id="memChart"></canvas>
          </div>
          <div id="memInfo" class="small mt-2 text-center"></div>
        </div>
      </div>
      <div class="col-md-4">
        <div class="card">
          <div class="card-title">Disk & Load</div>
          <div id="diskInfo" style="padding:10px; font-size:14px;"></div>
        </div>
      </div>
    </div>
    
    <!-- Network & Security Row -->
    <div class="row g-3 mb-3">
      <div class="col-md-8">
        <div class="card">
          <div class="card-title">Network Traffic (KB/s)</div>
          <div style="position: relative; height: 200px; width: 100%;">
            <canvas id="netChart"></canvas>
          </div>
        </div>
      </div>
      <div class="col-md-4">
        <div class="card">
          <div class="card-title"><i class="bi bi-shield-exclamation"></i> SSH Failed Attempts</div>
          <div id="sshFailsInfo"></div>
        </div>
      </div>
    </div>
    
    <!-- Active Connections & Suspicious Processes -->
    <div class="row g-3 mb-3">
      <div class="col-md-6">
        <div class="card">
          <div class="card-title">Active Connections</div>
          <div id="connectionsInfo" class="table-wrap"></div>
        </div>
      </div>
      <div class="col-md-6">
        <div class="card">
          <div class="card-title">Suspicious Processes</div>
          <div id="suspiciousProcs" class="table-wrap"></div>
        </div>
      </div>
    </div>
    
    <!-- Critical Logs -->
    <div class="card">
      <div class="card-title"><i class="bi bi-journal-text"></i> Critical System Logs</div>
      <div id="criticalLogs" style="max-height:300px; overflow-y:auto;"></div>
    </div>
    
    <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
    <script>
      // Chart.js setup
      const chartConfig = {
        type: 'line',
        options: {
          responsive: true,
          maintainAspectRatio: false,
          plugins: { legend: { display: false } },
          scales: {
            y: { beginAtZero: true, max: 100 },
            x: { display: false }
          },
          animation: { duration: 0 }
        }
      };
      
      const cpuChart = new Chart(document.getElementById('cpuChart'), {
        ...chartConfig,
        data: {
          labels: [],
          datasets: [{
            label: 'CPU %',
            data: [],
            borderColor: '#3b82f6',
            backgroundColor: 'rgba(59, 130, 246, 0.1)',
            tension: 0.4,
            fill: true
          }]
        }
      });
      
      const memChart = new Chart(document.getElementById('memChart'), {
        ...chartConfig,
        data: {
          labels: [],
          datasets: [{
            label: 'Memory %',
            data: [],
            borderColor: '#10b981',
            backgroundColor: 'rgba(16, 185, 129, 0.1)',
            tension: 0.4,
            fill: true
          }]
        }
      });
      
      const netChart = new Chart(document.getElementById('netChart'), {
        ...chartConfig,
        options: {
          ...chartConfig.options,
          scales: { y: { beginAtZero: true }, x: { display: false } }
        },
        data: {
          labels: [],
          datasets: [
            {
              label: 'Sent',
              data: [],
              borderColor: '#f59e0b',
              backgroundColor: 'rgba(245, 158, 11, 0.1)',
              tension: 0.4,
              fill: true
            },
            {
              label: 'Received',
              data: [],
              borderColor: '#06b6d4',
              backgroundColor: 'rgba(6, 182, 212, 0.1)',
              tension: 0.4,
              fill: true
            }
          ]
        }
      });
      
      // Update dashboard data
      function updateDashboard() {
        fetch('/api/soc/metrics')
          .then(r => r.json())
          .then(data => {
            // CPU
            const cpu = data.system.cpu;
            cpuChart.data.labels = data.system.timestamps;
            cpuChart.data.datasets[0].data = cpu.history;
            cpuChart.update();
            document.getElementById('cpuInfo').innerHTML = 
              `<strong>${cpu.percent}%</strong> ${getAlertBadge(cpu.alert)}`;
            
            // Memory
            const mem = data.system.memory;
            memChart.data.labels = data.system.timestamps;
            memChart.data.datasets[0].data = mem.history;
            memChart.update();
            document.getElementById('memInfo').innerHTML = 
              `<strong>${mem.used_gb}GB / ${mem.total_gb}GB</strong> ${getAlertBadge(mem.alert)}`;
            
            // Disk & Load
            const disk = data.system.disk;
            const load = data.system.load;
            document.getElementById('diskInfo').innerHTML = `
              <div><strong>Disk:</strong> ${disk.percent}% (${disk.used_gb}GB / ${disk.total_gb}GB) ${getAlertBadge(disk.alert)}</div>
              <div class="mt-2"><strong>Load Avg:</strong> ${load.load1}, ${load.load5}, ${load.load15}</div>
              <div class="mt-2"><strong>Uptime:</strong> ${data.system.uptime.days}d ${data.system.uptime.hours}h</div>
            `;
            
            // Network
            const net = data.network.traffic;
            netChart.data.labels = data.system.timestamps;
            netChart.data.datasets[0].data = net.sent_history;
            netChart.data.datasets[1].data = net.recv_history;
            netChart.update();
            
            // SSH Fails
            const ssh = data.security.ssh_fails;
            let sshHtml = `<div class="p-3 text-center" style="font-size:32px; font-weight:700;">${ssh.count}</div>`;
            sshHtml += `<div class="text-center">${getAlertBadge(ssh.alert)}</div>`;
            if (ssh.recent.length > 0) {
              sshHtml += '<div class="mt-2" style="max-height:150px; overflow-y:auto; font-size:12px;">';
              sshHtml += '<table style="width:100%; table-layout:fixed;"><tr><th style="width:40%;">User</th><th style="width:35%;">IP</th><th style="width:25%;">Time</th></tr>';
              ssh.recent.forEach(f => {
                sshHtml += `<tr>
                  <td style="overflow:hidden; text-overflow:ellipsis; white-space:nowrap;"><strong>${esc(f.user)}</strong></td>
                  <td style="overflow:hidden; text-overflow:ellipsis; white-space:nowrap;">${esc(f.ip)}</td>
                  <td style="overflow:hidden; text-overflow:ellipsis; white-space:nowrap; font-size:10px;">${esc(f.time)}</td>
                </tr>`;
              });
              sshHtml += '</table></div>';
            }
            document.getElementById('sshFailsInfo').innerHTML = sshHtml;
            
            // Connections
            const conns = data.network.connections;
            let connHtml = `<div class="p-2"><strong>${conns.active}</strong> active connections</div>`;
            if (conns.top.length > 0) {
              connHtml += '<table class="table-sm w-100"><tr><th>Local</th><th>Remote</th><th>State</th></tr>';
              conns.top.forEach(c => {
                connHtml += `<tr><td class="small">${esc(c.local)}</td><td class="small">${esc(c.remote)}</td><td class="small">${esc(c.status)}</td></tr>`;
              });
              connHtml += '</table>';
            }
            document.getElementById('connectionsInfo').innerHTML = connHtml;
            
            // Suspicious Processes
            const procs = data.security.suspicious_procs;
            let procHtml = '';
            if (procs.length > 0) {
              procHtml = '<table class="w-100"><tr><th>PID</th><th>Name</th><th>CPU%</th><th>Mem%</th></tr>';
              procs.forEach(p => {
                procHtml += `<tr><td>${esc(p.pid)}</td><td>${esc(p.name)}</td><td>${esc(p.cpu)}</td><td>${esc(p.mem)}</td></tr>`;
              });
              procHtml += '</table>';
            } else {
              procHtml = '<div class="p-3 text-muted text-center">No suspicious processes</div>';
            }
            document.getElementById('suspiciousProcs').innerHTML = procHtml;
            
            // Critical Logs
            const logs = data.logs;
            let logHtml = '';
            if (logs.length > 0) {
              logs.forEach(log => {
                const color = log.severity === 'error' ? '#ef4444' : (log.severity === 'warning' ? '#f59e0b' : '#94a3b8');
                logHtml += `<div class="p-2" style="border-bottom:1px solid var(--border-color); word-break:break-word;">
                  <span style="color:${color};">●</span>
                  <span class="small">${esc(log.time)}</span> 
                  <strong>${esc(log.service)}</strong>: <span style="font-size:13px;">${esc(log.message)}</span>
                </div>`;
              });
            } else {
              logHtml = '<div class="p-3 text-muted text-center">No critical logs</div>';
            }
            document.getElementById('criticalLogs').innerHTML = logHtml;
            
            // Alert Banner
            const alerts = [];
            if (cpu.alert === 'critical') alerts.push('🔴 CPU Critical');
            if (cpu.alert === 'warning') alerts.push('🟡 CPU High');
            if (mem.alert === 'critical') alerts.push('🔴 Memory Critical');
            if (mem.alert === 'warning') alerts.push('🟡 Memory High');
            if (disk.alert === 'critical') alerts.push('🔴 Disk Critical');
            if (ssh.alert === 'critical') alerts.push('🔴 High SSH Attack');
            
            const banner = document.getElementById('alertBanner');
            if (alerts.length > 0) {
              banner.innerHTML = `<div class="alert alert-warning">${alerts.join(' | ')}</div>`;
              banner.style.display = 'block';
            } else {
              banner.style.display = 'none';
            }
          })
          .catch(e => console.error('SOC update error:', e));
      }
      
      function getAlertBadge(alert) {
        if (alert === 'critical') return '<span class="sev-crit">CRITICAL</span>';
        if (alert === 'warning') return '<span class="sev-high">WARNING</span>';
        return '<span style="color:var(--success);">●</span>';
      }
      
      // Initial load
      updateDashboard();
      
      // Auto-refresh every 3 seconds
      setInterval(updateDashboard, 3000);
    </script>
    """
    
    return render_template_string(BASE_HTML, hostname=hostname, content=content)


@app.route("/api/soc/metrics")
def api_soc_metrics():
    """API endpoint for SOC metrics"""
    try:
        metrics = soc_get_all_metrics()
        return jsonify(metrics)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ================================================================


# ==================== PENTEST AGENT ROUTES ====================
# Web vulnerability scanning integration

def run_pentest_background(scan_id: str, target: str, options: dict):
    """Background thread function to run pentest scan."""
    global pentest_scans
    
    try:
        with pentest_scans_lock:
            pentest_scans[scan_id]["status"] = "running"
        
        # Create PentestAgent with options
        agent = PentestAgent(
            target,
            verify_tls=False,
            timeout_s=options.get("timeout", 15),
            delay_s=options.get("delay", 0.2),
            max_requests=options.get("max_requests", 500),
            threads=options.get("threads", 5),
            enable_sqli=options.get("sqli", True),
            enable_xss=options.get("xss", True),
            enable_headers=options.get("headers", True),
            enable_exposure=options.get("exposure", True),
            enable_cmdi=options.get("cmdi", True),
            enable_lfi=options.get("lfi", True),
            enable_cors=options.get("cors", True),
            enable_cookies=options.get("cookies", True),
            enable_tech=options.get("tech", True),
            enable_dorking=options.get("dorking", False),
            time_based_sqli=options.get("time_sqli", False),
            max_depth=options.get("max_depth", 3),
            verbose=False,
        )
        
        with pentest_scans_lock:
            pentest_scans[scan_id]["agent"] = agent
        
        # Run scan
        agent.scan(crawl=options.get("crawl", True))
        
        with pentest_scans_lock:
            pentest_scans[scan_id]["status"] = "completed"
            
    except Exception as e:
        with pentest_scans_lock:
            pentest_scans[scan_id]["status"] = "error"
            pentest_scans[scan_id]["error"] = str(e)


@app.route("/pentest")
def ui_pentest():
    """Pentest Agent UI - Web vulnerability scanner."""
    if not PENTEST_AVAILABLE:
        content = """
        <div class="card">
            <h4><i class="bi bi-exclamation-triangle text-warning"></i> Pentest Module Unavailable</h4>
            <p>The <code>pentest_agent.py</code> file was not found in the same directory as <code>diag_agent_single.py</code>.</p>
            <p>Please ensure both files are in the same folder and restart the server.</p>
        </div>
        """
        return render_template_string(BASE_HTML, content=content)
    
    content = """
    <style>
        .table-wrap { border: 1px solid var(--border-color); border-radius: 8px; overflow: hidden; margin-top: 15px; background: var(--bg-secondary); }
        .table-wrap table { margin-bottom: 0; border: none; }
        
        /* Status badges */
        .sev-crit { background: rgba(239, 68, 68, 0.2); color: #ef4444; padding: 4px 8px; border-radius: 4px; font-weight: bold; font-size: 11px; }
        .sev-high { background: rgba(245, 158, 11, 0.2); color: #f59e0b; padding: 4px 8px; border-radius: 4px; font-weight: bold; font-size: 11px; }
        .badge-soft { background: rgba(59, 130, 246, 0.15); color: var(--accent-secondary); padding: 4px 8px; border-radius: 4px; font-size: 11px; }
        
        /* Custom NMAP-style summary cards for Pentest */
        .pentest-summary { display: flex; gap: 15px; margin-bottom: 20px; flex-wrap: wrap; }
        .p-card { flex: 1; min-width: 150px; background: var(--bg-tertiary); border: 1px solid var(--border-color); border-radius: 12px; padding: 15px; display: flex; align-items: center; gap: 12px; }
        .p-card i { font-size: 24px; }
        .p-card .v { font-size: 20px; font-weight: bold; }
        .p-card .l { font-size: 12px; color: var(--text-secondary); }
    </style>
    <div class="card mb-4">
        <h4><i class="bi bi-bug-fill"></i> Web Vulnerability Scanner</h4>
        <p class="text-muted">Scan websites for SQL Injection, XSS, LFI, CORS, and other vulnerabilities.</p>
        
        <div class="alert alert-warning">
            <strong><i class="bi bi-exclamation-triangle"></i> Warning:</strong> 
            Only scan websites you own or have explicit authorization to test!
        </div>
        
        <form id="pentestForm" class="mt-3">
            <div class="row mb-3">
                <div class="col-md-8">
                    <label class="form-label">Target URL</label>
                    <input type="url" class="form-control" id="targetUrl" name="target" 
                           placeholder="https://example.com" required>
                    <small class="text-muted">Enter the full URL including http:// or https://</small>
                </div>
                <div class="col-md-4">
                    <label class="form-label">Threads</label>
                    <select class="form-control" id="threads" name="threads">
                        <option value="3">3 (Slow/Stealth)</option>
                        <option value="5" selected>5 (Normal)</option>
                        <option value="10">10 (Fast)</option>
                    </select>
                </div>
            </div>
            
            <div class="mb-3">
                <label class="form-label">Scan Modules</label>
                <div class="row">
                    <div class="col-md-3">
                        <div class="form-check">
                            <input class="form-check-input" type="checkbox" id="modSqli" name="sqli" checked>
                            <label class="form-check-label">SQL Injection</label>
                        </div>
                        <div class="form-check">
                            <input class="form-check-input" type="checkbox" id="modXss" name="xss" checked>
                            <label class="form-check-label">XSS (Reflected)</label>
                        </div>
                        <div class="form-check">
                            <input class="form-check-input" type="checkbox" id="modLfi" name="lfi" checked>
                            <label class="form-check-label">Path Traversal/LFI</label>
                        </div>
                    </div>
                    <div class="col-md-3">
                        <div class="form-check">
                            <input class="form-check-input" type="checkbox" id="modCmdi" name="cmdi" checked>
                            <label class="form-check-label">Command Injection</label>
                        </div>
                        <div class="form-check">
                            <input class="form-check-input" type="checkbox" id="modCors" name="cors" checked>
                            <label class="form-check-label">CORS Misconfig</label>
                        </div>
                        <div class="form-check">
                            <input class="form-check-input" type="checkbox" id="modCookies" name="cookies" checked>
                            <label class="form-check-label">Cookie Security</label>
                        </div>
                    </div>
                    <div class="col-md-3">
                        <div class="form-check">
                            <input class="form-check-input" type="checkbox" id="modHeaders" name="headers" checked>
                            <label class="form-check-label">Security Headers</label>
                        </div>
                        <div class="form-check">
                            <input class="form-check-input" type="checkbox" id="modExposure" name="exposure" checked>
                            <label class="form-check-label">Sensitive Files</label>
                        </div>
                        <div class="form-check">
                            <input class="form-check-input" type="checkbox" id="modTech" name="tech" checked>
                            <label class="form-check-label">Tech Fingerprint</label>
                        </div>
                    </div>
                    <div class="col-md-3">
                        <div class="form-check">
                            <input class="form-check-input" type="checkbox" id="modCrawl" name="crawl" checked>
                            <label class="form-check-label">Crawl Site First</label>
                        </div>
                    </div>
                </div>
            </div>
            
            <!-- Advanced Options (Collapsible) -->
            <div class="mb-3">
                <button class="btn btn-outline-secondary btn-sm" type="button" data-bs-toggle="collapse" data-bs-target="#advancedOptions">
                    <i class="bi bi-gear"></i> Advanced Options
                </button>
                <div class="collapse mt-3" id="advancedOptions">
                    <div class="card" style="background: var(--bg-tertiary); border: 1px solid var(--border-color);">
                        <div class="card-body">
                            <div class="row">
                                <div class="col-md-3">
                                    <label class="form-label">Max Requests</label>
                                    <select class="form-control" id="maxRequests" name="max_requests">
                                        <option value="100">100 (Quick Test)</option>
                                        <option value="500" selected>500 (Default)</option>
                                        <option value="1000">1,000</option>
                                        <option value="2000">2,000</option>
                                        <option value="5000">5,000 (Thorough)</option>
                                        <option value="10000">10,000 (Full)</option>
                                    </select>
                                    <small class="text-muted">Total HTTP requests limit</small>
                                </div>
                                <div class="col-md-3">
                                    <label class="form-label">Crawl Depth</label>
                                    <select class="form-control" id="maxDepth" name="max_depth">
                                        <option value="1">1 (Shallow)</option>
                                        <option value="2">2</option>
                                        <option value="3" selected>3 (Default)</option>
                                        <option value="5">5 (Deep)</option>
                                        <option value="10">10 (Very Deep)</option>
                                    </select>
                                    <small class="text-muted">Link following depth</small>
                                </div>
                                <div class="col-md-3">
                                    <label class="form-label">Request Delay</label>
                                    <select class="form-control" id="delayS" name="delay_s">
                                        <option value="0.05">0.05s (Aggressive)</option>
                                        <option value="0.1">0.1s (Fast)</option>
                                        <option value="0.2" selected>0.2s (Normal)</option>
                                        <option value="0.5">0.5s (Slow)</option>
                                        <option value="1.0">1.0s (Stealth)</option>
                                    </select>
                                    <small class="text-muted">Delay between requests</small>
                                </div>
                                <div class="col-md-3">
                                    <label class="form-label">Request Timeout</label>
                                    <select class="form-control" id="timeoutS" name="timeout_s">
                                        <option value="5">5s (Fast)</option>
                                        <option value="10">10s</option>
                                        <option value="15" selected>15s (Default)</option>
                                        <option value="30">30s (Slow servers)</option>
                                    </select>
                                    <small class="text-muted">Timeout per request</small>
                                </div>
                            </div>
                            <div class="row mt-3">
                                <div class="col-md-6">
                                    <div class="form-check">
                                        <input class="form-check-input" type="checkbox" id="timeSqli" name="time_sqli">
                                        <label class="form-check-label">
                                            <strong>Time-Based Blind SQLi</strong>
                                            <span class="badge bg-warning ms-2">Slow</span>
                                        </label>
                                        <br><small class="text-muted">Detects blind SQLi using time delays (more intrusive)</small>
                                    </div>
                                </div>
                                <div class="col-md-6">
                                    <div class="form-check">
                                        <input class="form-check-input" type="checkbox" id="modDorking" name="dorking">
                                        <label class="form-check-label">
                                            <strong>Google Dorking (OSINT)</strong>
                                            <span class="badge bg-warning ms-2">Very Slow</span>
                                        </label>
                                        <br><small class="text-muted">Reconnaissance via Google search (3-5s delays)</small>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
            
            <button type="submit" class="btn btn-primary btn-pill" id="btnScan">
                <i class="bi bi-play-circle"></i> Start Scan
            </button>
        </form>
    </div>
    
    <!-- Progress Section (hidden initially) -->
    <div class="card mb-4" id="progressCard" style="display:none;">
        <h4><i class="bi bi-hourglass-split"></i> Scan Progress</h4>
        <div class="progress mb-3" style="height: 24px;">
            <div class="progress-bar progress-bar-striped progress-bar-animated" id="progressBar" 
                 role="progressbar" style="width: 0%;">0%</div>
        </div>
        <div id="progressInfo">
            <span class="badge bg-info" id="statusBadge">Starting...</span>
            <span class="ms-3">URLs: <strong id="urlsCount">0</strong></span>
            <span class="ms-3">Requests: <strong id="requestsCount">0</strong></span>
            <span class="ms-3">Findings: <strong id="findingsCount">0</strong></span>
        </div>
    </div>
    
    <!-- Results Section (hidden initially) -->
    <div class="card" id="resultsCard" style="display:none;">
        <div class="d-flex justify-content-between align-items-center mb-3">
            <h4><i class="bi bi-list-check"></i> Scan Results</h4>
            <div class="d-flex align-items-center gap-2">
                <button class="btn btn-primary btn-pill btn-sm" id="btnDownloadPdf" style="display:none;">
                    <i class="bi bi-file-pdf"></i> PDF
                </button>
                <div class="input-group input-group-sm" id="telegramGroup" style="display:none; max-width:280px;">
                    <input type="text" class="form-control" id="telegramChatId" placeholder="Chat ID" 
                           style="border-radius: 20px 0 0 20px;">
                    <button class="btn btn-info btn-pill-end" id="btnSendTelegram" type="button" 
                            style="border-radius: 0 20px 20px 0;">
                        <i class="bi bi-telegram"></i> Send
                    </button>
                </div>
            </div>
        </div>
        
        <!-- Summary Cards -->
        <div class="pentest-summary" id="summaryCards"></div>
        
        <!-- Findings Table -->
        <div class="table-wrap">
            <table id="findingsTable">
                <thead>
                    <tr>
                        <th>Severity</th>
                        <th>Status</th>
                        <th>Type</th>
                        <th>URL</th>
                        <th>Evidence</th>
                        <th>Confidence</th>
                    </tr>
                </thead>
                <tbody id="findingsBody"></tbody>
            </table>
        </div>
    </div>
    
    <script>
    let currentScanId = null;
    let pollInterval = null;
    
    document.getElementById('pentestForm').addEventListener('submit', function(e) {
        e.preventDefault();
        startScan();
    });
    
    function startScan() {
        const form = document.getElementById('pentestForm');
        const formData = new FormData(form);
        const data = {
            target: formData.get('target'),
            threads: parseInt(formData.get('threads')),
            sqli: formData.has('sqli'),
            xss: formData.has('xss'),
            lfi: formData.has('lfi'),
            cmdi: formData.has('cmdi'),
            cors: formData.has('cors'),
            cookies: formData.has('cookies'),
            headers: formData.has('headers'),
            exposure: formData.has('exposure'),
            tech: formData.has('tech'),
            crawl: formData.has('crawl'),
            // Advanced options
            max_requests: parseInt(formData.get('max_requests') || 500),
            max_depth: parseInt(formData.get('max_depth') || 3),
            delay_s: parseFloat(formData.get('delay_s') || 0.2),
            timeout_s: parseInt(formData.get('timeout_s') || 15),
            time_sqli: formData.has('time_sqli'),
            dorking: formData.has('dorking'),
        };
        
        // Show progress, hide results
        document.getElementById('progressCard').style.display = 'block';
        document.getElementById('resultsCard').style.display = 'none';
        document.getElementById('btnScan').disabled = true;
        document.getElementById('btnScan').innerHTML = '<i class="bi bi-hourglass"></i> Scanning...';
        document.getElementById('progressBar').style.width = '10%';
        document.getElementById('progressBar').textContent = '10%';
        document.getElementById('statusBadge').textContent = 'Starting...';
        document.getElementById('statusBadge').className = 'badge bg-info';
        
        fetch('/api/pentest/run', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify(data)
        })
        .then(r => r.json())
        .then(response => {
            if (response.error) {
                alert('Error: ' + response.error);
                resetForm();
                return;
            }
            currentScanId = response.scan_id;
            pollInterval = setInterval(pollStatus, 2000);
        })
        .catch(err => {
            alert('Failed to start scan: ' + err);
            resetForm();
        });
    }
    
    function pollStatus() {
        if (!currentScanId) return;
        
        fetch('/api/pentest/status/' + currentScanId)
        .then(r => r.json())
        .then(data => {
            document.getElementById('urlsCount').textContent = data.urls_crawled || 0;
            document.getElementById('requestsCount').textContent = data.requests_made || 0;
            document.getElementById('findingsCount').textContent = data.findings_count || 0;
            
            // Update progress bar (estimate)
            const progress = Math.min(90, 10 + (data.requests_made || 0) / 5);
            document.getElementById('progressBar').style.width = progress + '%';
            document.getElementById('progressBar').textContent = Math.round(progress) + '%';
            
            if (data.status === 'running') {
                document.getElementById('statusBadge').textContent = 'Scanning in progress...';
                document.getElementById('statusBadge').className = 'badge bg-primary progress-bar-animated';
            } else if (data.status === 'completed') {
                clearInterval(pollInterval);
                document.getElementById('progressBar').style.width = '100%';
                document.getElementById('progressBar').textContent = '100%';
                document.getElementById('statusBadge').textContent = 'Scan Finished';
                document.getElementById('statusBadge').className = 'badge bg-success';
                loadResults();
            } else if (data.status === 'error') {
                clearInterval(pollInterval);
                document.getElementById('statusBadge').textContent = 'Error: ' + (data.error || 'Unknown');
                document.getElementById('statusBadge').className = 'badge bg-danger';
                resetForm();
            } else if (data.status === 'starting' || data.status === 'started') {
                document.getElementById('statusBadge').textContent = 'Preparing scan...';
                document.getElementById('statusBadge').className = 'badge bg-info';
            }
        })
        .catch(err => {
            console.error('Poll error:', err);
        });
    }
    
    function loadResults() {
        fetch('/api/pentest/results/' + currentScanId)
        .then(r => r.json())
        .then(data => {
            document.getElementById('resultsCard').style.display = 'block';
            
            // Summary cards
            const stats = data.stats || {};
            let summaryHtml = `
                <div class="p-card">
                    <i class="bi bi-bullseye text-primary"></i>
                    <div>
                        <div class="v">${stats.findings_count || 0}</div>
                        <div class="l">Total Findings</div>
                    </div>
                </div>
                <div class="p-card">
                    <i class="bi bi-droplet-fill text-danger"></i>
                    <div>
                        <div class="v">${stats.sqli_findings || 0}</div>
                        <div class="l">SQL Injection</div>
                    </div>
                </div>
                <div class="p-card">
                    <i class="bi bi-code-slash text-warning"></i>
                    <div>
                        <div class="v">${stats.xss_findings || 0}</div>
                        <div class="l">Reflected XSS</div>
                    </div>
                </div>
                <div class="p-card">
                    <i class="bi bi-folder-fill text-info"></i>
                    <div>
                        <div class="v">${stats.lfi_findings || 0}</div>
                        <div class="l">Path Traversal</div>
                    </div>
                </div>
                <div class="p-card">
                    <i class="bi bi-globe2 text-success"></i>
                    <div>
                        <div class="v">${stats.urls_crawled || 0}</div>
                        <div class="l">URLs Crawled</div>
                    </div>
                </div>
            `;
            document.getElementById('summaryCards').innerHTML = summaryHtml;
            
            // Findings table
            const findings = data.findings || [];
            let tableHtml = '';
            findings.forEach(f => {
                const sevClass = f.severity === 'CRITICAL' ? 'sev-crit' : (f.severity === 'HIGH' ? 'sev-high' : 'badge-soft');
                const statusLabel = (f.finding_status || 'ENUMERATED').replace(/_/g, ' ');
                const evidence = `${f.http_status || '-'} | ${f.content_type || '-'} | ${f.body_fingerprint || '-'}`;
                
                tableHtml += `<tr>
                    <td><span class="${sevClass}">${esc(f.severity)}</span></td>
                    <td><span class="badge-soft" style="background:rgba(107, 114, 128, 0.1); color:var(--text-secondary);">${esc(statusLabel)}</span></td>
                    <td>${esc(f.vuln_type)}</td>
                    <td style="max-width:250px; overflow:hidden; text-overflow:ellipsis;" title="${esc(f.target_url)}">${esc(f.target_url)}</td>
                    <td><code style="font-size:0.85em; opacity:0.8;">${esc(evidence)}</code></td>
                    <td>${esc(f.confidence)}</td>
                </tr>`;
            });
            
            if (findings.length === 0) {
                tableHtml = '<tr><td colspan="5" class="text-center text-muted">No vulnerabilities found!</td></tr>';
            }
            
            document.getElementById('findingsBody').innerHTML = tableHtml;
            document.getElementById('btnDownloadPdf').style.display = 'inline-block';
            document.getElementById('telegramGroup').style.display = 'flex';
            resetForm();
        })
        .catch(err => {
            console.error('Results error:', err);
            resetForm();
        });
    }
    
    function resetForm() {
        document.getElementById('btnScan').disabled = false;
        document.getElementById('btnScan').innerHTML = '<i class="bi bi-play-circle"></i> Start Scan';
    }
    
    document.getElementById('btnDownloadPdf').addEventListener('click', function() {
        if (currentScanId) {
            window.location.href = '/pentest/pdf/' + currentScanId;
        }
    });
    
    document.getElementById('btnSendTelegram').addEventListener('click', function() {
        if (currentScanId) {
            const btn = this;
            const chatId = document.getElementById('telegramChatId').value.trim();
            
            btn.disabled = true;
            btn.innerHTML = '<i class="bi bi-hourglass"></i> Sending...';
            
            fetch('/api/pentest/telegram/' + currentScanId, {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({ chat_id: chatId })
            })
            .then(r => r.json())
            .then(data => {
                if (data.success) {
                    btn.innerHTML = '<i class="bi bi-check-circle"></i> Sent!';
                    btn.classList.remove('btn-info');
                    btn.classList.add('btn-success');
                    setTimeout(() => {
                        btn.innerHTML = '<i class="bi bi-telegram"></i> Send';
                        btn.classList.remove('btn-success');
                        btn.classList.add('btn-info');
                        btn.disabled = false;
                    }, 3000);
                } else {
                    alert('Telegram: ' + data.message);
                    btn.innerHTML = '<i class="bi bi-telegram"></i> Send';
                    btn.disabled = false;
                }
            })
            .catch(err => {
                alert('Failed to send: ' + err);
                btn.innerHTML = '<i class="bi bi-telegram"></i> Send';
                btn.disabled = false;
            });
        }
    });
    </script>
    """
    
    return render_template_string(BASE_HTML, content=content)


@app.route("/api/pentest/run", methods=["POST"])
def api_pentest_run():
    """Start a new pentest scan in background thread."""
    if not PENTEST_AVAILABLE:
        return jsonify({"error": "Pentest module not available"}), 503
    
    data = request.get_json() or {}
    target = data.get("target", "").strip()
    
    if not target:
        return jsonify({"error": "Target URL is required"}), 400
    
    # Basic URL validation
    if not target.startswith(("http://", "https://")):
        return jsonify({"error": "Target must start with http:// or https://"}), 400
    
    # Create unique scan ID
    scan_id = str(uuid.uuid4())[:8]
    
    # Initialize scan entry
    with pentest_scans_lock:
        pentest_scans[scan_id] = {
            "status": "starting",
            "agent": None,
            "error": None,
            "target": target,
            "created": datetime.datetime.now().isoformat()
        }
    
    # Build options from request
    options = {
        "threads": data.get("threads", 5),
        "sqli": data.get("sqli", True),
        "xss": data.get("xss", True),
        "lfi": data.get("lfi", True),
        "cmdi": data.get("cmdi", True),
        "cors": data.get("cors", True),
        "cookies": data.get("cookies", True),
        "headers": data.get("headers", True),
        "exposure": data.get("exposure", True),
        "tech": data.get("tech", True),
        "crawl": data.get("crawl", True),
        # Advanced options
        "max_requests": data.get("max_requests", 500),
        "max_depth": data.get("max_depth", 3),
        "timeout": data.get("timeout_s", 15),
        "delay": data.get("delay_s", 0.2),
        "time_sqli": data.get("time_sqli", False),
        "dorking": data.get("dorking", False),
    }
    
    # Start background thread
    thread = threading.Thread(
        target=run_pentest_background,
        args=(scan_id, target, options),
        daemon=True
    )
    thread.start()
    
    return jsonify({"scan_id": scan_id, "status": "started"})


@app.route("/api/pentest/status/<scan_id>")
def api_pentest_status(scan_id):
    """Get status of a running pentest scan."""
    with pentest_scans_lock:
        scan = pentest_scans.get(scan_id)
    
    if not scan:
        return jsonify({"error": "Scan not found"}), 404
    
    result = {
        "status": scan["status"],
        "target": scan["target"],
        "error": scan.get("error"),
        "urls_crawled": 0,
        "requests_made": 0,
        "findings_count": 0
    }
    
    if scan["agent"]:
        agent = scan["agent"]
        result["urls_crawled"] = getattr(agent, '_stats', None).urls_crawled if hasattr(agent, '_stats') and agent._stats else 0
        result["requests_made"] = agent._request_count if hasattr(agent, '_request_count') else 0
        result["findings_count"] = len(agent._findings) if hasattr(agent, '_findings') else 0
    
    return jsonify(result)


@app.route("/api/pentest/results/<scan_id>")
def api_pentest_results(scan_id):
    """Get full results of a completed pentest scan."""
    with pentest_scans_lock:
        scan = pentest_scans.get(scan_id)
    
    if not scan:
        return jsonify({"error": "Scan not found"}), 404
    
    if scan["status"] not in ("completed", "error"):
        return jsonify({"error": "Scan not yet completed", "status": scan["status"]}), 202
    
    result = {
        "status": scan["status"],
        "target": scan["target"],
        "error": scan.get("error"),
        "findings": [],
        "stats": {}
    }
    
    if scan["agent"]:
        agent = scan["agent"]
        
        # Convert findings to dicts
        findings_list = []
        for f in agent._findings:
            if hasattr(f, '__dict__'):
                findings_list.append({
                    "vuln_type": getattr(f, 'vuln_type', 'Unknown'),
                    "severity": getattr(f, 'severity', 'INFO'),
                    "confidence": getattr(f, 'confidence', 'LOW'),
                    "target_url": getattr(f, 'target_url', ''),
                    "parameter": getattr(f, 'parameter', ''),
                    "payload": getattr(f, 'payload', ''),
                    "mitigation": getattr(f, 'mitigation', ''),
                    "cwe_id": getattr(f, 'cwe_id', ''),
                    "owasp_category": getattr(f, 'owasp_category', ''),
                    "finding_status": getattr(f, 'finding_status', 'POTENTIAL'),
                    "http_status": getattr(f, 'http_status', 0),
                    "content_type": getattr(f, 'content_type', ''),
                    "body_fingerprint": getattr(f, 'body_fingerprint', '')
                })
            elif isinstance(f, dict):
                findings_list.append(f)
        
        result["findings"] = findings_list
        
        # Stats
        if hasattr(agent, '_stats') and agent._stats:
            stats = agent._stats
            result["stats"] = {
                "urls_crawled": getattr(stats, 'urls_crawled', 0),
                "requests_made": getattr(stats, 'requests_made', 0),
                "findings_count": getattr(stats, 'findings_count', 0),
                "sqli_findings": getattr(stats, 'sqli_findings', 0),
                "xss_findings": getattr(stats, 'xss_findings', 0),
                "header_findings": getattr(stats, 'header_findings', 0),
                "lfi_findings": getattr(stats, 'lfi_findings', 0),
                "cors_findings": getattr(stats, 'cors_findings', 0),
            }
    
    return jsonify(result)


def generate_pentest_report_pdf(agent, target):
    """Generate PDF bytes for a pentest report (Shared Logic)."""
    
    # Import ExplanationDatabase (lazy import to avoid circular dep if needed, though they are in different files)
    from pentest_agent import ExplanationDatabase
    
    # Build HTML for PDF
    findings_html = ""
    for f in agent._findings:
        sev = getattr(f, 'severity', 'INFO')
        conf = getattr(f, 'confidence', 'LOW')
        status = (getattr(f, 'finding_status', 'ENUMERATED')).replace('_', ' ')
        sev_class = 'badge-crit' if sev == 'CRITICAL' else ('badge-high' if sev == 'HIGH' else 'badge-med')
        evidence = f"{getattr(f, 'http_status', '-')}"
        if getattr(f, 'content_type', ''):
            evidence += f" | {f.content_type}"
            
        vuln_type = getattr(f, 'vuln_type', 'Unknown')
        explanation = ExplanationDatabase.get_explanation(vuln_type)
        
        target_url = getattr(f, 'target_url', '')
        
        findings_html += f"""
        <tr class="finding-meta">
            <td><span class="{sev_class}">{sev}</span></td>
            <td><span style="font-size: 9pt; color: #64748b;">{status}</span></td>
            <td style="font-weight: bold; color: #1e293b;">{vuln_type}</td>
            <td style="font-size: 0.85em;">{evidence}</td>
            <td>{conf}</td>
        </tr>
        <tr class="finding-details">
            <td colspan="5">
                <div style="font-family: monospace; font-size: 9pt; color: #2563eb; margin-bottom: 4px; word-break: break-all;">
                    {target_url}
                </div>
                <div style="font-size: 9pt; color: #475569; line-height: 1.4;">
                    {explanation}
                </div>
            </td>
        </tr>
        """
    
    if not findings_html:
        findings_html = '<tr><td colspan="6" style="text-align:center;">No vulnerabilities found</td></tr>'
    
    stats = agent._stats if hasattr(agent, '_stats') else None
    
    # Calculate Overall Assessment
    assessment_text = "The security posture appears robust based on the scope of this automated scan. No critical vulnerabilities were identified."
    crits = getattr(stats, 'critical_findings', 0) if stats else 0
    highs = getattr(stats, 'high_findings', 0) if stats else 0
    
    # Simple check based on finding severity in the list if stats aren't granular enough
    has_crit = any(f.severity == 'CRITICAL' for f in agent._findings)
    has_high = any(f.severity == 'HIGH' for f in agent._findings)
    
    if has_crit:
        assessment_text = "The security posture requires **IMMEDIATE ATTENTION**. A critical vulnerability was matched which may allow remote code execution or significant data loss. Immediate manual verification and remediation is invalid."
    elif has_high:
        assessment_text = "The security posture shows signs of significant risk. High severity findings were identified that could compromise the confidentiality or integrity of the application. Remediation is recommended."
    
    # Status Definitions HTML
    status_legend = """
    <div class="summary-box" style="margin-top: 20px; font-size: 9pt;">
        <h3 style="margin-top: 0; color: #475569; font-size: 10pt;">ℹ️ Status Definitions</h3>
        <ul style="padding-left: 20px; list-style-type: square; color: #334155;">
            <li><strong>CONFIRMED:</strong> High-confidence finding with evidence of exploitability (e.g., actual secrets found).</li>
            <li><strong>ENUMERATED:</strong> Observed behavior/configuration (e.g., version headers) without direct proof of exploitability.</li>
            <li><strong>ACCESS CONTROLLED:</strong> Resource exists but is correctly protected (e.g., HTTP 403 Forbidden).</li>
            <li><strong>INFORMATIONAL:</strong> Public or expected information (e.g., robots.txt) with no direct security impact.</li>
        </ul>
    </div>
    """
    
    if not findings_html:
        findings_html = '<tr><td colspan="5" style="text-align:center;">No vulnerabilities found</td></tr>'
    
    stats = agent._stats if hasattr(agent, '_stats') else None
    
    # Add Appendix for Not Found Paths (if available)
    appendix_html = ""
    not_found_paths = getattr(agent, '_not_found_paths', [])
    if not_found_paths:
        appendix_items = ""
        for path in not_found_paths:
            appendix_items += f"<li style='margin-bottom: 4px;'>{path}</li>"
            
        appendix_html = f"""
        <div style="page-break-before: always;">
            <h2>📂 Appendix: Enumerated Paths (Not Found)</h2>
            <div class="summary-box">
                <p style="margin-bottom: 10px; font-weight: bold;">The following paths were probed but returned 404 Not Found. They are listed here for completeness but are NOT considered vulnerabilities.</p>
                <ul style="list-style-type: none; padding-left: 0; font-family: monospace; font-size: 9pt;">
                    {appendix_items}
                </ul>
            </div>
        </div>
        """

    html_content = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="utf-8">
        <style>
            body {{ font-family: Arial, sans-serif; font-size: 11pt; color: #333; margin: 20px; }}
            h1 {{ color: #1e3a8a; border-bottom: 2px solid #3b82f6; padding-bottom: 10px; }}
            h2 {{ color: #1e40af; margin-top: 25px; }}
            table {{ width: 100%; border-collapse: collapse; margin: 15px 0; }}
            th {{ background: #1e3a8a; color: white; padding: 10px; text-align: left; font-size: 10pt; }}
            td {{ padding: 8px; border-bottom: 1px solid #e2e8f0; font-size: 9pt; vertical-align: top; }}
            
            /* 2-Row Layout Styling */
            tr.finding-meta {{ background: #f8fafc; border-bottom: none; }}
            tr.finding-details {{ background: #f8fafc; border-bottom: 2px solid #cbd5e1; }}
            tr.finding-meta td {{ border-bottom: none; padding-bottom: 4px; }}
            tr.finding-details td {{ padding-top: 4px; padding-bottom: 12px; }}
            
            .badge-crit {{ background: #ef4444; color: white; padding: 3px 8px; border-radius: 4px; font-weight: bold; }}
            .badge-high {{ background: #f59e0b; color: white; padding: 3px 8px; border-radius: 4px; font-weight: bold; }}
            .badge-med {{ background: #3b82f6; color: white; padding: 3px 8px; border-radius: 4px; }}
            .summary-box {{ background: #f1f5f9; padding: 15px; border-radius: 8px; margin: 15px 0; }}
            .summary-item {{ display: inline-block; margin-right: 30px; }}
            .summary-value {{ font-size: 18pt; font-weight: bold; color: #1e3a8a; }}
            .summary-label {{ font-size: 10pt; color: #64748b; }}
            footer {{ margin-top: 30px; text-align: center; font-size: 10pt; color: #94a3b8; border-top: 1px solid #e2e8f0; padding-top: 15px; }}
        </style>
    </head>
    <body>
        <h1>🛡️ Web Vulnerability Scan Report</h1>
        
        <div class="summary-box">
            <p><strong>Target:</strong> {target}</p>
            <p><strong>Scan Date:</strong> {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
            <p><strong>Findings Found:</strong> {len(agent._findings)}</p>
            <p><strong>Generated by:</strong> Cybershield Diag Agent - Pentest Module</p>
        </div>
        
        <h2>📊 Scan Summary</h2>
        <div class="summary-box" style="margin-bottom: 20px;">
            <p style="margin-top: 0; font-size: 10pt; color: #444;">
                <strong>Overall Security Posture:</strong><br>
                {assessment_text}
            </p>
            <hr style="border: 0; border-top: 1px solid #e2e8f0; margin: 10px 0;">
            <div style="display: flex; justify-content: space-between;">
                <div class="summary-item">
                    <div class="summary-value">{getattr(stats, 'urls_crawled', 0) if stats else 0}</div>
                    <div class="summary-label">URLs Crawled</div>
                </div>
                <div class="summary-item">
                    <div class="summary-value">{getattr(stats, 'requests_made', 0) if stats else 0}</div>
                    <div class="summary-label">Requests</div>
                </div>
                <div class="summary-item">
                    <div class="summary-value">{getattr(stats, 'sqli_findings', 0) if stats else 0}</div>
                    <div class="summary-label">SQLi</div>
                </div>
                <div class="summary-item">
                    <div class="summary-value">{getattr(stats, 'xss_findings', 0) if stats else 0}</div>
                    <div class="summary-label">XSS</div>
                </div>
            </div>
        </div>
        
        {status_legend}
        
        <h2>🔍 Vulnerability Findings</h2>
        <table>
            <thead>
                <tr>
                    <th style="width: 15%;">Severity</th>
                    <th style="width: 20%;">Status</th>
                    <th style="width: 30%;">Type</th>
                    <th style="width: 20%;">Evidence</th>
                    <th style="width: 15%;">Confidence</th>
                </tr>
            </thead>
            <tbody>
                {findings_html}
            </tbody>
        </table>
        
        {appendix_html}

        <footer>
            Cybershield Solutions © 2025 — Pentest Report<br>
            Created by Vitaliy
        </footer>
    </body>
    </html>
    """
    
    # Generate PDF
    pdf_bytes = HTML(string=html_content).write_pdf()
    
    # Sign PDF if certificates are available
    cert_dir = os.path.join(os.path.dirname(__file__), "certs")
    key_path = os.path.join(cert_dir, "cybershield.key")
    cert_path = os.path.join(cert_dir, "cybershield.crt")
    
    signed_pdf_bytes = pdf_bytes  # Default to unsigned
    
    if os.path.exists(key_path) and os.path.exists(cert_path):
        try:
            from pyhanko.sign import signers
            from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
            from pyhanko import stamp
            from pyhanko.sign.fields import SigFieldSpec
            from cryptography.hazmat.primitives.serialization import load_pem_private_key
            from cryptography import x509
            
            # Load key and certificate
            with open(key_path, "rb") as f:
                key_data = f.read()
            with open(cert_path, "rb") as f:
                cert_data = f.read()
            
            private_key = load_pem_private_key(key_data, password=None)
            cert = x509.load_pem_x509_certificate(cert_data)
            
            # Create signer
            signer = signers.SimpleSigner.load(
                key_path, cert_path,
                key_passphrase=None
            )
            
            # Sign the PDF
            pdf_in = io.BytesIO(pdf_bytes)
            w = IncrementalPdfFileWriter(pdf_in)
            
            pdf_out = io.BytesIO()
            signers.sign_pdf(
                w,
                signers.PdfSignatureMetadata(
                    field_name='Cybershield_Signature',
                    reason='Pentest Report - Cybershield Solutions',
                    location='Barcelona, Spain'
                ),
                signer=signer,
                output=pdf_out
            )
            signed_pdf_bytes = pdf_out.getvalue()
            print(f"[INFO] Pentest PDF signed successfully for target {target}")
            
        except Exception as e:
            print(f"[ERROR] PDF Signing failed: {e}")
            
    return signed_pdf_bytes


@app.route("/pentest/pdf/<scan_id>")
def pentest_pdf(scan_id):
    """Generate and download PDF report for a pentest scan."""
    with pentest_scans_lock:
        scan = pentest_scans.get(scan_id)
    
    if not scan:
        abort(404, "Scan not found")
    
    if scan["status"] != "completed" or not scan["agent"]:
        abort(400, "Scan not completed or no results available")
    
    agent = scan["agent"]
    target = scan["target"]
    
    # Use Shared Generator
    pdf_bytes = generate_pentest_report_pdf(agent, target)
    
    filename = f"pentest_report_{scan_id}.pdf"
    
    return send_file(io.BytesIO(pdf_bytes), mimetype='application/pdf', as_attachment=True, download_name=filename)


@app.route("/api/pentest/telegram/<scan_id>", methods=["POST"])
def api_pentest_telegram(scan_id):
    """Generate PDF and send to Telegram for a pentest scan."""
    # Get chat_id from request body
    data = request.get_json() or {}
    chat_id = data.get("chat_id", "")
    
    with pentest_scans_lock:
        scan = pentest_scans.get(scan_id)
    
    if not scan:
        return jsonify({"success": False, "message": "Scan not found"}), 404
    
    if scan["status"] != "completed" or not scan["agent"]:
        return jsonify({"success": False, "message": "Scan not completed"}), 400
    
    agent = scan["agent"]
    target = scan["target"]
    
    findings_count = len(agent._findings) if hasattr(agent, '_findings') else 0
    
    # Generate PDF using shared logic
    try:
        pdf_bytes = generate_pentest_report_pdf(agent, target)
    except Exception as e:
        return jsonify({"success": False, "message": f"PDF generation failed: {e}"}), 500
    
    # Send to Telegram
    filename = f"pentest_report_{scan_id}.pdf"
    caption = f"🛡️ Pentest Report\n📎 Target: {target}\n🔍 Findings: {findings_count}\n📅 {datetime.datetime.now().strftime('%Y-%m-%d %H:%M')}"
    
    result = send_pdf_to_telegram(pdf_bytes, filename, caption, chat_id=chat_id)
    
    return jsonify(result)


# ==================== END PENTEST AGENT ROUTES ====================


# ---------------- Main ----------------
def parse_args():
    p = argparse.ArgumentParser()
    p.add_argument("--host", default="127.0.0.1", help="bind host")
    p.add_argument("--port", type=int, default=8080, help="listen port")
    p.add_argument("--allow-from", help="CIDR or comma-separated CIDRs/IPs allowed to connect")
    return p.parse_args()

if __name__ == "__main__":
    args = parse_args()
    if args.allow_from:
        nets = [n.strip() for n in args.allow_from.split(",") if n.strip()]
        for n in nets:
            try:
                ALLOWED_NETWORKS.append(ipaddress.ip_network(n, strict=False))
            except Exception as e:
                print("Bad network:", n, e)
    print("Allowed client nets:", ALLOWED_NETWORKS or "ANY")
    
    print(f"Starting Diag Agent on {args.host}:{args.port}")
    
    # Init Background Tasks
    threading.Thread(target=refresh_trivy_cache, daemon=True).start()
    
    app.run(host=args.host, port=args.port, debug=False)