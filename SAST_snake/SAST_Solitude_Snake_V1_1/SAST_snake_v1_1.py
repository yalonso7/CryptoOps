#!/usr/bin/env python3
"""
Smart Contract SAST Tool v1.1 "Solitude Snake"
A static analysis security testing tool for Solidity smart contracts
targeting OWASP Smart Contract Top 10 2025 vulnerabilities.
"""

import re
import os
import json
import argparse
from typing import List, Dict, Any, Tuple
from dataclasses import dataclass
from enum import Enum
from datetime import datetime


class Severity(Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


@dataclass
class Finding:
    rule_id: str
    title: str
    description: str
    severity: Severity
    line_number: int
    code_snippet: str
    recommendation: str
    owasp_category: str


class SolidityParser:
    """Enhanced Solidity code parser for extracting relevant information"""
    
    def __init__(self, content: str):
        self.content = content
        self.lines = content.split('\n')
        self.functions = self._extract_functions()
        self.modifiers = self._extract_modifiers()
        self.state_variables = self._extract_state_variables()
        self.imports = self._extract_imports()
        self.contracts = self._extract_contracts()
        self.events = self._extract_events()
        self.structs = self._extract_structs()
    
    def _extract_functions(self) -> List[Dict[str, Any]]:
        """Extract function definitions with their properties"""
        functions = []
        function_pattern = r'function\s+([A-Za-z_]\w*)\s*\(([^)]*)\)\s*(public|private|internal|external)?\s*(view|pure|payable)?\s*(returns\s*\([^)]*\))?\s*\{'
        
        for i, line in enumerate(self.lines):
            matches = re.finditer(function_pattern, line)
            for match in matches:
                func_info = {
                    'name': match.group(1),
                    'visibility': match.group(3) or 'internal',
                    'state_mutability': match.group(4) or '',
                    'returns': match.group(5) or '',
                    'line': i + 1,
                    'full_line': line.strip()
                }
                functions.append(func_info)
        
        return functions
    
    def _extract_modifiers(self) -> List[Dict[str, Any]]:
        """Extract modifier definitions"""
        modifiers = []
        modifier_pattern = r'modifier\s+([A-Za-z_]\w*)\s*\(([^)]*)\)\s*\{'
        
        for i, line in enumerate(self.lines):
            matches = re.finditer(modifier_pattern, line)
            for match in matches:
                mod_info = {
                    'name': match.group(1),
                    'line': i + 1,
                    'full_line': line.strip()
                }
                modifiers.append(mod_info)
        
        return modifiers
    
    def _extract_state_variables(self) -> List[Dict[str, Any]]:
        """Extract state variable declarations"""
        variables = []
        var_pattern = r'((?:uint256|uint\d*|int\d*|int|bool|address(?:\s+payable)?|string|bytes\d*|mapping\s*\([^)]+\)))\s+(public|private|internal)?\s+([A-Za-z_]\w*)'
        
        for i, line in enumerate(self.lines):
            if 'function' in line or line.strip().startswith('//'):
                continue
                
            matches = re.finditer(var_pattern, line)
            for match in matches:
                var_info = {
                    'type': match.group(1),
                    'visibility': match.group(2) or 'internal',
                    'name': match.group(3),
                    'line': i + 1,
                    'full_line': line.strip()
                }
                variables.append(var_info)
        
        return variables
    
    def _extract_imports(self) -> List[str]:
        """Extract import statements"""
        imports = []
        import_pattern = r'import\s+["\']([^"\']+)["\']'
        
        for line in self.lines:
            matches = re.finditer(import_pattern, line)
            for match in matches:
                imports.append(match.group(1))
        
        return imports
    
    def _extract_contracts(self) -> List[Dict[str, Any]]:
        """Extract contract definitions"""
        contracts = []
        contract_pattern = r'contract\s+([A-Za-z_]\w*)\s*(?:is\s+[^{]+)?\s*\{'
        
        for i, line in enumerate(self.lines):
            matches = re.finditer(contract_pattern, line)
            for match in matches:
                contract_info = {
                    'name': match.group(1),
                    'line': i + 1,
                    'full_line': line.strip()
                }
                contracts.append(contract_info)
        
        return contracts
    
    def _extract_events(self) -> List[Dict[str, Any]]:
        """Extract event definitions"""
        events = []
        event_pattern = r'event\s+([A-Za-z_]\w*)\s*\([^)]*\)'
        
        for i, line in enumerate(self.lines):
            matches = re.finditer(event_pattern, line)
            for match in matches:
                event_info = {
                    'name': match.group(1),
                    'line': i + 1,
                    'full_line': line.strip()
                }
                events.append(event_info)
        
        return events
    
    def _extract_structs(self) -> List[Dict[str, Any]]:
        """Extract struct definitions"""
        structs = []
        struct_pattern = r'struct\s+([A-Za-z_]\w*)\s*\{'
        
        for i, line in enumerate(self.lines):
            matches = re.finditer(struct_pattern, line)
            for match in matches:
                struct_info = {
                    'name': match.group(1),
                    'line': i + 1,
                    'full_line': line.strip()
                }
                structs.append(struct_info)
        
        return structs


class VulnerabilityDetector:
    """Enhanced vulnerability detection engine for OWASP 2025"""
    
    def __init__(self):
        self.rules = self._load_detection_rules()
    
    def _load_detection_rules(self) -> Dict[str, Dict[str, Any]]:
        """Load vulnerability detection rules based on OWASP Smart Contract Top 10 2025"""
        return {
            'SC01_2025': {
                'name': 'Access Control Vulnerabilities',
                'owasp_category': 'SC01:2025 - Access Control Vulnerabilities',
                'severity': Severity.CRITICAL,
                'patterns': [
                    r'function\s+\w+\s*\([^)]*\)\s*public\b(?![^;{]*\b(onlyOwner|onlyAdmin|onlyRole|require\s*\([^)]*msg\.sender))',
                    r'function\s+\w+\s*\([^)]*\)\s*external\b(?![^;{]*\b(onlyOwner|onlyAdmin|onlyRole|require\s*\([^)]*msg\.sender))',
                    r'_\w+\s*=\s*msg\.sender\s*;',  # Direct assignment without validation
                    r'owner\s*=\s*msg\.sender\s*;',  # Owner assignment without validation
                ],
                'description': 'Function lacks proper access control mechanisms',
                'recommendation': 'Implement proper access control using OpenZeppelin Ownable, AccessControl, or custom modifiers'
            },
            'SC02_2025': {
                'name': 'Price Oracle Manipulation',
                'owasp_category': 'SC02:2025 - Price Oracle Manipulation',
                'severity': Severity.HIGH,
                'patterns': [
                    r'block\.timestamp\s*[<>=]',  # Time-based price logic
                    r'block\.number\s*[<>=]',     # Block number based logic
                    r'keccak256\([^)]*block\.',   # Block-based randomness for prices
                    r'price\s*=\s*[^;]*block\.',  # Direct block usage in price calculation
                    r'rate\s*=\s*[^;]*block\.',   # Direct block usage in rate calculation
                    r'\.call\s*\([^)]*price',     # External price calls without validation
                ],
                'description': 'Price oracle manipulation vulnerability detected',
                'recommendation': 'Use decentralized price oracles like Chainlink, Band Protocol, or implement TWAP (Time-Weighted Average Price)'
            },
            'SC03_2025': {
                'name': 'Logic Errors',
                'owasp_category': 'SC03:2025 - Logic Errors',
                'severity': Severity.HIGH,
                'patterns': [
                    r'if\s*\(\s*[^)]*\)\s*return\s*;',  # Empty return without else
                    r'require\s*\([^)]*\)\s*;',         # Require without proper error message
                    r'assert\s*\([^)]*\)\s*;',          # Assert without proper error message
                    r'balance\s*[<>=]\s*amount\s*[<>=]', # Complex balance comparisons
                    r'amount\s*>\s*0\s*&&\s*amount\s*<', # Range checks that might have edge cases
                ],
                'description': 'Potential logic error in contract implementation',
                'recommendation': 'Review business logic carefully, add comprehensive tests, and implement proper error handling'
            },
            'SC04_2025': {
                'name': 'Lack of Input Validation',
                'owasp_category': 'SC04:2025 - Lack of Input Validation',
                'severity': Severity.HIGH,
                'patterns': [
                    r'function\s+\w+\s*\([^)]*address[^)]*\)\s*(?:public|external)',  # Address parameters without validation
                    r'function\s+\w+\s*\([^)]*uint[^)]*\)\s*(?:public|external)',     # Uint parameters without validation
                    r'function\s+\w+\s*\([^)]*\)\s*(?:public|external)(?![^;{]*require)', # No validation in external functions
                    r'msg\.value\s*[<>=]',  # Value checks without proper validation
                ],
                'description': 'Function lacks proper input validation',
                'recommendation': 'Implement comprehensive input validation using require statements and custom validation functions'
            },
            'SC05_2025': {
                'name': 'Reentrancy Attacks',
                'owasp_category': 'SC05:2025 - Reentrancy Attacks',
                'severity': Severity.CRITICAL,
                'patterns': [
                    r'\.call\s*\([^)]*\)\s*;',      # External calls
                    r'\.send\s*\([^)]*\)\s*;',      # Send calls
                    r'\.transfer\s*\([^)]*\)\s*;',  # Transfer calls
                    r'address\([^)]+\)\.call',      # Address call patterns
                    r'delegatecall\s*\(',           # Delegatecall patterns
                ],
                'description': 'Potential reentrancy vulnerability detected',
                'recommendation': 'Use checks-effects-interactions pattern, ReentrancyGuard, or pull payment pattern'
            },
            'SC06_2025': {
                'name': 'Unchecked External Calls',
                'owasp_category': 'SC06:2025 - Unchecked External Calls',
                'severity': Severity.HIGH,
                'patterns': [
                    r'^(?!.*\b(require|assert|if)\s*\().*\.call\s*\([^)]*\)\s*;',
                    r'^(?!.*\b(require|assert|if)\s*\().*\.send\s*\([^)]*\)\s*;',
                    r'^(?!.*\b(require|assert|if)\s*\().*\.delegatecall\s*\([^)]*\)\s*;',
                    r'^(?!.*\b(require|assert|if)\s*\().*\.staticcall\s*\([^)]*\)\s*;',
                ],
                'description': 'External call without checking return value',
                'recommendation': 'Always check return values from external calls and handle failures appropriately'
            },
            'SC07_2025': {
                'name': 'Flash Loan Attacks',
                'owasp_category': 'SC07:2025 - Flash Loan Attacks',
                'severity': Severity.HIGH,
                'patterns': [
                    r'flashLoan\s*\(',              # Flash loan function calls
                    r'flashSwap\s*\(',              # Flash swap patterns
                    r'borrow\s*\([^)]*\)\s*;',      # Borrow patterns
                    r'liquidity\s*[<>=]',          # Liquidity checks
                    r'reserve\s*[<>=]',            # Reserve checks
                    r'balanceOf\s*\([^)]*\)\s*[<>=]', # Balance checks that might be manipulated
                ],
                'description': 'Potential flash loan attack vulnerability',
                'recommendation': 'Implement proper validation for flash loan scenarios, use time-weighted averages, and validate external price feeds'
            },
            'SC08_2025': {
                'name': 'Integer Overflow and Underflow',
                'owasp_category': 'SC08:2025 - Integer Overflow and Underflow',
                'severity': Severity.MEDIUM,
                'patterns': [
                    r'\+\+|\-\-',                  # Increment/decrement operators
                    r'[A-Za-z_]\w*\s*[\+\-\\\/]\=\s*',  # Compound assignment operators
                    r'[A-Za-z_]\w*\s*=\s*[A-Za-z_]\w*\s*[\+\-\*\/]',  # Arithmetic operations
                    r'uint\d*\s+\w+\s*=\s*\d+',    # Large uint assignments
                ],
                'description': 'Potential integer overflow/underflow vulnerability',
                'recommendation': 'Use SafeMath library or Solidity ^0.8.0 built-in overflow protection'
            },
            'SC09_2025': {
                'name': 'Insecure Randomness',
                'owasp_category': 'SC09:2025 - Insecure Randomness',
                'severity': Severity.MEDIUM,
                'patterns': [
                    r'block\.timestamp',            # Block timestamp usage
                    r'block\.difficulty',           # Block difficulty usage
                    r'block\.number',               # Block number usage
                    r'blockhash\s*\(',              # Blockhash usage
                    r'keccak256\([^)]*block\.',     # Block-based randomness
                    r'random\s*=\s*[^;]*block\.',   # Random variable using block data
                ],
                'description': 'Insecure randomness source detected',
                'recommendation': 'Use secure randomness sources like Chainlink VRF, RANDAO, or commit-reveal schemes'
            },
            'SC10_2025': {
                'name': 'Denial of Service (DoS) Attacks',
                'owasp_category': 'SC10:2025 - Denial of Service (DoS) Attacks',
                'severity': Severity.MEDIUM,
                'patterns': [
                    r'for\s*\(\s*(?:uint(?:256)?\s+)?\w+\s*=\s*\d+\s*;\s*\w+\s*<\s*\w+\.length\s*;',  # Unbounded loops
                    r'while\s*\([^)]*\.length',    # While loops with length
                    r'gas\s*\(\s*\)',              # Gas usage
                    r'\.push\s*\([^)]*\)',         # Array push operations
                    r'\.pop\s*\(\s*\)',            # Array pop operations
                ],
                'description': 'Potential denial of service through gas limit issues',
                'recommendation': 'Implement gas-efficient loops, pagination, and avoid unbounded operations'
            }
        }
    
    def _strip_comments(self, content: str) -> str:
        """Remove /* ... */ and // ... comments to reduce false positives"""
        content = re.sub(r'/\*[\s\S]*?\*/', '', content)
        content = re.sub(r'//.*', '', content)
        return content

    def detect_vulnerabilities(self, content: str, filename: str) -> List[Finding]:
        """Detect vulnerabilities in the given Solidity content"""
        findings = []
        parser = SolidityParser(content)
        clean = self._strip_comments(content)
        
        # Run pattern-based detection
        findings.extend(self._pattern_based_detection(clean, filename))
        
        # Run context-aware detection
        findings.extend(self._context_aware_detection(parser, filename))
        
        # Run advanced detection for 2025 framework
        findings.extend(self._advanced_detection_2025(parser, filename))
        
        return findings
    
    def _pattern_based_detection(self, content: str, filename: str) -> List[Finding]:
        """Detect vulnerabilities using regex patterns"""
        findings = []
        lines = content.split('\n')
        
        for rule_id, rule in self.rules.items():
            for pattern in rule['patterns']:
                regex = re.compile(pattern)
                for line_num, line in enumerate(lines, 1):
                    if regex.search(line):
                        finding = Finding(
                            rule_id=rule_id,
                            title=rule['name'],
                            description=rule['description'],
                            severity=rule['severity'],
                            line_number=line_num,
                            code_snippet=line.strip(),
                            recommendation=rule['recommendation'],
                            owasp_category=rule['owasp_category']
                        )
                        findings.append(finding)
        
        return findings
    
    def _context_aware_detection(self, parser: SolidityParser, filename: str) -> List[Finding]:
        """Perform context-aware vulnerability detection"""
        findings = []
        
        # Enhanced access control detection
        for func in parser.functions:
            if func['visibility'] in ['public', 'external'] and 'payable' in func['state_mutability']:
                func_content = self._get_function_body(parser.content, func['line'])
                if not re.search(r'\brequire\s*\(|\bonlyOwner\b|\bonlyAdmin\b|\bonlyRole\b', func_content):
                    finding = Finding(
                        rule_id='SC01_2025_CTX',
                        title='Payable Function Without Access Control',
                        description=f'Payable function {func["name"]} lacks proper access control',
                        severity=Severity.CRITICAL,
                        line_number=func['line'],
                        code_snippet=func['full_line'],
                        recommendation='Add proper access control to payable functions using modifiers or require statements',
                        owasp_category='SC01:2025 - Access Control Vulnerabilities'
                    )
                    findings.append(finding)

        # Enhanced reentrancy detection
        for func in parser.functions:
            body = self._get_function_body(parser.content, func['line'])
            if not body:
                continue
            external_call = re.search(r'\b(?:call|delegatecall|staticcall|transfer|send)\s*\(', body)
            state_write = re.search(r'\b\w+\s*(?:\[\w+\]\s*)?=\s*|(?:\+\+|--)|\+\=|\-\=|\*\=|\/=', body)
            if external_call and state_write and external_call.start() < state_write.start():
                findings.append(Finding(
                    rule_id='SC05_2025_CTX',
                    title='External call before state change (Reentrancy Risk)',
                    description=f'Function {func["name"]} makes external call before updating state',
                    severity=Severity.CRITICAL,
                    line_number=func['line'],
                    code_snippet=func['full_line'],
                    recommendation='Apply checks-effects-interactions pattern and/or ReentrancyGuard',
                    owasp_category='SC05:2025 - Reentrancy Attacks'
                ))
        
        return findings
    
    def _advanced_detection_2025(self, parser: SolidityParser, filename: str) -> List[Finding]:
        """Advanced detection patterns specific to 2025 framework"""
        findings = []
        
        # Flash loan attack detection
        for func in parser.functions:
            body = self._get_function_body(parser.content, func['line'])
            if body and re.search(r'flashLoan|flashSwap|borrow', body, re.IGNORECASE):
                if not re.search(r'require\s*\([^)]*balance|require\s*\([^)]*reserve', body):
                    findings.append(Finding(
                        rule_id='SC07_2025_ADV',
                        title='Flash Loan Function Without Proper Validation',
                        description=f'Function {func["name"]} appears to handle flash loans without proper validation',
                        severity=Severity.HIGH,
                        line_number=func['line'],
                        code_snippet=func['full_line'],
                        recommendation='Implement proper flash loan validation and use time-weighted price feeds',
                        owasp_category='SC07:2025 - Flash Loan Attacks'
                    ))
        
        # Price oracle manipulation detection
        for func in parser.functions:
            body = self._get_function_body(parser.content, func['line'])
            if body and re.search(r'price|rate|oracle', body, re.IGNORECASE):
                if re.search(r'block\.(timestamp|number|difficulty)', body):
                    findings.append(Finding(
                        rule_id='SC02_2025_ADV',
                        title='Price Calculation Using Block Data',
                        description=f'Function {func["name"]} uses block data for price calculations',
                        severity=Severity.HIGH,
                        line_number=func['line'],
                        code_snippet=func['full_line'],
                        recommendation='Use decentralized price oracles instead of block data for price calculations',
                        owasp_category='SC02:2025 - Price Oracle Manipulation'
                    ))
        
        # Logic error detection - complex conditional statements
        for func in parser.functions:
            body = self._get_function_body(parser.content, func['line'])
            if body and re.search(r'if\s*\([^)]*\)\s*\{[^}]*\}\s*else\s*if\s*\([^)]*\)\s*\{[^}]*\}\s*else\s*if', body):
                findings.append(Finding(
                    rule_id='SC03_2025_ADV',
                    title='Complex Conditional Logic',
                    description=f'Function {func["name"]} has complex conditional logic that may contain errors',
                    severity=Severity.MEDIUM,
                    line_number=func['line'],
                    code_snippet=func['full_line'],
                    recommendation='Simplify complex conditional logic and add comprehensive tests',
                    owasp_category='SC03:2025 - Logic Errors'
                ))
        
        return findings
    
    def _get_function_body(self, content: str, start_line: int) -> str:
        """Extract function body for analysis"""
        lines = content.split('\n')
        if start_line > len(lines):
            return ""
        
        brace_count = 0
        function_body = []
        start_found = False
        
        for i in range(start_line - 1, len(lines)):
            line = lines[i]
            if '{' in line and not start_found:
                start_found = True
            
            if start_found:
                function_body.append(line)
                brace_count += line.count('{') - line.count('}')
                
                if brace_count == 0:
                    break
        
        return '\n'.join(function_body)


class ReportGenerator:
    """Enhanced report generator for 2025 framework"""
    
    @staticmethod
    def generate_json_report(findings: List[Finding], filename: str) -> Dict[str, Any]:
        """Generate JSON format report"""
        return {
            'file': filename,
            'timestamp': datetime.utcnow().isoformat() + 'Z',
            'framework_version': 'OWASP Smart Contract Top 10 2025',
            'total_findings': len(findings),
            'findings': [
                {
                    'rule_id': f.rule_id,
                    'title': f.title,
                    'description': f.description,
                    'severity': f.severity.value,
                    'line_number': f.line_number,
                    'code_snippet': f.code_snippet,
                    'recommendation': f.recommendation,
                    'owasp_category': f.owasp_category
                }
                for f in findings
            ]
        }
    
    @staticmethod
    def generate_text_report(findings: List[Finding], filename: str) -> str:
        """Generate human-readable text report"""
        if not findings:
            return f"No vulnerabilities found in {filename}\n"
        
        report = f"\n{'='*80}\n"
        report += f"SMART CONTRACT SECURITY ANALYSIS REPORT (OWASP 2025)\n"
        report += f"File: {filename}\n"
        report += f"Total Findings: {len(findings)}\n"
        report += f"{'='*80}\n\n"
        
        # Group findings by severity
        severity_groups: Dict[str, List[Finding]] = {}
        for finding in findings:
            severity = finding.severity.value
            if severity not in severity_groups:
                severity_groups[severity] = []
            severity_groups[severity].append(finding)
        
        # Display findings by severity
        for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']:
            if severity in severity_groups:
                report += f"\n{severity} SEVERITY FINDINGS:\n"
                report += f"{'-' * 40}\n"
                
                for finding in severity_groups[severity]:
                    report += f"\n[{finding.rule_id}] {finding.title}\n"
                    report += f"Line {finding.line_number}: {finding.code_snippet}\n"
                    report += f"Description: {finding.description}\n"
                    report += f"Category: {finding.owasp_category}\n"
                    report += f"Recommendation: {finding.recommendation}\n"
                    report += f"{'-' * 40}\n"
        
        return report


class SoliditySASTTool:
    """Enhanced SAST tool class for 2025 framework"""
    
    def __init__(self):
        self.detector = VulnerabilityDetector()
        self.report_generator = ReportGenerator()
    
    def scan_file(self, filepath: str) -> List[Finding]:
        """Scan a single Solidity file"""
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                content = f.read()
            
            return self.detector.detect_vulnerabilities(content, filepath)
        except Exception as e:
            print(f"Error scanning file {filepath}: {str(e)}")
            return []
    
    def scan_directory(self, directory: str) -> Dict[str, List[Finding]]:
        """Scan all .sol files in a directory"""
        results: Dict[str, List[Finding]] = {}
        
        for root, dirs, files in os.walk(directory):
            for file in files:
                if file.endswith('.sol'):
                    filepath = os.path.join(root, file)
                    findings = self.scan_file(filepath)
                    if findings:
                        results[filepath] = findings
        
        return results
    
    def generate_report(self, findings: Dict[str, List[Finding]], output_format: str = 'text') -> str:
        """Generate a comprehensive report"""
        if output_format == 'json':
            all_findings: List[Dict[str, Any]] = []
            for filepath, file_findings in findings.items():
                for f in file_findings:
                    all_findings.append({
                        'file': filepath,
                        'rule_id': f.rule_id,
                        'title': f.title,
                        'description': f.description,
                        'severity': f.severity.value,
                        'line_number': f.line_number,
                        'code_snippet': f.code_snippet,
                        'recommendation': f.recommendation,
                        'owasp_category': f.owasp_category
                    })
            
            return json.dumps({
                'framework_version': 'OWASP Smart Contract Top 10 2025',
                'total_files_scanned': len(findings),
                'total_findings': len(all_findings),
                'findings': all_findings,
                'generated_at': datetime.utcnow().isoformat() + 'Z'
            }, indent=2)
        
        else:  # text format
            report = f"\n{'='*100}\n"
            report += f"SMART CONTRACT SECURITY ANALYSIS - SUMMARY REPORT (OWASP 2025)\n"
            report += f"{'='*100}\n"
            report += f"Files scanned: {len(findings)}\n"
            report += f"Total findings: {sum(len(f) for f in findings.values())}\n"
            report += f"{'='*100}\n"
            
            for filepath, file_findings in findings.items():
                report += self.report_generator.generate_text_report(file_findings, filepath)
            
            return report


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(description='Smart Contract SAST Tool v1.1 - OWASP 2025 Framework')
    parser.add_argument('target', help='File or directory to scan')
    parser.add_argument('--output', '-o', help='Output file for report')
    parser.add_argument('--format', '-f', choices=['text', 'json'], default='text',
                       help='Output format (default: text)')
    parser.add_argument('--verbose', '-v', action='store_true', help='Verbose output')
    parser.add_argument('--version', action='version', version='SAST Snake v1.1 - OWASP 2025 Framework')
    
    args = parser.parse_args()
    
    tool = SoliditySASTTool()
    
    if os.path.isfile(args.target):
        findings = {args.target: tool.scan_file(args.target)}
    else:
        findings = tool.scan_directory(args.target)
    
    report = tool.generate_report(findings, args.format)
    
    if args.output:
        with open(args.output, 'w', encoding='utf-8') as f:
            f.write(report)
        print(f"Report saved to {args.output}")
    else:
        print(report)


if __name__ == '__main__':
    main()
