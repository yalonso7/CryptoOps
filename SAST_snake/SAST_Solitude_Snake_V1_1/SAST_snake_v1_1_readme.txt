v1.1 update changes:

OWASP Top 10 2025
SC01:2025 - Access Control Vulnerabilities
SC02:2025 - Price Oracle Manipulation
SC03:2025 - Logic Errors
SC04:2025 - Lack of Input Validation
SC05:2025 - Reentrancy Attacks
SC06:2025 - Unchecked External Calls
SC07:2025 - Flash Loan Attacks
SC08:2025 - Integer Overflow and Underflow
SC09:2025 - Insecure Randomness
SC10:2025 - Denial of Service (DoS) Attacks

New Features in update v1.1 "Solitude Snake"
Enhanced Parser: Added support for contracts, events, and structs
Advanced Detection: Context-aware analysis for flash loans and price oracles
2025 Framework Compliance: All rules updated to match OWASP 2025 priorities
Improved Severity Mapping: Updated severity levels based on 2025 framework
Better Reporting: Enhanced reports with framework version information
The tool now specifically targets the most critical vulnerabilities identified in the 2025 framework, with particular emphasis on access control, price oracle manipulation, and flash loan attacks that have become more prevalent in recent years.

# Basic usage - same as v1.0
python SAST_snake_v1_1.py CollateralGuard.sol

# Scan with verbose output
python SAST_snake_v1_1.py . --verbose

# Generate JSON report with 2025 framework
python SAST_snake_v1_1.py . --format json --output owasp_2025_report.json

# Check version
python SAST_snake_v1_1.py --version