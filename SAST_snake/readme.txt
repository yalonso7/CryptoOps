## Basic Usage Examples

### 1. Scan a single Solidity file
```bash
python SAST_snake.py CollateralGuard.sol
```

### 2. Scan a directory containing Solidity files
```bash
python SAST_snake.py .
```

### 3. Scan with verbose output
```bash
python SAST_snake.py CollateralGuard.sol --verbose
```

### 4. Generate JSON report
```bash
python SAST_snake.py CollateralGuard.sol --format json
```

### 5. Save report to a file
```bash
python SAST_snake.py CollateralGuard.sol --output security_report.txt
```

### 6. Generate JSON report and save to file
```bash
python SAST_snake.py . --format json --output security_analysis.json
```

### 7. Scan specific directory with verbose output and save report
```bash
python SAST_snake.py ./contracts --verbose --output detailed_report.txt
```

## Command Line Arguments

The tool accepts the following arguments:

- **`target`** (required): File or directory to scan
- **`--output` or `-o`**: Output file for the report
- **`--format` or `-f`**: Output format - either `text` (default) or `json`
- **`--verbose` or `-v`**: Enable verbose output

## What the Tool Does

The `SAST_snake.py` tool is a Static Application Security Testing (SAST) tool specifically designed for Solidity smart contracts. It:

1. **Scans for OWASP Smart Contract Top 10 vulnerabilities** including:
   - Reentrancy (SC01)
   - Integer Overflow/Underflow (SC02)
   - Unsafe External Calls (SC03)
   - Access Control Issues (SC04)
   - Denial of Service (SC05)
   - Bad Randomness (SC06)
   - Front-Running (SC07)
   - Time Manipulation (SC08)
   - Unchecked Return Values (SC09)
   - Short Address Attack (SC10)

2. **Supports multiple output formats**:
   - Human-readable text reports
   - JSON format for programmatic processing

3. **Can scan**:
   - Individual `.sol` files
   - Entire directories (recursively finds all `.sol` files)

The tool will analyze your Solidity code and provide detailed security findings with severity levels, line numbers, code snippets, and remediation recommendations.

P.S: Updates coming soon.