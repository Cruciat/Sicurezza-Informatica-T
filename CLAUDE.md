# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Repository Structure

This security exam toolkit is organized into thematic modules:
- `01_Enumeration/`: Network discovery and enumeration scripts
- `02_Web_Security/`: Web application security testing tools  
- `03_Binary_Exploitation/`: Binary exploitation techniques (currently empty)
- `04_Privilege_Escalation/`: Privilege escalation methods (currently empty)
- `05_Defenses/`: Defensive security mechanisms (currently empty)

## Key Scripts and Usage

### 01_Enumeration/auto_enum.sh
Network enumeration script that performs:
1. Host discovery using nmap ping scan
2. Full TCP port scan (all 65535 ports) on discovered hosts
3. Service/version detection and script scanning on open ports

Usage: `./auto_enum.sh <subnet>` (e.g., `./auto_enum.sh 192.168.56.0/24`)

### 02_Web_Security/cmd_encoder.sh
Command injection bypass encoder supporting:
- URL encoding (%xx)
- Double URL encoding (%25xx)
- Hex bash encoding ($'\xhh')
- Octal bash encoding ($'\ooo')

Interactive tool for encoding strings to bypass command injection filters.

### 02_Web_Security/sqli_enum.sh
UNION-based SQL injection column enumerator with features:
- Automatic detection of injection type (string/integer)
- Column count discovery via ORDER BY/UNION SELECT
- Data type identification for each column
- Reflection detection for data exfiltration points
- MySQL-optimized commenting (# instead of -- )

Usage: `./sqli_enum.sh [-t str|int|auto] URL_WITH_PAYLOAD_HERE`
Example: `./sqli_enum.sh "http://example.com/vuln.php?id=PAYLOAD_HERE"`

## Common Development Tasks

### Running Scripts
All scripts are bash executables. Ensure proper permissions:
```bash
chmod +x <script_name>.sh
```

### Testing Approach
- Test scripts in isolated/lab environments only
- Use against authorized targets (lab VMs, CTF platforms, etc.)
- Scripts include safety checks (e.g., skipping .1 and .254 IPs in enumeration)

### Modifying Scripts
When adding new features:
1. Maintain bash builtin-only dependencies where possible (see cmd_encoder.sh)
2. Include clear usage documentation at top of each script
3. Add error handling for edge cases
4. Consider output formatting for readability

## Security Notes
- These tools are for authorized security testing only
- Always obtain proper authorization before testing any systems
- Use in accordance with local laws and organizational policies
- The repository contains offensive security tools - handle responsibly