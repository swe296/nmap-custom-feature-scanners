# Custom Nmap Scripting Engine (NSE) Feature Scanners

This repository contains two custom Nmap Scripting Engine (NSE) Lua scripts developed for transport and application layer network feature scanning.

## Scripts Overview

### 1. `dns-feature-scanner.nse`
- **Protocol / Layer**: DNS (Layer 7 / Application Layer, UDP & TCP Port 53)
- **Purpose**: Scans a DNS server to identify supported query features without performing aggressive auditing.
- **Features Scanned**:
  - Recursive Query Resolution capability
  - IPv4 Address Lookup (A Records)
  - IPv6 Address Lookup (AAAA Records)
  - Mail Exchange Lookup (MX Records)
- **Usage**:
  ```bash
  sudo nmap -sU -p 53 --script ./dns-feature-scanner.nse 8.8.8.8
  ```

### 2. `tls-cert-scanner.nse`
- **Protocol / Layer**: SSL/TLS (Transport/Session Layer, TCP Port 443)
- **Purpose**: Scans secure sockets to extract public X.509 certificate metadata features.
- **Features Scanned**:
  - Subject Common Name (CN)
  - Issuing Certificate Authority (Issuer CN)
  - Operational Validity Period (Start & Expiration Dates)
  - Signature Hash Algorithm
  - Public Key Cipher Architecture and Bit Length
- **Usage**:
  ```bash
  sudo nmap -p 443 --script ./tls-cert-scanner.nse google.com
  ```

## Development and Testing Environment
- **Scanning Tool**: Nmap Network Mapper
- **Language**: Lua (Nmap Scripting Engine)
- **Libraries**: `dns`, `sslcert`, `shortport`, `stdnse`
