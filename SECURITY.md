# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 11.x    | Yes       |
| < 11    | Security fixes only when practical |

## Reporting a Vulnerability

If you discover a security vulnerability in SAGE, please report it responsibly:

1. **Do NOT open a public GitHub issue**
2. Use GitHub's private vulnerability reporting: **[Security → Report a vulnerability](https://github.com/l33tdawg/sage/security/advisories/new)**. The report stays private between you and the maintainers until an advisory is published, and it lets us coordinate a fix, a CVE, and credit in one place.
3. Include a description of the vulnerability, steps to reproduce, the affected version or commit, and any relevant logs or screenshots

If the private advisory form is unavailable to you for any reason, contact [@l33tdawg](https://github.com/l33tdawg) to arrange another channel — but please still do not open a public issue.

## Response Timeline

- **Acknowledgement:** Within 72 hours of report
- **Assessment:** Within 7 days
- **Fix or mitigation plan:** Within 30 days

## Credit

Reporters will be credited in the changelog unless anonymity is requested.

## Scope

- **SAGE Personal (sage-gui):** Single-user. Its management dashboard/API is intended for localhost on port 8080. Federation is separately opt-in and network-facing: a dedicated pinned-mTLS listener plus optional v11.6 libp2p NAT traversal/relay transport. Active agreements, certificate pins, and signed requests remain the federation authorization boundary.
- **SAGE Enterprise:** Multi-node BFT consensus. Broader attack surface including inter-validator communication, RBAC, and federation.

For a detailed security analysis, threat model, and known limitations, see [SECURITY_FAQ.md](SECURITY_FAQ.md).
