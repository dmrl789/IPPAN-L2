# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |

## Reporting a Vulnerability

If you discover a security vulnerability in IPPAN-L2, please report it responsibly.

### How to Report

1. **DO NOT** create a public GitHub issue for security vulnerabilities
2. Email security concerns to: `security@ippan.io` (or open a private security advisory)
3. Include:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if any)

### What to Expect

- **Acknowledgment**: Within 48 hours
- **Initial Assessment**: Within 1 week
- **Status Updates**: Every 2 weeks until resolved
- **Resolution**: Depends on severity and complexity

### Severity Levels

| Level | Response Time | Examples |
|-------|--------------|----------|
| Critical | 24-48 hours | Remote code execution, private key exposure |
| High | 1 week | Authentication bypass, data corruption |
| Medium | 2 weeks | Denial of service, information disclosure |
| Low | 1 month | Minor information leaks, best practice violations |

## Security Best Practices

### For Operators

1. **Secrets Management**
   - Never commit secrets to version control
   - Use environment variables or secrets managers
   - Rotate keys regularly

2. **Network Security**
   - Run services behind firewalls
   - Use TLS for all external connections
   - Restrict access to metrics/health endpoints

3. **Key Material**
   - Store private keys in HSM/secure enclave when possible
   - Use separate keys for testnet and mainnet
   - Implement key rotation procedures

4. **Updates**
   - Keep dependencies up to date
   - Subscribe to security advisories
   - Apply patches promptly

### For Developers

1. **Code Review**
   - All changes require review
   - Security-sensitive changes require additional review
   - Use automated tools (clippy, audit)

2. **Dependencies**
   - Minimize dependencies
   - Audit new dependencies
   - Use `cargo-deny` to check licenses and advisories

3. **Testing**
   - Write tests for security-critical code
   - Include edge cases and error conditions
   - Consider fuzzing for parsing code

## Security Measures

### Implemented

- [x] No unsafe code (`#![forbid(unsafe_code)]`)
- [x] No floating point in core types (determinism)
- [x] Strict clippy lints
- [x] Dependency auditing (`cargo-audit`)
- [x] License checking (`cargo-deny`)
- [x] Automated CI checks

### Planned

- [ ] Fuzzing for parsers
- [ ] Formal verification for core types
- [ ] Hardware security module (HSM) support
- [ ] Multi-signature support for oracle updates

## Disclosure Policy

We follow responsible disclosure:

1. Reporter notifies us privately
2. We acknowledge and investigate
3. We develop and test a fix
4. We release the fix and notify users
5. After 90 days (or when fix is deployed), public disclosure

## Bug Bounty

We do not currently have a formal bug bounty program. However, we greatly appreciate
security researchers who help improve our security and will acknowledge contributions
in our release notes (with permission).

## Contact

- Security issues: `security@ippan.io`
- General questions: Open a GitHub issue
- Private discussions: Open a GitHub security advisory
