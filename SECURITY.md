# Security Policy

## Responsible Disclosure

k8scan is a security tool designed for authorized testing only. If you discover a security vulnerability in k8scan itself, please report it responsibly.

## Reporting a Vulnerability

**Please DO NOT create a public GitHub issue for security vulnerabilities.**

Instead:

1. Email security concerns to: alperenkeskk@gmail.com
2. Include:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if any)

We will respond within 48 hours.

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.0.x   | :white_check_mark: |

## Security Best Practices

### When Using k8scan

✅ **DO**:
- Use only in authorized environments
- Run with read-only permissions when possible
- Use `--dry-run` for testing
- Keep exploitation results confidential
- Follow your organization's security policies

❌ **DON'T**:
- Use in production without authorization
- Share exploitation results publicly
- Use on systems you don't own or have permission to test
- Ignore warnings and confirmations

### RBAC Permissions

k8scan requires read-only access by default:

```yaml
# Minimum required permissions
- verbs: ["get", "list"]  # Read-only
```

**Never** grant write permissions unless absolutely necessary for specific testing scenarios.

## Disclaimer

This tool is provided for:
- Security testing in authorized environments
- Educational purposes
- Vulnerability research
- Capture the Flag (CTF) competitions

**Users are responsible for**:
- Obtaining proper authorization
- Compliance with applicable laws
- Secure handling of findings
- Responsible disclosure of vulnerabilities

## Legal Notice

Unauthorized access to computer systems is illegal. Use this tool only on systems you own or have explicit permission to test.

The authors and contributors:
- Assume no liability for misuse
- Do not endorse illegal activities
- Promote responsible security research

## Security Updates

Security fixes will be released as soon as possible. Users should:
- Watch the repository for updates
- Keep k8scan updated to the latest version
- Review changelogs for security fixes
