# Security Policy

## Supported Versions

We provide security updates for the following versions of the SMP-PQC-Testkit:

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |
| < 0.1.0 | :x:                |

## Reporting a Vulnerability

We take the security of our software seriously. If you believe you have found a security vulnerability in the SMP-PQC-Testkit, please report it to us through coordinated disclosure.

**Please do not report security vulnerabilities through public GitHub issues.**

Instead, please send an email to [security@smp-pqc-testkit.example.com](mailto:security@smp-pqc-testkit.example.com).

You should receive a response within 48 hours. If you do not, please follow up via email to ensure we received your original message.

Please include the following information in your report:

- Type of issue (e.g., buffer overflow, side-channel vulnerability, etc.)
- Full paths of source files related to the manifestation of the issue
- The location of the affected issue (line numbers, function names, etc.)
- Any special configuration required to reproduce the issue
- Step-by-step instructions to reproduce the issue
- Proof-of-concept or exploit code (if possible)
- Impact of the issue, including how an attacker might exploit it

This information will help us triage your report more quickly.

## Preferred Languages

We prefer all communications to be in English.

## Policy

### What Counts as a Vulnerability

We consider the following to be security vulnerabilities:

- Issues that allow an attacker to break the cryptographic guarantees of the algorithms we test
- Side-channel vulnerabilities that leak secret information through timing, power consumption, or other side channels
- Memory safety issues that could lead to arbitrary code execution
- Authentication bypasses in our testing tools
- Issues that allow attackers to manipulate test results to appear valid when they are not

We do **not** consider the following to be vulnerabilities in our context:

- Issues in the underlying cryptographic libraries we test (ml-kem, ml-dsa, slh-dsa) unless our wrapper code exacerbates them
- General performance issues that don't affect security
- Issues requiring physical access to the device
- Issues that require compromising the build system or development environment

### Our Commitment

Upon receiving a security vulnerability report, we will:

1. Acknowledge receipt of the report within 48 hours
2. Confirm whether the issue is a valid security vulnerability within 5 business days
3. Provide regular updates on our progress toward fixing the issue
4. Work with the reporter to ensure they understand the issue and the proposed fix
5. Coordinate the public disclosure of the fix

We aim to fix critical vulnerabilities within 30 days of receiving a report.

### Credit

We will gladly credit you for your discovery in our release notes and security advisories unless you wish to remain anonymous.

### Legal

Reports made in good faith will not result in any legal action against the reporter, even if we ultimately determine the issue is not a vulnerability.

We reserve the right to modify this policy at any time.