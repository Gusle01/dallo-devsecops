# Dallo DevSecOps Security Review Guide

This repository is an AI-based attack and defense analysis system.

When performing a security review, use this framing:

1. Red Team analysis
   - Identify exploitable code paths, not only generic lint findings.
   - Prioritize SQL injection, command injection, XSS, unsafe deserialization, path traversal, hardcoded secrets, weak cryptography, and dependency vulnerabilities.
   - For each finding, explain attack vector, exploitability, affected file/function, likely impact, and CWE where possible.

2. Blue Team remediation
   - Prefer secure refactors that preserve behavior and match the existing code style.
   - Use parameterized queries, safe subprocess APIs, output escaping, input validation, secret management, and modern cryptographic primitives as appropriate.
   - Do not introduce broad rewrites when a focused security fix is enough.

3. Before/after evidence
   - Explain what vulnerability is removed by the patch.
   - Call out any residual risk or manual verification still required.
   - Avoid claiming a fix is complete unless syntax checks and security revalidation support it.

4. Project-specific constraints
   - Shared data contracts live in `shared/schemas.py`.
   - Red/Blue derived posture logic lives in `shared/red_blue.py`.
   - The main analysis flow is `analyzer/pipeline.py`.
   - API output should remain compatible with the React dashboard.
   - Never commit real API keys, tokens, credentials, or private source snippets.
