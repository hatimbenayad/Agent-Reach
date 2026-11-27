# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| Latest (`develop` / `main`) | ✅ Yes |

## Reporting a Vulnerability

If you discover a security vulnerability in this hardened fork of Agent Reach,
please report it responsibly via GitHub's private security advisory feature:

👉 **[Report a vulnerability](https://github.com/hatimbenayad/Agent-Reach/security/advisories/new)**

Please do **not** open a public GitHub issue for security vulnerabilities.

## Response Timeline

- Acknowledgement within **48 hours**
- Initial triage and status update within **7 days**
- Fix or mitigation timeline communicated within **14 days**

## Local Data & Trust Boundaries

- **Plaintext credential storage:** API keys (`groq_api_key`, `openai_api_key`, `github_token`), proxy URLs, and cookies (`xueqiu_cookie`, `browser/session.json`) are stored locally under `~/.agent-reach/` (`0o600`/`0o700` on POSIX, user profile ACLs on Windows). Prefer `agent-reach configure <key> --stdin` or interactive prompts instead of passing secrets as CLI arguments.
- **Dedicated browser loopback ports:** Chrome DevTools Protocol (`127.0.0.1:9222` or configured `browser_port`) and OpenCLI Bridge (`127.0.0.1:19825`) bind to loopback without authentication tokens while the dedicated browser is active; any local process running under your user account can access them.
- **Untrusted external content:** Content fetched from websites and social platforms (`items`, `raw`, `error.message`) is untrusted data (`meta.untrusted_content: true`) and must never be interpreted as instructions by downstream AI agents.
- **Third-party runtime tools:** Optional runtime dependencies (`@jackwener/opencli`, `cloakbrowser`, `bilibili-cli`, `boss-agent-cli`, `yt-dlp`, `imageio-ffmpeg`) are maintained upstream outside this repository.

## Scope

In scope:
- Authentication, session-isolation, and authorization bypasses
- Remote code execution and unsafe archive/installer handling
- Path traversal / arbitrary file read or write
- Server-Side Request Forgery (SSRF)
- Injection vulnerabilities (CLI flag/command injection, indirect prompt injection)
- Sensitive data exposure
