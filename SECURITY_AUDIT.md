# Security Audit Report — Agent Reach

- **Target Repository:** `https://github.com/Panniantong/Agent-Reach` (audited at commit `8d9ecc1`, version `1.6.1`)
- **Audit Date:** 2026-11-27
- **Audited Scope:** Static manual review of `agent_reach/`, `scripts/`, `.github/workflows/`, `docs/`, `pyproject.toml`, `constraints.txt`, plus `bandit`, `pip-audit`, `ruff`, and pattern-based secret/URL scanning in an isolated environment (no repo code executed).

---

## 1. Summary Verdict

**Verdict: Safe with fixes**

No deliberate malice, obfuscated payloads, backdoors, hidden binaries, or undisclosed telemetry were found. Upstream recently fixed several important security issues (PR #1024: `b23.tv` URL validation, blocking `browser-cookie3` on `bili-cli`, pinning CDP loopback host/port, and capping `playwright` for `cloakbrowser`).

However, multiple **High**, **Medium**, and **Low** security weaknesses remain:
1. Remote code execution via `irm ... | iex` (Windows) and unverified `curl`/`urllib` shell script execution (POSIX) when installing `uv`, plus unpinned/unhashed downloads for the OpenCLI extension, `boss-agent-cli`, and self-updates, and `--ignore-scripts` only applied to one npm package.
2. SSRF bypasses in `transcribe.py` (no DNS-resolution/redirect IP check, missing `.local`/`.internal` blocklist) and `channels/bilibili.py` (`b23.tv` HEAD request follows redirects without re-validating destination).
3. Archive extraction symlink escape in `runtime/browser.py:_unzip` and legacy `tarfile.extractall` fallback in `runtime/tools.py`.
4. Path traversal in `channels/github.py` (`_TARGET_RE` allows `.` / `..` segments in `owner`/`repo`) and CLI flag/argument injection across `opencli`/`bili-cli`/`yt-dlp` invocations.
5. Plaintext credential/cookie storage (`config.yaml`, `session.json`), API key exposure via `curl` command-line arguments in `transcribe_xiaoyuzhou.sh`, and unauthenticated loopback CDP / OpenCLI Bridge ports.
6. Indirect prompt-injection exposure: untrusted web/social content and upstream error `hint` strings are passed directly to AI agents without trust-boundary markers or sanitization, while `SKILL.md` instructs agents to follow `error.hint`.
7. Supply-chain & CI/CD gaps: two known dependency CVEs in `constraints.txt` (`requests==2.32.5`, `pytest==8.0.0`), mutable action tags (`@v4`, `@v5`) and missing `permissions:` in GitHub Actions workflows, and no Dependabot config.

---

## 2. Findings Table

| ID | Severity | File + Line | Description | Impact | Conceptual Exploitation | Recommended Fix | Status |
|---|---|---|---|---|---|---|---|
| F-01 | **High** | `agent_reach/runtime/tools.py:428-439` | `_install_uv()` executes `powershell -ExecutionPolicy ByPass -c "irm https://astral.sh/uv/install.ps1 \| iex"` on Windows and downloads + runs `install.sh` via `sh` on POSIX with no checksum or signature verification. | Compromised upstream CDN, DNS, or MITM/proxy leads to arbitrary code execution during `agent-reach add` / `update`. | Attacker serving a modified installer script achieves immediate RCE under the user account. | Install `uv` via `pip` / wheel with hash verification or verify downloaded release archives against pinned SHA256 checksums instead of piping remote scripts to a shell. | **Fixed** (`b0b4b9b`, `646ff37`) |
| F-02 | **High** | `agent_reach/runtime/browser.py:275-294`, `393-444` | `_unzip()` extracts zip symlinks (`0o120000`) via `os.symlink(zf.read(info), target)` without validating that the symlink target stays inside `dest`. `refresh_extension()` also downloads the latest `opencli-extension-*.zip` from GitHub without version pinning, size cap, or hash verification. | Arbitrary file write/overwrite outside the extension extraction directory if a malicious zip is processed. | A zip entry creates a symlink pointing outside `dest`, followed by another entry writing through it (or an upstream release compromise ships arbitrary JS/files). | Reject symlinks whose resolved target escapes `dest`; enforce size caps on `_fetch`/`_download`; pin or allowlist extension release version/digest where feasible. | **Fixed** (`70ab56b`) |
| F-03 | **High** | `agent_reach/transcribe.py:211-245`, `247-275`; `agent_reach/channels/bilibili.py:50-55` | `transcribe._assert_safe_public_url()` only inspects literal IPs without DNS resolution or redirect validation, lacks `.local`/`.internal`/`.lan` suffix blocks, and does not reject `user:pass@` userinfo. `bilibili._bvid()` passes `b23.tv` URLs to `urllib.request.urlopen()` which follows HTTP redirects to arbitrary schemes/hosts. | Server-Side Request Forgery (SSRF) against localhost services (including CDP on `127.0.0.1:9222`), LAN hosts, or cloud metadata (`169.254.169.254`). | Supply a hostname resolving to `127.0.0.1` (e.g., `nip.io`) or a public URL returning `302 Location: http://127.0.0.1:9222/json` to probe internal endpoints. | Reuse `normalize_public_http_url()`, resolve DNS and block non-global IPs pre-request, disable or re-validate HTTP redirects on every hop, and restrict `urlopen` schemes to `http`/`https`. | **Mitigated** (`8431f4a`) — DNS & redirect hops validated; residual TOCTOU / `yt-dlp` internal redirects remain. |
| F-04 | **High** | `agent_reach/channels/github.py:26-29, 42-48, 151-161` | `_TARGET_RE` permits `[\w.-]+` for `owner` and `repo`, allowing `.` or `..` segments. | GitHub API path traversal: `agent-reach github read ../orgs/foo` causes `gh api` / `api.github.com` to hit unintended endpoints. | Pass `owner` or `repo` as `..` to escape `/repos/{owner}/{repo}` into arbitrary `GET` endpoints using the user's GitHub token. | Reject `.` and `..` for `owner`/`repo` and restrict to `^[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?$` / valid repo names. | **Fixed** (`83ae97d`) |
| F-05 | **High** | `agent_reach/scripts/transcribe_xiaoyuzhou.sh:228, 259` | Passes `Authorization: Bearer $GROQ_API_KEY` directly on the `curl` command line. | On multi-user systems, any local user can read `GROQ_API_KEY` from the process table (`ps`, `/proc/<pid>/cmdline`). | Local observer polls process listings during podcast transcription and captures the Groq API key. | Pass the `Authorization` header to `curl` via stdin config (`curl -K -`) or perform the upload via Python `urllib` reading the key from environment/file. | **Fixed** (`bf34602`) |
| F-06 | **Medium** | `agent_reach/runtime/tools.py:63-66, 334, 360, 413-421` | `npm --ignore-scripts` is only enabled for `opencli`, not other npm installs; `boss-agent-cli` installs from an unhashed GitHub zip URL; `pip install` runs without `--only-binary` or hashes; `_install_node()` has an unsafe `tarfile.extractall()` fallback on Python < 3.12 and unvalidated `zipfile.extractall()`. | Supply-chain / install-time code execution if an npm/pip dependency or archive is compromised, or path traversal on Python < 3.12 tar extraction. | Compromised transitive package or MITM archive executes arbitrary `postinstall`/`setup.py` or writes outside `out`. | Apply `--ignore-scripts` to all `_install_npm()` calls; enforce member path validation for zip/tar extraction (drop unsafe `extractall` fallback); document residual unhashed upstream tool installs. | **Mitigated** (`a626d2b`) — npm scripts disabled, zip/tar hardened, `boss-agent-cli` zip SHA256 pinned; transitive PyPI/npm deps of runtime tools remain unpinned. |
| F-07 | **Medium** | `agent_reach/channels/bilibili.py:232`, `twitter.py:79-91`, `reddit.py:79-96`, `instagram.py:49-56`, `facebook.py:39-43`, `linkedin.py:30-35`, `xiaohongshu.py:66-70`, `boss.py:133-137`, `youtube.py:164, 207` | User/agent-controlled strings (`query`, `username`, `city`, `location`, `target`, `name`) are passed as positional args to `bili`, `opencli`, and `yt-dlp` without `--` option-end separator or strict format validation (e.g., `twitter._opencli_thread` accepts non-numeric IDs). | CLI argument/flag injection into upstream tools (`bili`, `opencli`, `yt-dlp`), potentially altering tool behavior (e.g. output flags, config paths, cookies/debug flags). | Pass a query/username starting with `--` (such as `--config /tmp/x` or `--help`) to inject unexpected CLI options. | Insert `--` before positional user arguments where supported, reject leading `-` on identifiers/queries where `--` isn't supported by the upstream CLI, and validate tweet IDs / subreddit names strictly. | **Fixed** (`bce4473`) |
| F-08 | **Medium** | `agent_reach/skill/SKILL.md:40-53`, `SKILL_en.md:41-54`, `agent_reach/backends/opencli.py:44-56`, `agent_reach/runtime/result.py:85-102` | Untrusted external content (`items[].title`, `text`, `raw`) is returned to the LLM without trust-boundary markers or control-character sanitization, and upstream error `help`/`hint` strings are forwarded into `error.hint` which `SKILL.md` directs the agent to follow. | Indirect prompt injection: malicious posts, comments, video transcripts, or error messages can hijack the agent's next tool calls. | Embed imperative instructions in a webpage, tweet, or upstream error message; the LLM reads `items` or `error.hint` as trusted instructions. | Strip ASCII control characters from output fields, stop forwarding arbitrary upstream `hint` strings verbatim as authoritative instructions, add `meta.trust_boundary` / untrusted-data notice in envelopes, and update `SKILL.md` / `SKILL_en.md` to warn agents never to follow instructions found inside fetched content or raw upstream messages. | **Mitigated** (`85b5215`) — control chars stripped, `meta.untrusted_content` & skill warnings added, upstream hints dropped; LLM prompt injection remains an inherent residual risk. |
| F-09 | **Medium** | `agent_reach/config.py:100-198`, `agent_reach/runtime/browser.py:679-684`, `agent_reach/runtime/cli.py:352-364` | API keys (`groq_api_key`, `openai_api_key`, `github_token`), proxy URLs (potentially with credentials), and all browser cookies (`session.json`) are stored in plaintext under `~/.agent-reach/`. Windows has no explicit `icacls` restriction on these files, and `configure <key> <value>` accepts secrets as CLI args. | Any local process or backup with read access to `~/.agent-reach/` can steal all API keys and site session cookies; CLI args leak in shell history/process lists. | Read `~/.agent-reach/config.yaml` or `browser/session.json` directly, or inspect shell history after `agent-reach configure groq-key <secret>`. | Warn users when secrets are passed as positional CLI args (prefer `--stdin`/prompt), enforce restrictive Windows ACLs on `~/.agent-reach/` if feasible, support OS keyring or document residual plaintext risk clearly. | **Mitigated** (`2620385`, `646ff37`) — CLI arg warning & `--stdin`/getpass for all secret keys added, plaintext storage documented in `SECURITY.md`/`config.py`; OS keyring omitted for headless/container compatibility. |
| F-10 | **Medium** | `agent_reach/runtime/browser.py:262-273, 637-643`, `agent_reach/runtime/update_notice.py:36-42`, `agent_reach/channels/xueqiu.py:114-121, 197-201` | Unbounded `resp.read()` / `shutil.copyfileobj` calls in `browser._fetch`, `browser._download`, `update_notice.fetch_latest`, and `xueqiu._get_json` / `_error_code`; `browser.open_url` and `_fetch`/`_download` do not validate URL schemes (`http`/`https`). | Memory/disk exhaustion (DoS) on oversized responses; potential `file://` or `javascript:` navigation if non-HTTP URLs reach `open_url` or `urllib.request.urlopen`. | Server returns multi-GB body or `open_url` receives `file:///etc/passwd`. | Enforce strict `max_bytes` limits on all HTTP reads/downloads, validate `http`/`https` schemes in `open_url` and HTTP helpers, and validate `latest` version format in `update_notice.py` / `manage.py`. | **Fixed** (`4cff55d`, `c3e0dc7`) |
| F-11 | **Medium** | `constraints.txt:5, 11`, `pyproject.toml:30-35` | `pip-audit` identified 2 known CVEs in `constraints.txt`: `requests==2.32.5` (`CVE-2026-25645` / `PYSEC-2026-2275`, fixed in `2.33.0`) and `pytest==8.0.0` (`CVE-2025-71176` / `PYSEC-2026-1845`, fixed in `9.0.3`). `pyproject.toml` allows `requests>=2.28` and lacks hash-pinned lockfiles. | Vulnerable dependency versions can be installed; unpinned transitive dependencies create reproducibility and supply-chain risk. | Local attacker on shared host exploits predictable temp path in `requests.utils.extract_zipped_paths` or `/tmp/pytest-of-{user}` in `pytest`. | Bump `requests>=2.33.0` and `pytest>=9.0.3` in `pyproject.toml` and `constraints.txt`; generate a hash-pinned lockfile / requirements or tightened constraints and add Dependabot. | **Fixed** (`e028ed6`) — bumped to `requests==2.34.2` & `pytest==9.2.0`; added `.github/dependabot.yml`. |
| F-12 | **Medium** | `.github/workflows/pytest.yml:1-179`, `.github/workflows/release.yml:1-71` | Third-party GitHub Actions (`actions/checkout@v4`, `actions/setup-python@v5`, `astral-sh/setup-uv@v5`) use mutable version tags rather than commit SHAs; `pytest.yml` omits a top-level `permissions:` block (defaulting to broad token scope); no `.github/dependabot.yml`. | Compromise of an upstream action tag or PR workflow could compromise CI runners or release artifacts. | Upstream tag `v4`/`v5` is force-pushed to malicious commit; CI job runs with unnecessary write permissions. | Pin all Actions to full commit SHAs (with version comments), set `permissions: contents: read` in `pytest.yml` and minimal job-level permissions in `release.yml`, and add `.github/dependabot.yml`. | **Fixed** (`99ec492`) |
| F-13 | **Low** | `agent_reach/runtime/cdp.py:105`, `browser.py:364-380`, `bridge.py:18` | `cdp.py` calls `hashlib.sha1(...)` without `usedforsecurity=False` (Bandit `B324` High). Local CDP (`127.0.0.1:9222`) and OpenCLI Bridge (`127.0.0.1:19825`) have no authentication token. | Bandit SAST alert (`B324`); any local process on the machine can query CDP or OpenCLI Bridge while the dedicated browser is active. | Local unprivileged process connects to `127.0.0.1:9222` to read cookies or open tabs. | Add `usedforsecurity=False` to the RFC 6455 WebSocket `sha1` call; document loopback CDP/Bridge exposure as an accepted local-trust-boundary risk (upstream Chrome/OpenCLI design). | **Fixed / Accepted risk** (`9063d5e`) — `usedforsecurity=False` added; loopback CDP/Bridge accepted as single-user local trust boundary. |
| F-14 | **Low** | `agent_reach/scripts/transcribe_xiaoyuzhou.sh:121, 140, 377`, `agent_reach/runtime/manage.py:959` | `transcribe_xiaoyuzhou.sh` uses `curl --location` without `--proto =https,http`, reads `config.yaml` without `encoding="utf-8"`, and writes unescaped `$TITLE` into markdown; `manage.py:959` uses `shutil.which("agent-reach") or sys.argv[0]` after self-update. | Redirect to non-HTTP protocol in `curl`; potential CWD binary hijacking on Windows if `agent-reach.exe` is in the current working directory. | Malicious redirect to `file://` or rogue `agent-reach.exe` in CWD on Windows during `update`. | Add `--proto =https,http` and `--proto-redir =https` in `transcribe_xiaoyuzhou.sh`, specify UTF-8 encoding, and resolve the installed `uv` bin path directly in `manage.py:update()`. | **Fixed** (`e08494c`) |
| F-15 | **Info** | `README.md:244`, `docs/README_en.md:244`, `llms.txt:8`, `docs/install.md:5` | `README.md` / `docs/README_en.md` embed `api.star-history.com` SVG URLs containing `sealed_token=...` (public Star History chart tokens, not private credentials). Docs also note a third-party/unrelated `agent-reach` package on PyPI. | No secret exposure (`sealed_token` is a public Star History parameter); PyPI name collision poses typosquatting risk to users who ignore `install.md`. | User runs `pip install agent-reach` instead of installing from GitHub/fork. | Keep the PyPI warning prominent; no token rotation required for Star History `sealed_token`. | **Accepted risk** (`646ff37`) — PyPI warning retained; `sealed_token` verified as public chart token. |

---

## 3. External Domains Contacted

### Runtime / Active Tool Domains
- `api.github.com` — GitHub channel API (`github.py`), OpenCLI extension release lookup (`browser.py`), update check (`update_notice.py`).
- `github.com` (and `objects.githubusercontent.com` via release/archive redirects) — `boss-agent-cli` archive install (`tools.py`), OpenCLI extension zip download (`browser.py`), self-update archive (`manage.py`).
- `nodejs.org` — Node.js LTS index, binary archive, and `SHASUMS256.txt` (`tools.py`).
- `astral.sh` — Removed from runtime (`uv` now installs via SHA256-verified PyPI wheels); referenced only as an upstream documentation link.
- `pypi.org` / `files.pythonhosted.org` (via `pip` in `tools.py`) — `cloakbrowser`, `bilibili-cli`, `imageio-ffmpeg` installs.
- `registry.npmjs.org` (via `npm` in `tools.py`) — `@jackwener/opencli` install.
- `chromewebstore.google.com` — OpenCLI Chrome extension listing on Windows fallback (`opencli.py`, `browser.py`).
- `api.groq.com` — Groq Whisper transcription (`transcribe.py`, `transcribe_xiaoyuzhou.sh`) and Llama 3.3 70B transcript polishing (`transcribe_xiaoyuzhou.sh`).
- `api.openai.com` — OpenAI Whisper transcription (`transcribe.py`).
- `mcp.exa.ai` — Exa hosted MCP web search and page fetch (`channels/web.py`).
- `r.jina.ai` — Jina Reader web page extraction (`channels/web.py`).
- `api.bilibili.com`, `www.bilibili.com`, `b23.tv` — Bilibili public API, video pages, and short-link resolution (`channels/bilibili.py`, `bili-cli`).
- `www.v2ex.com` — V2EX public JSON API (`channels/v2ex.py`).
- `qt.gtimg.cn`, `smartbox.gtimg.cn` — Tencent stock quote and search endpoints (`channels/xueqiu.py`).
- `xueqiu.com`, `stock.xueqiu.com` — Xueqiu quotes, search, and community timeline (`channels/xueqiu.py`).
- `xiaoyuzhoufm.com`, `media.xyzcdn.net` — Xiaoyuzhou episode pages and audio CDN (`transcribe_xiaoyuzhou.sh`).
- `youtube.com`, `youtu.be` (plus Google/YouTube media CDNs via `yt-dlp`) — YouTube search, metadata, subtitles, and audio (`channels/youtube.py`, `transcribe.py`).
- Platform targets driven via OpenCLI / `boss-agent-cli` in the dedicated browser: `x.com` / `twitter.com`, `reddit.com` / `redd.it`, `xiaohongshu.com` / `xhslink.com`, `linkedin.com`, `zhipin.com`, `facebook.com` / `fb.com` / `fb.watch`, `instagram.com` / `instagr.am`.
- Arbitrary user-specified public HTTP(S) URLs passed to `web read` or `transcribe`.
- Local loopback only: `127.0.0.1:9222` (or `browser_port`, Chrome CDP) and `127.0.0.1:19825` (OpenCLI Bridge).

### Documentation / Badge Domains (non-runtime)
- `trendshift.io`, `api.star-history.com`, `www.star-history.com`, `img.shields.io`, `discord.gg`, `raw.githubusercontent.com`, `agentskillshub.top`, `atomgit.com`, `get.brightdata.com`, `www.rapidproxy.io`, `www.browseract.ai`, `www.tencentcloud.com`, `docs.astral.sh`, `exa.ai`, `www.python.org`.

---

## 4. Local Data Storage

All Reach-managed data lives under `~/.agent-reach/` (honoring `$HOME`), plus AI skill links/copies:

- `~/.agent-reach/config.yaml` — Plaintext YAML storing `groq_api_key`, `openai_api_key`, `github_token`, `proxy`, `browser_port`, and `xueqiu_cookie` (`0o600` on POSIX; user ACL on Windows).
- `~/.agent-reach/state.json` — Channel registrations, `removed_defaults`, installed tool metadata/versions, check results/health, skill link/unlink records, `owned_paths` deletion ledger, and `session_reuse` state.
- `~/.agent-reach/update-check.json` — Cached latest release version and release notes from `update --check`.
- `~/.agent-reach/installation-report.md` — Setup summary markdown.
- `~/.agent-reach/browser/` — Dedicated browser directory:
  - `profile/` — CloakBrowser/Chrome profile (cookies, localStorage, cache, history).
  - `session.json` — Plaintext JSON snapshot of all cookies from the dedicated browser.
  - `state.json` — Selected browser backend, executable path, `opencli_context`, `visited_origins`, `bridge_pid`.
  - `extension/` — Unpacked OpenCLI Chrome extension.
  - `watcher.log`, `last_used`, `start.lock`, `watcher.lock`, `session.lock`.
- `~/.agent-reach/browser-locks/*.lock` — Cross-process browser slot and state mutation locks.
- `~/.agent-reach/sessions/<tool>/` — Isolated `HOME` / data directories for native CLI tools (e.g., `bili-cli/.bilibili-cli/credential.json`, `boss-agent-cli/.boss-agent/reach-job-refs.json`).
- `~/.agent-reach/tools/<name>/` and `~/.agent-reach/tools/npm-global/` — Private venvs, node runtime, uv binary, ffmpeg binary, and npm installs.
- `~/.agent-reach/cloak-binaries/` — Downloaded CloakBrowser Chromium binaries.
- `~/.agent-reach/cache/downloads/` — `pip`, `uv`, `npm`, and `XDG_CACHE_HOME` caches.
- `~/.agent-reach/transcribe-*`, `agent-reach-subs-*`, `agent-reach-xyz-*` — Ephemeral temporary working directories.
- `~/.agents/skills/agent-reach/` (`SKILL.md`, `references/*.md`) and symlinks/copies in detected AI agent skill folders (`~/.claude/skills`, `~/.cursor/skills`, `~/.gemini/skills`, etc.).

---

## 5. Dependency Vulnerability Results

### Post-Hardening Scan (`pip-audit 2.10.1` on `constraints.txt`)
- Result after commit `e028ed6`: **No known vulnerabilities found** (`requests==2.34.2`, `pytest==9.2.0`).

### Baseline Scan (Pre-Hardening)
Tool: `pip-audit 2.10.1` against `constraints.txt` (`--no-deps --disable-pip`):

| Package | Version | Vulnerability ID | Aliases | Fix Version | Notes |
|---|---|---|---|---|---|
| `requests` | `2.32.5` | `PYSEC-2026-2275` | `CVE-2026-25645`, `GHSA-gc5v-m9x4-r6x2` | `2.33.0` | Fixed in `e028ed6` (bumped to `2.34.2`). |
| `pytest` | `8.0.0` | `PYSEC-2026-1845` | `CVE-2025-71176`, `GHSA-6w46-j5rx-g56g` | `9.0.3` | Fixed in `e028ed6` (bumped to `9.2.0`). |
| `loguru` | `0.7.3` | None | — | — | Clean. |
| `PyYAML` | `6.0.3` | None | — | — | Clean. |
| `yt-dlp` | `2026.8.19` | None | — | — | Clean. |
| `yt-dlp-ejs` | `0.8.0` | None | — | — | Clean. |
| `ruff` | `0.15.1` | None | — | — | Clean. |
| `mypy` | `1.19.1` | None | — | — | Clean. |
| `types-requests` | `2.32.4.20260107` | None | — | — | Clean. |
| `types-PyYAML` | `6.0.12.20250915` | None | — | — | Clean. |

*Note:* Transitive dependencies of `requests`, `yt-dlp[default]`, and runtime-installed external tools (`@jackwener/opencli`, `cloakbrowser`, `bilibili-cli`, `boss-agent-cli`, `imageio-ffmpeg`) are not listed in `constraints.txt` and were not audited by `pip-audit`.

---

## 6. Post-Hardening Verification & Residual Risk

- **Full git-history secret scan:** `gitleaks 8.30.1` (`--log-opts="--all"`) scanned all 447 commits (~3.37 MB) and found **0 leaks**.
- **SAST (`bandit 1.9.4`):** 0 High-severity issues (down from 3); 2 Medium `B310` notices remain on `v2ex.py:52` and `web.py:189` (both validate HTTPS URLs immediately before `urlopen`).
- **Lint & type checks:** `ruff` and `mypy agent_reach` (50 source files) pass with 0 errors.
- **Test suite (`pytest -q`):** All unit tests pass except 4 pre-existing Windows symlink tests (`test_manage.py` x3, `test_unified_entry.py` x1) that require Windows Developer Mode / SeCreateSymbolicLinkPrivilege (same 4 failures observed in the pre-hardening baseline).
- **What could NOT be verified:**
  - Source code and transitive dependencies of third-party runtime tools installed out-of-band (`@jackwener/opencli`, `cloakbrowser` binary/SDK, `bilibili-cli`, `boss-agent-cli`, `imageio-ffmpeg`) were not audited.
  - `semgrep`, `trufflehog`, `osv-scanner`, and `hadolint` (no Dockerfiles in repo) were not available locally.
  - Live network / authenticated platform integration checks were not executed during this audit.
