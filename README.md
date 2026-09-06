# AgentScan

Point it at code, get the risks back. Your source never leaves the machine.

Website: [https://hgus107.github.io/YoFile/suite.html?app=agentscan](https://hgus107.github.io/YoFile/suite.html?app=agentscan)

Current release: **v0.1.0**

## Why this exists

Most security scanners are a service: you hand your source to a website or a cloud pipeline and trust it to delete the copy afterwards. For a private repo, an agent's instruction file, or an MCP config holding a token, that is the wrong default. The analysis is a local operation — the code, the pattern rules, and the advisory database can all sit on your own disk.

AgentScan runs on your computer. It reads the code you point it at, checks it for security issues, and shows the findings grouped by area. Nothing is uploaded, no MCP servers are started, and no project files leave the machine. The one exception is dependency vulnerability lookups, which match your dependency list against the public OSV database.

## What it scans

Findings are grouped into four categories.

**Application Security**
1. Private key material — a real PEM header line — *critical*
2. Live credential — AWS, GitHub, Slack, Stripe, and Google key/token formats — *critical*
3. Hardcoded secret assignment — `password` / `api_key` / `secret` / `token` set to a literal
4. Dynamic code execution — `eval(` / `new Function(`
5. Shell command execution — `shell=true`, `os.system(`, `child_process` exec
6. Unsafe deserialization — `pickle.loads`, `yaml.load` without a safe loader
7. TLS verification disabled — `verify=False` in an HTTP/SSL context, `rejectUnauthorized:false`, `InsecureSkipVerify`
8. Wildcard CORS — `Access-Control-Allow-Origin: *`
9. Unsafe HTML sink — `dangerouslySetInnerHTML`, `.innerHTML =`, `document.write(`
10. Semgrep static analysis — the full rule engine when Semgrep is installed; error-severity rules are marked *critical*

**Dependencies**
1. Missing lockfile — a Node `package.json` with no lockfile committed
2. Registry over HTTP — an `http://` registry in `.npmrc`
3. Dependency over HTTP or raw git URL — in `package.json`
4. Known vulnerabilities — OSV-Scanner matches your dependencies against the OSV advisory database and reports CVEs; high and critical severities are marked *critical*

**Agent Security** (`AGENTS.md`, `CLAUDE.md`, `SKILL.md`)
1. Instruction-override text — "ignore previous instructions" and similar
2. Auto-approve authority — `--dangerously-skip-permissions`, `--yolo`, "auto-approve", "without asking", "no confirmation", "skip permission" — *critical*
3. Broad or destructive command authority — `rm -rf`, "run any command", "full access"
4. Network exfiltration instruction — `curl` / `wget` / "upload" / "post to" / "send to" / "exfiltrate" pointed at an `http(s)` URL
5. Credential or secret file access — `printenv`, `cat .env`, `~/.aws`, `.ssh/`, `id_rsa`, "credentials file"
6. Hidden Unicode in instructions — zero-width or bidirectional control characters that can hide injected text — *critical*
7. Unrestricted file-write authority — "outside the project", "write to any", "anywhere on the", `/etc/`, "system files"
8. Untrusted content elevated to instructions — "treat … as instructions", "follow the instructions in", "execute instructions from" — *critical*
9. Unreviewed memory persistence — "write to memory", "save to memory", "update memory", "persist … memory"
10. Safety or permission bypass instruction — "bypass", "override safety", "ignore safety", "disable" a permission/safety/guardrail — *critical*
11. Approval instructions not detected
12. No stuck or looping guidance detected

**MCP Security** (`mcp*.json` / `.toml` / `.yaml`)
1. Broad access — a root path `"/"`, `Bash(*)`, or `--allow-all` (`--allow-all` is *critical*)
2. Shell command in the configuration — `bash -c`, `sh -c`
3. Unpinned server version — `npx -y` / `npx --yes`, `@latest` / `:latest` / `"latest"`
4. Remote code fetched at launch — `curl … | sh`/`| bash`, or `node` / `python` / `wget` run against an `http(s)` URL — *critical*
5. Embedded secret in configuration — a `token` / `api_key` / `secret` / `password` set to a literal in the config — *critical*
6. Overly broad network or path scope — `0.0.0.0`, `"**"`, `*:*`, or an `allow-net` wildcard
7. Server sourced from a remote URL — `git+http`, `http(s)` in a `command` / `args` / `url` / `github.com` field
8. Writable or destructive tool capability — `"write"`, `"delete"`, `"execute"`, `write_file`, or `"all"`
9. No tool allowlist configured — no recognized `allowedTools` / `allowlist` / `permission` / `tools` declaration

## Optional tools

The built-in checks are pattern-based and run with no dependencies. Two external tools, when installed, add deeper analysis in folder scans:

- **Semgrep** — real static analysis (data-flow, OWASP/CWE rules) rather than keyword matching.
- **OSV-Scanner** — known-vulnerability lookups against the OSV database.

```bash
brew install semgrep osv-scanner
```

If neither is installed, AgentScan falls back to the pattern checks alone.

## Honest limits

- Pattern checks are heuristics: they can miss real issues and flag benign code. No findings does not mean secure.
- Semgrep and OSV run in **folder** scans (files on disk). Repository scans read a bare clone with no working tree, so those two tools do not run there yet.
- Files over 2 MB, binary files, symlinks, and generated directories (`node_modules`, `venv`, `site-packages`, `target`, caches, and similar) are skipped.
- AI-assisted and dynamic (running-app) vulnerability discovery are not implemented.

## Development

```bash
npm install
npm run tauri dev
```

## Distribution

- `npm run package:mac` builds a macOS `.app` and `.dmg`.
- Local development packages use compatible ad-hoc signing. A public release requires `AGENTSCAN_SIGNING_IDENTITY` plus `AGENTSCAN_NOTARY_PROFILE`; the packaging script then enables the hardened runtime, notarizes, and staples the ticket.
- Windows and Linux packages are not currently built or verified by this repository.

## Credits

The GitHub mark in `public/github.svg` is from Simple Icons 13.0.0 (CC0); GitHub trademarks belong to their owners.

## License

MIT.
