use serde::Serialize;
use std::{
    fs,
    path::{Path, PathBuf},
    process::{Command, Stdio},
};
use walkdir::WalkDir;
use tauri::{Emitter, Manager, WebviewUrl, WebviewWindowBuilder};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::OnceLock;
use std::io::{BufRead, BufReader, Read, Write};
mod github;

static SCAN_CANCEL: AtomicBool = AtomicBool::new(false);
fn scan_cancelled() -> bool {
    SCAN_CANCEL.load(Ordering::Relaxed)
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Finding {
    id: String,
    category: String,
    critical: bool,
    title: String,
    detail: String,
    location: String,
    recommendation: String,
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Report {
    id: String,
    label: String,
    project: String,
    path: String,
    files_scanned: usize,
    findings: Vec<Finding>,
    agent_detected: bool,
    mcp_detected: bool,
    skipped_files: usize,
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ScanResult {
    source_name: String,
    source_path: String,
    source_kind: String,
    reports: Vec<Report>,
    scanned_at: String,
}
fn ignored(name: &str) -> bool {
    matches!(
        name,
        ".git" | "node_modules" | "dist" | "build" | "target" | ".venv" | "venv" | "vendor"
            | "site-dist" | "site-packages" | "__pycache__" | ".tox" | ".mypy_cache"
            | ".pytest_cache" | ".gradle"
    )
}
fn project(p: &Path) -> bool {
    [
        "package.json",
        "Cargo.toml",
        "pyproject.toml",
        "go.mod",
        ".git",
    ]
    .iter()
    .any(|n| p.join(n).exists())
}
fn roots(p: &Path) -> Vec<PathBuf> {
    if project(p) {
        return vec![p.to_owned()];
    }
    let mut found = Vec::new();
    if let Ok(entries) = fs::read_dir(p) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir()
                && !entry.file_type().map(|t| t.is_symlink()).unwrap_or(true)
                && !ignored(&entry.file_name().to_string_lossy())
            {
                found.extend(roots(&path));
            }
        }
    }
    found.sort();
    found
}
fn add(r: &mut Report, cat: &str, critical: bool, title: &str, location: String, detail: &str, fix: &str) {
    r.findings.push(Finding {
        id: format!("{}:{}", r.id, r.findings.len()),
        category: cat.into(),
        critical,
        title: title.into(),
        detail: detail.into(),
        location,
        recommendation: fix.into(),
    });
}
fn secret_patterns() -> &'static Vec<(regex::Regex, &'static str)> {
    static P: OnceLock<Vec<(regex::Regex, &'static str)>> = OnceLock::new();
    P.get_or_init(|| {
        vec![
            (regex::Regex::new(r"AKIA[0-9A-Z]{16}").unwrap(), "AWS access key"),
            (regex::Regex::new(r"ghp_[0-9A-Za-z]{36}").unwrap(), "GitHub token"),
            (regex::Regex::new(r"github_pat_[0-9A-Za-z_]{20,}").unwrap(), "GitHub token"),
            (regex::Regex::new(r"xox[baprs]-[0-9A-Za-z-]{10,}").unwrap(), "Slack token"),
            (regex::Regex::new(r"sk_live_[0-9A-Za-z]{16,}").unwrap(), "Stripe live key"),
            (regex::Regex::new(r"AIza[0-9A-Za-z_\-]{35}").unwrap(), "Google API key"),
        ]
    })
}
fn generic_secret() -> &'static regex::Regex {
    static P: OnceLock<regex::Regex> = OnceLock::new();
    P.get_or_init(|| {
        regex::Regex::new(
            r#"(?i)(password|passwd|api[_-]?key|secret|access[_-]?token|auth[_-]?token)\s*[:=]\s*["'][^"']{8,}["']"#,
        )
        .unwrap()
    })
}
fn eval_call() -> &'static regex::Regex {
    static P: OnceLock<regex::Regex> = OnceLock::new();
    // eval( not preceded by an identifier char or dot, so literal_eval / x.eval( don't match
    P.get_or_init(|| regex::Regex::new(r"(?i)(?:^|[^0-9a-z_.])eval\s*\(").unwrap())
}
fn inspect(r: &mut Report, name: &str, body: &str) {
    r.files_scanned += 1;
    let lower = name.to_lowercase();
    let agent =
        lower.ends_with("agents.md") || lower.ends_with("skill.md") || lower.ends_with("claude.md");
    let mcp = lower.contains("mcp")
        && (lower.ends_with("json") || lower.ends_with("toml") || lower.ends_with("yaml"));
    let is_pkg = lower.ends_with("package.json");
    // Prose files (docs, logs, and this tool's own reports) shouldn't run code-injection checks.
    let code = !(lower.ends_with(".md")
        || lower.ends_with(".markdown")
        || lower.ends_with(".rst")
        || lower.ends_with(".txt")
        || lower.ends_with(".log"));
    r.agent_detected |= agent;
    r.mcp_detected |= mcp;
    for (i, line) in body.lines().enumerate() {
        let loc = format!("{} · line {}", name, i + 1);
        let low = line.to_lowercase();
        // --- Secrets (all files) ---
        let trimmed = line.trim_start();
        if trimmed.starts_with("-----BEGIN PRIVATE KEY-----")
            || trimmed.starts_with("-----BEGIN RSA PRIVATE KEY-----")
            || trimmed.starts_with("-----BEGIN OPENSSH PRIVATE KEY-----")
            || trimmed.starts_with("-----BEGIN EC PRIVATE KEY-----")
        {
            add(r,"Application Security",true,"Private key material found",loc.clone(),"A private-key header was found. Secret values are omitted from the report.","Remove the key from source and rotate it if it has been shared.");
        }
        for (re, label) in secret_patterns() {
            if re.is_match(line) {
                add(r,"Application Security",true,"Live credential detected",loc.clone(),&format!("A value matching a {label} pattern was found. The value itself is omitted from the report."),"Remove the secret from source, rotate it, and load it from a secret manager or environment variable.");
                break;
            }
        }
        if generic_secret().is_match(line) {
            add(r,"Application Security",false,"Hardcoded secret assignment",loc.clone(),"A password, API key, or token appears to be assigned a literal value.","Move the value to an environment variable or secret manager; do not commit secrets.");
        }
        // --- Dangerous execution ---
        if code && (eval_call().is_match(line) || low.contains("new function(")) {
            add(r,"Application Security",false,"Dynamic code execution",loc.clone(),"Use of eval or Function can execute arbitrary code, especially with untrusted input.","Avoid eval; parse data or dispatch explicitly.");
        }
        if code
            && (low.contains("shell=true")
                || low.contains("os.system(")
                || (low.contains("child_process") && (low.contains("exec(") || low.contains("execsync"))))
        {
            add(r,"Application Security",false,"Shell command execution",loc.clone(),"A shell command is executed; if any part comes from input this allows command injection.","Avoid shell=true; pass arguments as a list and never interpolate untrusted input.");
        }
        if code && (low.contains("pickle.loads(") || (low.contains("yaml.load(") && !low.contains("safeload"))) {
            add(r,"Application Security",false,"Unsafe deserialization",loc.clone(),"Deserializing untrusted data can execute arbitrary code.","Use a safe loader (e.g. yaml.safe_load) and never deserialize untrusted input.");
        }
        // --- Insecure configuration ---
        let verify_off = (low.contains("verify=false") || low.contains("verify = false"))
            && (low.contains("request")
                || low.contains("http")
                || low.contains("session")
                || low.contains("ssl")
                || low.contains("urlopen")
                || low.contains("aiohttp")
                || low.contains("curl"));
        if code
            && (verify_off
                || low.contains("rejectunauthorized:false")
                || low.contains("rejectunauthorized: false")
                || low.contains("insecureskipverify"))
        {
            add(r,"Application Security",false,"TLS verification disabled",loc.clone(),"Certificate verification is turned off, allowing man-in-the-middle attacks.","Enable certificate verification.");
        }
        if code && low.contains("access-control-allow-origin") && line.contains('*') {
            add(r,"Application Security",false,"Wildcard CORS policy",loc.clone(),"Access-Control-Allow-Origin is set to '*', allowing any origin.","Restrict CORS to specific trusted origins.");
        }
        // --- Web sinks ---
        if code && (line.contains("dangerouslySetInnerHTML") || low.contains(".innerhtml =") || low.contains(".innerhtml=") || low.contains("document.write(")) {
            add(r,"Application Security",false,"Unsafe HTML sink",loc.clone(),"Writing raw HTML can introduce cross-site scripting (XSS).","Sanitize input or use safe rendering APIs.");
        }
        // --- Dependencies ---
        if lower.ends_with(".npmrc") && line.contains("http://") {
            add(r,"Dependencies",false,"Registry uses unencrypted HTTP",loc.clone(),"Package registry traffic can be modified in transit.","Use an HTTPS registry endpoint.");
        }
        if is_pkg && (line.contains("git+http://") || line.contains("\"http://")) {
            add(r,"Dependencies",false,"Dependency fetched over HTTP",loc.clone(),"A dependency is referenced over an unencrypted or raw git URL.","Reference dependencies over HTTPS or a trusted registry version.");
        }
        // --- Agent Security ---
        if agent {
            if ["ignore previous instructions","ignore all previous","disregard the above","forget your instructions","forget previous instructions"].iter().any(|p| low.contains(p)) {
                add(r,"Agent Security",false,"Instruction override text requires review",loc.clone(),"Agent instructions contain an override phrase; context must be reviewed to determine whether this is an example or an active instruction.","Keep untrusted content separate from controlling instructions.");
            }
            if ["--dangerously-skip-permissions","--yolo","auto-approve","without asking","no confirmation","skip permission"].iter().any(|p| low.contains(p)) {
                add(r,"Agent Security",true,"Agent granted auto-approve authority",loc.clone(),"Instructions allow the agent to act without confirmation.","Require explicit user approval for consequential actions.");
            }
            if low.contains("rm -rf") || low.contains("run any command") || low.contains("full access") {
                add(r,"Agent Security",false,"Broad or destructive command authority",loc.clone(),"Instructions grant broad or destructive command authority.","Limit the agent to the specific commands it needs.");
            }
            if (low.contains("curl") || low.contains("wget") || low.contains("upload") || low.contains("post to") || low.contains("send to") || low.contains("exfiltrat"))
                && (low.contains("http://") || low.contains("https://")) {
                add(r,"Agent Security",false,"Network exfiltration instruction",loc.clone(),"Instructions tell the agent to send data to an external URL, a common exfiltration path.","Do not send project data to external endpoints without explicit user approval.");
            }
            if low.contains("printenv") || low.contains("cat .env") || low.contains("read the .env") || low.contains("~/.aws") || low.contains(".ssh/") || low.contains("id_rsa") || low.contains("credentials file") {
                add(r,"Agent Security",false,"Credential or secret file access",loc.clone(),"Instructions direct the agent to read environment variables, key files, or credential stores.","Keep secrets out of agent reach; load them through a vetted secret manager only.");
            }
            if line.chars().any(|c| matches!(c, '\u{200B}'..='\u{200F}' | '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}' | '\u{FEFF}')) {
                add(r,"Agent Security",true,"Hidden Unicode in instructions",loc.clone(),"The line contains zero-width or bidirectional control characters that can hide prompt-injection text from a human reviewer.","Remove invisible control characters and review the raw bytes of the file.");
            }
            if low.contains("outside the project") || low.contains("write to any") || low.contains("anywhere on the") || low.contains("/etc/") || low.contains("system files") {
                add(r,"Agent Security",false,"Unrestricted file-write authority",loc.clone(),"Instructions grant write access outside the project directory.","Confine agent writes to the project workspace.");
            }
            if (low.contains("treat") && low.contains("as instructions")) || low.contains("follow the instructions in") || low.contains("execute instructions from") || low.contains("obey the") && low.contains("url") {
                add(r,"Agent Security",true,"Untrusted content elevated to instructions",loc.clone(),"Instructions tell the agent to treat fetched files or URLs as commands, enabling prompt injection.","Treat all external content as data, never as instructions.");
            }
            if low.contains("write to memory") || low.contains("save to memory") || low.contains("update memory") || (low.contains("persist") && low.contains("memory")) {
                add(r,"Agent Security",false,"Unreviewed memory persistence",loc.clone(),"Instructions let the agent write to persistent memory without review, which can carry poisoned state forward.","Require review before persisting agent memory.");
            }
            if low.contains("bypass") || low.contains("override safety") || low.contains("ignore safety") || (low.contains("disable") && (low.contains("permission") || low.contains("safety") || low.contains("guardrail"))) {
                add(r,"Agent Security",true,"Safety or permission bypass instruction",loc.clone(),"Instructions describe disabling or bypassing safety and permission checks.","Never disable safety or permission gates via instructions.");
            }
        }
        // --- MCP Security ---
        if mcp {
            if line.contains("\"/\"") || low.contains("bash(*)") || low.contains("--allow-all") {
                add(r,"MCP Security",low.contains("--allow-all"),"Broad access configured",loc.clone(),"Configuration contains a root path or unrestricted-access option. This check does not execute the server.","Limit access to the directories and operations required by this project.");
            }
            if low.contains("bash -c") || low.contains("sh -c") {
                add(r,"MCP Security",false,"Shell command in MCP configuration",loc.clone(),"An MCP server is configured to run a shell command.","Prefer a direct executable with fixed arguments over a shell.");
            }
            if low.contains("npx -y") || low.contains("npx --yes") || low.contains("@latest") || low.contains(":latest") || low.contains("\"latest\"") {
                add(r,"MCP Security",false,"Unpinned server version",loc.clone(),"The server is launched from an unpinned or auto-installed package, so its code can change without review.","Pin the server to an exact version and verify it with a lockfile or hash.");
            }
            if (low.contains("curl") && (low.contains("| sh") || low.contains("|sh") || low.contains("| bash"))) || ((low.contains("node") || low.contains("python") || low.contains("wget")) && (low.contains("http://") || low.contains("https://"))) {
                add(r,"MCP Security",true,"Remote code fetched at launch",loc.clone(),"The command downloads and runs code from a remote URL when the server starts.","Install and pin the server locally; never pipe a remote script into an interpreter.");
            }
            if (low.contains("token") || low.contains("api_key") || low.contains("apikey") || low.contains("secret") || low.contains("password")) && line.contains(':') && line.contains('"') {
                add(r,"MCP Security",true,"Embedded secret in configuration",loc.clone(),"A token, key, or password appears to be set directly in the MCP config. The value is omitted from the report.","Reference secrets from environment variables or a secret manager, not the config file.");
            }
            if low.contains("0.0.0.0") || low.contains("allow-net") && line.contains('*') || low.contains("\"**\"") || low.contains("*:*") {
                add(r,"MCP Security",false,"Overly broad network or path scope",loc.clone(),"The configuration grants an unrestricted network or filesystem scope.","Restrict the server to the specific hosts and directories it needs.");
            }
            if (low.contains("git+http") || low.contains("http://") || low.contains("https://")) && (low.contains("command") || low.contains("args") || low.contains("url") || low.contains("github.com")) {
                add(r,"MCP Security",false,"Server sourced from a remote URL",loc.clone(),"The server is fetched from an arbitrary remote or git URL rather than a vetted, pinned source.","Use a trusted, version-pinned package for the server.");
            }
            if low.contains("\"write\"") || low.contains("\"delete\"") || low.contains("\"execute\"") || low.contains("write_file") || low.contains("\"all\"") {
                add(r,"MCP Security",false,"Writable or destructive tool capability",loc.clone(),"The server exposes write, delete, or execute capability without an explicit approval gate.","Gate destructive tools behind explicit user confirmation.");
            }
        }
    }
    if agent {
        let text = body.to_lowercase();
        if !["approval", "permission", "confirm"].iter().any(|x| text.contains(x)) {
            add(r,"Agent Security",false,"Approval instructions not detected",name.into(),"The instruction file has no recognized approval wording. This is a heuristic, not proof of unrestricted permissions.","Document which actions require explicit user approval.");
        }
        if !["stuck","loop","escalate","ask for help","cannot proceed","retry","time limit","give up"].iter().any(|x| text.contains(x)) {
            add(r,"Agent Security",false,"No stuck or looping guidance detected",name.into(),"The file has no recognized guidance for what to do when stuck, looping, or on a long-running task.","Describe when and how the agent should stop, escalate, or ask for help.");
        }
    }
    if mcp {
        let text = body.to_lowercase();
        if !["allowedtools","allowed_tools","allowlist","allow-list","permission","\"tools\""].iter().any(|x| text.contains(x)) {
            add(r,"MCP Security",false,"No tool allowlist configured",name.into(),"The configuration has no recognized tool allowlist, so every tool the server offers is enabled by default.","Declare an explicit allowlist limiting the server to the tools this project needs.");
        }
    }
}
fn finish(r: &mut Report, names: &[String]) {
    let node = names.iter().any(|s| s == "package.json");
    let lock = names.iter().any(|s| {
        [
            "package-lock.json",
            "pnpm-lock.yaml",
            "yarn.lock",
            "bun.lock",
            "bun.lockb",
            "npm-shrinkwrap.json",
        ]
        .contains(&s.as_str())
    });
    if node && !lock {
        add(r,"Dependencies",false,"Dependency lockfile not found","project root".into(),"This Node project has no recognized lockfile. Published libraries may intentionally leave version resolution to consumers.","For applications, commit the lockfile generated by your package manager.");
    }
}
fn locate(name: &str) -> PathBuf {
    for dir in [
        "/opt/homebrew/bin",
        "/usr/local/bin",
        "/usr/bin",
        "/opt/homebrew/opt/osv-scanner/bin",
    ] {
        let p = Path::new(dir).join(name);
        if p.is_file() {
            return p;
        }
    }
    name.into()
}
fn tool_available(exe: &Path) -> bool {
    Command::new(exe)
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}
fn run_capture(mut cmd: Command, timeout: u64) -> Option<Vec<u8>> {
    let mut child = cmd.stdout(Stdio::piped()).stderr(Stdio::null()).spawn().ok()?;
    let mut out = child.stdout.take().unwrap();
    let reader = std::thread::spawn(move || {
        use std::io::Read;
        let mut b = Vec::new();
        let _ = out.read_to_end(&mut b);
        b
    });
    let start = std::time::Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) => {}
            Err(_) => return None,
        }
        if scan_cancelled() || start.elapsed() > std::time::Duration::from_secs(timeout) {
            let _ = child.kill();
            let _ = child.wait();
            return None;
        }
        std::thread::sleep(std::time::Duration::from_millis(120));
    }
    reader.join().ok()
}
fn run_semgrep(r: &mut Report, path: &Path) {
    let exe = locate("semgrep");
    if !tool_available(&exe) {
        return;
    }
    let mut cmd = Command::new(&exe);
    cmd.args(["scan", "--json", "--quiet", "--config", "auto"])
        .arg(path);
    let Some(out) = run_capture(cmd, 300) else {
        return;
    };
    let Ok(v) = serde_json::from_slice::<serde_json::Value>(&out) else {
        return;
    };
    if let Some(results) = v["results"].as_array() {
        for res in results {
            let sev = res["extra"]["severity"].as_str().unwrap_or("");
            let critical = sev.eq_ignore_ascii_case("ERROR");
            let msg = res["extra"]["message"]
                .as_str()
                .unwrap_or("Semgrep static-analysis finding");
            let check = res["check_id"].as_str().unwrap_or("Semgrep finding");
            let file = res["path"].as_str().unwrap_or("");
            let line = res["start"]["line"].as_i64().unwrap_or(0);
            let rel = Path::new(file)
                .strip_prefix(path)
                .map(|p| p.to_string_lossy().into_owned())
                .unwrap_or_else(|_| file.to_string());
            add(
                r,
                "Application Security",
                critical,
                check,
                format!("{} · line {}", rel, line),
                msg,
                "Review and fix per the Semgrep rule guidance.",
            );
        }
    }
}
fn run_osv(r: &mut Report, path: &Path) {
    let exe = locate("osv-scanner");
    if !tool_available(&exe) {
        return;
    }
    let mut cmd = Command::new(&exe);
    cmd.args(["--format", "json", "-r"]).arg(path);
    let Some(out) = run_capture(cmd, 300) else {
        return;
    };
    let Ok(v) = serde_json::from_slice::<serde_json::Value>(&out) else {
        return;
    };
    let Some(results) = v["results"].as_array() else {
        return;
    };
    for result in results {
        let Some(packages) = result["packages"].as_array() else {
            continue;
        };
        for pkg in packages {
            let name = pkg["package"]["name"].as_str().unwrap_or("dependency");
            let version = pkg["package"]["version"].as_str().unwrap_or("");
            let Some(vulns) = pkg["vulnerabilities"].as_array() else {
                continue;
            };
            for vuln in vulns {
                let id = vuln["id"].as_str().unwrap_or("advisory");
                let summary = vuln["summary"]
                    .as_str()
                    .or_else(|| vuln["details"].as_str())
                    .unwrap_or("Known vulnerability in this dependency version.");
                let severity = vuln["database_specific"]["severity"]
                    .as_str()
                    .unwrap_or("");
                let critical =
                    severity.eq_ignore_ascii_case("CRITICAL") || severity.eq_ignore_ascii_case("HIGH");
                add(
                    r,
                    "Dependencies",
                    critical,
                    &format!("{id} — {name} {version}"),
                    format!("{name}@{version}"),
                    summary,
                    "Upgrade to a fixed version listed in the advisory.",
                );
            }
        }
    }
}
fn base(p: &Path, label: String) -> Report {
    Report {
        id: p.display().to_string() + ":" + &label,
        label,
        project: p.file_name().unwrap_or_default().to_string_lossy().into(),
        path: p.display().to_string(),
        files_scanned: 0,
        findings: vec![],
        agent_detected: false,
        mcp_detected: false,
        skipped_files: 0,
    }
}
fn scan_folder(p: &Path) -> Result<Report, String> {
    let mut r = base(
        p,
        p.file_name().unwrap_or_default().to_string_lossy().into(),
    );
    let mut names = vec![];
    for e in WalkDir::new(p)
        .follow_links(false)
        .into_iter()
        .filter_entry(|e| !ignored(&e.file_name().to_string_lossy()))
    {
        if scan_cancelled() {
            return Err("Scan cancelled.".into());
        }
        if let Ok(e) = e {
            if e.file_type().is_file() {
                let name = e
                    .path()
                    .strip_prefix(p)
                    .unwrap()
                    .to_string_lossy()
                    .replace('\\', "/");
                names.push(name.clone());
                if e.metadata().map(|m| m.len() <= 2_000_000).unwrap_or(false) {
                    match fs::read_to_string(e.path()) {
                        Ok(body) if !body.contains('\0') => inspect(&mut r, &name, &body),
                        _ => r.skipped_files += 1,
                    }
                } else {
                    r.skipped_files += 1;
                }
            }
        }
    }
    run_semgrep(&mut r, p);
    run_osv(&mut r, p);
    finish(&mut r, &names);
    Ok(r)
}
fn git(p: &Path, args: &[&str]) -> Result<Vec<u8>, String> {
    let output = Command::new("git")
        .arg("-C")
        .arg(p)
        .args(args)
        .output()
        .map_err(|e| e.to_string())?;
    if !output.status.success() {
        return Err("Git could not read the selected repository.".into());
    }
    Ok(output.stdout)
}
fn scan_repository(p: &Path) -> Result<Vec<Report>, String> {
    let refs = git(p, &["for-each-ref", "--format=%(refname)", "refs/heads"])?;
    let mut reports = vec![];
    for reference in String::from_utf8_lossy(&refs).lines() {
        if scan_cancelled() {
            return Err("Scan cancelled.".into());
        }
        let branch = reference.trim_start_matches("refs/heads/");
        let mut r = base(
            p,
            format!(
                "{} / {}",
                p.file_name().unwrap_or_default().to_string_lossy(),
                branch
            ),
        );
        // `-l` includes the blob size, so we avoid a `cat-file -s` per file.
        let tree = git(p, &["ls-tree", "-r", "-l", "-z", reference])?;
        let mut names = vec![];
        let mut blobs: Vec<(String, String)> = vec![]; // (oid, name)
        for item in tree.split(|b| *b == 0) {
            let entry = String::from_utf8_lossy(item);
            if let Some((meta, name)) = entry.split_once('\t') {
                if !meta.starts_with("100") || name.split('/').any(ignored) {
                    continue;
                }
                let mut fields = meta.split_whitespace();
                let oid = fields.nth(2).unwrap_or("").to_string();
                let size = fields.next().and_then(|s| s.parse::<usize>().ok()).unwrap_or(usize::MAX);
                names.push(name.to_string());
                if size > 2_000_000 {
                    r.skipped_files += 1;
                    continue;
                }
                blobs.push((oid, name.to_string()));
            }
        }
        // Read every blob for this branch from a single `git cat-file --batch` process.
        if !blobs.is_empty() {
            let mut child = Command::new("git")
                .arg("-C")
                .arg(p)
                .args(["cat-file", "--batch"])
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::null())
                .spawn()
                .map_err(|e| e.to_string())?;
            let mut stdin = child.stdin.take().unwrap();
            let oids: Vec<String> = blobs.iter().map(|(oid, _)| oid.clone()).collect();
            let writer = std::thread::spawn(move || {
                for oid in oids {
                    if writeln!(stdin, "{}", oid).is_err() {
                        break;
                    }
                }
            });
            let mut reader = BufReader::new(child.stdout.take().unwrap());
            for (_, name) in &blobs {
                if scan_cancelled() {
                    let _ = child.kill();
                    let _ = child.wait();
                    let _ = writer.join();
                    return Err("Scan cancelled.".into());
                }
                let mut header = String::new();
                if reader.read_line(&mut header).map_err(|e| e.to_string())? == 0 {
                    break;
                }
                let fields: Vec<&str> = header.split_whitespace().collect();
                // header is "<oid> <type> <size>" or "<oid> missing"
                if fields.len() < 3 {
                    continue;
                }
                let size: usize = fields[2].parse().unwrap_or(0);
                let mut buf = vec![0u8; size];
                reader.read_exact(&mut buf).map_err(|e| e.to_string())?;
                let mut newline = [0u8; 1];
                let _ = reader.read_exact(&mut newline);
                if let Ok(body) = String::from_utf8(buf) {
                    if !body.contains('\0') {
                        inspect(&mut r, name, &body);
                    }
                }
            }
            drop(reader);
            let _ = writer.join();
            let _ = child.wait();
        }
        finish(&mut r, &names);
        reports.push(r);
    }
    if reports.is_empty() {
        return Err("No committed local branches found.".into());
    }
    Ok(reports)
}
#[tauri::command]
async fn scan_path(path: String, mode: String) -> Result<ScanResult, String> {
    SCAN_CANCEL.store(false, Ordering::Relaxed);
    tauri::async_runtime::spawn_blocking(move || {
        let p = fs::canonicalize(path).map_err(|e| e.to_string())?;
        if !p.is_dir() {
            return Err("Select a directory.".into());
        }
        let reports = if mode == "repository" {
            scan_repository(&p)?
        } else {
            let mut projects = roots(&p);
            if projects.is_empty() {
                projects.push(p.clone())
            }
            projects
                .iter()
                .map(|p| scan_folder(p))
                .collect::<Result<Vec<_>, _>>()?
        };
        Ok(ScanResult {
            source_name: p.file_name().unwrap_or_default().to_string_lossy().into(),
            source_path: p.display().to_string(),
            source_kind: mode,
            reports,
            scanned_at: chrono::Local::now().format("%Y-%m-%d %H:%M").to_string(),
        })
    })
    .await
    .map_err(|e| e.to_string())?
}
#[tauri::command]
fn open_github() -> Result<(), String> {
    #[cfg(target_os = "macos")]
    let mut cmd = Command::new("open");
    #[cfg(target_os = "windows")]
    let mut cmd = {
        let mut c = Command::new("rundll32");
        c.arg("url.dll,FileProtocolHandler");
        c
    };
    #[cfg(target_os = "linux")]
    let mut cmd = Command::new("xdg-open");
    cmd.arg("https://github.com/")
        .spawn()
        .map_err(|e| format!("Could not open GitHub: {e}"))?;
    Ok(())
}

fn public_repository_url(url: &tauri::Url) -> Option<String> {
    if url.scheme() != "https" || url.host_str() != Some("github.com") {
        return None;
    }
    let parts: Vec<_> = url.path_segments()?.filter(|part| !part.is_empty()).collect();
    if parts.len() != 2 {
        return None;
    }
    let reserved = [
        "about", "apps", "collections", "contact", "customer-stories", "enterprise",
        "events", "explore", "features", "issues", "login", "marketplace", "new",
        "notifications", "orgs", "pricing", "pulls", "search", "security", "settings",
        "signup", "sponsors", "topics", "trending",
    ];
    if reserved.contains(&parts[0].to_ascii_lowercase().as_str()) {
        return None;
    }
    Some(format!("https://github.com/{}/{}", parts[0], parts[1].trim_end_matches(".git")))
}

#[tauri::command]
fn browse_public_github(app: tauri::AppHandle) -> Result<(), String> {
    if let Some(existing) = app.get_webview_window("github-public-browser") {
        existing.show().map_err(|error| error.to_string())?;
        existing.set_focus().map_err(|error| error.to_string())?;
        return Ok(());
    }
    let navigation_app = app.clone();
    let start = "https://github.com/search"
        .parse()
        .map_err(|error| format!("Could not open GitHub: {error}"))?;
    WebviewWindowBuilder::new(&app, "github-public-browser", WebviewUrl::External(start))
        .title("Choose a GitHub Repository")
        .inner_size(900.0, 650.0)
        .center()
        .on_navigation(move |url| {
            if let Some(repository) = public_repository_url(url) {
                let _ = navigation_app.emit_to("main", "github-repository-selected", repository);
                if let Some(window) = navigation_app.get_webview_window("github-public-browser") {
                    let _ = window.close();
                }
                false
            } else {
                url.scheme() == "https" && url.host_str() == Some("github.com")
            }
        })
        .build()
        .map_err(|error| format!("Could not open GitHub: {error}"))?;
    Ok(())
}
fn github_address(value: &str) -> Result<(String, String), String> {
    let value = value.trim().trim_end_matches('/');
    let rest = value
        .strip_prefix("https://github.com/")
        .ok_or("Enter https://github.com/owner/repository")?;
    let parts: Vec<_> = rest.split('/').collect();
    if parts.len() != 2
        || parts.iter().any(|s| {
            s.is_empty()
                || s.starts_with('.')
                || !s
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
        })
    {
        return Err("Enter a GitHub repository URL, without a branch path or query.".into());
    }
    let name = parts[1].trim_end_matches(".git");
    if name.is_empty() {
        return Err("Repository name is required.".into());
    }
    Ok((
        format!("https://github.com/{}/{}.git", parts[0], name),
        name.into(),
    ))
}
#[tauri::command]
async fn scan_github(url: String) -> Result<ScanResult, String> {
    let (address, name) = github_address(&url)?;
    SCAN_CANCEL.store(false, Ordering::Relaxed);
    tauri::async_runtime::spawn_blocking(move||{
        let temp=tempfile::Builder::new().prefix("agentscan-").tempdir().map_err(|e|e.to_string())?;
        let dest=temp.path().join(&name);
        let mut command=Command::new("git");
        command.env("GIT_TERMINAL_PROMPT","0").args(["-c","credential.interactive=false"]);
        let gh=github::executable();
        if Command::new(&gh).arg("--version").stdout(std::process::Stdio::null()).stderr(std::process::Stdio::null()).status().is_ok(){
            let helper=format!("credential.https://github.com.helper=!\"{}\" auth git-credential",gh.to_string_lossy().replace('\\',"/"));
            command.args(["-c","credential.helper=","-c",&helper]);
        }
        let mut child=command.args(["clone","--bare","--quiet","--"]).arg(&address).arg(&dest).stdout(std::process::Stdio::null()).stderr(std::process::Stdio::null()).spawn().map_err(|e|format!("Git is required to download repositories: {e}"))?;
        let started=std::time::Instant::now();
        loop {if let Some(status)=child.try_wait().map_err(|e|e.to_string())?{if !status.success(){return Err("Could not download repository. Check the URL and network connection. Private repositories require Git credentials configured on this computer.".into());}break;}
            if scan_cancelled(){let _=child.kill();let _=child.wait();return Err("Scan cancelled.".into());}
            if started.elapsed()>std::time::Duration::from_secs(180){let _=child.kill();let _=child.wait();return Err("Repository download exceeded three minutes. Check your connection or try a smaller repository.".into());}
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
        let mut reports=scan_repository(&dest)?;
        for report in &mut reports {report.path=url.clone();report.id=format!("{}:{}",url,report.label);}
        Ok(ScanResult{source_name:name,source_path:url,source_kind:"repository".into(),reports,scanned_at:chrono::Local::now().format("%Y-%m-%d %H:%M").to_string()})
    }).await.map_err(|e|e.to_string())?
}
#[tauri::command]
fn scan_cancel() {
    SCAN_CANCEL.store(true, Ordering::Relaxed);
}
#[tauri::command]
fn write_report(path: String, content: String) -> Result<(), String> {
    if !path.to_lowercase().ends_with(".md") {
        return Err("Choose a .md file.".into());
    }
    fs::write(path, content).map_err(|e| e.to_string())
}
pub fn run() {
    tauri::Builder::default()
        .manage(github::AuthJob::default())
        .plugin(tauri_plugin_dialog::init())
        .invoke_handler(tauri::generate_handler![
            github::github_session,
            github::github_repositories,
            github::github_public_search,
            github::github_auth_start,
            github::github_auth_progress,
            github::github_auth_cancel,
            scan_path,
            scan_github,
            scan_cancel,
            open_github,
            browse_public_github,
            write_report
        ])
        .run(tauri::generate_context!())
        .expect("AgentScan could not start");
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn github_urls_are_validated() {
        assert_eq!(
            github_address("https://github.com/octocat/Hello-World")
                .unwrap()
                .0,
            "https://github.com/octocat/Hello-World.git"
        );
        for bad in [
            "/tmp/project",
            "https://github.com.evil.test/a/b",
            "https://github.com/a/b/tree/main",
            "https://github.com/a/..",
            "https://github.com/a/b?token=secret",
            "file:///tmp/repo",
        ] {
            assert!(github_address(bad).is_err(), "accepted {bad}");
        }
    }
    #[test]
    #[ignore = "uses GitHub network"]
    fn github_download_and_branch_scan() {
        let result = tauri::async_runtime::block_on(scan_github(
            "https://github.com/octocat/Hello-World".into(),
        ))
        .unwrap();
        assert_eq!(result.source_kind, "repository");
        assert!(!result.reports.is_empty());
        assert!(result.reports.iter().any(|r| r.files_scanned > 0));
        assert!(result
            .reports
            .iter()
            .all(|r| r.path == "https://github.com/octocat/Hello-World"));
    }
    #[test]
    fn detects_private_key_without_exposing_value() {
        let mut r = base(Path::new("sample"), "sample".into());
        inspect(
            &mut r,
            "key.pem",
            "-----BEGIN PRIVATE KEY-----\nsecret-value",
        );
        assert_eq!(r.findings.len(), 1);
        assert!(!serde_json::to_string(&r).unwrap().contains("secret-value"));
    }
    #[test]
    fn ordinary_source_is_not_agent_policy() {
        let mut r = base(Path::new("sample"), "sample".into());
        inspect(&mut r, "app.ts", "const x=1;");
        assert!(r.findings.is_empty());
    }
    #[test]
    fn lockfile_check_respects_existing_lock() {
        let mut r = base(Path::new("sample"), "sample".into());
        finish(&mut r, &["package.json".into(), "pnpm-lock.yaml".into()]);
        assert!(r.findings.is_empty());
        finish(&mut r, &["package.json".into()]);
        assert_eq!(r.findings.len(), 1);
    }
    #[test]
    fn branches_scan_distinct_commits_without_checkout() {
        let dir = std::env::temp_dir().join(format!("agentscan-test-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        git(&dir, &["init", "-b", "main"]).unwrap();
        fs::write(dir.join("app.txt"), "ordinary content").unwrap();
        git(&dir, &["add", "app.txt"]).unwrap();
        git(
            &dir,
            &[
                "-c",
                "user.name=Test",
                "-c",
                "user.email=test@example.invalid",
                "commit",
                "-m",
                "initial",
            ],
        )
        .unwrap();
        git(&dir, &["checkout", "-b", "test-branch"]).unwrap();
        fs::write(dir.join("key.pem"), "-----BEGIN PRIVATE KEY-----").unwrap();
        git(&dir, &["add", "key.pem"]).unwrap();
        git(
            &dir,
            &[
                "-c",
                "user.name=Test",
                "-c",
                "user.email=test@example.invalid",
                "commit",
                "-m",
                "fixture",
            ],
        )
        .unwrap();
        let before = git(&dir, &["rev-parse", "HEAD"]).unwrap();
        let reports = scan_repository(&dir).unwrap();
        assert_eq!(reports.len(), 2);
        assert!(reports
            .iter()
            .find(|r| r.label.ends_with(" / main"))
            .unwrap()
            .findings
            .is_empty());
        assert_eq!(
            reports
                .iter()
                .find(|r| r.label.ends_with(" / test-branch"))
                .unwrap()
                .findings
                .len(),
            1
        );
        assert_eq!(before, git(&dir, &["rev-parse", "HEAD"]).unwrap());
        fs::remove_dir_all(&dir).unwrap();
    }
}
