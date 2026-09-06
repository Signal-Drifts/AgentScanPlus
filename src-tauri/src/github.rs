use serde::{Deserialize, Serialize};
use std::{
    io::{BufRead, BufReader, Write},
    path::PathBuf,
    process::{Command, Stdio},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    time::{Duration, Instant},
};

pub fn executable() -> PathBuf {
    for path in ["/opt/homebrew/bin/gh", "/usr/local/bin/gh", "/usr/bin/gh"] {
        if std::path::Path::new(path).is_file() {
            return path.into();
        }
    }
    "gh".into()
}
fn output(args: &[&str]) -> Result<std::process::Output, String> {
    let mut child = Command::new(executable())
        .args(args)
        .env("GH_PROMPT_DISABLED", "1")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|_| "Install GitHub CLI (gh), then reopen the picker.".to_string())?;
    let pipe = child.stdout.take().unwrap();
    let reader = std::thread::spawn(move || {
        use std::io::Read;
        let mut data = Vec::new();
        let _ = BufReader::new(pipe).take(16_000_000).read_to_end(&mut data);
        data
    });
    let start = Instant::now();
    loop {
        if let Some(status) = child.try_wait().map_err(|e| e.to_string())? {
            return Ok(std::process::Output {
                status,
                stdout: reader.join().unwrap_or_default(),
                stderr: vec![],
            });
        }
        if start.elapsed() > Duration::from_secs(45) {
            let _ = child.kill();
            let _ = child.wait();
            return Err(
                "GitHub did not respond within 45 seconds. Check your connection and retry.".into(),
            );
        }
        std::thread::sleep(Duration::from_millis(80));
    }
}
#[derive(Serialize)]
pub struct Session {
    available: bool,
    connected: bool,
    login: String,
}
#[tauri::command]
pub async fn github_session() -> Result<Session, String> {
    tauri::async_runtime::spawn_blocking(|| {
        if Command::new(executable())
            .arg("--version")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .is_err()
        {
            return Ok(Session {
                available: false,
                connected: false,
                login: String::new(),
            });
        }
        let out = output(&["api", "--hostname", "github.com", "user"])?;
        if !out.status.success() {
            return Ok(Session {
                available: true,
                connected: false,
                login: String::new(),
            });
        }
        let data: serde_json::Value = serde_json::from_slice(&out.stdout)
            .map_err(|_| "Could not read GitHub account details.")?;
        Ok(Session {
            available: true,
            connected: true,
            login: data["login"].as_str().unwrap_or("").into(),
        })
    })
    .await
    .map_err(|e| e.to_string())?
}
#[derive(Serialize, Deserialize)]
pub struct Repository {
    full_name: String,
    html_url: String,
    private: bool,
}
#[derive(Serialize, Deserialize)]
pub struct PublicResults {
    items: Vec<Repository>,
    total_count: u64,
}
#[tauri::command]
pub async fn github_public_search(query: String, page: u32) -> Result<PublicResults, String> {
    if page == 0 || page > 34 || query.len() > 256 {
        return Err("Invalid search or page.".into());
    }
    tauri::async_runtime::spawn_blocking(move||{
        let client=reqwest::blocking::Client::builder().user_agent("AgentScan/0.1").timeout(Duration::from_secs(30)).build().map_err(|_|"Could not initialize public search.")?;
        let q=format!("{} is:public",query.trim());
        // Deliberately unauthenticated: browsing public repositories never requires signing in.
        let response=client.get("https://api.github.com/search/repositories").query(&[("q",q),("per_page","30".into()),("page",page.to_string()),("sort","stars".into())]).send().map_err(|_|"Could not reach GitHub. Check your connection.")?;
        if matches!(response.status().as_u16(),403|429){return Err("GitHub public search rate limit reached. Wait a minute and retry, or paste a public repository URL directly.".into());}
        if !response.status().is_success(){return Err("GitHub could not complete this search. Try a repository name or owner/name.".into());}
        response.json().map_err(|_|"Could not read GitHub search results.".into())
    }).await.map_err(|e|e.to_string())?
}
#[tauri::command]
pub async fn github_repositories(page: u32) -> Result<Vec<Repository>, String> {
    if page == 0 || page > 1000 {
        return Err("Invalid repository page.".into());
    }
    tauri::async_runtime::spawn_blocking(move||{
        let endpoint=format!("user/repos?per_page=100&page={page}&sort=updated&affiliation=owner,collaborator,organization_member");
        let out=output(&["api","--hostname","github.com",&endpoint])?;
        if !out.status.success(){return Err("Could not load repositories. Check your GitHub connection and organization access.".into());}
        serde_json::from_slice(&out.stdout).map_err(|_|"Could not read the repository list.".into())
    }).await.map_err(|e|e.to_string())?
}
#[derive(Clone, Default, Serialize)]
pub struct AuthProgress {
    running: bool,
    code: String,
    error: String,
    complete: bool,
}
#[derive(Default)]
pub struct AuthJob {
    progress: Arc<Mutex<AuthProgress>>,
    cancel: Arc<AtomicBool>,
}
fn device_code(text: &str) -> Option<String> {
    // Only the short OAuth device code leaves the authentication process.
    let re = regex::Regex::new(r"\b[A-Z0-9]{4}-[A-Z0-9]{4}\b").unwrap();
    re.find(text).map(|m| m.as_str().to_string())
}
#[tauri::command]
pub fn github_auth_start(job: tauri::State<AuthJob>) -> Result<(), String> {
    let mut current = job
        .progress
        .lock()
        .map_err(|_| "Authentication state unavailable")?;
    if current.running {
        return Err("GitHub sign-in is already running.".into());
    }
    let mut child = Command::new(executable())
        .args([
            "auth",
            "login",
            "--hostname",
            "github.com",
            "--git-protocol",
            "https",
            "--web",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|_| "Install GitHub CLI (gh) to connect your account.")?;
    *current = AuthProgress {
        running: true,
        ..Default::default()
    };
    job.cancel.store(false, Ordering::Relaxed);
    let progress = job.progress.clone();
    let cancel = job.cancel.clone();
    for stream in [
        Box::new(child.stdout.take().unwrap()) as Box<dyn std::io::Read + Send>,
        Box::new(child.stderr.take().unwrap()) as Box<dyn std::io::Read + Send>,
    ] {
        let progress = progress.clone();
        std::thread::spawn(move || {
            for line in BufReader::new(stream).lines().map_while(Result::ok) {
                if let Some(code) = device_code(&line) {
                    if let Ok(mut p) = progress.lock() {
                        p.code = code;
                    }
                }
            }
        });
    }
    if let Some(mut stdin) = child.stdin.take() {
        let _ = stdin.write_all(b"\n");
    }
    std::thread::spawn(move || {
        let start = Instant::now();
        let (complete, error) = loop {
            match child.try_wait() {
                Ok(Some(status)) => {
                    break (
                        status.success(),
                        if status.success() {
                            String::new()
                        } else {
                            "GitHub authorization was not completed. Try again.".into()
                        },
                    )
                }
                Err(_) => break (false, "Could not check authorization status.".into()),
                _ => {}
            }
            if cancel.load(Ordering::Relaxed) || start.elapsed() > Duration::from_secs(600) {
                let _ = child.kill();
                let _ = child.wait();
                break (false, "GitHub sign-in cancelled or expired.".into());
            }
            std::thread::sleep(Duration::from_millis(150));
        };
        if let Ok(mut p) = progress.lock() {
            p.running = false;
            p.complete = complete;
            p.error = error;
        }
    });
    Ok(())
}
#[tauri::command]
pub fn github_auth_progress(job: tauri::State<AuthJob>) -> Result<AuthProgress, String> {
    job.progress
        .lock()
        .map(|p| p.clone())
        .map_err(|_| "Authentication state unavailable".into())
}
#[tauri::command]
pub fn github_auth_cancel(job: tauri::State<AuthJob>) {
    job.cancel.store(true, Ordering::Relaxed);
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    #[ignore="uses unauthenticated GitHub public search"]
    fn public_search_without_sign_in(){
        let results=tauri::async_runtime::block_on(github_public_search("Hello-World user:octocat".into(),1)).unwrap();
        assert!(results.items.iter().any(|r|r.full_name=="octocat/Hello-World"));
        assert!(results.items.iter().all(|r|!r.private));
    }
    #[test]
    fn captures_only_device_code() {
        assert_eq!(
            device_code("First copy your one-time code: ABCD-1234"),
            Some("ABCD-1234".into())
        );
        assert_eq!(device_code("gho_secretvalue"), None);
    }
    #[test]
    #[ignore = "uses existing GitHub account"]
    fn lists_authenticated_repositories() {
        let session = tauri::async_runtime::block_on(github_session()).unwrap();
        assert!(session.connected);
        let repos = tauri::async_runtime::block_on(github_repositories(1)).unwrap();
        assert!(repos
            .iter()
            .all(|r| r.html_url.starts_with("https://github.com/")));
    }
}
