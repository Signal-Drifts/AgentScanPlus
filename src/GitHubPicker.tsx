import {useEffect, useRef, useState} from "react";
import {invoke} from "@tauri-apps/api/core";
import {listen} from "@tauri-apps/api/event";

export type Repo = {full_name:string; html_url:string; private:boolean};
export type Session = {available:boolean; connected:boolean; login:string};
export type InitialPicker = {session:Session|null; repos:Repo[]; error:string; tab:"mine"|"public"};
type Auth = {running:boolean; code:string; error:string; complete:boolean};

export async function preparePicker():Promise<InitialPicker> {
  let session:Session|null = null;
  try { session = await invoke<Session>("github_session"); } catch {}
  if (!session?.connected) return {session, repos:[], error:"", tab:"public"};
  try {
    const repos = await invoke<Repo[]>("github_repositories", {page:1});
    return {session, repos, error:"", tab:"mine"};
  } catch (error) {
    return {session, repos:[], error:String(error), tab:"mine"};
  }
}

export default function GitHubPicker({initial,onSelect,onClose}:{initial:InitialPicker;onSelect:(url:string)=>void;onClose:()=>void}) {
  const dialog = useRef<HTMLDialogElement>(null);
  const active = useRef(true);
  const [session,setSession] = useState(initial.session);
  const [repos,setRepos] = useState(initial.repos);
  const [selected,setSelected] = useState("");
  const [error,setError] = useState(initial.error);
  const [busy,setBusy] = useState(false);
  const [auth,setAuth] = useState<Auth|null>(null);
  const [tab,setTab] = useState<"mine"|"public">(initial.tab);

  useEffect(() => {
    active.current = true;
    dialog.current?.showModal();
    return () => { active.current = false; };
  }, []);

  useEffect(() => {
    let unlisten:undefined|(()=>void);
    void listen<string>("github-repository-selected", event => onSelect(event.payload)).then(stop => {unlisten=stop;});
    return () => unlisten?.();
  }, [onSelect]);

  useEffect(() => {
    if (!auth?.running) return;
    let pending = false;
    const timer = window.setInterval(async () => {
      if (pending) return;
      pending = true;
      try {
        const progress = await invoke<Auth>("github_auth_progress");
        if (!active.current) return;
        setAuth(progress);
        if (progress.complete) {
          const nextSession = await invoke<Session>("github_session");
          const nextRepos = await invoke<Repo[]>("github_repositories", {page:1});
          if (active.current) { setSession(nextSession); setRepos(nextRepos); setTab("mine"); }
        } else if (progress.error) setError(progress.error);
      } catch (nextError) {
        if (active.current) { setError(String(nextError)); setAuth(null); }
      } finally { pending = false; }
    }, 800);
    return () => window.clearInterval(timer);
  }, [auth?.running]);

  function close() {
    if (auth?.running) void invoke("github_auth_cancel");
    onClose();
  }

  async function signIn() {
    setError("");
    try {
      await invoke("github_auth_start");
      setAuth({running:true,code:"",error:"",complete:false});
    } catch (nextError) { setError(String(nextError)); }
  }

  async function browsePublic() {
    setBusy(true); setError("");
    try { await invoke("browse_public_github"); }
    catch (nextError) { setError(String(nextError)); }
    finally { setBusy(false); }
  }

  return <dialog ref={dialog} className="github-picker" onCancel={event=>{event.preventDefault();close();}}>
    <div className="picker-title"><h2>Select GitHub repository</h2><button className="picker-close" aria-label="Close" onClick={close}>×</button></div>
    <div className="picker-tabs">
      <button aria-pressed={tab==="mine"} onClick={()=>{setTab("mine");setSelected("");setError("");}}>Your repositories</button>
      <button aria-pressed={tab==="public"} onClick={()=>{setTab("public");setSelected("");setError("");}}>Public GitHub</button>
    </div>
    <div className="picker-content">
      {tab === "mine" ? session?.connected ? <>
        <p className="picker-account">Connected as {session.login}</p>
        <div className="picker-list">
          {repos.map(repo=><button key={repo.html_url} className={selected===repo.html_url?"repo-choice selected":"repo-choice"} aria-pressed={selected===repo.html_url} onClick={()=>setSelected(repo.html_url)}><span>{repo.full_name}</span><small>{repo.private?"Private":"Public"}</small></button>)}
          {!repos.length && <p className="picker-empty">No repositories available.</p>}
        </div>
      </> : <div className="connect-panel">
        <p>Connect GitHub to browse repositories available to your account.</p>
        {session?.available===false ? <p>Install GitHub CLI (gh) to connect.</p> : auth?.running ? <div className="auth-progress"><p>Approve access in your browser.</p>{auth.code&&<strong>{auth.code}</strong>}</div> : <button className="primary compact-button" onClick={signIn}>Connect GitHub</button>}
      </div> : <div className="public-picker">
        <p>Open GitHub and click a public repository. AgentScan will place its URL in the main field.</p>
        <button className="primary browse-public" disabled={busy} onClick={browsePublic}>{busy?"Opening…":"Browse Public GitHub"}</button>
      </div>}
    </div>
    {error && <p className="picker-error" role="alert">{error}</p>}
    <div className="picker-actions">
      <button className="secondary" onClick={close}>Cancel</button>
      {tab==="mine"&&<button className="primary" disabled={!selected} onClick={()=>onSelect(selected)}>Select repository</button>}
    </div>
  </dialog>;
}
