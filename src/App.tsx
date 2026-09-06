import { useEffect, useMemo, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { open, save } from "@tauri-apps/plugin-dialog";
import { AlertTriangle, Bot, Box, ChevronDown, Code2, FileDown, FolderOpen, PlugZap, ScanLine, ShieldCheck } from "lucide-react";
import type { Category, Finding, Report, ScanResult } from "./types";

const categories: { name: Category; icon: typeof Code2 }[] = [
  { name: "Application Security", icon: Code2 },
  { name: "Dependencies", icon: Box },
  { name: "Agent Security", icon: Bot },
  { name: "MCP Security", icon: PlugZap }
];

const empty: ScanResult = {sourceName:"",sourcePath:"",sourceKind:"folder",scannedAt:"Not scanned",reports:[]};

function markdownFor(result: ScanResult, reports: Report[]) {
  const lines = [`# AgentScan Report`, ``, `Source: ${result.sourcePath}`, `Scanned: ${result.scannedAt}`, ``, `Coverage: initial static checks only; full SAST and dependency advisory analysis are not implemented. Files over 2 MB, binary files, symlinks and generated directories are excluded.`, ``];
  for (const report of reports) {
    lines.push(`## ${report.label}`, ``, `Files scanned: ${report.filesScanned}`, ``);
    for (const category of categories) {
      lines.push(`### ${category.name}`, ``);
      const found = report.findings.filter(f => f.category === category.name);
      if (!found.length) lines.push(`- No matches in available checks`);
      for (const finding of found) lines.push(`- ${finding.critical ? "**CRITICAL** — " : ""}${finding.title} — \`${finding.location}\``, `  - ${finding.detail}`, `  - Fix: ${finding.recommendation}`);
      lines.push("");
    }
  }
  return lines.join("\n");
}

export default function App() {
  const [result, setResult] = useState<ScanResult | null>(null);
  const [selected, setSelected] = useState("all");
  const [filter, setFilter] = useState<"all" | "critical" | "other">("all");
  const [collapsed, setCollapsed] = useState<Record<string, boolean>>({});
  const [dots, setDots] = useState(1);
  function toggleCollapse(id: string){ setCollapsed(c => ({ ...c, [id]: !c[id] })); }
  const [scanning, setScanning] = useState(false);
  const [error, setError] = useState("");
  const shown = result ?? empty;
  const [mode, setMode] = useState("folder");
  const [folderPath, setFolderPath] = useState("");
  const [repoUrl, setRepoUrl] = useState("");
  const [saved, setSaved] = useState("");
  useEffect(() => {
    let unlisten: undefined | (() => void);
    void listen<string>("github-repository-selected", event => { setRepoUrl(event.payload); setResult(null); setError(""); }).then(stop => { unlisten = stop; });
    return () => unlisten?.();
  }, []);
  useEffect(() => {
    if (!scanning) return;
    setDots(1);
    const id = window.setInterval(() => setDots(d => (d >= 3 ? 1 : d + 1)), 400);
    return () => window.clearInterval(id);
  }, [scanning]);
  async function browseGitHub(){ if(scanning) return; setError(""); try{ await invoke("browse_public_github"); } catch(e){ setError(String(e)); } }
  function clearScreen(){if(scanning)return;setFolderPath("");setRepoUrl("");setResult(null);setSelected("all");setFilter("all");setCollapsed({});setError("");setSaved("");}
  function changeMode(next: string) { setMode(next); setError(""); setSaved(""); }
  async function cancelScan(){ try{ await invoke("scan_cancel"); }catch(e){ setError(String(e)); } }
  const reports = selected === "all" ? shown.reports : shown.reports.filter(r => r.id === selected);
  const counts = useMemo(() => ({ critical: reports.flatMap(r => r.findings).filter(f => f.critical).length, other: reports.flatMap(r => r.findings).filter(f => !f.critical).length }), [reports]);

  async function chooseFolder() {
    try { const path = await open({directory:true,multiple:false,title:"Select Folder"}); if(path){setFolderPath(path);setResult(null);setError("");setSaved("");} } catch(e){setError(String(e));}
  }
  async function scanSource() {
    if (scanning) return;
    try {
    if (mode === "folder" && !folderPath) { await chooseFolder(); return; }
    setScanning(true); setError(""); setSaved("");
      const scan = mode === "folder" ? await invoke<ScanResult>("scan_path", { path: folderPath, mode:"folder" }) : await invoke<ScanResult>("scan_github", { url: repoUrl });
      setResult(scan); setFilter("all"); setCollapsed({}); setSelected(scan.sourceKind === "repository" ? (scan.reports.find(r=>r.label.endsWith(" / main")) ?? scan.reports[0])?.id ?? "all" : scan.reports.length > 1 ? "all" : scan.reports[0]?.id ?? "all");
    } catch (e) { const m = String(e); if (!m.includes("Scan cancelled")) setError(m); } finally { setScanning(false); }
  }

  async function exportMarkdown() {
    try {
    const destination = await save({ defaultPath: `${shown.sourceName}-agentscan.md`, filters: [{ name: "Markdown", extensions: ["md"] }] });
    if (destination) { await invoke("write_report", { path: destination, content: markdownFor(shown, reports) }); setSaved("Markdown saved"); }
    } catch(e) { setError(String(e)); }
  }

  return <div className="app-shell">
    <header className="topbar"><div className="brand"><span className="brand-mark"><ScanLine size={16}/></span>AgentScan</div><div className="promise"><span/>Local and Free</div></header>
    <div className="workspace">
      <aside className="sidebar">
        <div className="source-heading">Select Folder or Repo <span className="help-wrap"><button className="tiny-help" aria-label="Folder and Git repo help" aria-describedby="source-help">?</button><span id="source-help" role="tooltip"><b>Folder:</b> A project folder at laptop.<br/><b>Git repo:</b> A github repo URL</span></span></div>
        <div className="source-modes"><button disabled={scanning} className={mode==="folder"?"active":""} onClick={()=>changeMode("folder")}>Folder</button><button disabled={scanning} className={mode==="repository"?"active":""} onClick={()=>changeMode("repository")}>Git repo</button></div>
        {mode === "folder" ? <button className="source-card" title={folderPath || "Select Folder"} onClick={chooseFolder}><FolderOpen size={18}/><span><b>{folderPath.split(/[\\/]/).filter(Boolean).pop() || "Select Folder"}</b><small>{folderPath || "Choose a project folder"}</small></span></button> : <div className="source-card repo-source" title={repoUrl}><div className="url-row"><input id="github-url" type="url" placeholder="Paste repository URL" value={repoUrl} onChange={e=>{setRepoUrl(e.target.value);setError("");}}/><button className="github-icon" disabled={scanning} aria-label="Browse GitHub for a repository" title="Browse GitHub for a repository" onClick={browseGitHub}><img src="/github.svg" width="22" height="22" alt=""/></button></div></div>}
        <div className="scan-action"><button className="secondary clear-button" onClick={clearScreen} disabled={scanning}>Clear</button>{scanning ? <button className="primary scan-button" onClick={cancelScan}>Cancel</button> : <button className="primary scan-button" onClick={scanSource} disabled={mode==="repository"&&!repoUrl.trim()}>Scan</button>}</div>
        {shown.reports.length > 1 ? <><label className="eyebrow" htmlFor="report-select">{shown.sourceKind === "repository" ? "Branch report" : "Project report"}</label><div className="select-wrap"><select id="report-select" value={selected} onChange={e => setSelected(e.target.value)}><option value="all">{shown.sourceKind === "repository" ? "All branches" : "All projects"}</option>{shown.reports.map(r => <option key={r.id} value={r.id}>{r.label}</option>)}</select><ChevronDown size={14}/></div></> : <><p className="eyebrow">{shown.sourceKind === "repository" ? "Branch report" : "Project report"}</p><div className="single-project">{shown.reports[0]?.label ?? "No project"}</div></>}
        <div className="scan-meta"><div><span>{shown.sourceKind === "repository" ? "Branches" : "Projects"}</span><b>{shown.reports.length}</b></div><div><span>Files scanned</span><b>{reports.reduce((n,r)=>n+r.filesScanned,0).toLocaleString()}</b></div></div>
        <button className="primary save-button" disabled={!result || scanning} onClick={exportMarkdown}><FileDown size={15}/>Save Markdown</button>
        <span className="save-status" role="status">{saved}</span>
      </aside>
      <main className="report-area">
        {error && <div className="error"><AlertTriangle size={16}/>{error}</div>}
        {scanning ? <div className="report-empty"><h1 className="scanning-dots">Scanning<span className="dots">{".".repeat(dots)}</span></h1></div> : !result ? <div className="report-empty"><h1>Scan Report</h1></div> : <>
          <div className="report-head">
            <div>
              <h1>{filter === "critical" ? `${shown.sourceName} — Critical findings` : filter === "other" ? `${shown.sourceName} — Other findings` : selected === "all" ? `${shown.sourceName} — ${shown.sourceKind === "repository" ? "All branches" : "All projects"}` : reports[0]?.label}</h1>
              <p>{filter === "all" ? "Findings grouped by security area" : "Findings grouped by project"}</p>
            </div>
            <div className="totals">
              {filter !== "all" && <button className="back-full" onClick={() => setFilter("all")}>← Back to full report</button>}
              <button className={`total-pill critical${filter === "critical" ? " active" : ""}`} aria-pressed={filter === "critical"} onClick={() => setFilter("critical")}><span className="total-num">{counts.critical}</span><span className="total-label">Critical</span></button>
              <button className={`total-pill${filter === "other" ? " active" : ""}`} aria-pressed={filter === "other"} onClick={() => setFilter("other")}><span className="total-num">{counts.other}</span><span className="total-label">Other Findings</span></button>
            </div>
          </div>
          <div className="report-scroll">
            {filter === "all" ? <>
              <p className="coverage-note">Initial checks: private-key headers, registry transport, agent instruction patterns and broad MCP configuration. Full code analysis and package advisory checks are not yet implemented. No matches does not establish safety.</p>
              {reports.map(report => <ProjectSection key={report.id} report={report} collapsed={!!collapsed[report.id]} onToggle={() => toggleCollapse(report.id)}/>)}
            </> : <FilteredList reports={reports} critical={filter === "critical"}/>}
          </div>
        </>}
      </main>
    </div>
  </div>;
}

function ProjectSection({ report, collapsed, onToggle }: { report: Report; collapsed: boolean; onToggle: () => void }) {
  return <section className="project-report">
    <button className="project-header" aria-expanded={!collapsed} onClick={onToggle}>
      <h2>{report.label}</h2>
      <span className="project-files">{report.filesScanned.toLocaleString()} files</span>
      <ChevronDown size={16} className={collapsed ? "chev collapsed" : "chev"}/>
    </button>
    {!collapsed && <div className="project-body">
      {categories.map(category => <CategoryBlock key={category.name} status={category.name === "Agent Security" && !report.agentDetected ? "No agents detected in recognized instruction files" : category.name === "MCP Security" && !report.mcpDetected ? "No MCP configurations detected" : "No matches in available checks"} category={category.name} icon={category.icon} findings={report.findings.filter(f => f.category === category.name)}/>)}
    </div>}
  </section>;
}

function FilteredList({ reports, critical }: { reports: Report[]; critical: boolean }) {
  const groups = reports.map(r => ({ id: r.id, label: r.label, items: r.findings.filter(f => critical ? f.critical : !f.critical) })).filter(g => g.items.length);
  if (!groups.length) return <div className="clean"><ShieldCheck size={15}/>{critical ? "No critical findings." : "No other findings."}</div>;
  return <div className="filtered-list">{groups.map(g => <div className="filtered-project" key={g.id}>
    <h2>{g.label}</h2>
    {g.items.map(f => <article className={`finding ${f.critical ? "is-critical" : ""}`} key={f.id}><span className="finding-dot"/><div><b>{f.title}</b><code>{f.category} · {f.location}</code><p>{f.detail}</p><em>Fix: {f.recommendation}</em></div>{f.critical && <strong className="critical-tag">CRITICAL</strong>}</article>)}
  </div>)}</div>;
}

function CategoryBlock({ category, icon: Icon, findings, status }: { status: string; category: Category; icon: typeof Code2; findings: Finding[] }) {
  return <section className="category-card"><header><span className="category-icon"><Icon size={15}/></span><h3>{category}</h3><small>{findings.length} {findings.length === 1 ? "finding" : "findings"}</small></header>
    {findings.length ? findings.map(f => <article className={`finding ${f.critical ? "is-critical" : ""}`} key={f.id}><span className="finding-dot"/><div><b>{f.title}</b><code>{f.location}</code><p>{f.detail}</p><em>Fix: {f.recommendation}</em></div>{f.critical && <strong className="critical-tag">CRITICAL</strong>}</article>) : <div className="clean"><ShieldCheck size={15}/>{status}</div>}
  </section>;
}
