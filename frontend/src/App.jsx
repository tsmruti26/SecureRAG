import { useEffect, useMemo, useState } from "react";
import {
  ShieldCheck, MessageSquare, LayoutDashboard, FileText, Activity,
  Settings, LockKeyhole, Send, CheckCircle2, AlertTriangle, ShieldAlert,
  Bot, UserRound, Database, LogOut, Search, ClipboardList, Siren, Globe
} from "lucide-react";
import "./App.css";
import Login from "./Login";
import QrScan from "./QrScan";
import Incidents, { CreateIncidentFromScan } from "./Incidents";
import ReactMarkdown from "react-markdown";

const API_BASE = "http://localhost:8001";

const recordedTests = [
  "Engineering blocked from HR data",
  "HR user can retrieve HR data",
  "Unknown department denied",
  "Missing document department denied",
  "Unexpected classification denied",
  "Missing user department denied",
  "Salary absent from Engineering context",
  "Salary absent when department is missing",
  "Prompt-injection payload retrieval",
];

const employeeWelcome =
  "Welcome to SecureRAG. Ask about your authorized company knowledge base. Access is determined by your signed-in account.";
const socWelcome =
  "Welcome to the SOC Analyst workspace. Ask about alert triage, authentication events, phishing, threat hunting, cloud IAM, or incident response. Responses use the SOC knowledge base when relevant.";

function prettyDepartment(value) {
  const labels = {
    hr: "Human Resources",
    engineering: "Engineering",
    finance: "Finance",
    soc: "SOC",
  };
  return labels[String(value || "").toLowerCase()] || "Unrecognized department";
}

function getInitialMessage(session) {
  return [{
    role: "assistant",
    text: String(session?.department || "").toLowerCase() === "soc"
      ? socWelcome
      : employeeWelcome,
    sources: [],
  }];
}

export default function App() {
  const [session, setSession] = useState(null);
  const [page, setPage] = useState("Overview");
  const [messages, setMessages] = useState([]);
  const [input, setInput] = useState("");
  const [busy, setBusy] = useState(false);
  const [backendStatus, setBackendStatus] = useState("Checking");
  const [alertText, setAlertText] = useState("");
  const [alertResult, setAlertResult] = useState(null);
  const [reportText, setReportText] = useState("");
  const [reportTitle, setReportTitle] = useState("Security Incident Report");
  const [scanDomain, setScanDomain] = useState("");
  const [checkDns, setCheckDns] = useState(true);
  const [scanBusy, setScanBusy] = useState(false);
  const [scanResult, setScanResult] = useState(null);
  const [scanError, setScanError] = useState("");

  const department = String(session?.department || "").toLowerCase();
  const isSoc = department === "soc" || session?.role === "soc_analyst";
  const departmentLabel = prettyDepartment(department);

  const navItems = useMemo(() => {
    const common = [
      ["Overview", LayoutDashboard],
      ["Incidents", ShieldAlert],
      ["Chat", MessageSquare],
      ["Knowledge Base", Database],
      ["Security Tests", ShieldCheck],
      ["Activity Logs", Activity],
    ];
    if (isSoc) {
      return [
        ["Overview", LayoutDashboard],
      ["Incidents", ShieldAlert],
        ["Alert Investigation", Siren],
        ["Security Assistant", MessageSquare],
        ["Incident Report", ClipboardList],
        ["Typosquatting Scanner", Globe],
        ["QR Phishing", ShieldAlert],
        ["Knowledge Base", Database],
        ["Security Tests", ShieldCheck],
        ["Activity Logs", Activity],
      ];
    }
    return common;
  }, [isSoc]);

  async function checkBackend() {
    try {
      const response = await fetch(`${API_BASE}/api/health`);
      if (!response.ok) throw new Error("Health check failed");
      setBackendStatus("Connected");
    } catch {
      setBackendStatus("Unavailable");
    }
  }

  // Check backend after login and whenever the signed-in identity changes.
  // A manual refresh is available from Settings.
  useEffect(() => {
    if (session) checkBackend();
  }, [session]);

  function handleLogin(data) {
    setSession(data);
    setMessages(getInitialMessage(data));
    setPage("Overview");
  }

  function handleLogout() {
    setSession(null);
    setMessages([]);
    setInput("");
    setAlertText("");
    setAlertResult(null);
    setReportText("");
    setPage("Overview");
  }

  
async function askBackend(question) {
  const response = await fetch(`${API_BASE}/api/chat`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${session.access_token}`,
    },
    body: JSON.stringify({ question }),
  });

  const raw = await response.text();

  console.log("SecureRAG API status:", response.status);
  console.log("SecureRAG API raw response:", raw);

  if (!response.ok) {
    let detail = raw;
    try {
      detail = JSON.parse(raw).detail || raw;
    } catch {}
    throw new Error(detail || `Request failed (${response.status})`);
  }

  if (!raw.trim()) {
    throw new Error("The API returned an empty response body.");
  }

  try {
    return JSON.parse(raw);
  } catch {
    throw new Error("The API returned invalid JSON.");
  }
}


  async function sendMessage(e) {
    e?.preventDefault();
    const question = input.trim();
    if (!question || busy) return;

    setMessages((old) => [...old, { role: "user", text: question }]);
    setInput("");
    setPage(isSoc ? "Security Assistant" : "Chat");
    setBusy(true);

    try {
      
        const data = await askBackend(question);

        if (!data || typeof data !== "object") {
          throw new Error("The API returned an empty or invalid response.");
        }

        setMessages((old) => [
          ...(Array.isArray(old) ? old.filter(Boolean) : []),
          {
            role: "assistant",
            text: data.answer || "The API returned no answer.",
            sources: Array.isArray(data.sources) ? data.sources : [],
          },
        ]);

        setBackendStatus("Connected");

    } catch (error) {
      setMessages((old) => [...old, {
        role: "assistant",
        text: `Could not get a response: ${error.message}. Check that the FastAPI backend is running on port 8001.`,
        sources: [],
      }]);
      setBackendStatus("Unavailable");
    } finally {
      setBusy(false);
    }
  }

  async function investigateAlert(e) {
    e.preventDefault();
    const rawAlert = alertText.trim();
    if (!rawAlert || busy) return;
    setBusy(true);
    setAlertResult(null);
    try {
      const data = await askBackend(
        `You are assisting a SOC analyst. Analyze the following alert or log excerpt using only relevant retrieved SOC playbooks. Do not claim to have queried live SIEM tools. Separate observed facts from hypotheses. Provide: 1) brief triage summary, 2) severity estimate with rationale, 3) investigation steps, 4) evidence to preserve, 5) containment considerations, 6) missing information, and 7) relevant retrieved sources. If the evidence is insufficient, say so.\\n\\nAlert/log excerpt:\\n${rawAlert}`
      );
      setAlertResult(data);
      setBackendStatus("Connected");
    } catch (error) {
      setAlertResult({ answer: `Investigation request failed: ${error.message}`, sources: [] });
      setBackendStatus("Unavailable");
    } finally {
      setBusy(false);
    }
  }

  async function draftIncidentReport() {
    if (busy) return;
    setBusy(true);
    try {
      const data = await askBackend(
        `Draft a concise SOC incident report template using the SOC knowledge base. Include incident summary, observed evidence, timeline (mark unknown values as TBD), affected assets/accounts, assessment, actions taken (do not invent actions), recommended next steps, evidence to preserve, and open questions. Clearly label any unknowns as TBD. Do not fabricate events.`
      );
      const sources = (data.sources || []).map((s) =>
        typeof s === "string" ? s : s.source
      ).filter(Boolean);
      setReportText(`${data.answer || ""}${sources.length ? `\n\nRetrieved sources: ${sources.join(", ")}` : ""}`);
      setBackendStatus("Connected");
    } catch (error) {
      setReportText(`Could not draft report: ${error.message}`);
      setBackendStatus("Unavailable");
    } finally {
      setBusy(false);
    }
  }

  async function runTyposquattingScan(e) {
    e.preventDefault();
    const domain = scanDomain.trim();
    if (!domain || scanBusy) return;
    setScanBusy(true);
    setScanError("");
    setScanResult(null);
    try {
      const response = await fetch(`${API_BASE}/api/soc/typosquatting-scan`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${session.access_token}`,
        },
        body: JSON.stringify({ domain, check_dns: checkDns }),
      });
      const raw = await response.text();
      let data;
      try {
        data = raw ? JSON.parse(raw) : null;
      } catch {
        throw new Error("The scanner returned an invalid response.");
      }
      if (!response.ok) throw new Error(data?.detail || `Scan failed (${response.status}).`);
      if (!data || typeof data !== "object") throw new Error("The scanner returned an empty response.");
      setScanResult(data);
    } catch (error) {
      setScanError(error.message || "Could not complete the scan.");
    } finally {
      setScanBusy(false);
    }
  }

  if (!session) return <Login onLogin={handleLogin} />;

  const pageTitle = page === "Security Assistant" ? "Security Assistant" : page;
  const sourceLabel = (source) => {
    if (typeof source === "string") return source;
    return [source?.source || source?.filename || "Document", source?.classification]
      .filter(Boolean).join(" · ");
  };

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="brand">
          <div className="brand-icon"><ShieldCheck size={24} /></div>
          <div><strong>SecureRAG</strong><span>{isSoc ? "SOC ANALYST WORKSPACE" : "SECURE KNOWLEDGE"}</span></div>
        </div>
        <div className="workspace-label">WORKSPACE</div>
        {navItems.map(([name, Icon]) => (
          <button key={name} className={`nav-item ${page === name ? "active" : ""}`} onClick={() => setPage(name)}>
            <Icon size={18} /><span>{name}</span>
          </button>
        ))}
        <div className="sidebar-bottom">
          <div className="system-status"><span className={`status-dot ${backendStatus === "Unavailable" ? "offline" : ""}`} />
            Backend <span className="status-right">{backendStatus}</span>
          </div>
          <button className={`nav-item ${page === "Settings" ? "active" : ""}`} onClick={() => setPage("Settings")}><Settings size={18} /> Settings</button>
          <div className="profile">
            <div className="avatar">{isSoc ? "S" : (session.email?.[0] || "U").toUpperCase()}</div>
            <div><strong>{session.email || "Signed-in user"}</strong><span>{session.role || "Authenticated user"}</span></div>
          </div>
          <button className="nav-item" onClick={handleLogout}><LogOut size={18} /><span>Sign out</span></button>
        </div>
      </aside>

      <main className="main">
        <header className="topbar">
          <div className="breadcrumb"><span>SecureRAG</span><span>/</span><strong>{pageTitle}</strong></div>
          <div className="top-actions">
            <span className="environment"><span className={`status-dot ${backendStatus === "Unavailable" ? "offline" : ""}`} /> {backendStatus.toUpperCase()}</span>
            <span className="muted-tag">{departmentLabel.toUpperCase()}</span>
          </div>
        </header>

        {page === "Overview" && (
          <div className="content">
            <div className="welcome-row">
              <div>
                <div className="eyebrow">{isSoc ? "SECURITY OPERATIONS / SOC" : "SECURE KNOWLEDGE / WORKSPACE"}</div>
                <h1>{isSoc ? "SOC Analyst Overview" : "Secure Knowledge Overview"}</h1>
                <p>{isSoc ? "Investigate security events with guidance grounded in your authorized SOC playbooks." : "Ask questions against the knowledge base authorized for your signed-in account."}</p>
              </div>
              <button className="primary-button" onClick={() => setPage(isSoc ? "Alert Investigation" : "Chat")}>
                {isSoc ? <Siren size={16} /> : <MessageSquare size={16} />}
                {isSoc ? "Investigate an Alert" : "Open Secure Chat"}
              </button>
            </div>

            <div className="banner">
              <div className="banner-icon"><ShieldCheck size={24} /></div>
              <div><strong>Authenticated access enabled</strong><p>Your backend-issued token determines the identity and department used for document authorization.</p></div>
              <span className="banner-badge">{isSoc ? "SOC WORKSPACE" : "AUTHORIZED ACCESS"}</span>
            </div>

            <section className="stats-grid">
              <Stat icon={LockKeyhole} label="Signed-in department" value={departmentLabel} detail={`Role: ${session.role || "not supplied"}`} tone="purple" />
              <Stat icon={Database} label="Knowledge access" value={isSoc ? "SOC playbooks" : "Company handbook"} detail="Backend authorization applies" tone="blue" />
              <Stat icon={Activity} label="Backend status" value={backendStatus} detail="Checked via health endpoint" tone={backendStatus === "Connected" ? "green" : "amber"} />
              <Stat icon={ShieldCheck} label="Security tests" value="Recorded" detail="Not live test execution" tone="amber" />
            </section>

            <div className="section-heading"><div><h2>{isSoc ? "SOC workflow" : "Access policy"}</h2><p>{isSoc ? "Available investigation tools" : "Current knowledge access"}</p></div><span className="muted-tag">PROTOTYPE</span></div>
            <div className="lower-grid">
              <div className="panel">
                <div className="panel-title"><div><h3>{isSoc ? "Investigation tools" : "Access controls"}</h3><p>{isSoc ? "Start with evidence, then validate hypotheses" : "Authorization is enforced by the API"}</p></div><LockKeyhole size={19} /></div>
                {isSoc ? <>
                  <PolicyRow title="Alert Investigation" desc="Paste an alert or log excerpt for a structured triage checklist." status="AVAILABLE" green />
                  <PolicyRow title="Security Assistant" desc="Ask questions grounded in retrieved SOC playbooks." status="AVAILABLE" green />
                  <PolicyRow title="Incident Report" desc="Draft a report and mark unknown facts as TBD." status="AVAILABLE" green />
                </> : <>
                  <PolicyRow title="Shared internal documents" desc="Available when allowed by backend policy." status="POLICY-BASED" green />
                  <PolicyRow title="Confidential HR documents" desc="HR department only under the configured policy." status="RESTRICTED" />
                  <PolicyRow title="Missing or invalid metadata" desc="Should not satisfy explicit allow rules." status="DENIED" />
                </>}
                <div className="panel-note"><AlertTriangle size={16} /> Prototype only. Validate authorization with automated tests before relying on it.</div>
              </div>
              <div className="panel">
                <div className="panel-title"><div><h3>Quick actions</h3><p>Go to a workspace tool</p></div><ArrowIcon /></div>
                {(isSoc ? [
                  ["Alert Investigation", "Triage pasted logs or alerts", Siren],
                  ["Security Assistant", "Ask about SOC procedures", MessageSquare],
                  ["Incident Report", "Draft an incident report", ClipboardList],
                ] : [
                  ["Chat", "Ask about authorized company documents", MessageSquare],
                  ["Knowledge Base", "View configured knowledge sources", Database],
                ]).map(([name, desc, Icon]) => (
                  <button className="quick-action" key={name} onClick={() => setPage(name)}>
                    <Icon size={18} /><span><strong>{name}</strong><small>{desc}</small></span><span>→</span>
                  </button>
                ))}
              </div>
            </div>
            <div className="footer-note"><ShieldAlert size={15} /> Research prototype · Not production security software · No live SIEM connection is implied.</div>
          </div>
        )}

        {(page === "Chat" || page === "Security Assistant") && (
          <div className="chat-layout">
            <div className="chat-header">
              <div><div className="eyebrow">RETRIEVAL-AUGMENTED GENERATION</div><h1>{isSoc ? "Security Assistant" : "Secure Chat"}</h1><p>{isSoc ? "Ask about triage, phishing, authentication, threat hunting, cloud IAM, and response." : "Ask questions against your authorized company knowledge base."}</p></div>
              <span className="muted-tag">{departmentLabel.toUpperCase()}</span>
            </div>
            <div className="chat-messages">
              {messages.filter(Boolean).map((m, i) => (
                <div key={i} className={`message ${m.role}`}>
                  <div className="message-avatar">{m.role === "assistant" ? <Bot size={18} /> : <UserRound size={18} />}</div>
                  <div>
                    <div className="message-label">{m.role === "assistant" ? "SecureRAG Assistant" : "You"}</div>
                    <div className="message-bubble markdown-content">
                    {m.role === "assistant" ? (
                      <ReactMarkdown>{m.text}</ReactMarkdown>
                    ) : (
                      m.text
                    )}
                  </div>
                    {m.role === "assistant" && m.sources?.length > 0 && (
                      <div className="message-sources"><div className="sources-label">Retrieved sources</div><div className="source-list">
                        {m.sources.map((source, index) => <span className="source-chip" key={index}>{sourceLabel(source)}</span>)}
                      </div></div>
                    )}
                  </div>
                </div>
              ))}
              {busy && <div className="panel-note"><Activity size={16} /> Working on your request…</div>}
            </div>
            <form className="chat-composer" onSubmit={sendMessage}>
              <textarea value={input} onChange={(e) => setInput(e.target.value)} placeholder={isSoc ? "Ask about an alert, event ID, phishing indicator, or response step..." : "Ask about company policies..."} rows="2" disabled={busy} onKeyDown={(e) => { if (e.key === "Enter" && !e.shiftKey) { e.preventDefault(); sendMessage(e); } }} />
              <button className="send-button" type="submit" disabled={busy || !input.trim()}><Send size={17} /> {busy ? "Working…" : "Send"}</button>
            </form>
            <p className="chat-disclaimer">Answers may be incomplete. Verify findings against original logs and approved procedures.</p>
          </div>
        )}

        {page === "Alert Investigation" && isSoc && (
          <div className="content">
            <div className="welcome-row"><div><div className="eyebrow">SOC / TRIAGE</div><h1>Alert Investigation</h1><p>Submit a sanitized alert or log excerpt to get a playbook-grounded triage plan.</p></div><Siren size={28} /></div>
            <div className="banner"><div className="banner-icon"><ShieldCheck size={24} /></div><div><strong>Analyst-assisted investigation</strong><p>This sends your text to the RAG backend and configured language model. It does not query a live SIEM or automatically contain threats.</p></div><span className="banner-badge">MANUAL INPUT</span></div>
            <form className="panel investigation-form" onSubmit={investigateAlert}>
              <label htmlFor="alert-input"><strong>Alert / log excerpt</strong></label>
              <textarea id="alert-input" rows="9" value={alertText} onChange={(e) => setAlertText(e.target.value)} placeholder={'Paste sanitized evidence, for example:\nEvent ID: 4625\nHost: workstation-07\nAccount: test-user\nSeveral failed logons within 2 minutes…'} />
              <p className="chat-disclaimer">Remove passwords, tokens, personal data, and unrelated sensitive information before submitting.</p>
              <button className="primary-button" type="submit" disabled={busy || !alertText.trim()}><Search size={16} /> {busy ? "Investigating…" : "Generate triage guidance"}</button>
            </form>
            {alertResult && <div className="panel investigation-result"><h2>Investigation guidance</h2><div className="message-bubble">{alertResult.answer}</div>{alertResult.sources?.length > 0 && <><h3>Retrieved sources</h3><div className="source-list">{alertResult.sources.map((s, i) => <span className="source-chip" key={i}>{sourceLabel(s)}</span>)}</div></>}</div>}
          </div>
        )}

        {page === "Incident Report" && isSoc && (
          <div className="content">
            <div className="welcome-row"><div><div className="eyebrow">SOC / DOCUMENTATION</div><h1>Incident Report</h1><p>Draft a report template grounded in the SOC playbooks, then edit it with verified evidence.</p></div><ClipboardList size={28} /></div>
            <div className="panel investigation-form">
              <label htmlFor="report-title"><strong>Report title</strong></label>
              <input id="report-title" value={reportTitle} onChange={(e) => setReportTitle(e.target.value)} />
              <p className="chat-disclaimer">The generated draft is a template. Do not treat unknown details as confirmed facts.</p>
              <button className="primary-button" onClick={draftIncidentReport} disabled={busy}><FileText size={16} /> {busy ? "Drafting…" : "Generate report draft"}</button>
              {reportText && <>
                <label htmlFor="report-body"><strong>Editable report draft</strong></label>
                <textarea id="report-body" rows="16" value={`${reportTitle}\n\n${reportText}`} onChange={(e) => setReportText(e.target.value.replace(`${reportTitle}\n\n`, ""))} />
                <button className="text-button" onClick={() => navigator.clipboard?.writeText(`${reportTitle}\n\n${reportText}`)}>Copy report text</button>
              </>}
            </div>
          </div>
        )}

        {page === "Typosquatting Scanner" && isSoc && (
          <div className="content">
            <div className="welcome-row">
              <div>
                <div className="eyebrow">SOC / DOMAIN INVESTIGATION</div>
                <h1>Typosquatting Scanner</h1>
                <p>Generate lookalike domains and optionally check their DNS records.</p>
              </div>
              <Globe size={28} />
            </div>
            <div className="banner">
              <div className="banner-icon"><ShieldCheck size={24} /></div>
              <div>
                <strong>Analyst-assisted domain screening</strong>
                <p>Generated lookalikes are candidates for investigation, not proof of malicious activity. DNS records do not prove registration or maliciousness.</p>
              </div>
              <span className="banner-badge">SOC ONLY</span>
            </div>
            <form className="panel investigation-form" onSubmit={runTyposquattingScan}>
              <label htmlFor="typo-domain"><strong>Domain to investigate</strong></label>
              <input id="typo-domain" value={scanDomain} onChange={(e) => setScanDomain(e.target.value)}
                placeholder="example.com" autoComplete="off" spellCheck="false" required maxLength={253} />
              <label className="dns-option" htmlFor="typo-dns">
                <input id="typo-dns" type="checkbox" checked={checkDns}
                  onChange={(e) => setCheckDns(e.target.checked)} />
                <span><strong>Check DNS records</strong><small>Queries A, AAAA, MX and NS records for generated candidates.</small></span>
              </label>
              <p className="chat-disclaimer">Enter a domain only, such as example.com. DNS checks may take longer because multiple candidates are queried.</p>
              <button className="primary-button" type="submit" disabled={scanBusy || !scanDomain.trim()}>
                <Search size={16} /> {scanBusy ? "Scanning…" : "Scan lookalike domains"}
              </button>
            </form>
            {scanError && <div className="panel scan-error" role="alert">
              <AlertTriangle size={18} /><div><strong>Scan failed</strong><p>{scanError}</p></div>
            </div>}
            {scanResult && <div className="panel standalone">
              <div className="section-heading scan-heading">
                <div><h2>Scan results</h2><p>Original domain: <strong>{scanResult.original_domain}</strong></p></div>
                <span className="muted-tag">{scanResult.total_variants ?? scanResult.results?.length ?? 0} CANDIDATES</span>
              </div>
              <div className="scan-note">{checkDns
                ? "DNS checks were requested. A DNS response is not a verdict that a domain is malicious."
                : "DNS checks were disabled. Candidate domains have not been checked for DNS records."}</div>
              <div className="scan-table-wrap">
                <table className="scan-table">
                  <thead><tr><th>Candidate domain</th><th>DNS status</th><th>Records</th><th>Risk score</th></tr></thead>
                  <tbody>{(scanResult.results || []).map((item) => <tr key={item.domain}>
                    <td className="scan-domain-cell">{item.domain}</td>
                    <td><span className={`scan-status ${item.registration_status === "dns_records_found" ? "scan-found" : item.registration_status === "lookup_error" ? "scan-warning" : ""}`}>
                      {item.registration_status === "dns_records_found" ? "DNS records found"
                        : item.registration_status === "no_dns_records_found" ? "No DNS records found"
                        : item.registration_status === "lookup_error" ? "Lookup error" : "Not checked"}
                    </span></td>
                    <td>{Array.isArray(item.dns_records) && item.dns_records.length ? item.dns_records.join(", ") : "—"}</td>
                    <td>{item.risk_score ?? "Not scored"}</td>
                  </tr>)}</tbody>
                </table>
              </div>
              {session?.role !== "auditor" && <CreateIncidentFromScan token={session.access_token} scan={scanResult} />}
              <p className="chat-disclaimer">Similarity candidates are generated heuristically. Review results manually and validate against trusted threat-intelligence sources before taking action.</p>
            </div>}
          </div>
        )}

        {page === "Incidents" && (
          <Incidents token={session.access_token} role={session.role} />
        )}

        {page === "QR Phishing" && isSoc && (
          <QrScan token={session.access_token} />
        )}

        {page === "Security Tests" && (
          <div className="content">
            <div className="welcome-row"><div><div className="eyebrow">VALIDATION / REGRESSION</div><h1>Security Tests</h1><p>Previously recorded checks. This page does not execute the test suite.</p></div><span className="muted-tag">RECORDED ONLY</span></div>
            <div className="panel test-panel">{recordedTests.map((test, i) => <div className="full-test-row" key={test}><div className="test-number">{String(i + 1).padStart(2, "0")}</div><div className="test-info"><strong>{test}</strong><span>{i === 8 ? "A payload retrieval check does not prove resistance to prompt injection." : "Previously recorded local result; rerun tests to confirm current behavior."}</span></div><span className="muted-tag">RECORDED</span></div>)}</div>
            <div className="panel-note standalone"><AlertTriangle size={17} /> Do not present these as fresh test results. Run your current Python test suite and document the actual output.</div>
          </div>
        )}

        {page === "Knowledge Base" && (
          <div className="content">
            <div className="welcome-row"><div><div className="eyebrow">DATA / DOCUMENTS</div><h1>Knowledge Base</h1><p>{isSoc ? "SOC playbooks are indexed in the separate SOC Chroma collection." : "Company documents are filtered by backend authorization."}</p></div><Database size={26} /></div>
            <div className="panel">
              {(isSoc ? [
                ["01_siem_alert_triage.md", "Internal", "SOC only"],
                ["02_windows_linux_authentication.md", "Internal", "SOC only"],
                ["03_phishing_and_url_investigation.md", "Internal", "SOC only"],
                ["04_mitre_threat_hunting.md", "Internal", "SOC only"],
                ["05_incident_response_and_reporting.md", "Internal", "SOC only"],
                ["06_cloud_iam_and_api_abuse.md", "Internal", "SOC only"],
              ] : [
                ["company_handbook.txt", "Internal", "Policy-based"],
                ["security_notice.txt", "Internal", "Policy-based"],
                ["hr_confidential.txt", "Confidential", "HR only"],
              ]).map(([name, cls, access]) => (
                <div className="document-row" key={name}><FileText size={20} /><div><strong>{name}</strong><span>Indexed knowledge source · local prototype</span></div><span className="muted-tag">{cls}</span><span className={access === "HR only" ? "restricted-tag" : "pass-tag"}>{access}</span></div>
              ))}
            </div>
            <div className="panel-note standalone"><AlertTriangle size={17} /> This list is a configured display, not a live inventory query. Actual access depends on backend collection routing and authorization.</div>
          </div>
        )}

        {page === "Activity Logs" && (
          <div className="content"><div className="welcome-row"><div><div className="eyebrow">OBSERVABILITY / EVENTS</div><h1>Activity Logs</h1><p>Illustrative lab events only; these are not a live audit log.</p></div><Activity size={26} /></div>
            <div className="panel"><div className="log-row"><span className="log-time">CONFIG</span><CheckCircle2 size={17} /><div><strong>JWT-backed workspace</strong><span>Frontend uses the token returned by the login endpoint.</span></div></div><div className="log-row"><span className="log-time">RAG</span><Database size={17} /><div><strong>Knowledge retrieval</strong><span>Queries are routed by the backend identity and configured collections.</span></div></div><div className="log-row"><span className="log-time">NOTICE</span><AlertTriangle size={17} /><div><strong>Not a live SIEM feed</strong><span>No automatic ingestion, alert streaming, or containment is implemented by this screen.</span></div></div></div>
          </div>
        )}

        {page === "Settings" && (
          <div className="content"><div className="welcome-row"><div><div className="eyebrow">CONFIGURATION</div><h1>Settings</h1><p>Local prototype status.</p></div><Settings size={26} /></div>
            <div className="panel settings-panel"><h3>Signed-in identity</h3><p>Email: {session.email || "Not supplied"}</p><p>Department: {departmentLabel}</p><p>Role: {session.role || "Not supplied"}</p><h3>Backend connection</h3><p>Status: {backendStatus}</p><button className="primary-button" onClick={checkBackend}><Activity size={16} /> Check backend</button><h3>Security note</h3><p>The backend must remain the source of truth for identity and document authorization. Frontend navigation is not an access-control boundary.</p></div>
          </div>
        )}
      </main>
    </div>
  );
}

function Stat({ icon: Icon, label, value, detail, tone }) {
  return <div className="stat-card"><div className={`stat-icon ${tone}`}><Icon size={19} /></div><div className="stat-label">{label}</div><div className="stat-value">{value}</div><div className="stat-detail">{detail}</div></div>;
}

function PolicyRow({ title, desc, status, green }) {
  return <div className="policy-row"><div><strong>{title}</strong><span>{desc}</span></div><span className={green ? "pass-tag" : "restricted-tag"}>{status}</span></div>;
}

function ArrowIcon() {
  return <Activity size={19} />;
}
