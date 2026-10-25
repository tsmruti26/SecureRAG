import { useCallback, useEffect, useState } from "react";

const API = "http://localhost:8001";
const NEXT = {
  new: ["triage"], triage: ["investigating", "false_positive"],
  investigating: ["contained", "false_positive"], contained: ["eradicated"],
  eradicated: ["recovered"], reopened: ["investigating"],
};
const ACTION_TYPES = ["block_domain", "block_ip", "disable_account", "reset_credentials",
  "isolate_host", "revoke_sessions", "takedown_request", "other"];

async function call(token, path, method = "GET", body) {
  const res = await fetch(`${API}${path}`, {
    method,
    headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
    body: body ? JSON.stringify(body) : undefined,
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    const d = data.detail;
    throw new Error(typeof d === "string" ? d : "Request failed or not permitted.");
  }
  return data;
}

/** Button for the typosquatting results: sends the candidates that had DNS records. */
export function CreateIncidentFromScan({ token, scan }) {
  const [msg, setMsg] = useState("");
  const picked = (scan?.results || [])
    .filter((r) => r.registration_status === "dns_records_found")
    .map((r) => r.domain).slice(0, 50);
  if (!scan || picked.length === 0) return null;
  const create = async () => {
    try {
      const r = await call(token, "/api/soc/typosquatting-scan/incident", "POST",
        { domain: scan.original_domain, candidates: picked });
      setMsg(`Created ${r.incident_id}`);
    } catch (e) { setMsg(e.message); }
  };
  return (
    <div>
      <button onClick={create}>Create incident from {picked.length} candidates with DNS records</button>
      {msg && <span style={{ marginLeft: 8 }}>{msg}</span>}
    </div>
  );
}

export default function Incidents({ token, role }) {
  const [rows, setRows] = useState([]);
  const [sel, setSel] = useState(null);
  const [filters, setFilters] = useState({ status: "", severity: "" });
  const [text, setText] = useState("");
  const [err, setErr] = useState("");
  const isLead = role === "soc_lead";
  const isSoc = role === "soc_analyst" || isLead;

  const load = useCallback(async () => {
    const q = new URLSearchParams(Object.entries(filters).filter(([, v]) => v));
    try { setRows((await call(token, `/api/incidents?${q}`)).incidents); setErr(""); }
    catch (e) { setErr(e.message); }
  }, [token, filters]);
  useEffect(() => { load(); }, [load]);

  const open = async (id) => {
    try { setSel((await call(token, `/api/incidents/${id}`)).incident); setErr(""); }
    catch (e) { setErr(e.message); }
  };
  const act = async (path, body) => {
    try { await call(token, path, "POST", body); setText(""); await load(); if (sel) await open(sel.incident_id); }
    catch (e) { setErr(e.message); }
  };
  const needReason = () => { if (!text.trim()) { setErr("Enter a reason or note first."); return false; } return true; };
  const id = sel?.incident_id;

  return (
    <div style={{ display: "grid", gridTemplateColumns: "minmax(280px,1fr) 2fr", gap: 16 }}>
      <section>
        <h3>Incidents</h3>
        <select value={filters.status} onChange={(e) => setFilters({ ...filters, status: e.target.value })}>
          <option value="">any status</option>
          {["new", "triage", "investigating", "contained", "eradicated", "recovered", "closed", "false_positive", "reopened"]
            .map((s) => <option key={s}>{s}</option>)}
        </select>{" "}
        <select value={filters.severity} onChange={(e) => setFilters({ ...filters, severity: e.target.value })}>
          <option value="">any severity</option>
          {["low", "medium", "high", "critical"].map((s) => <option key={s}>{s}</option>)}
        </select>
        {role === "employee" && (
          <button style={{ marginLeft: 8 }} onClick={async () => {
            const title = window.prompt("What did you see? (short title)");
            const summary = title && window.prompt("Describe it");
            if (title && summary) act("/api/incidents/report", { title, summary });
          }}>Report suspected incident</button>
        )}
        {err && <p role="alert" style={{ color: "crimson" }}>{err}</p>}
        <ul style={{ listStyle: "none", padding: 0 }}>
          {rows.map((r) => (
            <li key={r.incident_id}>
              <button style={{ width: "100%", textAlign: "left" }} onClick={() => open(r.incident_id)}>
                {r.incident_id} · {r.status}{r.severity ? ` · ${r.severity}` : ""}<br />{r.title}
              </button>
            </li>
          ))}
          {rows.length === 0 && <li>No incidents visible to you.</li>}
        </ul>
      </section>

      <section>
        {!sel ? <p>Select an incident.</p> : (
          <>
            <h3>{sel.incident_id}: {sel.title}</h3>
            <p><b>Status:</b> {sel.status}{sel.severity && <> · <b>Severity:</b> {sel.severity} · <b>TLP:</b> {sel.tlp}</>}</p>
            {sel.summary && <p style={{ whiteSpace: "pre-wrap" }}>{sel.summary}</p>}
            {sel.ai_provenance && !sel.ai_provenance.human_verified && (
              <p style={{ color: "darkorange" }}>AI-generated content not yet verified by a second person.</p>
            )}
            {isSoc && (
              <>
                <input style={{ width: "100%" }} value={text} placeholder="Reason / note"
                  onChange={(e) => setText(e.target.value)} />
                <div style={{ margin: "8px 0" }}>
                  <button onClick={() => needReason() && act(`/api/incidents/${id}/notes`, { note: text })}>Add note</button>{" "}
                  {(NEXT[sel.status] || []).map((to) => (
                    <button key={to} onClick={() => needReason() && act(`/api/incidents/${id}/status`, { to, reason: text })}>→ {to}</button>
                  ))}{" "}
                  <select defaultValue="" onChange={(e) => e.target.value && needReason() &&
                    act(`/api/incidents/${id}/actions`, { action_type: e.target.value, reason: text })}>
                    <option value="">propose action…</option>
                    {ACTION_TYPES.map((a) => <option key={a}>{a}</option>)}
                  </select>{" "}
                  <button onClick={() => act(`/api/incidents/${id}/verify-ai`)}>Verify AI content</button>
                  {isLead && ["recovered", "false_positive"].includes(sel.status) && (
                    <button onClick={() => needReason() && act(`/api/incidents/${id}/close`, { reason: text })}>Close</button>)}
                  {isLead && sel.status === "closed" && (
                    <button onClick={() => needReason() && act(`/api/incidents/${id}/reopen`, { reason: text })}>Reopen</button>)}
                </div>
              </>
            )}
            <h4>Actions</h4>
            <ul>{(sel.actions || []).map((a) => (
              <li key={a.id}>{a.id} {a.type} — <b>{a.state}</b>{" "}
                {isLead && a.state === "proposed" && (<>
                  <button onClick={() => needReason() && act(`/api/incidents/${id}/actions/${a.id}/approve`, { reason: text })}>Approve</button>{" "}
                  <button onClick={() => needReason() && act(`/api/incidents/${id}/actions/${a.id}/reject`, { reason: text })}>Reject</button></>)}
                {isSoc && a.state === "approved" && (
                  <button onClick={() => needReason() && act(`/api/incidents/${id}/actions/${a.id}/executed`, { reason: text })}>Mark executed (manual)</button>)}
              </li>))}</ul>
            <h4>Indicators</h4>
            <ul>{(sel.indicators || []).map((i, n) => <li key={n}>{i.type}: {i.value} ({i.confidence} confidence)</li>)}</ul>
            <h4>Timeline</h4>
            <ul>{(sel.timeline || []).map((t, n) => <li key={n}>{t.ts} · {t.kind} · {t.event}</li>)}</ul>
          </>
        )}
      </section>
    </div>
  );
}
