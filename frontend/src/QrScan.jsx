import { useState } from "react";

const API_BASE = "http://localhost:8001";

export default function QrScan({ token }) {
  const [url, setUrl] = useState("");
  const [brand, setBrand] = useState("");
  const [image, setImage] = useState(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [data, setData] = useState(null);
  const [created, setCreated] = useState({});

  const headers = { "Content-Type": "application/json", Authorization: `Bearer ${token}` };

  function pick(e) {
    const f = e.target.files?.[0];
    if (!f) return;
    if (f.size > 2_000_000) { setError("Image must be under 2 MB."); return; }
    const reader = new FileReader();
    reader.onload = () => { setImage(reader.result); setUrl(""); setError(""); };
    reader.readAsDataURL(f);
  }

  async function scan() {
    setBusy(true); setError(""); setData(null); setCreated({});
    try {
      const body = image ? { image_b64: image, brand_domain: brand } : { url, brand_domain: brand };
      const r = await fetch(`${API_BASE}/api/soc/qr-scan`, { method: "POST", headers, body: JSON.stringify(body) });
      const j = await r.json().catch(() => ({}));
      if (!r.ok) throw new Error(j.detail || `Scan failed (${r.status})`);
      setData(j);
    } catch (e) { setError(e.message); } finally { setBusy(false); }
  }

  async function createIncident(payload) {
    try {
      const r = await fetch(`${API_BASE}/api/soc/qr-scan/incident`, {
        method: "POST", headers, body: JSON.stringify({ url: payload, brand_domain: brand }),
      });
      const j = await r.json().catch(() => ({}));
      if (!r.ok) throw new Error(j.detail || `Failed (${r.status})`);
      setCreated((c) => ({ ...c, [payload]: j.incident_id || j.id || "created" }));
    } catch (e) { setError(e.message); }
  }

  return (
    <div className="panel standalone">
      <h2>QR phishing check</h2>
      <p className="chat-disclaimer">Upload a QR image or paste the decoded URL. The link is analysed for risk signals only and is never opened.</p>
      <input type="file" accept="image/png,image/jpeg" onChange={pick} />
      <p>or</p>
      <input value={url} onChange={(e) => { setUrl(e.target.value); setImage(null); }} placeholder="https://example.com/login" style={{ width: "100%" }} />
      <input value={brand} onChange={(e) => setBrand(e.target.value)} placeholder="Brand domain to compare (optional), e.g. mycompany.com" style={{ width: "100%", marginTop: 8 }} />
      <button className="text-button" disabled={busy || (!image && !url.trim())} onClick={scan}>{busy ? "Scanning..." : "Analyse"}</button>
      {error && <div className="panel scan-error" role="alert">{error}</div>}
      {data && data.results.map((r, i) => (
        <div key={i} className="panel" style={{ marginTop: 12 }}>
          <p><strong>{r.type === "url" ? r.url_defanged : r.payload}</strong></p>
          <p>Verdict: <strong>{r.verdict.replaceAll("_", " ")}</strong> (heuristic)</p>
          {r.signals.length > 0 && (
            <table className="scan-table"><tbody>
              {r.signals.map((s) => <tr key={s.signal}><td>{s.signal}</td><td>{s.detail}</td></tr>)}
            </tbody></table>
          )}
          <p className="chat-disclaimer">{r.note}</p>
          {r.type === "url" && (created[r.payload]
            ? <p>Incident {created[r.payload]} created.</p>
            : <button className="text-button" onClick={() => createIncident(r.payload)}>Create incident</button>)}
        </div>
      ))}
    </div>
  );
}
