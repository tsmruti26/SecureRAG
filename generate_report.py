"""Generate an HTML report (incidents + audit log) from the running SecureRAG API.
Usage: python generate_report.py [--role auditor|lead] [--open]
Default role is auditor (read-only, PII masked). Output: reports/securerag_report_<time>.html"""
import os, sys, secrets, json, html
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path
import httpx, jwt
from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parent
if not (ROOT / ".env").exists():
    ROOT = ROOT.parent
load_dotenv(ROOT / ".env")
BASE = os.getenv("API_BASE", "http://localhost:8001")
role = "lead" if "--role" in sys.argv and sys.argv[sys.argv.index("--role") + 1] == "lead" else "auditor"
api_role = {"lead": "soc_lead", "auditor": "auditor"}[role]

def token():
    e, p = os.getenv(f"DEMO_{role.upper()}_EMAIL", ""), os.getenv(f"DEMO_{role.upper()}_PASSWORD", "")
    if e and p:
        r = httpx.post(f"{BASE}/api/login", json={"email": e, "password": p}, timeout=30)
        if r.status_code == 200:
            return r.json()["access_token"]
    return jwt.encode({"sub": f"report.{role}@example.com", "department": "soc", "role": api_role,
                       "jti": secrets.token_hex(8), "exp": datetime.now(timezone.utc) + timedelta(minutes=10)},
                      os.environ["JWT_SECRET"], algorithm="HS256")

tok = token()
client = httpx.Client(base_url=BASE, headers={"Authorization": f"Bearer {tok}"}, timeout=60)

def rows(body):
    if isinstance(body, list): return body
    if isinstance(body, dict):
        for k in ("items", "incidents", "entries", "events", "results"):
            if isinstance(body.get(k), list): return body[k]
    return []

r = client.get("/api/incidents", params={"limit": 200}); r.raise_for_status()
incidents = rows(r.json())
r = client.get("/api/audit", params={"limit": 200}); r.raise_for_status()
audit = rows(r.json())

def g(d, *path, default=""):
    for k in path:
        d = d.get(k) if isinstance(d, dict) else None
        if d is None: return default
    return d

e = lambda v: html.escape(str(v))
by_status = Counter(g(i, "status") for i in incidents)
by_sev = Counter(g(i, "severity") for i in incidents)
now = datetime.now().strftime("%Y-%m-%d %H:%M")
out = ["<!doctype html><meta charset=utf-8><title>SecureRAG report</title><style>",
       "body{font:14px system-ui;margin:2rem;max-width:1100px}table{border-collapse:collapse;width:100%;margin:1rem 0}",
       "th,td{border:1px solid #ccc;padding:6px 8px;text-align:left;vertical-align:top}th{background:#f2f2f2}.k{display:inline-block;margin:0 1rem 1rem 0;padding:8px 14px;background:#eef;border-radius:6px}",
       "</style>", f"<h1>SecureRAG security report</h1><p>Generated {e(now)} as <b>{e(role)}</b> ", 
       "(data shown is what this role is allowed to see; free text is untrusted and escaped).</p>",
       f"<div class=k>Incidents: <b>{len(incidents)}</b></div>"]
out += [f"<div class=k>{e(s or 'n/a')}: <b>{n}</b></div>" for s, n in by_status.most_common()]
out += ["<h2>By severity</h2><p>" + ", ".join(f"{e(s or 'n/a')}: {n}" for s, n in by_sev.most_common()) + "</p>",
        "<h2>Incidents</h2><table><tr><th>ID</th><th>Title</th><th>Status</th><th>Severity</th><th>Category</th><th>TLP</th></tr>"]
for i in incidents:
    out.append("<tr>" + "".join(f"<td>{e(g(i, k))}</td>" for k in ("incident_id", "title", "status", "severity", "category", "tlp")) + "</tr>")
out += ["</table><h2>Recent audit events</h2><table><tr><th>Time</th><th>Subject</th><th>Action</th><th>Decision</th><th>Resource</th></tr>"]
for a in audit[-100:]:
    out.append("<tr>" + "".join(f"<td>{e(g(a, *k) if isinstance(k, tuple) else g(a, k))}</td>"
               for k in (("ts",), ("subject",), ("action",), ("decision",), ("resource",))) + "</tr>")
out.append("</table>")

dest = ROOT / "reports"; dest.mkdir(exist_ok=True)
path = dest / f"securerag_report_{datetime.now():%Y%m%d_%H%M}.html"
path.write_text("".join(out), encoding="utf-8")
print("Wrote", path, f"({len(incidents)} incidents, {len(audit)} audit events)")
if "--open" in sys.argv and hasattr(os, "startfile"): os.startfile(path)
