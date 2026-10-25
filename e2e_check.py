"""End-to-end check of SecureRAG against a RUNNING API. Seeds demo incidents so the
Incidents tab shows records. Usage (repo root, API on :8001):  python scripts/e2e_check.py"""
import os, sys, secrets
from datetime import datetime, timedelta, timezone
from pathlib import Path
import httpx, jwt
from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parent
if not (ROOT / ".env").exists():
    ROOT = ROOT.parent
load_dotenv(ROOT / ".env")
BASE = os.getenv("API_BASE", "http://localhost:8001")
SECRET = os.getenv("JWT_SECRET", "")
http = httpx.Client(base_url=BASE, timeout=60)
results = []

def check(name, ok, detail=""):
    results.append((name, bool(ok)))
    print(f"  [{'PASS' if ok else 'FAIL'}] {name}" + (f"  -> {detail}" if not ok and detail else ""))

def hdr(tok): return {"Authorization": f"Bearer {tok}"}

def call(method, path, tok=None, **kw):
    r = http.request(method, path, headers=hdr(tok) if tok else None, **kw)
    try: body = r.json()
    except Exception: body = r.text
    return r.status_code, body

def find(obj, key):
    if isinstance(obj, dict):
        if key in obj and obj[key]: return obj[key]
        for v in obj.values():
            f = find(v, key)
            if f: return f
    if isinstance(obj, list):
        for v in obj:
            f = find(v, key)
            if f: return f

def login(dept):
    e = os.getenv(f"DEMO_{dept}_EMAIL", ""); p = os.getenv(f"DEMO_{dept}_PASSWORD", "")
    if not e or not p: return None
    s, b = call("POST", "/api/login", json={"email": e, "password": p})
    return b["access_token"] if s == 200 else None

def mint(role, email):  # dev token signed with JWT_SECRET (same as the API verifies)
    return jwt.encode({"sub": email, "department": "soc", "role": role, "jti": secrets.token_hex(8),
                       "exp": datetime.now(timezone.utc) + timedelta(minutes=30)}, SECRET, algorithm="HS256")

print(f"\nAPI: {BASE}")
s, _ = call("GET", "/api/health"); check("health", s == 200, s)
if s != 200: sys.exit("API not running")

print("\n== Login ==")
s, _ = call("POST", "/api/login", json={"email": "x@example.com", "password": "wrong"})
check("bad password -> 401", s == 401, s)
tok = {d: login(d) for d in ("HR", "ENGINEERING", "FINANCE", "SOC")}
for d, t in tok.items(): check(f"login {d}", t)
tok["LEAD"] = login("LEAD") or mint("soc_lead", "lead.e2e@example.com")
tok["AUDITOR"] = login("AUDITOR") or mint("auditor", "auditor.e2e@example.com")
hr, eng, soc, lead, aud = tok["HR"], tok["ENGINEERING"], tok["SOC"], tok["LEAD"], tok["AUDITOR"]
if not (hr and eng and soc): sys.exit("Need HR, ENGINEERING and SOC demo logins in .env")

print("\n== RAG chat (needs Groq + Chroma) ==")
s, b = call("POST", "/api/chat", hr, json={"question": "What is Alex Example's salary?"})
check("HR chat works", s == 200, f"{s} {str(b)[:150]}")
if s == 200: check("HR sees hr_confidential", any(x["source"] == "hr_confidential.txt" for x in b["sources"]))
s, b = call("POST", "/api/chat", eng, json={"question": "What is Alex Example's salary?"})
check("Engineering chat works", s == 200, f"{s} {str(b)[:150]}")
if s == 200: check("Engineering never gets HR docs", all(x["source"] != "hr_confidential.txt" for x in b["sources"]))
s, b = call("POST", "/api/chat", soc, json={"question": "How do I triage a SIEM alert?"})
check("SOC chat works", s == 200, f"{s} {str(b)[:150]}")

print("\n== Employee ==")
s, b = call("POST", "/api/incidents/report", hr, json={"title": "E2E: suspicious email", "summary": "Received a login-reset email I did not request."})
check("employee reports incident", s == 200, f"{s} {str(b)[:200]}")
emp_id = find(b, "incident_id")
s, b = call("GET", "/api/incidents", hr); check("employee lists own incidents", s == 200, s)
s, _ = call("POST", "/api/soc/typosquatting-scan", hr, json={"domain": "example.com", "check_dns": False})
check("employee blocked from scanner (403)", s == 403, s)
s, _ = call("GET", "/api/audit", hr); check("employee blocked from audit", s in (401, 403), s)
s, _ = call("POST", "/api/incidents/INC-2099-000001/close", hr, json={"reason": "x"}); check("employee cannot close", s in (403, 404, 400), s)
s, a = call("GET", f"/api/incidents/{emp_id}", eng) if emp_id else (0, "")
check("other employee cannot read it", s in (403, 404), s)

print("\n== SOC analyst ==")
s, b = call("POST", "/api/soc/typosquatting-scan", soc, json={"domain": "example.com", "check_dns": False})
check("typosquat scan", s == 200 and b.get("results"), s)
cands = [r["domain"] for r in b.get("results", [])][:3] if s == 200 else []
s, b = call("POST", "/api/soc/typosquatting-scan/incident", soc, json={"domain": "example.com", "candidates": cands, "note": "E2E seed"})
check("create incident from scan", s == 200, f"{s} {str(b)[:200]}")
inc = find(b, "incident_id")
s, _ = call("POST", "/api/soc/typosquatting-scan/incident", soc, json={"domain": "example.com", "candidates": ["evil-not-generated.com"]})
check("injected IOC rejected (400)", s == 400, s)
if inc:
    s, _ = call("POST", f"/api/incidents/{inc}/notes", soc, json={"note": "Checked registrar data.", "kind": "analysis"}); check("add note", s == 200, s)
    s, _ = call("POST", f"/api/incidents/{inc}/status", soc, json={"to": "triage", "reason": "Starting triage"}); check("status new->triage", s == 200, s)
    s, _ = call("POST", f"/api/incidents/{inc}/status", soc, json={"to": "investigating", "reason": "Confirmed"}); check("status ->investigating", s == 200, s)
    s, spec = call("GET", "/openapi.json")
    enum = spec["components"]["schemas"]["Proposal"]["properties"]["action_type"] if s == 200 else {}
    enum = (enum.get("enum") or (spec["components"]["schemas"].get("ActionType", {}).get("enum") if s == 200 else None) or ["block_domain"])
    s, b = call("POST", f"/api/incidents/{inc}/actions", soc, json={"action_type": enum[0], "reason": "Block lookalike domains"})
    check("propose action", s == 200, f"{s} {str(b)[:200]}")
    act = find(b, "action_id")
    s, g = call("GET", f"/api/incidents/{inc}", soc)
    act = act or (find(g.get("actions", []), "action_id") if isinstance(g, dict) else None)
    if act:
        s, _ = call("POST", f"/api/incidents/{inc}/actions/{act}/approve", soc, json={"reason": "self"})
        check("four-eyes: proposer cannot approve", s in (403, 409, 400), s)
        s, _ = call("POST", f"/api/incidents/{inc}/actions/{act}/approve", lead, json={"reason": "Approved by lead"})
        check("lead approves action", s == 200, s)
    s, _ = call("POST", f"/api/incidents/{inc}/close", soc, json={"reason": "try"}); check("analyst cannot close", s in (403, 409, 400), s)
    s, _ = call("POST", f"/api/incidents/{inc}/verify-ai", lead); check("lead verifies AI content", s == 200, s)
    for st in ("contained", "eradicated", "recovered"):
        s, _ = call("POST", f"/api/incidents/{inc}/status", lead, json={"to": st, "reason": "E2E walk"}); check(f"status ->{st}", s == 200, s)
    s, _ = call("POST", f"/api/incidents/{inc}/close", lead, json={"reason": "Resolved in E2E", "root_cause": "n/a", "lessons_learned": "n/a"})
    check("lead closes incident", s == 200, s)
    s, _ = call("POST", f"/api/incidents/{inc}/notes", lead, json={"note": "late"}); check("closed incident read-only", s != 200, s)

print("\n== Auditor / audit log ==")
s, b = call("GET", "/api/incidents", aud); check("auditor lists incidents", s == 200, s)
s, _ = call("POST", f"/api/incidents/{inc}/notes", aud, json={"note": "x"}) if inc else (403, "")
check("auditor cannot write", s in (403, 409, 400), s)
s, b = call("GET", "/api/audit", lead); check("lead reads audit log", s == 200, s)
s, b = call("GET", "/api/audit", aud); check("auditor reads audit log", s == 200, s)

print("\n== Open (not closed) record for the dashboard ==")
s, b = call("POST", "/api/soc/typosquatting-scan/incident", soc, json={"domain": "google.com", "candidates": [], "note": ""}) if False else (0, "")
s, b = call("POST", "/api/soc/typosquatting-scan", soc, json={"domain": "google.com", "check_dns": False})
c2 = [r["domain"] for r in b.get("results", [])][:2] if s == 200 else []
s, b = call("POST", "/api/soc/typosquatting-scan/incident", soc, json={"domain": "google.com", "candidates": c2, "note": "Open demo record"})
check("seed open incident", s == 200, s)

print("\n== Logout / revocation ==")
s, _ = call("POST", "/api/logout", hr); check("logout", s == 200, s)
s, _ = call("GET", "/api/incidents", hr); check("revoked token rejected (401)", s == 401, s)

p = sum(ok for _, ok in results)
print(f"\n{p}/{len(results)} passed")
for n, ok in results:
    if not ok: print("  FAILED:", n)
print("\nDashboard: open http://localhost:5173 and log in as the DEMO_SOC account ->")
print("  Incidents tab: 1 closed typosquatting incident, 1 open one, plus the employee report.")
print("  Log in as the DEMO_HR account -> Incidents shows only the employee's own report.")
sys.exit(0 if p == len(results) else 1)
