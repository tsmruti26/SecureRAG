"""v2 tests: four-eyes approvals, rate limit, API router, policy-driven retrieval parity."""
import os
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
os.environ.setdefault("JWT_SECRET", "unit-test-secret-unit-test-secret-1234")
os.environ["SECURERAG_DATA_DIR"] = tempfile.mkdtemp()
os.environ["SECURERAG_POLICY_DIR"] = str(ROOT / "policies")

import jwt
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from langchain_core.documents import Document

from authorization import retrieve_authorized_documents
from incident_api import build_router
from mcp_server import server as srv
from mcp_server.incidents import IncidentCreate, Indicator
from typosquatting import generate_variants

CURRENT = {}
app = FastAPI()
app.include_router(build_router(lambda: CURRENT["user"]))
client = TestClient(app)


def api_as(role, dept, email):
    CURRENT["user"] = {"username": email, "role": role, "department": dept, "jti": "j1"}


def mcp_as(role, dept, email):
    os.environ["SECURERAG_MCP_TOKEN"] = jwt.encode(
        {"sub": email, "role": role, "department": dept,
         "exp": datetime.now(timezone.utc) + timedelta(minutes=5)}, os.environ["JWT_SECRET"], "HS256")


def new_incident(**kw):
    mcp_as("soc_analyst", "soc", "analyst@example.com")
    return srv.incident_create(IncidentCreate(title="Test incident", summary="s", **kw))["incident_id"]


def test_action_approval_requires_different_lead_and_manual_execution():
    iid = new_incident()
    mcp_as("soc_lead", "soc", "lead1@example.com")
    act = srv.incident_propose_action(iid, "block_domain", "lookalike domain")["action_id"]
    mcp_as("soc_analyst", "soc", "analyst@example.com")
    with pytest.raises(PermissionError): srv.incident_approve_action(iid, act, "ok")   # not a lead
    mcp_as("soc_lead", "soc", "lead1@example.com")
    with pytest.raises(PermissionError): srv.incident_approve_action(iid, act, "self")  # four-eyes
    mcp_as("soc_lead", "soc", "lead2@example.com")
    with pytest.raises(PermissionError): srv.incident_approve_action(iid, act, " ")     # reason
    assert srv.incident_approve_action(iid, act, "confirmed")["state"] == "approved"
    with pytest.raises(ValueError): srv.incident_approve_action(iid, act, "again")      # not proposed
    mcp_as("soc_analyst", "soc", "analyst@example.com")
    assert srv.incident_mark_executed(iid, act, "blocked in DNS")["state"] == "executed_manually"


def test_cannot_mark_unapproved_action_executed():
    iid = new_incident()
    mcp_as("soc_analyst", "soc", "analyst@example.com")
    act = srv.incident_propose_action(iid, "block_ip", "scanner")["action_id"]
    with pytest.raises(ValueError): srv.incident_mark_executed(iid, act, "skip approval")


def test_creator_cannot_verify_own_ai_content():
    iid = new_incident(ai_generated_sections=["summary"])
    mcp_as("soc_analyst", "soc", "analyst@example.com")
    with pytest.raises(PermissionError): srv.incident_verify_ai(iid)
    mcp_as("soc_analyst", "soc", "second@example.com")
    srv.incident_verify_ai(iid)


def test_rate_limit(monkeypatch):
    monkeypatch.setenv("SECURERAG_RATE_LIMIT", "3")
    srv._rate.clear()
    mcp_as("soc_analyst", "soc", "rate@example.com")
    for _ in range(3): srv.incident_list()
    with pytest.raises(PermissionError, match="Rate limit"): srv.incident_list()
    srv._rate.clear()


# ---------------- API router -----------------------------------------------
def test_api_employee_report_and_isolation():
    api_as("employee", "hr", "bob@example.com")
    r = client.post("/api/incidents/report", json={"title": "Odd email", "summary": "please check"})
    assert r.status_code == 200
    iid = r.json()["incident_id"]
    assert client.get(f"/api/incidents/{iid}").status_code == 200
    api_as("employee", "finance", "eve@example.com")
    assert client.get(f"/api/incidents/{iid}").status_code == 403
    assert client.post("/api/incidents", json={"title": "nope!", "summary": "x"}).status_code == 403
    assert client.get("/api/audit").status_code == 403


def test_api_scan_to_incident_validates_candidates():
    variants = generate_variants("example.com")[:2]
    api_as("soc_analyst", "soc", "analyst@example.com")
    ok = client.post("/api/soc/typosquatting-scan/incident",
                     json={"domain": "example.com", "candidates": variants, "note": "seen in logs"})
    assert ok.status_code == 200, ok.text
    inc = client.get(f"/api/incidents/{ok.json()['incident_id']}").json()["incident"]
    assert {i["value"] for i in inc["indicators"]} == set(variants)
    assert all(i["confidence"] == "low" for i in inc["indicators"])
    assert inc["attack"]["techniques"] == ["T1566.002"]
    bad = client.post("/api/soc/typosquatting-scan/incident",
                      json={"domain": "example.com", "candidates": ["evil.com"]})
    assert bad.status_code == 400
    api_as("employee", "hr", "bob@example.com")
    assert client.post("/api/soc/typosquatting-scan/incident",
                       json={"domain": "example.com", "candidates": variants}).status_code == 403


def test_api_full_lifecycle_and_validation():
    api_as("soc_analyst", "soc", "analyst@example.com")
    iid = client.post("/api/incidents", json={"title": "Lifecycle", "summary": "s"}).json()["incident_id"]
    assert client.post(f"/api/incidents/{iid}/status", json={"to": "closed", "reason": "x"}).status_code == 400
    assert client.post(f"/api/incidents/{iid}/status", json={"to": "bogus", "reason": "x"}).status_code == 422
    for to in ("investigating", "contained", "eradicated", "recovered"):
        assert client.post(f"/api/incidents/{iid}/status", json={"to": to, "reason": "ok"}).status_code == 200
    api_as("soc_lead", "soc", "lead@example.com")
    assert client.post(f"/api/incidents/{iid}/close", json={"reason": "done"}).status_code == 200
    assert client.get("/api/audit").json()["chain_ok"] is True


# ---------------- retrieval parity (mock stores, no Chroma needed) ---------
class Store:
    DOCS = [Document(page_content="handbook", metadata={"source": "h.txt", "department": "all", "classification": "internal"}),
            Document(page_content="salary", metadata={"source": "hr.txt", "department": "hr", "classification": "confidential"}),
            Document(page_content="playbook", metadata={"source": "p.md", "department": "soc", "classification": "internal"}),
            Document(page_content="odd", metadata={"source": "x.txt", "department": "hr", "classification": "unknown"}),
            Document(page_content="nometa", metadata={"source": "n.txt"})]

    def similarity_search(self, q, k=10, filter=None):  # ignores filter: post-check must hold
        return list(self.DOCS)


def sources(user):
    return {d.metadata["source"] for d in retrieve_authorized_documents(Store(), "q", user)}


def test_retrieval_matches_legacy_rules():
    assert sources({"username": "b", "department": "hr", "role": "employee"}) == {"h.txt", "hr.txt"}
    assert sources({"username": "a", "department": "engineering", "role": "employee"}) == {"h.txt"}
    assert sources({"username": "f", "department": "finance"}) == {"h.txt"}      # legacy shape
    assert sources({"username": "s", "department": "soc", "role": "soc_analyst"}) == {"p.md"}
    assert sources({"username": "l", "department": "soc", "role": "soc_lead"}) == {"p.md"}
    assert sources({"username": "x"}) == set()
    assert sources({"username": "x", "department": "marketing", "role": "employee"}) == set()
