"""FastAPI routes for incidents. Same policy engine and audit log as the MCP server:
the JWT already verified by api.get_current_user becomes the acting subject."""
import os
from pathlib import Path
from typing import Literal, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from mcp_server import server as core
from mcp_server.incidents import (ActionType, Asset, Category, EventKind, Indicator,
                                  IncidentCreate, Severity, Status)
from mcp_server.policy import Subject
from typosquatting import generate_variants, normalize_domain

BASE_DIR = Path(__file__).resolve().parent


def _revoked_path() -> Path:
    return Path(os.getenv("SECURERAG_REVOKED_JTI", BASE_DIR / "mcp_data" / "revoked_jti.txt"))


def revoked_jtis() -> set:
    p = _revoked_path()
    return set(p.read_text().split()) if p.exists() else set()


def revoke_jti(jti: str) -> None:
    p = _revoked_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    with p.open("a") as f:
        f.write(jti + "\n")


class Reason(BaseModel):
    reason: str = Field(min_length=1, max_length=1000)


class Report(BaseModel):
    title: str = Field(min_length=3, max_length=200)
    summary: str = Field(min_length=1, max_length=4000)


class StatusChange(Reason):
    to: Status


class Note(BaseModel):
    note: str = Field(min_length=1, max_length=2000)
    kind: EventKind = "analysis"


class Proposal(Reason):
    action_type: ActionType


class Close(Reason):
    root_cause: str = Field(default="", max_length=2000)
    lessons_learned: str = Field(default="", max_length=2000)


class ScanIncident(BaseModel):
    domain: str = Field(min_length=4, max_length=253)
    candidates: list[str] = Field(min_length=1, max_length=50)
    note: str = Field(default="", max_length=1000)


def build_router(get_current_user) -> APIRouter:
    router = APIRouter()

    def run(user: dict, fn, *args, **kwargs):
        subject = Subject(str(user["username"]).strip().lower(), user["role"], user["department"])
        try:
            with core.acting_as(subject):
                return fn(*args, **kwargs)
        except PermissionError as exc:
            raise HTTPException(status_code=403, detail=str(exc))
        except ValueError as exc:  # includes pydantic validation errors
            raise HTTPException(status_code=400, detail=str(exc)[:500])
        except RuntimeError as exc:
            raise HTTPException(status_code=409, detail=str(exc))

    @router.get("/api/incidents")
    def list_incidents(status: Optional[Status] = None, severity: Optional[Severity] = None,
                       category: Optional[Category] = None, limit: int = 20, offset: int = 0,
                       user: dict = Depends(get_current_user)):
        return run(user, core.incident_list, status, severity, category, limit, offset)

    @router.get("/api/incidents/{incident_id}")
    def get_incident(incident_id: str, user: dict = Depends(get_current_user)):
        return run(user, core.incident_get, incident_id)

    @router.post("/api/incidents")
    def create_incident(payload: IncidentCreate, user: dict = Depends(get_current_user)):
        return run(user, core.incident_create, payload)

    @router.post("/api/incidents/report")
    def report(body: Report, user: dict = Depends(get_current_user)):
        return run(user, core.incident_report_suspected, body.title, body.summary)

    @router.post("/api/incidents/{incident_id}/status")
    def set_status(incident_id: str, body: StatusChange, user: dict = Depends(get_current_user)):
        return run(user, core.incident_update_status, incident_id, body.to, body.reason)

    @router.post("/api/incidents/{incident_id}/notes")
    def add_note(incident_id: str, body: Note, user: dict = Depends(get_current_user)):
        return run(user, core.incident_add_note, incident_id, body.note, body.kind)

    @router.post("/api/incidents/{incident_id}/actions")
    def propose(incident_id: str, body: Proposal, user: dict = Depends(get_current_user)):
        return run(user, core.incident_propose_action, incident_id, body.action_type, body.reason)

    @router.post("/api/incidents/{incident_id}/actions/{action_id}/{decision}")
    def decide_action(incident_id: str, action_id: str,
                      decision: Literal["approve", "reject", "executed"], body: Reason,
                      user: dict = Depends(get_current_user)):
        fn = {"approve": core.incident_approve_action, "reject": core.incident_reject_action,
              "executed": core.incident_mark_executed}[decision]
        return run(user, fn, incident_id, action_id, body.reason)

    @router.post("/api/incidents/{incident_id}/verify-ai")
    def verify_ai(incident_id: str, user: dict = Depends(get_current_user)):
        return run(user, core.incident_verify_ai, incident_id)

    @router.post("/api/incidents/{incident_id}/close")
    def close(incident_id: str, body: Close, user: dict = Depends(get_current_user)):
        return run(user, core.incident_close, incident_id, body.reason,
                   body.root_cause, body.lessons_learned)

    @router.post("/api/incidents/{incident_id}/reopen")
    def reopen(incident_id: str, body: Reason, user: dict = Depends(get_current_user)):
        return run(user, core.incident_reopen, incident_id, body.reason)

    @router.get("/api/audit")
    def audit(limit: int = 50, user: dict = Depends(get_current_user)):
        return run(user, core.audit_query, limit)

    @router.post("/api/soc/typosquatting-scan/incident")
    def incident_from_scan(body: ScanIncident, user: dict = Depends(get_current_user)):
        """Create an incident from analyst-selected scan candidates. Candidates must be
        genuine generated variants of the domain, so arbitrary IOCs cannot be injected."""
        try:
            original = normalize_domain(body.domain)
            allowed = set(generate_variants(original))
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc))
        chosen = sorted({c.strip().lower() for c in body.candidates})
        if any(c not in allowed for c in chosen):
            raise HTTPException(status_code=400, detail="Candidates must come from the scan.")
        summary = (f"Analyst-selected lookalike candidates of {original}. They were generated "
                   "heuristically; DNS records or registration do not prove malicious intent.")
        if body.note.strip():
            summary += f"\nAnalyst note: {body.note.strip()}"
        payload = IncidentCreate(
            title=f"Typosquatting candidates for {original}", summary=summary[:4000],
            severity="medium", category="domain_abuse", source="typosquatting_scan",
            tactics=["TA0001"], techniques=["T1566.002"],
            affected_assets=[Asset(type="domain", id=original, criticality="high")],
            indicators=[Indicator(type="domain", value=c, source="typosquatting_scan",
                                  confidence="low") for c in chosen])
        return run(user, core.incident_create, payload)

    @router.post("/api/logout")
    def logout(user: dict = Depends(get_current_user)):
        if user.get("jti"):
            revoke_jti(user["jti"])
        return {"status": "logged_out"}

    return router
