"""SOC QR-phishing routes. Analysis only (no URL is ever fetched). Incident creation reuses
the policy-checked incident core, so RBAC and audit apply."""
import base64
import binascii
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from qr_phishing import MAX_IMAGE_BYTES, analyze_payload, decode_qr


class QrScanRequest(BaseModel):
    url: Optional[str] = Field(default=None, max_length=2048)
    image_b64: Optional[str] = Field(default=None, max_length=3_000_000)
    brand_domain: str = Field(default="", max_length=253)


class QrIncidentRequest(BaseModel):
    url: str = Field(min_length=4, max_length=2048)
    brand_domain: str = Field(default="", max_length=253)
    note: str = Field(default="", max_length=1000)


def build_router(get_current_user) -> APIRouter:
    router = APIRouter()

    def require_soc(user: dict):
        if user.get("department") != "soc" or user.get("role") not in {"soc_analyst", "soc_lead"}:
            raise HTTPException(status_code=403, detail="Only SOC analysts can use this scanner.")

    @router.post("/api/soc/qr-scan")
    def qr_scan(body: QrScanRequest, user: dict = Depends(get_current_user)):
        require_soc(user)
        if bool(body.url) == bool(body.image_b64):
            raise HTTPException(status_code=400, detail="Provide exactly one of url or image_b64.")
        if body.url:
            payloads, source = [body.url], "pasted_url"
        else:
            try:
                raw = base64.b64decode(body.image_b64.split(",")[-1], validate=False)
                if len(raw) > MAX_IMAGE_BYTES:
                    raise ValueError("Image too large (max 2 MB).")
                payloads, source = decode_qr(raw), "image"
            except (binascii.Error, ValueError) as exc:
                raise HTTPException(status_code=400, detail=str(exc) or "Bad image.") from exc
            except ImportError as exc:
                raise HTTPException(status_code=501, detail="Install opencv-python-headless numpy.") from exc
        if not payloads:
            raise HTTPException(status_code=422, detail="No QR code found in the image.")
        return {"source": source,
                "results": [analyze_payload(p, body.brand_domain) for p in payloads]}

    @router.post("/api/soc/qr-scan/incident")
    def qr_incident(body: QrIncidentRequest, user: dict = Depends(get_current_user)):
        require_soc(user)
        from fastapi import HTTPException as HE  # noqa: F401
        from mcp_server import server as core
        from mcp_server.incidents import Asset, IncidentCreate, Indicator
        from mcp_server.policy import Subject

        analysis = analyze_payload(body.url, body.brand_domain)  # re-derived server-side
        if analysis["type"] != "url":
            raise HTTPException(status_code=400, detail="Only URL payloads can become incidents.")
        host = analysis["host"]
        signals = ", ".join(s["signal"] for s in analysis["signals"]) or "none"
        summary = (f"Analyst-submitted QR code pointing to {analysis['url_defanged']}. Heuristic "
                   f"signals: {signals}. The URL was not visited; these signals do not prove malicious intent.")
        if body.note.strip():
            summary += f"\nAnalyst note: {body.note.strip()}"
        indicators = [Indicator(type="url", value=body.url.strip(), source="qr_scan", confidence="low")]
        assets = []
        if not analysis["host_is_ip"]:
            indicators.append(Indicator(type="domain", value=host, source="qr_scan", confidence="low"))
        else:
            indicators.append(Indicator(type="ip", value=host, source="qr_scan", confidence="low"))
        payload = IncidentCreate(
            title=f"QR phishing suspect: {host}"[:200], summary=summary[:4000], severity="medium",
            category="phishing", source="user_report", tactics=["TA0001"], techniques=["T1566.002"],
            affected_assets=assets, indicators=indicators)
        subject = Subject(str(user["username"]).strip().lower(), user["role"], user["department"])
        try:
            with core.acting_as(subject):
                return core.incident_create(payload)
        except PermissionError as exc:
            raise HTTPException(status_code=403, detail=str(exc))
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)[:500])

    return router
