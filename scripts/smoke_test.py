import asyncio, os, sys, uuid, jwt
from datetime import datetime, timedelta, timezone
from pathlib import Path
from dotenv import load_dotenv
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

load_dotenv(Path(".env"))
SECRET = os.environ["JWT_SECRET"]

def token(role, dept, email):
    return jwt.encode({"sub": email, "role": role, "department": dept, "jti": str(uuid.uuid4()),
        "exp": datetime.now(timezone.utc) + timedelta(minutes=10)}, SECRET, "HS256")

async def run_as(role, dept, email, calls):
    env = {**os.environ, "SECURERAG_MCP_TOKEN": token(role, dept, email)}
    params = StdioServerParameters(command=sys.executable, args=["-m", "mcp_server.server"], env=env)
    async with stdio_client(params) as (r, w):
        async with ClientSession(r, w) as s:
            await s.initialize()
            print(f"\n=== {role} ({email}) ===")
            for name, args in calls:
                res = await s.call_tool(name, args)
                text = res.content[0].text if res.content else ""
                print(("DENIED/ERR " if res.isError else "OK ") + name + ": " + text[:200].replace("\n", " "))

async def main():
    await run_as("employee", "hr", "bob@example.com", [
        ("incident_report_suspected", {"title": "Weird login email", "summary": "Got a password reset I did not request"}),
        ("incident_list", {}),
        ("incident_create", {"payload": {"title": "Not allowed", "summary": "x"}}),
    ])
    await run_as("soc_analyst", "soc", "analyst@example.com", [
        ("incident_create", {"payload": {"title": "Typosquat g00gle.com", "summary": "Lookalike domain found",
            "severity": "high", "category": "domain_abuse", "source": "typosquatting_scan",
            "techniques": ["T1566.002"], "reporter_email": "victim@example.com"}}),
        ("incident_list", {}),
        ("incident_close", {"incident_id": "INC-2026-000002", "reason": "try"}),
    ])
    await run_as("soc_lead", "soc", "lead@example.com", [
        ("incident_get", {"incident_id": "INC-2026-000002"}),
        ("audit_query", {"limit": 5}),
    ])
asyncio.run(main())
