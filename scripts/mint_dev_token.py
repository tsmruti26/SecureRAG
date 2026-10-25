"""Mint a short-lived DEV token for MCP testing. Refuses unless ALLOW_DEV_TOKENS=1.
Usage: ALLOW_DEV_TOKENS=1 python scripts/mint_dev_token.py soc_lead soc lead@example.com"""
import os
import sys
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

import jwt
from dotenv import load_dotenv

load_dotenv(Path(__file__).resolve().parent.parent / ".env")
if os.getenv("ALLOW_DEV_TOKENS") != "1":
    sys.exit("Set ALLOW_DEV_TOKENS=1 to mint dev tokens (never in production).")
role, department, email = sys.argv[1:4]
print(jwt.encode({"sub": email, "role": role, "department": department, "jti": str(uuid.uuid4()),
                  "exp": datetime.now(timezone.utc) + timedelta(minutes=30)},
                 os.environ["JWT_SECRET"], algorithm="HS256"))
