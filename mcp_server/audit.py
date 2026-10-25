"""Append-only, hash-chained JSONL audit log. Never stores note bodies/secrets."""
from __future__ import annotations

import hashlib
import json
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path

GENESIS = "0" * 64


def args_hash(args: dict) -> str:
    return hashlib.sha256(json.dumps(args, sort_keys=True, default=str).encode()).hexdigest()[:16]


class AuditLog:
    def __init__(self, path: Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()

    def _last_hash(self) -> str:
        if not self.path.exists():
            return GENESIS
        last = GENESIS
        with self.path.open(encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    last = json.loads(line)["hash"]
        return last

    @staticmethod
    def _digest(entry: dict) -> str:
        body = {k: v for k, v in entry.items() if k != "hash"}
        return hashlib.sha256(json.dumps(body, sort_keys=True).encode()).hexdigest()

    def log(self, *, subject: str, role: str, action: str, resource_id: str | None,
            decision: str, rule_id: str, obligations=(), args: dict | None = None,
            request_id: str | None = None) -> dict:
        with self._lock:
            entry = {
                "ts": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                "subject": subject, "role": role, "action": action,
                "resource_id": resource_id, "decision": decision, "rule_id": rule_id,
                "obligations": list(obligations), "args_hash": args_hash(args or {}),
                "request_id": request_id or str(uuid.uuid4()),
                "prev_hash": self._last_hash(),
            }
            entry["hash"] = self._digest(entry)
            with self.path.open("a", encoding="utf-8") as f:
                f.write(json.dumps(entry) + "\n")
        return entry

    def entries(self) -> list[dict]:
        if not self.path.exists():
            return []
        with self.path.open(encoding="utf-8") as f:
            return [json.loads(line) for line in f if line.strip()]

    def verify(self) -> tuple[bool, int | None]:
        prev = GENESIS
        for i, e in enumerate(self.entries()):
            if e["prev_hash"] != prev or e["hash"] != self._digest(e):
                return False, i
            prev = e["hash"]
        return True, None
