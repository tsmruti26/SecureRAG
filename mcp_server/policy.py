"""Small ABAC policy engine: YAML rules, explicit deny wins, default deny.

decide(subject, action, resource) -> Decision
Rules are evaluated in file order. Any matching `deny` rule wins; otherwise
the FIRST matching `allow` rule is used, so put specific rules first.
Unknown condition keys raise at load time (fail closed, not silently open).
"""
from __future__ import annotations

import copy
import hashlib
from dataclasses import dataclass
from fnmatch import fnmatchcase
from pathlib import Path

import yaml

MASK = "[MASKED]"

RULE_KEYS = {"id", "effect", "subject", "action", "resource", "mask",
             "columns_only", "kb_scopes", "obligations", "description"}
SUBJECT_KEYS = {"role", "department"}
RESOURCE_KEYS = {"tlp_in", "tlp_not", "unless_owner", "reporter_is_subject",
                 "status_in", "requires_ai_verified", "collection"}


@dataclass(frozen=True)
class Subject:
    id: str
    role: str
    department: str = ""

    @property
    def ref(self) -> str:
        """Stable pseudonymous reference stored instead of the raw email."""
        return "user:" + hashlib.sha256(self.id.lower().encode()).hexdigest()[:16]


@dataclass(frozen=True)
class Decision:
    allow: bool
    rule_id: str
    reason: str = ""
    mask: tuple = ()
    columns_only: tuple = ()
    kb_scopes: tuple = ()
    obligations: tuple = ()


DEFAULT_DENY = Decision(False, "default-deny", "no matching allow rule")


def _as_list(value):
    if value is None:
        return []
    return list(value) if isinstance(value, (list, tuple)) else [value]


class PolicyEngine:
    def __init__(self, rules: list[dict]):
        self.rules = list(rules)
        self._validate()

    @classmethod
    def from_dir(cls, path) -> "PolicyEngine":
        rules: list[dict] = []
        for file in sorted(Path(path).glob("*.yaml")):
            data = yaml.safe_load(file.read_text(encoding="utf-8")) or {}
            rules.extend(data.get("rules", []))
        return cls(rules)

    def _validate(self) -> None:
        seen = set()
        for rule in self.rules:
            rid = rule.get("id")
            if not rid or rid in seen:
                raise ValueError(f"Missing or duplicate rule id: {rid!r}")
            seen.add(rid)
            if rule.get("effect") not in {"allow", "deny"}:
                raise ValueError(f"{rid}: effect must be allow or deny")
            if "action" not in rule:
                raise ValueError(f"{rid}: action is required")
            if set(rule) - RULE_KEYS:
                raise ValueError(f"{rid}: unknown keys {set(rule) - RULE_KEYS}")
            if set(rule.get("subject", {})) - SUBJECT_KEYS:
                raise ValueError(f"{rid}: unknown subject keys")
            if set(rule.get("resource", {})) - RESOURCE_KEYS:
                raise ValueError(f"{rid}: unknown resource keys")

    # ---- matching -------------------------------------------------------
    @staticmethod
    def _subject_ok(rule, subject: Subject) -> bool:
        cond = rule.get("subject", {})
        for key in ("role", "department"):
            allowed = _as_list(cond.get(key))
            if allowed and "*" not in allowed and getattr(subject, key) not in allowed:
                return False
        return True

    @staticmethod
    def _action_ok(rule, action: str) -> bool:
        return any(fnmatchcase(action, p) for p in _as_list(rule["action"]))

    @staticmethod
    def _resource_ok(rule, subject: Subject, resource: dict | None) -> bool:
        cond = rule.get("resource", {})
        if not cond or resource is None:
            return True  # action-level check; row checks happen per resource
        tlp = str(resource.get("tlp", "")).lower()
        if "tlp_in" in cond and tlp not in _as_list(cond["tlp_in"]):
            return False
        if "tlp_not" in cond and tlp in _as_list(cond["tlp_not"]):
            owner = resource.get("owner")
            if not (cond.get("unless_owner") and owner and owner == subject.id):
                return False
        if cond.get("reporter_is_subject") and resource.get("reporter_ref") != subject.ref:
            return False
        if "status_in" in cond and resource.get("status") not in _as_list(cond["status_in"]):
            return False
        if cond.get("requires_ai_verified") and not resource.get("ai_content_verified"):
            return False
        if "collection" in cond and resource.get("collection") not in _as_list(cond["collection"]):
            return False
        return True

    def _matches(self, rule, subject, action, resource) -> bool:
        return (self._subject_ok(rule, subject)
                and self._action_ok(rule, action)
                and self._resource_ok(rule, subject, resource))

    # ---- public API -----------------------------------------------------
    def decide(self, subject: Subject, action: str, resource: dict | None = None) -> Decision:
        for rule in self.rules:
            if (rule["effect"] == "deny"
                    and not (rule.get("resource") and resource is None)  # row-deny needs a row
                    and self._matches(rule, subject, action, resource)):
                return Decision(False, rule["id"], rule.get("description", "explicit deny"))
        for rule in self.rules:
            if rule["effect"] == "allow" and self._matches(rule, subject, action, resource):
                return Decision(
                    True, rule["id"],
                    mask=tuple(rule.get("mask", [])),
                    columns_only=tuple(rule.get("columns_only", [])),
                    kb_scopes=tuple(tuple(sorted(s.items())) for s in rule.get("kb_scopes", [])),
                    obligations=tuple(rule.get("obligations", [])),
                )
        return DEFAULT_DENY

    def allowed_actions(self, subject: Subject, actions) -> list[str]:
        return [a for a in actions if self.decide(subject, a).allow]


# ---- column controls -----------------------------------------------------
def _mask_path(obj, parts):
    if not parts or not isinstance(obj, dict) or parts[0] not in obj:
        return
    if len(parts) == 1:
        if obj[parts[0]] not in (None, "", [], {}):
            obj[parts[0]] = MASK
    else:
        _mask_path(obj[parts[0]], parts[1:])


def apply_columns(row: dict, decision: Decision) -> dict:
    """Return a copy of row with column policy applied (never mutates input)."""
    out = copy.deepcopy(row)
    if decision.columns_only:
        out = {k: v for k, v in out.items() if k in decision.columns_only}
    for path in decision.mask:
        _mask_path(out, path.split("."))
    return out


def kb_scope_filter(decision: Decision) -> dict | None:
    """Build a Chroma metadata pre-filter from the decision's kb_scopes."""
    clauses = []
    for scope in decision.kb_scopes:
        s = dict(scope)
        clauses.append({"$and": [
            {"department": {"$eq": s["department"]}},
            {"classification": {"$eq": s["classification"]}},
        ]})
    if not clauses:
        return None
    return clauses[0] if len(clauses) == 1 else {"$or": clauses}
