"""Patch api.py: soc_lead/auditor accounts, jti + revocation, router mount. Atomic."""
import ast, pathlib, shutil, sys
p = pathlib.Path("api.py")
src = p.read_text(encoding="utf-8")
if "build_router" in src:
    print("api.py: v2 patch already applied - skipped"); sys.exit(0)

def rep(s, old, new):
    if s.count(old) < 1:
        sys.exit(f"api.py: expected text not found, nothing changed:\n{old[:80]}")
    return s.replace(old, new)

s = src
s = rep(s, 'for department, account in DEMO_ACCOUNTS.items():\n    if not account["email"]',
 '''# Optional extra accounts (only created when set in .env).
for _key, _role in (("lead", "soc_lead"), ("auditor", "auditor")):
    _email = os.getenv(f"DEMO_{_key.upper()}_EMAIL", "").strip().lower()
    _pw = os.getenv(f"DEMO_{_key.upper()}_PASSWORD")
    if _email and _pw:
        DEMO_ACCOUNTS[_key] = {"email": _email, "password": _pw,
                               "role": _role, "department": "soc"}

for department, account in DEMO_ACCOUNTS.items():
    if not account["email"]''')
s = rep(s, '    for department, account in DEMO_ACCOUNTS.items():\n        if (',
 '    for _key, account in DEMO_ACCOUNTS.items():\n        department = account.get("department", _key)\n        if (')
s = rep(s, '                    "role": account["role"],\n                    "exp": expires,',
 '                    "role": account["role"],\n                    "jti": secrets.token_hex(16),\n                    "exp": expires,')
s = rep(s, '''            "soc": "soc_analyst",
        }''', '''            "soc": {"soc_analyst", "soc_lead", "auditor"},
        }''')
for k in ("hr", "engineering", "finance"):
    s = rep(s, f'            "{k}": "employee",\n', f'            "{k}": {{"employee"}},\n')
s = rep(s, 'or role != expected_roles[department]', 'or role not in expected_roles[department]')
s = rep(s, '        role = payload.get("role")\n',
 '''        role = payload.get("role")
        jti = payload.get("jti")
        if jti and jti in revoked_jtis():
            raise HTTPException(status_code=401, detail="Token revoked")
''')
s = rep(s, '            "role": role,\n        }', '            "role": role,\n            "jti": jti,\n        }')
s = rep(s, 'if current_user["role"] == "soc_analyst":',
        'if current_user["role"] in {"soc_analyst", "soc_lead", "auditor"}:')
s = rep(s, 'if department != "soc" or role != "soc_analyst":',
        'if department != "soc" or role not in {"soc_analyst", "soc_lead"}:')
s = s.rstrip() + '''


# Incident management routes (policy-checked, audited; see incident_api.py).
from incident_api import build_router, revoke_jti, revoked_jtis  # noqa: E402

app.include_router(build_router(get_current_user))
'''
ast.parse(s)
shutil.copy(p, "api.py.v2.bak")
p.write_text(s, encoding="utf-8")
print("api.py: v2 patch applied (backup: api.py.v2.bak)")
