# SecureRAG — AI Security & SOC Investigation Lab

SecureRAG is a security-focused Retrieval-Augmented Generation (RAG) application that combines department-aware document retrieval with a SOC analyst workspace. It explores how to protect retrieved knowledge, limit access to confidential information, and support analyst workflows with AI-generated investigation guidance.

> **Project status:** Working prototype. It is not production security software and does not connect to a live SIEM or automatically contain threats.

## Highlights

- **Authenticated access:** FastAPI login issues JWTs; protected endpoints derive department and role from the verified token.
- **Department-aware RAG:** Employee requests use the company handbook collection, while SOC analyst requests use a separate SOC playbook collection.
- **Retrieval authorization:** Retrieved documents are filtered by department and classification using explicit allow rules.
- **Groq-powered responses:** LangChain's `ChatGroq` provides LLM generation. Configure a valid model available to your Groq account.
- **Local embeddings and vector store:** Sentence Transformers embeddings and ChromaDB run locally.
- **SOC workspace:** Security Assistant, alert investigation guidance, and incident-report drafting.
- **Typosquatting scanner:** Generates lookalike-domain candidates and optionally checks DNS records for candidates.
- **Security-focused prompt:** Retrieved documents are treated as untrusted reference material, not instructions.
- **Regression testing:** Existing authorization tests cover selected cross-department and metadata-denial cases.

## Architecture

1. **Login:** React sends credentials to the FastAPI login endpoint. The API returns a JWT containing the user's subject, department, role, and expiry.
2. **Authenticated requests:** The frontend sends the token as a Bearer token to protected API endpoints.
3. **Knowledge-base routing:** The backend routes SOC analysts to `soc_security_kb` and employee accounts to `company_handbook`.
4. **Authorized retrieval:** The authorization layer filters retrieved chunks using department and classification metadata.
5. **Generation:** Authorized context is passed to a security-focused LangChain prompt and the configured Groq chat model.
6. **SOC domain screening:** The SOC-only typosquatting endpoint generates candidate lookalike domains and can query A, AAAA, MX, and NS DNS records.
7. **Frontend:** React provides the authenticated dashboard, chat, alert investigation, incident report, and typosquatting scanner screens.

## Technology Stack

- Python and FastAPI
- React, Vite, and CSS
- LangChain and `langchain-groq`
- Groq API for LLM generation
- ChromaDB for vector storage
- Hugging Face Sentence Transformers (`sentence-transformers/all-MiniLM-L6-v2`) for local embeddings
- PyJWT and password hashing for the demo login flow
- `dnspython` for optional DNS checks
- Git and GitHub

## Security Controls and Testing

- **JWT-protected endpoints:** Chat and typosquatting requests require a valid token.
- **Role-aware routing:** The server selects the knowledge base based on the verified JWT identity.
- **SOC scanner authorization:** The typosquatting API checks that the authenticated user has the SOC department and `soc_analyst` role.
- **Metadata-based retrieval policy:** Department and classification metadata determine whether candidate chunks can be returned.
- **Default-deny behavior:** The current authorization function rejects unsupported departments and does not allow documents with unexpected classification values.
- **Prompt-injection awareness:** The prompt instructs the model to treat retrieved content as untrusted data. This is a mitigation, not a guarantee.
- **Recorded regression cases:** The frontend lists previously recorded security checks. That page is informational and does not execute tests.

Run the project's available automated tests locally before publishing claims about current test status. Previously recorded results are not proof that the current checkout passes.

### Typosquatting scanner limitations

The scanner creates heuristic lookalike candidates using transformations such as character omission, repetition, transposition, keyboard substitutions, hyphen insertion, and alternative top-level domains. It can optionally query DNS records for generated candidates.

- A generated candidate is not necessarily registered, malicious, or impersonating a brand.
- DNS records do not prove maliciousness or definitively establish domain registration status.
- A DNS lookup error is not evidence that a domain is safe or unavailable.
- The current scanner does not provide a calibrated risk score; `risk_score` may be `null`.
- Validate findings using trusted threat-intelligence sources and manual investigation before taking action.

### SOC workflow limitations

The assistant provides guidance based on retrieved playbooks and user-provided evidence. It does not query a live SIEM, independently verify cloud activity, revoke credentials, terminate sessions, or automatically contain incidents. Analysts must validate generated guidance against original logs and approved incident-response procedures.

## Project Structure

```text
SecureRAG/
├── api.py
├── authorization.py
├── rag_chatbot.py
├── ingest_soc_knowledge.py
├── typosquatting.py
├── SecureRAG_SOC_Knowledge_Base/
│   ├── 01_siem_alert_triage.md
│   ├── 02_windows_linux_authentication.md
│   ├── 03_phishing_and_url_investigation.md
│   ├── 04_mitre_threat_hunting.md
│   ├── 05_incident_response_and_reporting.md
│   └── 06_cloud_iam_and_api_abuse.md
├── frontend/
│   ├── src/
│   │   ├── App.jsx
│   │   ├── App.css
│   │   └── Login.jsx
│   ├── package.json
│   └── package-lock.json
├── chroma_db/                 # Generated locally; do not commit
├── .env                       # Local secrets; do not commit
├── .gitignore
└── README.md
```

Other local test and ingestion scripts may exist in the repository. ChromaDB files, environment files, virtual environments, and dependency folders should remain untracked.

## Getting Started

### Prerequisites

- Python installed
- Node.js and npm installed
- A Groq API key
- Git (optional, for cloning the repository)

### 1. Clone the repository

```bash
git clone <your-repository-url>
cd SecureRAG
```

### 2. Create and activate a Python virtual environment

On Windows PowerShell:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -U pip
```

Install the Python dependencies used by the project. If a `requirements.txt` is present in the repository, use:

```powershell
pip install -r requirements.txt
```

Otherwise, install the dependencies listed in the Python imports and project setup, including FastAPI, Uvicorn, LangChain, `langchain-groq`, `langchain-chroma`, `langchain-huggingface`, `sentence-transformers`, `python-dotenv`, `PyJWT`, `pwdlib`, `email-validator`, and `dnspython`.

### 3. Configure environment variables

Create a local `.env` file in the repository root. Add your own values; do not commit this file.

```dotenv
GROQ_API_KEY=your_groq_api_key
JWT_SECRET=replace_with_a_long_random_secret

DEMO_HR_EMAIL=hr@example.com
DEMO_HR_PASSWORD=replace_with_a_demo_password

DEMO_ENGINEERING_EMAIL=engineering@example.com
DEMO_ENGINEERING_PASSWORD=replace_with_a_demo_password

DEMO_FINANCE_EMAIL=finance@example.com
DEMO_FINANCE_PASSWORD=replace_with_a_demo_password

DEMO_SOC_EMAIL=soc@example.com
DEMO_SOC_PASSWORD=replace_with_a_demo_password
```

Use unique local demo passwords and a long, random JWT secret. The application expects all four demo account values to be configured. Never commit actual credentials, API keys, or JWTs.

### 4. Build the knowledge bases

If the source documents are present and you need to create or refresh the employee knowledge base, run the project's employee ingestion script (for example, `build_knowledge_base.py`, if present).

To ingest the SOC playbooks:

```powershell
python ingest_soc_knowledge.py
```

The application expects ChromaDB collections named `company_handbook` and `soc_security_kb` in the local `chroma_db/` directory. Build both collections before testing the corresponding workspace.

### 5. Start the FastAPI backend

From the repository root:

```powershell
python -m uvicorn api:app --reload --port 8001
```

Check the health endpoint at <http://localhost:8001/api/health> and the interactive API documentation at <http://localhost:8001/docs>.

### 6. Start the React frontend

Open a second PowerShell window:

```powershell
cd frontend
npm install
npm run dev
```

Open the local URL printed by Vite, commonly <http://localhost:5173>.

### 7. Test the typosquatting endpoint

Sign in through the frontend using the local SOC analyst demo account. For API testing, open <http://localhost:8001/docs>, authorize with a valid SOC Bearer token, and try `POST /api/soc/typosquatting-scan` with:

```json
{
  "domain": "google.com",
  "check_dns": false
}
```

This mode tests candidate generation without DNS queries. Set `check_dns` to `true` to request DNS checks. Only use the scanner for legitimate security investigation.

### 8. Run authorization tests

Run the test scripts that exist in the checkout, for example:

```powershell
python test_authorization.py
```

Check the current repository for the actual test filenames and dependencies before running them. Do not describe historical test results as current results without rerunning the tests.

## Security and Privacy Notes

- `.env`, API keys, passwords, JWTs, local databases, virtual environments, and dependency folders must not be committed.
- Use synthetic or sanitized data during testing. Do not paste secrets or confidential production logs into the assistant.
- Frontend navigation is not an access-control boundary. Authorization must be enforced by the API.
- This prototype has not undergone a comprehensive production security assessment.
- Model output can be incorrect or incomplete; verify decisions using source evidence and approved procedures.

## Current Status and Future Work

The prototype includes authenticated department-aware RAG, separate employee and SOC collections, SOC investigation/report workflows, and an API-backed typosquatting scanner. The scanner endpoint has been manually tested with DNS checks disabled, returning generated candidate domains.

Potential next steps include automated API authorization tests, broader retrieval-leakage tests, scanner UI regression tests, improved audit logging, optional integration with trusted domain reputation sources, and deployment hardening.

---

**Disclaimer:** SecureRAG is an educational security prototype. It is not a substitute for a production IAM system, a dedicated threat-intelligence platform, or an organization's approved incident-response process.

## Policy-controlled MCP server (incident management)

`mcp_server/` exposes typed tools over MCP (stdio). Identity comes only from the verified JWT in
`SECURERAG_MCP_TOKEN`; no tool accepts a user or role argument. Every call is policy-checked
(`policies/*.yaml`, default deny, explicit deny wins) and written to a hash-chained audit log
(`mcp_data/audit.log.jsonl`). There is no raw-SQL tool and the server never executes containment.

Roles: `employee`, `soc_analyst`, `soc_lead`, `auditor`. Incidents follow `incident://schema`
(NIST 800-61 lifecycle, MITRE ATT&CK ids, TLP, AI provenance). Run `python -m mcp_server.server`
and `python -m pytest tests/test_policy_matrix.py -q`. The login endpoint currently issues only
`employee` and `soc_analyst` tokens; use `scripts/mint_dev_token.py` (dev only) for the others.
Prototype: not production IAM.
