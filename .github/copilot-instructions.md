# GitHub Copilot Instructions for Hancock

This document provides guidance for AI coding agents working on the Hancock cybersecurity agent project by CyberViser.

## 🎯 Project Overview

**Hancock** is an AI-powered cybersecurity agent built on Mistral 7B, fine-tuned with MITRE ATT&CK, NVD/CVE, CISA KEV, and security knowledge bases. It operates in multiple specialist modes:

- **SOC Analyst**: Alert triage, SIEM queries (Splunk SPL/Elastic KQL/Sentinel KQL), incident response (PICERL), threat hunting
- **Penetration Tester**: Reconnaissance, exploitation, CVE analysis, post-exploitation (PTES methodology)
- **Detection Engineer**: Sigma/YARA rule generation, IOC analysis
- **CISO Advisor**: Risk assessment, compliance, board reporting
- **Security Code**: Code generation (Python, Bash, YARA, Sigma, KQL, SPL)

## 📁 Repository Structure

```
Hancock/
├── hancock_agent.py          # Main agent (CLI + REST API server)
├── hancock_pipeline.py       # Data collection pipeline
├── hancock_finetune*.py      # Fine-tuning scripts (LoRA, GPU, CPU)
├── hancock_constants.py      # Shared constants
├── collectors/               # Knowledge base collectors
│   ├── mitre_collector.py   # MITRE ATT&CK techniques
│   ├── nvd_collector.py     # CVE/vulnerability data
│   ├── atomic_collector.py  # Atomic Red Team tests
│   ├── cisa_kev_collector.py # CISA Known Exploited Vulnerabilities
│   ├── ghsa_collector.py    # GitHub Security Advisories
│   ├── pentest_kb.py        # Pentesting Q&A pairs
│   ├── soc_kb.py            # SOC/IR Q&A pairs
│   ├── soc_collector.py     # Sigma examples
│   ├── graphql_security_kb.py # GraphQL auth/authz knowledge
│   └── graphql_security_tester.py # GraphQL security testing
├── formatter/                # Data formatters for training
├── clients/                  # SDK clients
│   ├── python/              # Python SDK (hancock-client)
│   └── nodejs/              # Node.js SDK
├── tests/                    # Test suite
│   ├── test_hancock_api.py  # API endpoint tests
│   ├── test_graphql_security.py # GraphQL security tests
│   └── test_sdk_client.py   # SDK tests
├── data/                     # Training data (gitignored)
├── docs/                     # Documentation & guides
├── spaces_app.py            # Gradio UI for Hugging Face Spaces
├── Dockerfile               # Production container
├── docker-compose.yml       # Local Ollama + Hancock stack
├── oracle-cloud-setup.sh    # Oracle Cloud deployment script
├── fly.toml                 # Fly.io deployment config
└── requirements.txt         # Python dependencies
```

## 🏗️ Architecture

### Backend Selection (LLM Providers)

Hancock supports 3 LLM backends (configured via `.env`):

1. **Ollama** (default) — Local models (llama3.1:8b, qwen2.5-coder:7b)
2. **NVIDIA NIM** — Cloud inference (Mistral 7B Instruct, Qwen 2.5 Coder 32B)
3. **OpenAI** — Fallback (gpt-4o-mini)

### REST API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/health` | Agent status & capabilities |
| `GET` | `/metrics` | Prometheus-compatible counters |
| `POST` | `/v1/chat` | Conversational AI with history + streaming |
| `POST` | `/v1/ask` | Single-shot question |
| `POST` | `/v1/triage` | SOC alert triage + MITRE ATT&CK mapping |
| `POST` | `/v1/hunt` | Threat hunting query generator |
| `POST` | `/v1/respond` | PICERL incident response playbook |
| `POST` | `/v1/code` | Security code generation |
| `POST` | `/v1/ciso` | CISO advisory & risk analysis |
| `POST` | `/v1/sigma` | Sigma detection rule generator |
| `POST` | `/v1/yara` | YARA malware rule generator |
| `POST` | `/v1/ioc` | IOC threat intel enrichment |
| `POST` | `/v1/webhook` | SIEM/EDR push webhook auto-triage |

### Authentication & Security

- **API Key**: Bearer token authentication (`HANCOCK_API_KEY` in `.env`)
- **Rate Limiting**: In-memory rate limiter (default: 60 req/min per IP)
- **Webhook Signatures**: HMAC-SHA256 validation for `/v1/webhook`
- **Deployment**: Nginx reverse proxy on Oracle Cloud, Fly.io auto-scaling

## 🛠️ Development Workflow

### Initial Setup

```bash
# 1. Clone and create virtualenv
git clone https://github.com/juanaquas/Hancock.git
cd Hancock
python3 -m venv .venv
source .venv/bin/activate

# 2. Install dependencies
pip install -r requirements.txt
pip install -r requirements-dev.txt  # for testing

# 3. Configure environment
cp .env.example .env
# Edit .env: set NVIDIA_API_KEY or configure Ollama
```

### Running Hancock

```bash
# CLI mode (interactive chat)
python hancock_agent.py

# Server mode (REST API on port 5000)
python hancock_agent.py --server --port 5000

# Using Makefile
make run       # CLI
make server    # API server
```

### Testing

```bash
# Run tests
make test                # pytest with short traceback
make test-cov            # with HTML coverage report

# Lint
make lint                # flake8 (errors only)
```

### Docker Deployment

```bash
# Local stack (Ollama + Hancock)
docker-compose up -d

# Production image
docker build -t cyberviser/hancock:latest .
docker run -p 5000:5000 --env-file .env cyberviser/hancock
```

## 📝 Code Conventions

### Python Style

- **Python 3.10+** required
- **No strict linter** — follow PEP 8 and existing code patterns
- **Type hints encouraged** for new code
- **Docstrings** for public functions (Google style)

### API Response Format

All `/v1/*` endpoints return JSON:

```json
{
  "response": "...",
  "model": "mistralai/mistral-7b-instruct-v0.3",
  "usage": { "prompt_tokens": 123, "completion_tokens": 456 }
}
```

### System Prompts

System prompts are defined as module-level constants in `hancock_agent.py`:

- `PENTEST_SYSTEM` — Penetration tester persona
- `SOC_SYSTEM` — SOC analyst persona
- `AUTO_SYSTEM` — Combined persona
- `CODE_SYSTEM` — Code generation persona
- `CISO_SYSTEM` — CISO advisor persona
- `SIGMA_SYSTEM`, `YARA_SYSTEM`, `IOC_SYSTEM` — Specialized personas

### Knowledge Base Structure

Collectors in `collectors/` generate JSON files in `data/`:

```python
KB = [
    {
        "category": "soc_analysis",
        "user": "How do I triage a Mimikatz alert?",
        "assistant": "Step 1: Confirm LSASS access...",
    },
    # ... more Q&A pairs
]
```

## 🔒 Security Guidelines

### Ethical Boundaries

- **Hancock operates STRICTLY within authorized scope**
- Never remove authorization checks or ethical guardrails
- All pentesting features assume explicit written permission
- Training data must be from **public, legally sourced** knowledge bases

### Common Security Patterns

1. **Authentication Check**: All API endpoints use `_check_auth_and_rate()`
2. **HMAC Validation**: Webhook signatures verified with `hmac.compare_digest()`
3. **Rate Limiting**: Per-IP request tracking with sliding window
4. **Input Sanitization**: User inputs validated before passing to LLM
5. **Error Handling**: Never leak internal paths/stack traces to users

### GraphQL Security Module

Recent additions cover GraphQL authentication/authorization:

- **IDOR/BOLA Prevention**: Ownership validation in resolvers
- **Field-Level Authorization**: Sensitive fields require permissions
- **JWT Security**: Strong algorithms only (RS256/ES256)
- **Testing Guide**: `docs/graphql-security-quickstart.md`
- **Knowledge Base**: `collectors/graphql_security_kb.py`

## 🚀 Deployment Targets

### Oracle Cloud Always-Free Tier

```bash
# On Oracle VM (Ubuntu 22.04)
curl -sO https://raw.githubusercontent.com/cyberviser/Hancock/main/oracle-cloud-setup.sh
chmod +x oracle-cloud-setup.sh && ./oracle-cloud-setup.sh
```

Provisions:
- Docker + Docker Compose
- Nginx reverse proxy (port 80 → 5000)
- UFW firewall + iptables rules
- Systemd service for auto-restart

### Fly.io (PaaS)

```bash
fly launch --config fly.toml
fly secrets set HANCOCK_API_KEY=$(python -c "import secrets; print(secrets.token_urlsafe(32))")
fly secrets set HANCOCK_LLM_BACKEND=openai  # no local Ollama
fly secrets set OPENAI_API_KEY=sk-...
fly deploy
```

### Hugging Face Spaces (Gradio UI)

1. Fork/upload to Spaces
2. Set secrets: `HANCOCK_API_URL`, `HANCOCK_API_KEY`
3. Spaces auto-deploys `spaces_app.py`

## 📊 Data Pipeline & Fine-Tuning

### Collecting Training Data

```bash
# Run all collectors
make pipeline

# Run specific phase
python hancock_pipeline.py --phase 3  # KEV + Atomic + GHSA
```

Outputs JSON files to `data/raw_*.json` → formatted to `data/train_v3.jsonl`

### Fine-Tuning

```bash
# LoRA fine-tuning (GPU required)
python hancock_finetune_v3.py

# CPU adapter fine-tuning
python hancock_cpu_finetune.py

# Colab notebooks available:
# - Hancock_Finetune_v3.ipynb (full)
# - Hancock_Kaggle_Finetune.ipynb (Kaggle GPU)
```

## 🧪 Testing Patterns

### API Endpoint Tests

```python
# tests/test_hancock_api.py
def test_triage_endpoint(test_client):
    response = test_client.post("/v1/triage", json={
        "alert": "Mimikatz detected on DC01"
    })
    assert response.status_code == 200
    assert "MITRE ATT&CK" in response.json["response"]
```

### SDK Client Tests

```python
# tests/test_sdk_client.py
from hancock_client import HancockClient

def test_sdk_triage():
    client = HancockClient(api_key="test-key")
    result = client.triage("Suspicious PowerShell execution")
    assert "T1059" in result
```

## 🤝 Contributing Guidelines

1. **Fork** the repository
2. **Create a branch**: `feat/add-sigma-tuning` or `fix/rate-limit-leak`
3. **Test locally**: Run `make test` and manual validation
4. **Commit** using conventional commits:
   - `feat:` new feature
   - `fix:` bug fix
   - `docs:` documentation
   - `refactor:` code refactor
   - `test:` add/update tests
5. **Pull Request**: Use the template in `.github/pull_request_template.md`

## 📦 Dependencies

### Runtime (requirements.txt)

- `openai>=1.0.0` — Universal API client (Ollama, NIM, OpenAI)
- `flask>=3.0.0` — REST API server
- `python-dotenv>=1.0.0` — Environment config
- `requests>=2.31.0` — HTTP client for collectors
- `httpx>=0.25.0` — Async HTTP for streaming

### Development (requirements-dev.txt)

- `pytest>=7.4.0` — Test framework
- `pytest-cov>=4.1.0` — Coverage reporting
- `flake8>=6.1.0` — Code linter
- `gradio>=4.0.0` — UI for Spaces

## 🔍 Common Tasks for AI Agents

### Adding a New API Endpoint

1. Add route in `hancock_agent.py` inside `build_app()`:
   ```python
   @app.route("/v1/newfeature", methods=["POST"])
   def newfeature_endpoint():
       ok, err, _ = _check_auth_and_rate()
       if not ok:
           return jsonify({"error": err}), 401 if "Unauthorized" in err else 429
       data = request.get_json(force=True)
       # ... process request
   ```

2. Add test in `tests/test_hancock_api.py`:
   ```python
   def test_newfeature_endpoint(test_client):
       response = test_client.post("/v1/newfeature", json={"input": "test"})
       assert response.status_code == 200
   ```

3. Update README.md API reference table

### Adding a New Knowledge Base Collector

1. Create `collectors/newdomain_kb.py`:
   ```python
   OUTPUT_FILE = Path(__file__).parent.parent / "data" / "raw_newdomain_kb.json"
   
   KB = [
       {"category": "newdomain", "user": "Q?", "assistant": "A."},
   ]
   
   if __name__ == "__main__":
       OUTPUT_FILE.parent.mkdir(exist_ok=True)
       OUTPUT_FILE.write_text(json.dumps(KB, indent=2))
   ```

2. Add to `hancock_pipeline.py` phase
3. Update formatter to include new category

### Updating System Prompts

System prompts in `hancock_agent.py` are module constants. When editing:

1. Maintain the ethical guardrails
2. Keep technical accuracy (reference real tools/CVEs)
3. Follow existing structure and tone
4. Test with `make test` and manual API calls

### Cloud Permission & Deployment Changes

When modifying deployment scripts:

1. **Oracle Cloud** (`oracle-cloud-setup.sh`):
   - Update firewall rules (ufw + iptables)
   - Modify Nginx config
   - Update systemd service

2. **Fly.io** (`fly.toml`):
   - Adjust VM resources (`memory`, `cpu_kind`)
   - Update secrets management
   - Modify health check endpoint/interval

3. **Hugging Face Spaces** (`spaces_app.py`, `spaces_README.md`):
   - Update Gradio UI components
   - Add/modify Space secrets requirements
   - Update SDK version in frontmatter

## 🎯 Agent-Specific Guidance

### For Documentation Agents

- Update `README.md` when adding features
- Keep `docs/` guides accurate (GraphQL security, API reference)
- Maintain `CHANGELOG.md` with version history
- Update `CONTRIBUTING.md` if workflow changes

### For Testing Agents

- Follow existing test patterns in `tests/`
- Use `test_client` fixture for API tests
- Mock external dependencies (NVIDIA NIM, OpenAI)
- Maintain >80% coverage for critical paths

### For Security Agents

- Run `make lint` before committing
- Review authentication/authorization changes carefully
- Never commit secrets to `.env`
- Validate input sanitization in new endpoints
- Check GraphQL security patterns against OWASP guidelines

### For Deployment Agents

- Test Docker builds locally first
- Validate environment variable propagation
- Check health check endpoints respond correctly
- Verify rate limiting and auth work in production
- Document any new secrets in `.env.example`

## 📚 Key Documentation

- **API Guide**: `README.md` (API Reference section)
- **Business Plan**: `BUSINESS_PROPOSAL.md`
- **Security**: `SECURITY.md`, `docs/SECURITY_SUMMARY.md`
- **GraphQL Security**: `docs/graphql-security-guide.md`, `docs/graphql-security-quickstart.md`
- **Launch Strategy**: `LAUNCH.md`
- **Competitor Analysis**: `COMPETITOR_ANALYSIS.md`

## 🚨 Critical Reminders

1. **NEVER** commit `.env` or secrets
2. **ALWAYS** test authentication changes with `test_hancock_api.py`
3. **MAINTAIN** ethical guardrails in system prompts
4. **VALIDATE** that fine-tuning data is from public, legal sources
5. **RUN** `make test` before pushing code
6. **UPDATE** documentation when changing APIs or deployment
7. **USE** `.gitignore` for `data/`, `.venv/`, `__pycache__/`, build artifacts

## 💡 Tips for Efficient Agent Work

- **Use Makefile targets** instead of raw commands
- **Parallelize** independent operations (file reads, API tests)
- **Check existing patterns** before implementing new features
- **Read test files** to understand expected behavior
- **Consult knowledge bases** in `collectors/` for domain context
- **Verify changes** with `git diff` before committing

---

**Version**: 0.5.0  
**Last Updated**: 2026-03-02  
**Maintainer**: CyberViser (https://cyberviser.netlify.app)
