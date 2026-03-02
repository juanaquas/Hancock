# Hancock AI Agent — Copilot Instructions

## Project Overview

**Hancock** is CyberViser's AI-powered cybersecurity agent, a specialized LLM fine-tuned on Mistral 7B for:
- **Pentest operations**: Reconnaissance, exploitation, CVE analysis, PTES reporting
- **SOC analysis**: Alert triage, SIEM queries, incident response, Sigma/YARA rule generation
- **CISO advisory**: Risk assessment, compliance, board reporting, framework guidance
- **Security code generation**: Detection rules (Sigma, YARA), SIEM queries (SPL, KQL), security scripts

The project is a Flask-based REST API server with CLI support, backed by NVIDIA NIM inference.

## Architecture

```
hancock_agent.py          # Main Flask REST API + CLI interface
├── /v1/triage           # SOC alert triage + MITRE ATT&CK mapping
├── /v1/hunt             # Threat hunting query generator (Splunk/Elastic/Sentinel)
├── /v1/respond          # PICERL incident response playbook
├── /v1/code             # Security code generation
├── /v1/ciso             # CISO advisory (risk/compliance/reporting)
├── /v1/sigma            # Sigma detection rule generator
├── /v1/yara             # YARA malware detection rule generator
├── /v1/ioc              # IOC threat intelligence enrichment
├── /v1/webhook          # SIEM/EDR alert ingestion webhook
└── /v1/chat             # Conversational AI with streaming

hancock_pipeline.py       # Training data collection orchestrator
collectors/               # Data collectors for training datasets
├── mitre_collector.py   # MITRE ATT&CK TTPs
├── nvd_collector.py     # NVD/CVE vulnerability data
├── pentest_kb.py        # Pentest knowledge base (static)
├── soc_kb.py            # SOC analyst knowledge base (static)
├── soc_collector.py     # SOC detection data (Sigma rules)
├── cisa_kev_collector.py # CISA Known Exploited Vulnerabilities
├── atomic_collector.py  # Atomic Red Team test cases
├── ghsa_collector.py    # GitHub Security Advisories
├── graphql_security_kb.py # GraphQL security vulnerabilities KB
└── graphql_security_tester.py # GraphQL security testing framework

formatter/                # Dataset formatters
├── to_mistral_jsonl.py  # v1 formatter (pentest only)
├── to_mistral_jsonl_v2.py # v2 formatter (pentest + SOC)
└── formatter_v3.py      # v3 formatter (+ KEV + Atomic + GHSA)

hancock_finetune*.py      # LoRA fine-tuning scripts (GPU/CPU/Colab/Kaggle)
hancock_constants.py      # Shared constants

clients/                  # SDK clients
├── python/              # Python SDK
└── nodejs/              # Node.js SDK

tests/                    # Test suite
├── test_hancock_api.py  # API endpoint tests
├── test_sdk_client.py   # SDK integration tests
└── test_graphql_security.py # GraphQL security tests

data/                     # Training datasets (generated)
├── hancock_pentest_v1.jsonl  # v1 dataset
├── hancock_v2.jsonl     # v2 dataset (pentest + SOC)
└── hancock_v3.jsonl     # v3 dataset (+ KEV + Atomic + GHSA)
```

## Development Setup

### Prerequisites
- Python 3.10+
- NVIDIA API key (free at https://build.nvidia.com)
- Optional: GPU for local fine-tuning (or use Colab/Kaggle T4 free tier)

### Quick Start
```bash
# 1. Clone and setup virtualenv
git clone https://github.com/cyberviser/Hancock.git
cd Hancock
make setup  # or: python3 -m venv .venv && source .venv/bin/activate && pip install -r requirements.txt

# 2. Configure environment
cp .env.example .env
# Edit .env and add: NVIDIA_API_KEY=nvapi-...

# 3. Run CLI or server
source .venv/bin/activate
python hancock_agent.py              # CLI mode
python hancock_agent.py --server     # REST API on :5000
```

### Common Commands (via Makefile)
```bash
make setup          # Create venv + install deps + copy .env
make run            # Start CLI
make server         # Start REST API (:5000)
make pipeline       # Build training dataset (all phases)
make pipeline-v3    # Build v3 dataset only (KEV + Atomic + GHSA)
make finetune       # LoRA fine-tuning on Mistral 7B
make lint           # Run flake8 linter
make test           # Run pytest test suite
make test-cov       # Run tests with HTML coverage report
make clean          # Remove build artifacts
make docker         # Build Docker image
make docker-up      # Start with docker-compose
make client-python  # Run Python SDK CLI
make client-node    # Run Node.js SDK CLI
```

## Code Organization & Conventions

### File Naming
- `hancock_*.py` — Core application files
- `*_collector.py` — Data collectors in `collectors/`
- `*_kb.py` — Static knowledge bases in `collectors/`
- `to_mistral_*.py` — Dataset formatters in `formatter/`
- `test_*.py` — Test files in `tests/`

### Coding Style
- **PEP 8** with 4-space indentation
- **Docstrings**: Module-level docstring with usage examples
- **Type hints**: Not strictly enforced but encouraged for public APIs
- **Error handling**: Try-except with informative error messages
- **Logging**: Use `print()` for CLI output, structured logs for production
- **Comments**: ASCII art section dividers (e.g., `# ── Section ──────`)

### Key Patterns

#### 1. System Prompts (in `hancock_agent.py`)
```python
PENTEST_SYSTEM = """You are Hancock, a cybersecurity AI agent..."""
SOC_SYSTEM = """You are Hancock, a SOC analyst AI..."""
CISO_SYSTEM = """You are Hancock, a CISO advisor..."""
```
All personas use Mistral 7B via NVIDIA NIM API (OpenAI-compatible).

#### 2. API Endpoints Structure
```python
@app.route("/v1/<endpoint>", methods=["POST"])
def endpoint_func():
    # 1. Auth & rate limiting
    ok, err, _ = _check_auth_and_rate()
    if not ok:
        return jsonify({"error": err}), 401 if "Unauthorized" in err else 429
    
    # 2. Metrics
    _inc("requests_total")
    _inc("requests_by_endpoint", f"/v1/{endpoint}")
    
    # 3. Parse input
    data = request.get_json(force=True)
    param = data.get("param", "")
    
    # 4. Build prompt
    prompt = f"Do something with {param}"
    messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": prompt},
    ]
    
    # 5. Call LLM
    resp = client.chat.completions.create(
        model=model, messages=messages,
        max_tokens=1200, temperature=0.4, top_p=0.95
    )
    result = resp.choices[0].message.content
    
    # 6. Return response
    return jsonify({
        "result": result,
        "model": model,
        "usage": resp.usage.model_dump() if resp.usage else {},
    })
```

#### 3. Data Collectors Pattern
```python
def collect():
    """Fetch data from external API and save to data/*.json"""
    print(f"[{collector_name}] Fetching data...")
    try:
        # Fetch data from API/source
        data = fetch_from_source()
        
        # Transform to internal format
        transformed = process(data)
        
        # Save to data/ directory
        output = Path(__file__).parent.parent / "data" / f"{collector_name}.json"
        with open(output, "w") as f:
            json.dump(transformed, f, indent=2)
        
        print(f"[{collector_name}] Saved {len(transformed)} items to {output}")
    except Exception as e:
        print(f"[{collector_name}] ERROR: {e}")
        raise
```

#### 4. Knowledge Base Pattern (`*_kb.py`)
```python
def build():
    """Build static training data for a specific domain"""
    examples = [
        {
            "instruction": "Question or task description",
            "response": "Detailed answer or guidance",
        },
        # ... more examples
    ]
    
    output = Path(__file__).parent.parent / "data" / "kb_name.json"
    with open(output, "w") as f:
        json.dump(examples, f, indent=2)
    
    print(f"[kb-name] Generated {len(examples)} samples → {output}")
```

## Testing

### Test Structure
- `tests/test_hancock_api.py` — Flask API endpoint tests (pytest + Flask test client)
- `tests/test_sdk_client.py` — SDK integration tests
- `tests/test_graphql_security.py` — GraphQL security framework tests

### Running Tests
```bash
# Run all tests
make test

# Run with coverage
make test-cov  # Opens htmlcov/index.html

# Run specific test file
.venv/bin/pytest tests/test_hancock_api.py -v

# Run specific test
.venv/bin/pytest tests/test_hancock_api.py::test_health_endpoint -v
```

### Writing Tests
```python
def test_endpoint_name():
    """Test description"""
    from hancock_agent import build_app
    from unittest.mock import MagicMock
    
    # Mock OpenAI client
    mock_client = MagicMock()
    mock_resp = MagicMock()
    mock_resp.choices[0].message.content = "Expected response"
    mock_client.chat.completions.create.return_value = mock_resp
    
    # Build Flask test client
    app = build_app(mock_client, model="test-model")
    client = app.test_client()
    
    # Make request
    response = client.post("/v1/endpoint", json={"param": "value"})
    
    # Assertions
    assert response.status_code == 200
    data = response.get_json()
    assert "result" in data
    assert data["result"] == "Expected response"
```

## Fine-Tuning Workflow

### Dataset Generation Pipeline
```bash
# Phase 1: Pentest only (MITRE + NVD + pentest KB)
python hancock_pipeline.py --phase 1

# Phase 2: Add SOC data (Sigma rules + SOC KB)
python hancock_pipeline.py --phase 2

# Phase 3: Add v3 enrichment (CISA KEV + Atomic Red Team + GHSA)
python hancock_pipeline.py --phase 3

# Or run all phases at once
make pipeline  # or: python hancock_pipeline.py --phase all

# Outputs:
# - data/hancock_pentest_v1.jsonl (phase 1)
# - data/hancock_v2.jsonl (phases 1+2)
# - data/hancock_v3.jsonl (phases 1+2+3)
```

### Fine-Tuning Options

#### 1. GPU (Local or Cloud)
```bash
# Requires: CUDA GPU with 16GB+ VRAM (e.g., T4, A10G, V100)
python hancock_finetune_v3.py --steps 300 --export-gguf --push-to-hub
```

#### 2. Free GPU (Colab or Kaggle)
```bash
# Open Hancock_Universal_Finetune.ipynb in Colab or Kaggle
# Enable GPU (T4 recommended)
# Run all cells (~30 min)
# Downloads GGUF Q4_K_M for Ollama at end
```

#### 3. CPU (No GPU Required)
```bash
# Quick test (10 steps, ~40 min on 16-core CPU)
python hancock_cpu_finetune.py --debug

# Full run (500 steps, ~25 hr on 16-core CPU)
python hancock_cpu_finetune.py --max-steps 500

# Test saved adapter
python hancock_cpu_finetune.py --test
```

#### 4. Modal.com (Serverless GPU)
```bash
# Requires Modal account (free $30/mo credit)
modal run train_modal.py
```

### After Fine-Tuning
```bash
# Load fine-tuned model in Ollama
ollama create hancock -f Modelfile.hancock-finetuned
ollama run hancock

# Or use with Hancock agent (set OLLAMA_BASE_URL in .env)
export OLLAMA_BASE_URL=http://localhost:11434
python hancock_agent.py --model hancock
```

## API Endpoints Reference

### Core Endpoints

#### Health Check
```bash
GET /health
# Returns: {"status": "ok", "model": "...", "capabilities": [...]}
```

#### Metrics (Prometheus)
```bash
GET /metrics
# Returns: Prometheus-compatible metrics (requests_total, errors_total, etc.)
```

#### Chat (Conversational)
```bash
POST /v1/chat
{
  "message": "Your question or task",
  "mode": "auto|pentest|soc|code|ciso",  # optional, default: auto
  "history": [{"role": "user", "content": "..."}],  # optional
  "stream": true  # optional, default: false
}
```

### Specialist Endpoints

#### SOC Alert Triage
```bash
POST /v1/triage
{
  "alert": "Raw SIEM/EDR/IDS alert text",
  "context": "Additional context (optional)"
}
# Returns: Severity, MITRE ATT&CK TTP(s), TP/FP likelihood, containment actions
```

#### Threat Hunting Query Generator
```bash
POST /v1/hunt
{
  "target": "TTP or threat to hunt",
  "siem": "splunk|elastic|sentinel",  # optional, default: splunk
  "technique": "T1078.004"  # optional MITRE ATT&CK technique ID
}
# Returns: SIEM-specific query (SPL, KQL, Lucene)
```

#### Incident Response Playbook
```bash
POST /v1/respond
{
  "incident": "ransomware|phishing|data-breach|..."
}
# Returns: PICERL playbook (Preparation, Identification, Containment, Eradication, Recovery, Lessons)
```

#### Security Code Generation
```bash
POST /v1/code
{
  "task": "Generate YARA rule for Cobalt Strike beacon",
  "language": "yara|sigma|kql|spl|python|bash",  # optional, auto-detected
  "context": "Additional requirements (optional)"
}
# Returns: Commented, production-ready security code
```

#### CISO Advisory
```bash
POST /v1/ciso
{
  "question": "Top 5 risks for the board",
  "output": "advice|board-summary|gap-analysis|policy",  # optional, default: advice
  "context": "Company profile (e.g., '50-person SaaS, AWS')"  # optional
}
# Returns: Executive-level guidance, risk reports, compliance advice
```

#### Sigma Detection Rule Generator
```bash
POST /v1/sigma
{
  "description": "Detect LSASS memory dump",
  "logsource": "windows sysmon",  # optional
  "technique": "T1003.001"  # optional MITRE ATT&CK technique ID
}
# Returns: Sigma rule with MITRE ATT&CK tags
```

#### YARA Malware Detection Rule
```bash
POST /v1/yara
{
  "description": "Cobalt Strike beacon default HTTP profile",
  "file_type": "PE|ELF|Mach-O|memory"  # optional
}
# Returns: YARA rule with metadata and strings
```

#### IOC Threat Intelligence Enrichment
```bash
POST /v1/ioc
{
  "indicator": "185.220.101.35",
  "type": "ip|domain|url|hash|email"  # optional, auto-detected
}
# Returns: Threat intel report with reputation, campaigns, recommendations
```

#### SIEM/EDR Webhook (Auto-Triage)
```bash
POST /v1/webhook
{
  "source": "splunk|elastic|sentinel|crowdstrike|...",
  "alert": {/* raw alert JSON */}
}
# Auto-triages alert + optional Slack/Teams notification
# Set SLACK_WEBHOOK_URL or TEAMS_WEBHOOK_URL in .env
```

## Common Tasks

### Adding a New API Endpoint

1. **Add system prompt** (if needed):
```python
NEW_MODE_SYSTEM = """You are Hancock, specialized in..."""
```

2. **Add route** in `hancock_agent.py`:
```python
@app.route("/v1/newmode", methods=["POST"])
def newmode_endpoint():
    ok, err, _ = _check_auth_and_rate()
    if not ok:
        return jsonify({"error": err}), 401 if "Unauthorized" in err else 429
    _inc("requests_total")
    _inc("requests_by_endpoint", "/v1/newmode")
    
    data = request.get_json(force=True)
    param = data.get("param", "")
    if not param:
        return jsonify({"error": "param required"}), 400
    
    messages = [
        {"role": "system", "content": NEW_MODE_SYSTEM},
        {"role": "user", "content": param},
    ]
    resp = client.chat.completions.create(
        model=model, messages=messages,
        max_tokens=1200, temperature=0.4, top_p=0.95
    )
    result = resp.choices[0].message.content
    
    return jsonify({
        "result": result,
        "model": model,
        "usage": resp.usage.model_dump() if resp.usage else {},
    })
```

3. **Add test** in `tests/test_hancock_api.py`:
```python
def test_newmode_endpoint():
    """Test /v1/newmode endpoint"""
    # ... see "Writing Tests" section above
```

4. **Update README.md** API reference section

### Adding a New Data Collector

1. **Create collector** in `collectors/new_collector.py`:
```python
#!/usr/bin/env python3
"""New data source collector for Hancock training"""
import json
from pathlib import Path

def collect():
    """Fetch data from new source"""
    print("[new-source] Fetching data...")
    # Fetch and process data
    data = fetch_from_api()
    
    output = Path(__file__).parent.parent / "data" / "new_source.json"
    with open(output, "w") as f:
        json.dump(data, f, indent=2)
    
    print(f"[new-source] Saved {len(data)} items → {output}")

if __name__ == "__main__":
    collect()
```

2. **Integrate into pipeline** (`hancock_pipeline.py`):
```python
def run_new_source(data_dir: Path) -> bool:
    print("\n[new-source] Collecting new data...")
    try:
        from collectors.new_collector import collect
        collect()
        return True
    except Exception as e:
        print(f"[new-source] ERROR: {e}")
        return False
```

3. **Update formatter** to include new data source in `formatter/formatter_v3.py`

### Debugging Tips

#### Enable Verbose Logging
```bash
# Set in .env or export before running
export DEBUG=1
python hancock_agent.py
```

#### Check API Response Format
```bash
# Use curl with -v flag
curl -v -X POST http://localhost:5000/v1/triage \
  -H "Content-Type: application/json" \
  -d '{"alert": "Test alert"}'
```

#### Test Specific Collector
```bash
# Run collector directly
python collectors/mitre_collector.py
python collectors/soc_kb.py

# Check generated output
cat data/mitre_attack.json
cat data/soc_kb.json
```

#### Test Fine-Tuning Without Full Training
```bash
# Use debug mode (10 steps only)
python hancock_cpu_finetune.py --debug

# Or use very small dataset
head -n 50 data/hancock_v3.jsonl > data/test_small.jsonl
# Edit finetune script to use test_small.jsonl
```

## Environment Variables

Required:
- `NVIDIA_API_KEY` — NVIDIA NIM API key (get free at https://build.nvidia.com)

Optional:
- `HANCOCK_API_KEY` — Authentication for /v1/* endpoints (if set, clients must provide in X-API-Key header)
- `SLACK_WEBHOOK_URL` — Slack webhook for /v1/webhook notifications
- `TEAMS_WEBHOOK_URL` — Microsoft Teams webhook for /v1/webhook notifications
- `DEBUG` — Enable verbose logging (set to `1` or `true`)
- `OLLAMA_BASE_URL` — Use local Ollama instead of NVIDIA NIM (e.g., `http://localhost:11434`)

## Deployment

### Docker
```bash
# Build image
make docker  # or: docker build -t cyberviser/hancock:latest .

# Run container
docker run -d -p 5000:5000 \
  -e NVIDIA_API_KEY=nvapi-... \
  cyberviser/hancock:latest

# Or use docker-compose
make docker-up  # or: docker-compose up -d
```

### Fly.io
```bash
# Install flyctl
curl -L https://fly.io/install.sh | sh

# Login
fly auth login

# Deploy
make fly-deploy  # or: flyctl deploy --config fly.toml
```

## SDK Clients

### Python SDK
```python
from openai import OpenAI

client = OpenAI(
    base_url="http://localhost:5000/v1",
    api_key="your-hancock-api-key"  # if HANCOCK_API_KEY is set
)

# Use like OpenAI API
response = client.chat.completions.create(
    model="auto",
    messages=[
        {"role": "system", "content": "You are a cybersecurity expert"},
        {"role": "user", "content": "Explain CVE-2024-1234"}
    ]
)
print(response.choices[0].message.content)
```

### Node.js SDK
```javascript
const OpenAI = require('openai');

const client = new OpenAI({
  baseURL: 'http://localhost:5000/v1',
  apiKey: 'your-hancock-api-key'  // if HANCOCK_API_KEY is set
});

async function ask(question) {
  const response = await client.chat.completions.create({
    model: 'auto',
    messages: [
      { role: 'system', content: 'You are a cybersecurity expert' },
      { role: 'user', content: question }
    ]
  });
  return response.choices[0].message.content;
}
```

## License & Contributing

- **License**: CyberViser Proprietary License (see LICENSE)
- **Contributing**: See CONTRIBUTING.md for guidelines
- **Commercial use**: Contact contact@cyberviser.ai for licensing

## Support & Resources

- **Website**: https://cyberviser.netlify.app
- **API Docs**: https://cyberviser.netlify.app/api
- **Issues**: https://github.com/cyberviser/Hancock/issues
- **Business Proposal**: See BUSINESS_PROPOSAL.md
- **Security**: See SECURITY.md for vulnerability reporting

## Quick Reference Card

```bash
# Setup
make setup && source .venv/bin/activate

# Run
make run           # CLI
make server        # REST API on :5000

# Build dataset
make pipeline      # All phases
make pipeline-v3   # v3 only (KEV + Atomic + GHSA)

# Fine-tune
make finetune      # or: python hancock_finetune_v3.py

# Test
make test          # Run tests
make test-cov      # With coverage
make lint          # Linter

# Clean
make clean         # Remove artifacts

# Docker
make docker        # Build image
make docker-up     # Start with compose

# Clients
make client-python # Python SDK CLI
make client-node   # Node.js SDK CLI
```

## AI Agent Best Practices

When working with this codebase as an AI agent:

1. **Always run linters and tests** before and after changes:
   - `make lint` — Check for syntax errors
   - `make test` — Validate functionality

2. **Follow existing patterns**: Study similar code before implementing new features

3. **Minimal changes**: Make surgical, focused modifications

4. **Test endpoints manually** after changes:
   ```bash
   make server  # Start server
   # In another terminal:
   curl -X POST http://localhost:5000/v1/triage -d '{"alert":"test"}'
   ```

5. **Update documentation** when adding endpoints or features

6. **Validate training data** after collector changes:
   ```bash
   python collectors/new_collector.py
   python -m json.tool data/new_source.json  # Validate JSON
   ```

7. **Use type hints** for new functions to improve code quality

8. **Add docstrings** for public functions with usage examples

9. **Check dependencies** before adding new ones — prefer built-in libraries

10. **Security first**: This is a security tool — never introduce vulnerabilities
