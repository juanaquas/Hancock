# Hancock — AI Coding Agent Instructions

This document provides context and guidance for AI coding agents working on the Hancock cybersecurity AI agent project by CyberViser.

## Project Overview

**Hancock** is an AI-powered cybersecurity agent built on top of NVIDIA NIM (primarily Mistral 7B), fine-tuned on specialized security datasets including MITRE ATT&CK, NVD/CVE data, penetration testing knowledge, SOC analysis, and incident response procedures.

### Core Capabilities
- **Pentest Specialist**: Reconnaissance, exploitation, vulnerability analysis, and penetration testing methodologies
- **SOC Analyst**: Alert triage, SIEM queries, incident response (PICERL), threat hunting, detection engineering
- **Code Security**: YARA/Sigma rule generation, security code assistance
- **CISO Advisory**: Risk assessment, compliance, board reporting
- **IOC Analysis**: Threat intelligence enrichment for indicators of compromise

## Architecture

```
hancock_agent.py          → Main entry point (CLI + REST API server)
hancock_pipeline.py       → Data collection orchestrator
hancock_finetune*.py      → Model fine-tuning scripts (LoRA on Mistral 7B)

collectors/               → Data collection modules
  ├── mitre_collector.py      → MITRE ATT&CK TTPs
  ├── nvd_collector.py        → NVD/CVE vulnerability data
  ├── pentest_kb.py           → Pentest knowledge base
  ├── soc_kb.py               → SOC analyst knowledge base
  ├── cisa_kev_collector.py   → CISA Known Exploited Vulnerabilities
  ├── atomic_collector.py     → Atomic Red Team test cases
  ├── ghsa_collector.py       → GitHub Security Advisories
  └── graphql_security_*.py   → GraphQL security testing

formatter/                → Dataset formatters for training
  ├── to_mistral_jsonl.py     → v1 formatter (Pentest only)
  ├── to_mistral_jsonl_v2.py  → v2 formatter (Pentest + SOC)
  └── formatter_v3.py         → v3 formatter (all sources)

clients/                  → SDK clients
  ├── python/                 → Python SDK
  └── nodejs/                 → Node.js SDK

data/                     → Training datasets (JSONL format)
tests/                    → Test suite
docs/                     → Documentation and API specs
```

### REST API Structure

The Flask-based API (`hancock_agent.py --server`) exposes:
- `/health` - Status and capabilities
- `/metrics` - Prometheus-compatible metrics
- `/v1/chat` - Conversational AI with history
- `/v1/ask` - Single-shot questions
- `/v1/triage` - SOC alert triage with MITRE ATT&CK mapping
- `/v1/hunt` - Threat hunting query generation (Splunk/Elastic/Sentinel)
- `/v1/respond` - PICERL incident response playbook
- `/v1/code` - Security code generation
- `/v1/ciso` - CISO advisory endpoint
- `/v1/sigma` - Sigma detection rule generator
- `/v1/yara` - YARA malware detection rule generator
- `/v1/ioc` - IOC threat intelligence enrichment

## Development Workflow

### Setup
```bash
make setup              # Create venv, install deps, copy .env.example
# Edit .env and add NVIDIA_API_KEY
make run                # Start CLI
make server             # Start REST API server (port 5000)
```

### Data Pipeline
```bash
make pipeline           # Run all collectors + formatter (v1/v2)
make pipeline-v3        # Run v3 data collection (KEV + Atomic + GHSA)
python hancock_pipeline.py --kb-only  # Offline mode (static KB only)
```

### Fine-tuning
```bash
make finetune                        # Local GPU fine-tuning
python hancock_finetune_v3.py        # v3 fine-tuning script
python hancock_cpu_finetune.py       # CPU-only fine-tuning (TinyLlama)
# Colab/Kaggle: Use Hancock_Universal_Finetune.ipynb
```

### Testing
```bash
make lint               # Run flake8 linter
make test               # Run test suite
make test-cov           # Run tests with coverage report
```

## Project-Specific Conventions

### Code Style
- **Python 3.10+** required
- Follow existing code patterns (no strict linter enforced)
- Use type hints where appropriate
- Keep functions focused and modular
- Document complex security logic with comments

### Commit Messages
Use conventional commits:
```
feat: add new SOC triage endpoint
fix: handle empty alert in /v1/triage
docs: update API reference
refactor: clean up collector logic
test: add tests for Sigma rule generation
```

### API Design
- All POST endpoints accept JSON payloads
- Use descriptive parameter names (`description`, `logsource`, `technique`)
- Return JSON responses with consistent structure
- Include error handling and validation
- Follow existing patterns in `hancock_agent.py`

### Security Principles
- **NEVER** remove authorization checks or ethical guardrails
- All pentesting features must emphasize authorized scope
- Validate inputs to prevent injection attacks
- Rate limiting is implemented via `_check_auth_and_rate()`
- API key authentication via `X-API-Key` header or `?api_key=` query param

### Training Data
- All training data must be from **public, legally sourced** knowledge bases
- Supported formats: JSONL with Mistral instruction format
- Each sample: `{"messages": [{"role": "user", "content": "..."}, {"role": "assistant", "content": "..."}]}`
- Balance between different modes (pentest, SOC, CISO, code)

## Integration Points

### NVIDIA NIM Backend
- Primary model: `mistralai/mistral-7b-instruct-v0.3`
- Code mode: `qwen/qwen2.5-coder-32b-instruct`
- Client: OpenAI-compatible client via `openai` Python package
- Base URL: `https://integrate.api.nvidia.com/v1`

### Fine-tuning Stack
- **Framework**: Unsloth (optimized transformers + PEFT)
- **Method**: LoRA (Low-Rank Adaptation)
- **Base Model**: Mistral 7B Instruct v0.3
- **Dataset Format**: Mistral instruction format (JSONL)
- **Export**: GGUF Q4_K_M quantization for local Ollama deployment

### External Data Sources
- **MITRE ATT&CK**: STIX 2.0 data via `stix2` + `libtaxii`
- **NVD**: REST API (rate limited, optional API key)
- **CISA KEV**: JSON catalog
- **Atomic Red Team**: GitHub repository scraping
- **GitHub Security Advisories**: GraphQL API
- **Sigma Rules**: SigmaHQ repository

### Deployment
- **Docker**: `Dockerfile` + `docker-compose.yml` for containerized deployment
- **Fly.io**: `fly.toml` configuration for cloud deployment
- **Local**: Virtualenv with `requirements.txt`

## Common Tasks

### Adding a New API Endpoint
1. Define endpoint function in `hancock_agent.py` inside `build_app()`
2. Add authentication check: `ok, err, _ = _check_auth_and_rate()`
3. Increment metrics: `_inc("requests_total"); _inc("requests_by_endpoint", "<path>")`
4. Parse JSON payload: `data = request.get_json(force=True)`
5. Build prompt with appropriate system message
6. Call NVIDIA NIM: `completion = client.chat.completions.create(...)`
7. Return JSON response with error handling
8. Update README.md with endpoint documentation
9. Add tests in `tests/test_hancock_api.py`

### Adding a New Collector
1. Create `collectors/my_collector.py`
2. Implement `collect()` function that writes to `data/my_data.json`
3. Add collector call in `hancock_pipeline.py`
4. Update formatter in `formatter/` to ingest new data
5. Document data source and format in comments
6. Test with `python collectors/my_collector.py` (standalone)

### Extending Training Data
1. Add new Q&A pairs to knowledge bases (`collectors/*_kb.py`)
2. Or add new collector for external data source
3. Run `make pipeline-v3` to regenerate dataset
4. Verify output: `wc -l data/hancock_v3.jsonl`
5. Fine-tune: `make finetune` or use Colab notebook
6. Test fine-tuned model with `ollama run hancock`

### Updating Documentation
- **API docs**: Edit `docs/api.html` and `docs/openapi.yaml`
- **Main README**: Update `README.md` (features, usage, examples)
- **Website**: Update `docs/index.html` for cyberviser.netlify.app
- **Contributing**: Update `CONTRIBUTING.md` for contributor guidelines

## Testing Guidelines

### Manual Testing
```bash
# Start server in one terminal
make server

# Test endpoints in another
curl http://localhost:5000/health
curl -X POST http://localhost:5000/v1/triage \
  -H "Content-Type: application/json" \
  -d '{"alert": "Test alert"}'

# CLI testing
make run
# Use /mode pentest, /mode soc, /mode code commands
```

### Automated Tests
- **API tests**: `tests/test_hancock_api.py` - tests all REST endpoints
- **SDK tests**: `tests/test_sdk_client.py` - tests Python SDK
- **GraphQL tests**: `tests/test_graphql_security.py` - tests GraphQL security features
- **Coverage target**: Aim for >70% on core logic (excluding collectors)

### Test Data
- Use small, deterministic test cases
- Mock external API calls (NVIDIA NIM, NVD, MITRE)
- Keep test execution time under 60 seconds total
- Document any API keys required for integration tests

## Security Best Practices

### Input Validation
- Sanitize all user inputs before passing to LLM
- Validate JSON payloads against expected schema
- Limit input sizes to prevent DoS
- Escape special characters in prompts

### Authentication
- Use `X-API-Key` header for API authentication
- Check `os.getenv("HANCOCK_API_KEY")` for validation
- Implement rate limiting per API key
- Log authentication failures for monitoring

### Prompt Engineering
- Always include ethical guardrails in system messages
- Emphasize "authorized scope only" for pentest features
- Avoid prompt injection vulnerabilities
- Use structured output formats where possible

### Code Security
- No hardcoded secrets (use `.env` and environment variables)
- Validate all file paths to prevent directory traversal
- Use `subprocess` with argument arrays, never shell string interpolation
- Keep dependencies up to date (Dependabot enabled)

## Troubleshooting

### Common Issues

**Import Error: OpenAI module not found**
- Run `pip install -r requirements.txt` or `make setup`

**NVIDIA API Key Invalid**
- Check `.env` file has valid `NVIDIA_API_KEY=nvapi-...`
- Get free key at https://build.nvidia.com

**Rate Limiting on NVD**
- Use `--skip-nvd` flag: `python hancock_pipeline.py --skip-nvd`
- Or add NVD API key to `.env`: `NVD_API_KEY=...`

**Fine-tuning Out of Memory**
- Use CPU version: `python hancock_cpu_finetune.py`
- Or use Colab/Kaggle with free T4 GPU
- Reduce batch size in fine-tuning script

**Test Failures**
- Ensure server is not running during tests (conflicts on port 5000)
- Check API key is set: `export NVIDIA_API_KEY=...`
- Run individual test: `pytest tests/test_hancock_api.py::test_health -v`

## AI Agent Guidelines

When working on Hancock as an AI coding agent:

1. **Understand context**: This is a security-focused AI project with ethical responsibilities
2. **Preserve guardrails**: Never remove authorization checks or ethical constraints
3. **Follow patterns**: Match existing code style and API design patterns
4. **Test thoroughly**: Security code must be reliable and well-tested
5. **Document changes**: Update relevant docs when adding features
6. **Think security**: Consider injection, auth, rate limiting in all changes
7. **Stay focused**: Make minimal, surgical changes to address specific issues
8. **Validate data sources**: Ensure training data is public and legally sourced

## Resources

- **Main Repository**: https://github.com/cyberviser/Hancock
- **Website**: https://cyberviser.netlify.app
- **API Documentation**: https://cyberviser.netlify.app/api
- **NVIDIA NIM**: https://build.nvidia.com
- **MITRE ATT&CK**: https://attack.mitre.org
- **NVD**: https://nvd.nist.gov
- **License**: Proprietary (see LICENSE) - Commercial use requires agreement

## Version Information

- **Current Version**: 0.4.0
- **Python**: 3.10+
- **Base Model**: Mistral 7B Instruct v0.3
- **Framework**: Flask (API), Unsloth (fine-tuning)
- **Deployment**: Docker, Fly.io, local virtualenv

---

**For questions or issues, open a GitHub issue or see CONTRIBUTING.md**
