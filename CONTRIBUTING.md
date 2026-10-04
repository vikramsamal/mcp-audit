# Contributing to mcp-audit

Thank you for contributing to `mcp-audit`! We welcome contributions that align with our core priorities:

**Safety → Accuracy → Transparency → Reliability → Simplicity → Documentation → Features**

---

## Development Setup

Requirements:
- Python 3.11+
- Git

### 1. Clone the repository & create virtual environment

```bash
git clone https://github.com/vikramsamal/mcp-audit.git
cd mcp-audit
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]" || pip install pytest ruff build
```

### 2. Running Tests

```bash
pytest
```

Run security-specific tests:
```bash
pytest tests/test_security.py -v
```

### 3. Linting and Formatting

```bash
ruff check .
```

To automatically format or fix supported lint rules:
```bash
ruff check --fix .
```

---

## Architecture Guidelines

1. **Keep it small and deterministic**: Do not introduce LLM runtime dependencies or cloud APIs.
2. **Never execute untrusted input**: Configuration is untrusted data.
3. **Multi-signal heuristics**: Avoid naive keyword flags that trigger false positives on documentation or search tools.
4. **Transparent findings**: Every finding must answer:
   - What did we observe?
   - Why might it matter?
   - What evidence supports it?
   - What should the developer review?

---

## Pull Request Checklist

Before submitting your PR, ensure:
- [ ] All unit and security tests pass (`pytest`)
- [ ] Ruff lint checks pass with zero errors (`ruff check .`)
- [ ] Package builds successfully (`python -m build`)
- [ ] New functionality includes corresponding unit tests in `tests/`
