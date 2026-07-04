# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

This is **llm_ir_dt** — a dockerized incident response testbed ("digital twin") for autonomous IR research. Python project (JetBrains/PyCharm-managed, Python SDK `ccs26`). Follows patterns from `../ccs26_incident_response/ccs-response-planner-backend/`.

## Architecture

- **src layout**: `src/llm_ir_dt/` with setuptools
- **DockerManager**: static-method facade using Docker SDK (`docker_manager/docker_manager.py`)
- **Constants**: `DOCKER`, `DIGITAL_TWIN` classes in `constants/constants.py`
- **Network topology**: client network (10.0.1.0/24) and server network (10.0.2.0/24) connected by a Snort IDS gateway

## Build & Run Commands

```bash
# Install
pip install -e .

# Build container images
docker compose build

# Run tests
pytest

# Lint
flake8 src tests

# Type check
mypy src

# Run all checks via tox
tox
```

## Coding Conventions

- Python 3.11+, strict mypy, type hints on all functions
- Docstrings: reST format (`"""` on own line, `:param:`, `:return:`)
- flake8: 120 char max line, flake8-rst-docstrings
- 4 dependency files kept in sync: pyproject.toml (`==`), setup.cfg (`>=`), requirements.txt, requirements_dev.txt
- Logging: `logging.getLogger(__name__)`
