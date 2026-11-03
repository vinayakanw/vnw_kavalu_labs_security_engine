# Kavalu Security Engine - developer shortcuts.  Run `make help`.
# Assumes an activated virtual environment (see `make venv`).

PYTHON ?= python3
HOST   ?= 127.0.0.1
PORT   ?= 5000
IMAGE  ?= kavalu-security-engine

.DEFAULT_GOAL := help
.PHONY: help venv install dev run demo-target test test-ui cov lint fix audit check docker-build docker-run clean

help:  ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-14s\033[0m %s\n", $$1, $$2}'

venv:  ## Create .venv (then: source .venv/bin/activate)
	$(PYTHON) -m venv .venv
	@echo "Now run: source .venv/bin/activate   (Windows: .venv\\Scripts\\activate)"

install:  ## Install runtime dependencies only
	python -m pip install -r requirements.txt

dev:  ## Install runtime + development dependencies and git hooks
	python -m pip install -r requirements-dev.txt
	@pre-commit install || echo "pre-commit not available on this Python (needs 3.11+); skipping git hooks"

run:  ## Run the dashboard + API locally (bound to loopback only)
	flask --app app run --host $(HOST) --port $(PORT)

demo-target:  ## Start a deliberately vulnerable local practice target to scan
	python -m tests.vulnerable_server

test:  ## Run the test suite
	python -m pytest

test-ui:  ## Browser-level dashboard test (needs Node.js 22.22.2 or newer)
	npm ci --prefix tests/dashboard
	python scripts/run_dashboard_tests.py

cov:  ## Run tests with a coverage report
	python -m pytest --cov --cov-report=term-missing

lint:  ## Static checks: lint and formatting (ruff)
	ruff check .
	ruff format --check .

fix:  ## Auto-fix lint problems and format the code
	ruff check . --fix
	ruff format .

audit:  ## Check pinned dependencies for known vulnerabilities
	pip-audit -r requirements.txt --no-deps --disable-pip

check: lint test  ## Everything CI runs locally: lint + tests

docker-build:  ## Build the container image
	docker build -t $(IMAGE) .

docker-run:  ## Run the container on http://127.0.0.1:5000
	docker run --rm -p 127.0.0.1:5000:10000 $(IMAGE)

clean:  ## Remove caches and coverage output (never touches reports/ or logs/)
	find . -type d -name __pycache__ -not -path './.venv/*' -prune -exec rm -rf {} +
	rm -rf .pytest_cache .ruff_cache .coverage coverage.xml htmlcov
