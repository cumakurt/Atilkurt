# AtilKurt - Makefile
# Active Directory Security Health Check Tool

PYTHON ?= python3
VENV_DIR ?= .venv
VENV_BIN = $(VENV_DIR)/bin
PIP = $(VENV_BIN)/pip
PY = $(VENV_BIN)/python

# AtilKurt run parameters (override from env or: make run DOMAIN=corp.local USER=admin PASS=secret DC=10.0.0.1)
DOMAIN ?= example.com
USER ?= username
PASS ?=
DC_IP ?= 192.168.1.10
OUTPUT ?= report.html

# Docker
DOCKER_IMAGE ?= atilkurt:latest
DOCKER_OUTPUT_DIR ?= ./output

.PHONY: help venv install install-dev test lint clean run docker-build docker-run docker-shell docker-run-interactive

help:
	@echo "AtilKurt - Active Directory Security Health Check"
	@echo ""
	@echo "Setup:"
	@echo "  make venv        Create virtual environment (.venv)"
	@echo "  make install     Install dependencies (uses venv)"
	@echo "  make install-dev Install with dev dependencies (pytest, ruff)"
	@echo ""
	@echo "Run (local):"
	@echo "  make run         Run AtilKurt (DOMAIN, USER, PASS, DC_IP required)"
	@echo "  make run ARGS='--ssl --json-export out.json'  Extra arguments"
	@echo ""
	@echo "Docker:"
	@echo "  make docker-build   Build Docker image"
	@echo "  make docker-run     Run inside container (report written to ./output)"
	@echo "  make docker-shell   Open shell in container"
	@echo ""
	@echo "Quality:"
	@echo "  make test        Run unit tests"
	@echo "  make lint        Lint with ruff (if ruff installed)"
	@echo "  make clean       Remove cache and temporary files"
	@echo ""
	@echo "Example:"
	@echo "  make install"
	@echo "  make run DOMAIN=corp.local USER=admin PASS=MyPass123 DC_IP=10.0.0.1"
	@echo "  make docker-run DOMAIN=corp.local USER=admin PASS=MyPass123 DC_IP=10.0.0.1"

venv:
	$(PYTHON) -m venv $(VENV_DIR)
	@echo "Virtual environment created: $(VENV_DIR)"
	@echo "Activate with: source $(VENV_DIR)/bin/activate"

install: venv
	$(PIP) install -r requirements.txt
	@echo "Dependencies installed."

install-dev: install
	$(PIP) install pytest ruff 2>/dev/null || true
	@echo "Dev tools added."


run:
	@if [ -z "$(PASS)" ]; then \
		$(PYTHON) AtilKurt.py -d $(DOMAIN) -u $(USER) --dc-ip $(DC_IP) --output $(OUTPUT) $(ARGS); \
	else \
		$(PYTHON) AtilKurt.py -d $(DOMAIN) -u $(USER) -p "$(PASS)" --dc-ip $(DC_IP) --output $(OUTPUT) $(ARGS); \
	fi

test:
	$(PYTHON) -m pytest tests/ -v --tb=short

lint:
	@command -v ruff >/dev/null 2>&1 && ruff check . --exclude .venv || echo "Ruff not installed: pip install ruff"

clean:
	rm -rf .pytest_cache .ruff_cache
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete 2>/dev/null || true

# --- Docker targets ---

docker-build:
	docker build -t $(DOCKER_IMAGE) .

docker-run:
	@mkdir -p $(DOCKER_OUTPUT_DIR)
	@if [ -z "$(PASS)" ]; then \
		echo "Error: PASS required. Example: make docker-run DOMAIN=corp.local USER=admin PASS=xxx DC_IP=10.0.0.1"; exit 1; \
	fi
	docker run --rm \
		-e ATILKURT_DOMAIN=$(DOMAIN) \
		-e ATILKURT_USER=$(USER) \
		-e ATILKURT_PASS=$(PASS) \
		-e ATILKURT_DC_IP=$(DC_IP) \
		-e ATILKURT_OUTPUT=/output/$(OUTPUT) \
		-v "$(abspath $(DOCKER_OUTPUT_DIR)):/output" \
		$(DOCKER_IMAGE) $(ARGS)

docker-run-interactive:
	@mkdir -p $(DOCKER_OUTPUT_DIR)
	docker run -it --rm \
		-e ATILKURT_DOMAIN=$(DOMAIN) \
		-e ATILKURT_USER=$(USER) \
		-e ATILKURT_DC_IP=$(DC_IP) \
		-e ATILKURT_OUTPUT=/output/$(OUTPUT) \
		-v "$(abspath $(DOCKER_OUTPUT_DIR)):/output" \
		$(DOCKER_IMAGE) $(ARGS)

docker-shell:
	docker run -it --rm --entrypoint /bin/sh $(DOCKER_IMAGE)
