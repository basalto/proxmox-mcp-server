.PHONY: install test lint build

install:
	uv pip install -e ".[dev]"

test:
	uv run pytest

lint:
	uv run ruff check src tests
	uv run black --check src tests

build:
	docker build -t ghcr.io/basalto/proxmox-mcp-server:latest .
