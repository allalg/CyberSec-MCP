.PHONY: dev test lint format typecheck build-sandboxes lab-up lab-down clean install

# Development
install:
	uv sync --all-extras

dev:
	uv run mcp dev server/main.py

run:
	uv run python -m server.main

# Quality
lint:
	uv run ruff check server/ tests/

format:
	uv run ruff format server/ tests/

typecheck:
	uv run mypy server/

# Testing
test:
	uv run pytest -v

test-cov:
	uv run pytest --cov=server --cov-report=html

# Docker sandbox images
build-sandboxes:
	docker build -t cybersec-mcp/nmap:latest sandboxes/nmap/
	docker build -t cybersec-mcp/web-tools:latest sandboxes/web/
	docker build -t cybersec-mcp/analysis:latest sandboxes/analysis/

# Attack lab
lab-up:
	docker compose -f lab/docker-compose.yml up -d

lab-down:
	docker compose -f lab/docker-compose.yml down -v

lab-restart:
	docker compose -f lab/docker-compose.yml restart

# Cleanup
clean:
	find . -type d -name __pycache__ -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete
	rm -f audit.db
	rm -rf .pytest_cache .mypy_cache htmlcov
