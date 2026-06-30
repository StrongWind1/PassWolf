.PHONY: test lint format typecheck check build clean distclean install install-tool install-dev docs docs-check docs-serve

test:
	uv run pytest

lint:
	uv run ruff check
	uv run ruff format --check

format:
	uv run ruff format
	uv run ruff check --fix

typecheck:
	uv run ty check

check: lint typecheck test docs-check

build:
	uv build

install:
	uv pip install .

install-tool:
	uv tool install .

install-dev:
	uv sync

docs:
	uv run --group docs mkdocs build

docs-check:
	uv run --group docs mkdocs build --strict
	@rm -rf site/
	@echo "Docs checks passed."

docs-serve:
	uv run --group docs mkdocs serve

clean:
	rm -rf dist/ build/ *.egg-info site/
	find . -type d -name __pycache__ -exec rm -rf {} +
	rm -rf .pytest_cache .ruff_cache .ty .cache

distclean: clean
	rm -rf .venv/
