.DEFAULT_GOAL := help

.PHONY: all help format lint unit integration

all: format lint unit  ## Run all quick, local commands

help:  ## Display help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-15s\033[0m %s\n", $$1, $$2}'

format:  ## Format and auto-fix with ruff
	uv run --group dev ruff check --preview --fix
	uv run --group dev ruff format --preview

lint:  ## Lint with ruff, type-check with pyright, and check code spelling with codespell
	uv run --group dev ruff check --preview
	uv run --group dev ruff format --preview --check
	# pyright also type-checks tests/integration/, which imports jubilant and
	# pytest, so it needs the integration group installed alongside dev too.
	PYTHONPATH=src:lib uv run --group dev --group integration pyright
	uv run --group dev codespell

unit:  ## Run unit tests. To provide extra args, use: make unit ARGS='extra_args'
	PYTHONPATH=src:lib uv run --group dev coverage run --source=src -m unittest -v $(ARGS)
	uv run --group dev coverage report -m

integration:  ## Run integration tests
	uv run --group integration pytest tests/integration -v --log-cli-level=INFO
