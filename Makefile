.PHONY: install fmt lint test check gui clean

PY ?= .venv/bin/python
RUFF ?= .venv/bin/ruff

install:
	python3 -m venv .venv
	.venv/bin/pip install --quiet --upgrade pip
	.venv/bin/pip install --quiet -e .

dev:
	.venv/bin/pip install --quiet ruff keyring

fmt:
	$(RUFF) format sonargaze tests
	$(RUFF) check --fix sonargaze tests

lint:
	$(RUFF) check sonargaze tests

test:
	xvfb-run -a $(PY) -m unittest discover -s tests -t . -v

gui:
	$(PY) -m sonargaze.gui

check: lint test

clean:
	rm -rf .pytest_cache .ruff_cache build dist *.egg-info
	find . -name __pycache__ -type d -prune -exec rm -rf {} +
