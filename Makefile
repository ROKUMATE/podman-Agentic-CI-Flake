VENV := .venv
PY   := $(VENV)/bin/python
PIP  := $(VENV)/bin/pip
BIN  := $(VENV)/bin

.PHONY: install test demo eval clean

## Create a venv and install flakectl in editable mode with dev extras.
install:
	python3 -m venv $(VENV)
	$(PIP) install --quiet --upgrade pip
	$(PIP) install --quiet -e ".[dev]"
	@echo "installed: $(BIN)/flakectl"

## Run the unit tests.
test:
	$(BIN)/pytest

## Run the end-to-end demo (offline, no API key, no network).
demo:
	./demo.sh

## Score the categorizer against the hand-labelled corpus.
eval:
	$(PY) eval/run.py

clean:
	rm -rf $(VENV) .pytest_cache **/__pycache__ *.egg-info report.json weekly-report.md flakectl.db
