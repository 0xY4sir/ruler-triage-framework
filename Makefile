PYTHON ?= python3
FILE ?=

.PHONY: install run validate test lint clean

install:
	$(PYTHON) -m pip install -r requirements.txt

run:
	$(PYTHON) ruler_triage.py "$(FILE)"

validate:
	$(PYTHON) ruler_triage.py --validate-case

test:
	$(PYTHON) -m pytest tests/ -v

lint:
	$(PYTHON) -m compileall -q ruler_triage.py app.py tests

clean:
	find . -path ./venv -prune -o -type d -name __pycache__ -prune -exec rm -rf {} +
	rm -rf .pytest_cache
