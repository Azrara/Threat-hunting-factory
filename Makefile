VENV ?= .venv
PY := $(VENV)/bin/python

.PHONY: install run test sample clean

install:
	python3 -m venv $(VENV)
	$(VENV)/bin/pip install --upgrade pip
	$(VENV)/bin/pip install -r requirements.txt

run:
	$(VENV)/bin/uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload

test:
	$(PY) -m pytest

sample:
	$(PY) tools/generate_sample_evidence.py sample-evidence.zip

clean:
	rm -rf .pytest_cache **/__pycache__ data/uploads
