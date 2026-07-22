PYTHON ?= python3.12

.PHONY: install web-install lint format-check typecheck test web-test web-build \
	compose-check check dev down logs

install:
	$(PYTHON) -m pip install -e ".[dev]"

web-install:
	npm --prefix web ci

lint:
	ruff check .

format-check:
	ruff format --check .

typecheck:
	mypy .

test:
	$(PYTHON) -m pytest

web-test:
	npm --prefix web test

web-build:
	npm --prefix web run build

compose-check:
	docker compose config --quiet

dev:
	docker compose up --build

down:
	docker compose down

logs:
	docker compose logs --follow

check: lint format-check typecheck test web-test web-build compose-check
