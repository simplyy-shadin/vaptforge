.PHONY: install test lint api lab-up lab-down

install:
	python -m pip install -e ".[dev]"

test:
	pytest

lint:
	ruff check .

api:
	uvicorn vaptforge.api.main:app --reload

lab-up:
	docker compose -f labs/docker-compose.yml up -d

lab-down:
	docker compose -f labs/docker-compose.yml down
