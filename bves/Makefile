.PHONY: help setup up down logs test test-py test-contracts lint fmt samples demo evaluate evaluate-offline api ui ingestor

help:            ## show targets
	@grep -E '^[a-z-]+:.*##' Makefile | awk -F':.*## ' '{printf "  %-18s %s\n", $$1, $$2}'

setup:           ## create .env from the template (if missing)
	@test -f .env || (cp .env.example .env && echo "created .env")

up: setup        ## build and start the whole stack
	docker compose up --build -d
	@echo "UI: http://localhost:8501   API docs: http://localhost:8000/docs"

down:            ## stop the stack (add -v to drop volumes: docker compose down -v)
	docker compose down

logs:            ## tail logs
	docker compose logs -f --tail=100

test: test-py test-contracts  ## run all tests

test-py:         ## Python unit/API tests
	python -m pytest -q

test-contracts:  ## Hardhat contract tests (needs `npm install`)
	npx hardhat test

lint:            ## ruff + black check
	ruff check . && black --check .

fmt:             ## auto-format
	ruff check --fix . ; black .

samples:         ## regenerate sample CloudTrail logs
	python scripts/generate_samples.py

demo:            ## tamper demo against the running stack
	python scripts/tamper_demo.py

evaluate:        ## full evaluation against the running stack
	python scripts/evaluate.py

evaluate-offline: ## evaluation with in-memory chain/IPFS (no gas data)
	python scripts/evaluate.py --offline

# --- local (non-docker) dev: run each in its own terminal ---
api:             ## uvicorn on :8000 (needs hardhat node + deploy + ipfs)
	alembic upgrade head && uvicorn api.main:app --reload --port 8000

ui:              ## streamlit on :8501
	PYTHONPATH=. streamlit run ui/app.py

ingestor:        ## watch ./incoming
	python -m ingestor.watcher
