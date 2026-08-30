.PHONY: help dev dev-api dev-frontend build test lint clean migrate seed deploy-aws deploy-azure

help:  ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' Makefile | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

# ---- Development ----

dev:  ## Start full dev stack (docker compose)
	docker compose -f docker-compose.yml -f docker-compose.dev.yml up -d
	@echo "API:       http://localhost:8000/api/docs"
	@echo "Frontend:  http://localhost:5173"
	@echo "MailHog:   http://localhost:8025"

dev-api:  ## Start API only with hot reload
	uvicorn certmanager.api.app:app --reload --host 0.0.0.0 --port 8000

dev-frontend:  ## Start frontend dev server
	cd frontend && npm run dev

# ---- Build ----

build:  ## Build all Docker images
	docker build -f docker/Dockerfile.api -t certmanager-api .
	docker build -f docker/Dockerfile.worker -t certmanager-worker .
	docker build -f docker/Dockerfile.agent -t certmanager-agent .
	docker build -f docker/Dockerfile.frontend -t certmanager-frontend .

# ---- Database ----

migrate:  ## Run database migrations
	python -m alembic -c alembic/alembic.ini upgrade head

migrate-down:  ## Rollback last migration
	python -m alembic -c alembic/alembic.ini downgrade -1

migrate-new:  ## Create a new migration (usage: make migrate-new MSG="description")
	python -m alembic -c alembic/alembic.ini revision --autogenerate -m "$(MSG)"

seed:  ## Seed RBAC roles and admin user
	python -m certmanager.cli seed

# ---- Testing ----

test:  ## Run test suite
	pytest -v --cov=certmanager --cov-report=term-missing

test-watch:  ## Run tests on file changes
	ptw -- --testmon

lint:  ## Run linters
	ruff check certmanager/
	ruff format --check certmanager/

lint-fix:  ## Auto-fix linting issues
	ruff check --fix certmanager/
	ruff format certmanager/

# ---- Infrastructure (OpenTofu) ----

deploy-aws:  ## Plan and apply AWS deployment
	cd deploy/aws && tofu init && tofu plan && tofu apply

deploy-azure:  ## Plan and apply Azure deployment
	cd deploy/azure && tofu init && tofu plan && tofu apply

# ---- Utility ----

clean:  ## Remove build artifacts and caches
	find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name ".pytest_cache" -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name "*.egg-info" -exec rm -rf {} + 2>/dev/null || true
	rm -rf dist/ build/ htmlcov/ .coverage

deps:  ## Install all dependencies
	pip install -e ".[dev]"
	cd frontend && npm install
