# Assessment Operations Platform

Sanitized public showcase of a Flask and PostgreSQL web application extracted
from a larger private codebase.

This repo is meant to demonstrate backend and product engineering patterns:

- Flask app with both API endpoints and server-rendered dashboard flows
- Session-based admin authentication and API-key protected routes
- Postgres connection pooling and service-layer modules
- Input validation with Pydantic plus standardized JSON error responses
- Operational concerns such as rate limiting, CORS, compression, and logging

## What Is Included

- Core Flask app entrypoint in `app.py`
- Authentication and audit helpers under `auth/`
- Service-layer modules under `services/`
- HTML templates for the dashboard and workflow screens
- Representative tests for startup, validation, and integration patterns

## What Was Removed

This public snapshot intentionally excludes:

- customer data and production exports
- private prompts and internal agent implementations
- proprietary documentation and operational notes
- deployment secrets and environment-specific configuration
- full database schema, migrations, and seed data

## Local Setup

1. Create and activate a virtual environment.
2. Install dependencies:

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
```

3. Copy the example environment file and fill in your values:

```powershell
Copy-Item .env.example .env
```

4. Start the app:

```powershell
python app.py
```

The app expects a PostgreSQL database with tables that match the original
private project. Basic startup and code structure are preserved here, but the
full schema and private integrations are intentionally not published.

## Environment Variables

See `.env.example` for the minimum settings required to boot the app.

## Docker

Build and run a local container:

```powershell
docker build -t assessment-ops-showcase .
docker run --rm -p 5000:5000 --env-file .env assessment-ops-showcase
```

## Notes

- `agents/` integrations are optional and intentionally omitted from this repo.
- The included integration tests assume a running app and a seeded database.
- This repository is intended as a portfolio sample, not a drop-in production deployment.