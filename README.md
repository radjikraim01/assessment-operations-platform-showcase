# Assessment Operations Platform

This repository is a sanitized public showcase extracted from a larger private
Flask/PostgreSQL application. It is intended to demonstrate backend and
product-engineering work without exposing client data, proprietary logic, or
internal operating details.

## What This Project Shows

The codebase is structured around a typical internal operations product with:

- a Flask application serving both JSON APIs and server-rendered admin pages
- session-based admin authentication plus API-key protected integrations
- service-layer modules for workflow actions and status changes
- Postgres access through direct queries and pooled connections
- request validation, standardized error handling, and security guardrails
- operational concerns such as rate limiting, compression, CORS, and audit logging

## Representative Features

The published snapshot keeps several useful engineering slices intact:

- role and catalog style data retrieval through API endpoints
- admin login and protected dashboard flows
- access-request style review and status-management workflows
- integration endpoints for external systems
- validation logic for structured request payloads
- tests covering startup, validation, and selected regression paths

The exact business context has been deliberately generalized. The point of this
repo is to show application structure, code organization, and engineering
approach rather than disclose the original deployment.

## Architecture Overview

Key areas in the repo:

- `app.py`: main Flask app, route registration, middleware-style protections, and app bootstrap
- `auth/`: authentication, authorization helpers, and audit utilities
- `services/`: workflow-oriented business logic extracted out of route handlers
- `db_pool.py`: pooled database access and transaction helpers
- `validators.py`: Pydantic models and input validation rules
- `templates/`: server-rendered dashboard and admin UI templates
- `tests/`: representative startup, validation, and regression checks

## What Was Removed

This public snapshot intentionally excludes:

- customer data and operational exports
- secrets, credentials, and environment-specific deployment values
- proprietary prompts, private agent implementations, and internal notes
- confidential documentation and organization-specific process details
- the full schema, migrations, and seed data required to reproduce production

Because of that, this repository is best treated as a portfolio sample rather
than a fully reproducible product release.

## Running Locally

1. Create and activate a virtual environment.
2. Install dependencies.
3. Copy the example environment file and supply your own values.
4. Start the app.

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
Copy-Item .env.example .env
python app.py
```

The app expects a PostgreSQL database and tables compatible with the original
private project. The included code is structurally valid, but the complete
private schema and deployment scaffolding are intentionally not published here.

## Docker

```powershell
docker build -t assessment-ops-showcase .
docker run --rm -p 5000:5000 --env-file .env assessment-ops-showcase
```

## Notes

- Optional integration routes referenced by the app are intentionally omitted.
- Some tests assume a running local app and a database seeded with compatible records.
- The repository is curated to show design and implementation quality, not to mirror the original system one-to-one.