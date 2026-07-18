# Contributing to SOFE Server

Thanks for your interest in contributing to sofe-server!

## What is sofe-server?

A thin FastAPI wrapper around the [SOFE engine](https://github.com/breakingthecloud/sofe). It exposes the engine's functionality via REST endpoints. All evaluation logic lives in the engine — this repo is just the HTTP layer.

## Setting Up Development

```bash
git clone https://github.com/breakingthecloud/sofe-server.git
git clone https://github.com/breakingthecloud/sofe.git  # engine (dependency)
cd sofe-server
uv venv && source .venv/bin/activate
uv pip install -e . -e ../sofe/
uvicorn sofe_server.app:app --reload --port 8080
```

## Project Structure

```
sofe-server/
├── sofe_server/
│   ├── app.py       # FastAPI application (all endpoints)
│   ├── main.py      # Entry point (uvicorn runner)
│   └── __init__.py
├── docs/
│   ├── openapi.yaml # API spec
│   └── testing.md   # Test guide
├── pyproject.toml
├── Dockerfile
└── LICENSE
```

## Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/health` | Health check |
| POST | `/evaluate` | Evaluate AWS against policies |
| POST | `/validate` | Validate BYaML YAML |
| GET | `/policies` | List loaded policies |
| GET | `/collectors` | List registered collectors |
| GET | `/metrics` | Metrics per collector |
| POST | `/connect/test` | Test STS AssumeRole |

## Pull Requests

- New endpoints should be thin wrappers around sofe engine functions
- Keep the server stateless (no database, no persistence)
- No authentication logic (that's the SaaS layer's job)
- Test with `curl localhost:8080/your-endpoint`

## What We Accept

- ✅ New endpoints wrapping existing engine functions
- ✅ Bug fixes
- ✅ Performance improvements
- ✅ Docker improvements
- ✅ Documentation

## What We Don't Accept

- ❌ Authentication/authorization (belongs in the SaaS API layer)
- ❌ Database/persistence (this is stateless)
- ❌ Direct AWS calls (should go through sofe engine)
- ❌ Heavy dependencies

## Questions?

Open an issue or see [sofe.dev/docs](https://sofe.dev/docs).
