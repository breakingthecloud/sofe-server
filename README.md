<p align="center">
  <img alt="SOFE Server" src="https://img.shields.io/badge/🟢-SOFE_Server-22C55E?style=for-the-badge" height="50">
</p>

<p align="center">
  <b>REST API for the SOFE FinOps Engine</b><br>
  Multi-tenant evaluation platform with catalog, history, and alerts.
</p>

<p align="center">
  <a href="#quick-start">Quick Start</a>
  ·
  <a href="#endpoints">Endpoints</a>
  ·
  <a href="#usage">Usage</a>
  ·
  <a href="#ecosystem">Ecosystem</a>
</p>

<p align="center">
  <img src="https://img.shields.io/pypi/v/sofe-server?style=flat-square&logo=pypi&color=22C55E" alt="PyPI">
  <img src="https://img.shields.io/badge/python-3.11%2B-blue?style=flat-square&logo=python" alt="Python">
  <img src="https://img.shields.io/badge/license-Apache_2.0-22C55E?style=flat-square" alt="License">
  <img src="https://img.shields.io/badge/FastAPI-0.115-009688?style=flat-square&logo=fastapi" alt="FastAPI">
  <img src="https://img.shields.io/badge/PRs-welcome-brightgreen?style=flat-square" alt="PRs">
</p>

---

Wraps the [SOFE](https://github.com/breakingthecloud/sofe) Python engine in a FastAPI application, enabling HTTP-based evaluations.

```bash
pip install sofe sofe-server
sofe-server
# → http://localhost:8080
```

## Quick Start

```bash
# Install
pip install sofe sofe-server

# Start server
sofe-server

# Evaluate your AWS account
curl -X POST http://localhost:8080/evaluate \
  -H "Content-Type: application/json" \
  -d '{"profile": "default"}'
```

Or use the Go CLI:
```bash
sofe serve    # starts sofe-server in background
sofe evaluate # calls localhost:8080/evaluate
```

## Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/health` | Health check |
| POST | `/evaluate` | Evaluate AWS account against policies |
| POST | `/validate` | Validate an Architecture Graph (BYaML v0.4 JSON) |
| GET | `/policies` | List all loaded policies |
| GET | `/collectors` | List available collectors |
| GET | `/metrics` | List metrics per collector |
| POST | `/connect/test` | Test STS AssumeRole connection |

## Usage

### Evaluate a different AWS account (cross-account role)

Pass the role to assume and its ExternalId. The server calls `sts:AssumeRole` and runs
**every** collector with those temporary credentials, so the account behind the role is
the one that gets evaluated:

```bash
curl -X POST http://localhost:8080/evaluate \
  -H "Content-Type: application/json" \
  -d '{
    "role_arn": "arn:aws:iam::123456789012:role/sofe-read-only",
    "external_id": "your-external-id"
  }'
```

| Field | Notes |
|-------|-------|
| `role_arn` | IAM role ARN to assume. Takes precedence over `profile`. |
| `external_id` | Required with `role_arn` (2-1224 chars: letters, digits, `+=,.@:/-`). |

The response says what was actually read: `account_id`, `evaluated_via`
(`assumed_role` \| `profile` \| `default_credentials`) and `evaluated_role_arn`.

| Status | Meaning |
|--------|---------|
| `400` | Missing/invalid `role_arn` or `external_id`, or a role is required (see below). No AWS call is made. |
| `403` | STS denied the assume: the role does not exist in that account or its trust policy ExternalId does not match. |
| `502` | STS failed for another reason. |
| `501` | The installed `sofe` engine is too old for role-based evaluation (upgrade `sofe`). |

The ExternalId is never echoed in responses or logs.

### Hosted deployments: require a role

By default, a request without `role_arn` evaluates the account of the server's own
credentials (or `profile`) — the right behavior for self-hosted use. A **hosted** server
that evaluates *other people's* accounts must never do that. Set:

```bash
SOFE_REQUIRE_ROLE=true
```

and any `/evaluate` request that does not name a role is rejected with `400` before any
AWS API is called.

### List policies

```bash
curl http://localhost:8080/policies
```

## Docker

```bash
docker run -p 8080:8080 -v ~/.aws:/root/.aws:ro \
  ghcr.io/breakingthecloud/sofe-community:latest
```

## Architecture

```
sofe-server (this repo)
    │
    │ imports
    ▼
sofe/ (engine — pip install sofe)
    │
    │ boto3
    ▼
Your AWS Account (read-only)
```

sofe-server is a **thin wrapper** — all policy evaluation logic lives in the [sofe engine](https://github.com/breakingthecloud/sofe).

## Requirements

- Python 3.11+
- `sofe` >= 0.2.0 (engine)
- AWS credentials (profile or role)

## Development

```bash
git clone https://github.com/breakingthecloud/sofe-server.git
cd sofe-server
uv venv && source .venv/bin/activate
uv pip install -e ".[dev]" -e ../sofe/
uvicorn sofe_server.app:app --reload --port 8080

# Tests (no AWS needed: STS and the engine are faked)
pytest
```

## Ecosystem

| Project | Description |
|---------|-------------|
| [sofe](https://github.com/breakingthecloud/sofe) | Python engine (collectors + policies) |
| [sofe-cli](https://github.com/breakingthecloud/sofe-cli) | Go CLI (19 commands, TUI) |
| [sofe-action](https://github.com/breakingthecloud/sofe-action) | GitHub Action for CI/CD |
| [platform.sofe.dev](https://platform.sofe.dev) | SaaS dashboard (free tier) |
| [sofe.dev/docs](https://sofe.dev/docs) | Documentation (26 pages) |

## License

Apache 2.0 — see [LICENSE](LICENSE).

---

<p align="center">
  <a href="https://sofe.dev">sofe.dev</a> · <a href="https://github.com/breakingthecloud/sofe">Engine</a> · <a href="https://finoptix.dev">finoptix.dev</a>
</p>
