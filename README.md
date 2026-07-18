# 🟢 SOFE Server — FinOps Policy Engine API

REST API server for the [SOFE](https://sofe.dev) (Stairway Open FinOps Engine). Wraps the SOFE Python engine in a FastAPI application, enabling HTTP-based evaluations.

## Quick Start

```bash
pip install sofe sofe-server
sofe-server
# → http://localhost:8080
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
| POST | `/validate` | Validate a BYaML YAML file |
| GET | `/policies` | List all loaded policies |
| GET | `/collectors` | List available collectors |
| GET | `/metrics` | List metrics per collector |
| POST | `/connect/test` | Test STS AssumeRole connection |

## Usage

### Evaluate your AWS account

```bash
curl -X POST http://localhost:8080/evaluate \
  -H "Content-Type: application/json" \
  -d '{"aws_profile": "default"}'
```

### With cross-account role

```bash
curl -X POST http://localhost:8080/evaluate \
  -H "Content-Type: application/json" \
  -d '{
    "role_arn": "arn:aws:iam::123456789012:role/SOFEReadOnlyRole",
    "external_id": "sofe-abc123"
  }'
```

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

sofe-server is a **thin wrapper** — all logic lives in the [sofe engine](https://github.com/breakingthecloud/sofe).

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
```

## Related Projects

| Project | Description |
|---------|-------------|
| [sofe](https://github.com/breakingthecloud/sofe) | Python engine (collectors + policies) |
| [sofe-cli](https://github.com/breakingthecloud/sofe-cli) | Go CLI (19 commands, TUI) |
| [sofe-action](https://github.com/breakingthecloud/sofe-action) | GitHub Action for CI/CD |
| [platform.sofe.dev](https://platform.sofe.dev) | SaaS dashboard (free tier) |
| [sofe.dev/docs](https://sofe.dev/docs) | Documentation (26 pages) |

## License

Apache 2.0 — see [LICENSE](LICENSE)
