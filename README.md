# 🚀 SOFE Server

**REST API for the Stairway Open FinOps Engine.**

Wraps the [SOFE](https://github.com/breakingthecloud/sofe) policy engine as a FastAPI service. Run locally for development or deploy to production (Docker, K8s, Lambda).

```bash
pip install sofe-server
sofe-server
# → http://localhost:8080
```

---

## Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/health` | Service health check |
| `GET` | `/metrics` | List available metrics |
| `GET` | `/policies` | List loaded policies |
| `POST` | `/evaluate` | Evaluate policies against live AWS |
| `POST` | `/validate` | Validate policy YAML schema |

### Swagger UI

Once running, open http://localhost:8080/docs for interactive API documentation.

---

## Quick Start

### Install

```bash
pip install sofe-server
```

### Run

```bash
# Start server (port 8080)
sofe-server

# Or with uvicorn directly
uvicorn sofe_server.app:app --host 0.0.0.0 --port 8080
```

### Docker

```bash
docker build -t sofe-server .
docker run -p 8080:8080 -v ~/.aws:/root/.aws:ro sofe-server
```

---

## Usage Examples

### Health Check

```bash
curl http://localhost:8080/health
```
```json
{"status": "ok", "version": "0.1.0"}
```

### List Policies

```bash
curl http://localhost:8080/policies?policies_dir=./policies
```
```json
[
  {"name": "no-idle-ec2", "severity": "high", "resource_types": ["aws.ec2"], "metric": "avg_cpu_utilization"},
  {"name": "require-cost-tags", "severity": "medium", "resource_types": ["aws.ec2", "aws.s3", "aws.lambda", "aws.rds"], "metric": "has_tag:owner"}
]
```

### Evaluate Policies

```bash
curl -X POST http://localhost:8080/evaluate \
  -H "Content-Type: application/json" \
  -d '{"policies_dir": "./policies", "profile": "my-aws-profile"}'
```
```json
{
  "evaluation_id": "a1b2c3d4-...",
  "timestamp": "2026-06-26T17:00:00Z",
  "policies_evaluated": 4,
  "resources_scanned": 6,
  "findings_count": 10,
  "total_estimated_savings": 0.00,
  "failed": false,
  "findings": [
    {
      "policy_name": "require-cost-tags",
      "severity": "medium",
      "resource_id": "my-bucket",
      "message": "has_tag:owner = 0.0 (threshold: ==0.0)",
      "recommendation": "Add 'owner' tag for cost allocation and accountability"
    }
  ]
}
```

### Evaluate with Fail Threshold (CI/CD)

```bash
curl -X POST http://localhost:8080/evaluate \
  -H "Content-Type: application/json" \
  -d '{"policies_dir": "./policies", "profile": "production", "fail_on": "high"}'
```

The response includes `"failed": true` if findings at or above the threshold severity exist.

### Validate a Policy

```bash
curl -X POST http://localhost:8080/validate \
  -H "Content-Type: application/json" \
  -d '{"policy_yaml": "apiVersion: sofe/v1\nkind: Policy\nmetadata:\n  name: test\n  description: test\nspec:\n  scope:\n    resource_types: [aws.ec2]\n  rule:\n    metric: avg_cpu_utilization\n    operator: \"<\"\n    threshold: 5\n  severity: high\n  actions:\n    - type: finding"}'
```
```json
{"valid": true, "errors": []}
```

---

## Configuration

### AWS Credentials

The server uses boto3's credential chain. Options:

- AWS profile: pass `"profile": "my-profile"` in the evaluate request
- Environment variables: `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`
- IAM role (EC2/ECS/Lambda): automatic

### Policies Directory

Pass `policies_dir` as query param (GET) or in request body (POST). Default: `./policies`.

---

## Auth (Hosted Mode)

For local development, no auth is required. For hosted deployments (`api.sofe.dev`), pass an API key:

```bash
curl -H "X-API-Key: your-key-here" http://api.sofe.dev/evaluate ...
```

---

## Architecture

```
sofe-server (this repo)
    │
    │ imports
    ▼
sofe (PyPI) ← engine, models, collectors, loader
    │
    │ boto3
    ▼
AWS APIs (EC2, S3, Lambda, RDS, CloudWatch, Cost Explorer)
```

The server is a thin wrapper. All evaluation logic lives in the `sofe` engine package.

---

## Deploy Options

| Method | Command | Use Case |
|--------|---------|----------|
| Local | `sofe-server` | Development |
| Docker | `docker run -p 8080:8080 sofe-server` | Teams |
| Docker Compose | `docker compose up` | With MongoDB |
| Kubernetes | Helm chart (coming) | Production |
| AWS Lambda | Mangum adapter (coming) | Serverless |

---

## OpenAPI Spec

Full spec: [`docs/openapi.yaml`](docs/openapi.yaml)

---

## Related

- [sofe](https://github.com/breakingthecloud/sofe) — Engine + CLI (`pip install sofe`)
- [sofe-catalog](https://github.com/breakingthecloud/sofe-catalog) — Browse policies, collectors, coverage
- [PyPI](https://pypi.org/project/sofe/) — `pip install sofe`

---

## License

Apache 2.0
