# SOFE Server — Testing Guide

## Prerequisites

- Python 3.11+
- AWS credentials configured (any profile with read access)
- Policies directory with at least 1 valid SOFE policy

## Setup

```bash
cd sofe-server
uv venv --python 3.11 .venv
source .venv/bin/activate
uv pip install fastapi uvicorn pydantic boto3 pyyaml click rich
uv pip install -e ../sofe  # or: pip install sofe
```

## Start Server

```bash
python -m sofe_server.main
# → INFO: Uvicorn running on http://0.0.0.0:8080
```

---

## Test: Health

```bash
curl -s http://localhost:8080/health
```

Expected:
```json
{"status": "ok", "version": "0.1.0"}
```

---

## Test: List Metrics

```bash
curl -s http://localhost:8080/metrics | python -m json.tool
```

Expected: Array of 7 metrics with name, source, resource_types, description.

---

## Test: List Policies

```bash
curl -s "http://localhost:8080/policies?policies_dir=../sofe/policies" | python -m json.tool
```

Expected:
```json
[
  {"name": "no-idle-ec2", "description": "...", "severity": "high", "resource_types": ["aws.ec2"], "metric": "avg_cpu_utilization"},
  {"name": "require-cost-tags", "description": "...", "severity": "medium", ...},
  {"name": "no-unattached-ebs", "description": "...", "severity": "medium", ...},
  {"name": "s3-require-environment-tag", "description": "...", "severity": "low", ...}
]
```

---

## Test: Evaluate (Real AWS)

```bash
curl -s -X POST http://localhost:8080/evaluate \
  -H "Content-Type: application/json" \
  -d '{
    "policies_dir": "../sofe/policies",
    "profile": "your-aws-profile",
    "resource_types": ["aws.ec2", "aws.s3", "aws.lambda"]
  }' | python -m json.tool
```

Expected response structure:
```json
{
  "evaluation_id": "uuid",
  "timestamp": "ISO-8601",
  "policies_evaluated": 4,
  "resources_scanned": 6,
  "findings_count": 10,
  "total_estimated_savings": 0.0,
  "failed": false,
  "findings": [
    {
      "policy_name": "require-cost-tags",
      "severity": "medium",
      "resource_id": "bucket-name",
      "resource_type": "aws.s3",
      "message": "has_tag:owner = 0.0 (threshold: ==0.0)",
      "recommendation": "Add 'owner' tag for cost allocation and accountability"
    }
  ]
}
```

### Verify findings
- Resources without `owner` tag → `require-cost-tags` findings (medium)
- S3 without `Environment` tag → `s3-require-environment-tag` findings (low)
- EC2 with <5% CPU → `no-idle-ec2` findings (high)

---

## Test: Evaluate with --fail-on

```bash
# Should return "failed": true if medium+ findings exist
curl -s -X POST http://localhost:8080/evaluate \
  -H "Content-Type: application/json" \
  -d '{"policies_dir": "../sofe/policies", "profile": "your-aws-profile", "fail_on": "medium"}'  \
  | python -c "import sys,json; d=json.load(sys.stdin); print(f'failed={d[\"failed\"]}')"
```

Expected: `failed=True` (because resources lack `owner` tag)

```bash
# Should return "failed": false if no high+ findings
curl -s -X POST http://localhost:8080/evaluate \
  -H "Content-Type: application/json" \
  -d '{"policies_dir": "../sofe/policies", "profile": "your-aws-profile", "fail_on": "high"}'  \
  | python -c "import sys,json; d=json.load(sys.stdin); print(f'failed={d[\"failed\"]}')"
```

Expected: `failed=False` (no high/critical findings in test account)

---

## Test: Validate Policy

### Valid policy
```bash
curl -s -X POST http://localhost:8080/validate \
  -H "Content-Type: application/json" \
  -d '{"policy_yaml": "apiVersion: sofe/v1\nkind: Policy\nmetadata:\n  name: test-policy\n  description: A test\nspec:\n  scope:\n    resource_types: [aws.ec2]\n  rule:\n    metric: avg_cpu_utilization\n    operator: \"<\"\n    threshold: 5\n  severity: high\n  actions:\n    - type: finding"}'
```

Expected:
```json
{"valid": true, "errors": []}
```

### Invalid policy (missing required field)
```bash
curl -s -X POST http://localhost:8080/validate \
  -H "Content-Type: application/json" \
  -d '{"policy_yaml": "apiVersion: sofe/v1\nkind: Policy\nmetadata:\n  name: bad\nspec:\n  scope:\n    resource_types: [aws.ec2]"}'
```

Expected:
```json
{"valid": false, "errors": ["..."]}
```

---

## Test Results (Jun 2026)

All endpoints verified against a real AWS account:

| Endpoint | Request | Response | Status |
|----------|---------|----------|:------:|
| GET /health | — | `{"status":"ok"}` | ✅ |
| GET /metrics | — | 7 metrics returned | ✅ |
| GET /policies | policies_dir=../sofe/policies | 4 policies | ✅ |
| POST /evaluate | profile + resource_types | 10 findings (6 medium + 4 low) | ✅ |
| POST /evaluate | fail_on=medium | `"failed": true` | ✅ |
| POST /evaluate | fail_on=high | `"failed": false` | ✅ |
| POST /validate | valid YAML | `{"valid": true}` | ✅ |
| POST /validate | invalid YAML | `{"valid": false, "errors": [...]}` | ✅ |
