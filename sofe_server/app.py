from __future__ import annotations
import uuid
from datetime import datetime, timezone
from typing import Optional

from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel

from sofe.loader import load_policies, validate_policies
from sofe.collectors import collect_all
from sofe.engine import evaluate

app = FastAPI(
    title="SOFE API",
    version="0.1.0",
    description="Stairway Open FinOps Engine — FinOps Policies as Code",
)

# --- Models ---

class EvaluateRequest(BaseModel):
    policies_dir: str = "./policies"
    profile: Optional[str] = None
    resource_types: Optional[list[str]] = None
    regions: Optional[list[str]] = None
    fail_on: Optional[str] = None

class ValidateRequest(BaseModel):
    policy_yaml: str

# --- Auth (optional) ---

def check_api_key(x_api_key: Optional[str] = Header(None)):
    # Local mode: no key required. Hosted mode: validate key (future).
    pass

# --- Routes ---

@app.get("/health")
async def health():
    return {"status": "ok", "version": "0.1.0"}

@app.post("/evaluate")
async def evaluate_endpoint(req: EvaluateRequest):
    policies = load_policies(req.policies_dir)
    if not policies:
        raise HTTPException(status_code=422, detail="No policies found")

    resources = collect_all(
        profile=req.profile,
        resource_types=req.resource_types,
        regions=req.regions,
    )

    findings = evaluate(policies, resources)

    severity_order = ["critical", "high", "medium", "low", "info"]
    failed = False
    if req.fail_on:
        threshold_idx = severity_order.index(req.fail_on)
        failed = any(
            severity_order.index(f.severity.value) <= threshold_idx
            for f in findings
        )

    total_savings = sum(f.estimated_savings or 0 for f in findings)

    return {
        "evaluation_id": str(uuid.uuid4()),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "policies_evaluated": len(policies),
        "resources_scanned": len(resources),
        "findings_count": len(findings),
        "total_estimated_savings": total_savings,
        "failed": failed,
        "findings": [
            {
                "id": str(uuid.uuid4()),
                "policy_name": f.policy_name,
                "severity": f.severity.value,
                "resource_id": f.resource_id,
                "resource_type": f.resource_type,
                "region": f.region,
                "account_id": f.account_id,
                "message": f.message,
                "estimated_savings": f.estimated_savings,
                "recommendation": f.recommendation,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
            for f in findings
        ],
    }

@app.post("/validate")
async def validate_endpoint(req: ValidateRequest):
    import tempfile, os, yaml
    # Write YAML to temp file, validate
    tmp = tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False)
    tmp.write(req.policy_yaml)
    tmp.close()
    try:
        results = validate_policies(os.path.dirname(tmp.name), filename=os.path.basename(tmp.name))
        r = results[0] if results else {"valid": False, "error": "No policy parsed"}
        return {"valid": r.get("valid", False), "errors": [r.get("error", "")] if not r.get("valid") else []}
    finally:
        os.unlink(tmp.name)

@app.get("/policies")
async def list_policies(policies_dir: str = "./policies"):
    policies = load_policies(policies_dir)
    return [
        {
            "name": p.metadata.name,
            "description": p.metadata.description,
            "severity": p.spec.severity.value,
            "resource_types": p.spec.scope.resource_types,
            "metric": p.spec.rule.metric,
        }
        for p in policies
    ]

@app.get("/metrics")
async def list_metrics():
    return [
        {"name": "avg_cpu_utilization", "source": "CloudWatch", "resource_types": ["aws.ec2", "aws.rds"], "description": "Average CPU % over period"},
        {"name": "monthly_cost", "source": "Cost Explorer", "resource_types": ["*"], "description": "Monthly cost in USD"},
        {"name": "running_days", "source": "LaunchTime", "resource_types": ["aws.ec2", "aws.rds"], "description": "Days since launch"},
        {"name": "has_tag:{key}", "source": "Tags API", "resource_types": ["*"], "description": "1.0 if tag exists, 0.0 if missing"},
        {"name": "invocations", "source": "CloudWatch", "resource_types": ["aws.lambda"], "description": "Total invocations over period"},
        {"name": "connections", "source": "CloudWatch", "resource_types": ["aws.rds"], "description": "Active connections"},
        {"name": "attached", "source": "EC2 API", "resource_types": ["aws.ebs"], "description": "1.0 if attached, 0.0 if not"},
    ]
