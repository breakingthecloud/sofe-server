from __future__ import annotations
import uuid
from datetime import datetime, timezone
from typing import Optional

from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel

from sofe.loader import load_policies, validate_policies
from sofe.collectors import collect_all
from sofe.engine import evaluate, evaluate_architecture

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

    # Architecture-aware evaluation (includes cross-resource analysis)
    arch_result = evaluate_architecture(policies, resources)
    findings = arch_result["findings"]
    insights = arch_result["insights"]

    severity_order = ["critical", "high", "medium", "low", "info"]
    failed = False
    if req.fail_on:
        threshold_idx = severity_order.index(req.fail_on)
        failed = any(
            severity_order.index(f.severity.value) <= threshold_idx
            for f in findings
        )

    total_savings = sum(f.estimated_savings or 0 for f in findings)

    # Count resources by type for topology visualization + include IDs for BYaML generation
    resources_by_type: dict[str, int] = {}
    resources_detail: dict[str, list[dict]] = {}
    for r in resources:
        resources_by_type[r.resource_type] = resources_by_type.get(r.resource_type, 0) + 1
        if r.resource_type not in resources_detail:
            resources_detail[r.resource_type] = []
        resources_detail[r.resource_type].append({
            "resource_id": r.resource_id,
            "region": r.region,
        })

    # Get remediation commands for each finding
    from sofe.remediation.commands import get_remediation_commands

    return {
        "evaluation_id": str(uuid.uuid4()),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "policies_evaluated": len(policies),
        "resources_scanned": len(resources),
        "findings_count": len(findings),
        "total_estimated_savings": total_savings,
        "failed": failed,
        "resources_by_type": resources_by_type,
        "resources_detail": resources_detail,
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
                "remediation_commands": get_remediation_commands(
                    f.policy_name, f.resource_id, f.resource_type, f.region, f.account_id or ""
                ),
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
            for f in findings
        ],
        "insights": {
            "relationships_count": insights.get("relationships_count", 0),
            "single_points_of_failure": insights.get("single_points_of_failure", []),
            "blast_radius": insights.get("blast_radius", {}),
            "team_costs": insights.get("team_costs", {}),
        },
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


@app.get("/collectors")
async def list_collectors():
    from sofe.collectors.aws import COLLECTORS
    return [
        {
            "name": collector_cls.__name__.replace("Collector", ""),
            "resource_type": resource_type,
            "metrics": _get_collector_metrics(resource_type),
        }
        for resource_type, collector_cls in COLLECTORS.items()
    ]

def _get_collector_metrics(resource_type: str) -> list[str]:
    """Return known metrics for a resource type."""
    metrics_map = {
        "aws.ec2": ["avg_cpu_utilization", "monthly_cost", "running_days", "has_tag:*", "purchase_option_spot", "instance_generation_old", "ebs_optimized", "public_ip_attached"],
        "aws.s3": ["monthly_cost", "encryption_enabled", "has_lifecycle_rules", "has_tag:*", "versioning_enabled", "public_access_blocked", "logging_enabled"],
        "aws.lambda": ["monthly_cost", "has_tag:*", "memory_size_mb", "timeout_seconds", "runtime_deprecated", "code_size_mb"],
        "aws.rds": ["avg_connections", "monthly_cost", "has_tag:*", "multi_az", "storage_encrypted", "backup_retention_days", "publicly_accessible"],
        "aws.ebs": ["attached", "monthly_cost", "has_tag:*", "size_gb", "volume_type_gp2", "encrypted"],
        "aws.ecs": ["avg_cpu_utilization", "has_tag:*", "running_count", "desired_count", "launch_type_fargate"],
        "aws.eks": ["monthly_cost", "has_tag:*", "endpoint_public_access", "logging_enabled", "version_outdated"],
        "aws.elasticache": ["monthly_cost", "at_rest_encryption", "transit_encryption", "num_nodes"],
        "aws.redshift": ["monthly_cost", "encrypted", "publicly_accessible", "num_nodes"],
        "aws.dynamodb": ["monthly_cost", "has_tag:*", "billing_mode_provisioned", "item_count", "table_size_mb"],
        "aws.cloudfront": ["compression_enabled", "monthly_cost", "https_only", "waf_enabled", "price_class_all"],
        "aws.apigateway": ["throttle_configured", "monthly_cost", "logging_enabled", "endpoint_type_edge"],
        "aws.natgateway": ["monthly_cost", "connectivity_public"],
        "aws.elb": ["has_targets", "monthly_cost", "waf_enabled", "internet_facing"],
        "aws.route53": ["record_count", "private_zone"],
        "aws.secretsmanager": ["rotation_enabled", "days_since_last_rotation", "days_since_last_access"],
        "aws.sagemaker": ["monthly_cost", "instance_count", "endpoint_active"],
    }
    return metrics_map.get(resource_type, ["monthly_cost"])


@app.post("/connect/test")
async def test_connection(body: dict):
    """Test STS AssumeRole — verifies the user's IAM role works."""
    import boto3
    role_arn = body.get("role_arn")
    external_id = body.get("external_id")
    
    if not role_arn or not external_id:
        raise HTTPException(status_code=400, detail="role_arn and external_id required")
    
    try:
        sts = boto3.client("sts")
        resp = sts.assume_role(
            RoleArn=role_arn,
            RoleSessionName="sofe-connect-test",
            ExternalId=external_id,
            DurationSeconds=900,
        )
        account_id = resp["AssumedRoleUser"]["Arn"].split(":")[4]
        return {"success": True, "account_id": account_id}
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"AssumeRole failed: {str(e)}")
