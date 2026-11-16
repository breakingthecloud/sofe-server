from __future__ import annotations
import hmac
import inspect
import os
import re
import sys
import uuid
from datetime import datetime, timezone
from typing import List, Optional

import boto3
from botocore.exceptions import BotoCoreError, ClientError
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from sofe.loader import load_policies, validate_policies
from sofe.collectors import collect_all
from sofe.engine import evaluate, evaluate_architecture

from .billing import router as billing_router

app = FastAPI(
    title="SOFE API",
    version="0.4.0",
    description="Stairway Open FinOps Engine — FinOps Policies as Code",
)
app.include_router(billing_router)

# --- Models ---

class EvaluateRequest(BaseModel):
    policies_dir: str = "./policies"
    # Credential source — exactly one applies, in this order of precedence:
    #   role_arn (+ external_id): assume the role and evaluate THAT account (S111).
    #   profile:                  a named local AWS profile (self-hosted).
    #   neither:                  the server's own default credentials.
    profile: Optional[str] = None
    role_arn: Optional[str] = None
    external_id: Optional[str] = None
    resource_types: Optional[list[str]] = None
    regions: Optional[list[str]] = None
    fail_on: Optional[str] = None

class ValidateRequest(BaseModel):
    policy_yaml: str

# --- Auth ---
#
# Hosted deployments MUST set at least one of:
#   SOFE_API_KEY           - bearer-style key for direct API clients
#   SOFE_INTERNAL_SECRET   - shared secret used by the Cloudflare Workers
#                            (sent as `x-sofe-internal-secret`)
# Requests without a valid secret are rejected. If neither env var is set the
# server runs in open "local mode" (fine for `localhost`, never for the
# internet) and logs a warning on startup.
#
# Rotating the internal secret without downtime: set SOFE_INTERNAL_SECRET to the new
# value and SOFE_INTERNAL_SECRET_PREVIOUS to the old one, switch the Workers to the
# new value, then remove SOFE_INTERNAL_SECRET_PREVIOUS. While both are set either is
# accepted. PREVIOUS only ever ADDS an accepted value; it never opens the server.

SOFE_API_KEY = os.environ.get("SOFE_API_KEY", "")
SOFE_INTERNAL_SECRET = os.environ.get("SOFE_INTERNAL_SECRET", "")
SOFE_INTERNAL_SECRET_PREVIOUS = os.environ.get("SOFE_INTERNAL_SECRET_PREVIOUS", "")


def _internal_secrets() -> List[str]:
    """Internal secrets currently accepted (empty values are not secrets)."""
    return [v for v in (SOFE_INTERNAL_SECRET, SOFE_INTERNAL_SECRET_PREVIOUS) if v]


def _matches(candidate: Optional[str], secret: str) -> bool:
    """Constant-time comparison; an empty candidate or secret never matches."""
    if not candidate or not secret:
        return False
    return hmac.compare_digest(candidate.encode("utf-8"), secret.encode("utf-8"))


def _used_previous_secret(x_internal: Optional[str]) -> bool:
    """True when the request authenticates ONLY with the previous (rotating-out) secret."""
    return _matches(x_internal, SOFE_INTERNAL_SECRET_PREVIOUS) and not _matches(x_internal, SOFE_INTERNAL_SECRET)


def _authorized(x_api_key: Optional[str], x_internal: Optional[str]) -> bool:
    secrets = _internal_secrets()
    if any(_matches(x_internal, secret) for secret in secrets):
        return True
    if SOFE_API_KEY and _matches(x_api_key, SOFE_API_KEY):
        return True
    # Local mode: no secrets configured at all — open access for self-hosted dev.
    # A configured PREVIOUS secret counts as configured: a half-finished rotation stays closed.
    if not SOFE_API_KEY and not secrets:
        return True
    return False


@app.middleware("http")
async def require_auth(request: Request, call_next):
    if request.url.path == "/health":
        return await call_next(request)
    if not _authorized(
        request.headers.get("x-api-key"),
        request.headers.get("x-sofe-internal-secret"),
    ):
        return JSONResponse({"error": "Unauthorized"}, status_code=401)
    if _used_previous_secret(request.headers.get("x-sofe-internal-secret")):
        # Rotation monitor: while any caller still logs this line, the previous secret must not be removed.
        # Never log the value.
        print(f"auth: previous internal secret used path={request.url.path}", file=sys.stderr, flush=True)
    return await call_next(request)

# --- Routes ---

@app.get("/health")
async def health():
    return {"status": "ok", "version": "0.4.0"}

# --- Role-based evaluation (S111) ---
#
# Hosted deployments evaluate a CUSTOMER's account: the caller passes the
# customer's role_arn + external_id, we AssumeRole and run every collector with
# those temporary credentials. Without this, boto3 would silently fall back to
# the host's own credentials and evaluate the host's account instead.
#
# Self-hosted/OSS keeps working unchanged: no role_arn => `profile` or the
# default credential chain, exactly as before. Hosted servers set
# SOFE_REQUIRE_ROLE=true so a request that names no role is rejected instead of
# reading the host's own account.

_EXTERNAL_ID_RE = re.compile(r"^[\w+=,.@:/-]{2,1224}$", re.ASCII)  # STS ExternalId constraints
_ASSUME_SESSION_NAME = "sofe-evaluate"
_ASSUME_SESSION_SECONDS = 900  # evaluations take seconds; keep the exposure window minimal
_ENGINE_SUPPORTS_SESSION = "session" in inspect.signature(collect_all).parameters


def _role_required() -> bool:
    """True on hosted servers (SOFE_REQUIRE_ROLE=true): every evaluation must name a customer role."""
    return os.environ.get("SOFE_REQUIRE_ROLE", "").strip().lower() in ("1", "true", "yes", "on")


def _check_credential_source(req: "EvaluateRequest") -> None:
    """Validate how the request selects credentials. Touches no AWS API."""
    if req.role_arn:
        if not req.external_id:
            raise HTTPException(status_code=400, detail="external_id is required when role_arn is provided")
        if not _EXTERNAL_ID_RE.match(req.external_id):
            raise HTTPException(status_code=400, detail="external_id has an invalid format")
        _validate_role_arn(req.role_arn)
        if not _ENGINE_SUPPORTS_SESSION:
            raise HTTPException(
                status_code=501,
                detail="The installed 'sofe' engine does not support role-based evaluation; upgrade the 'sofe' package",
            )
    elif req.external_id:
        raise HTTPException(status_code=400, detail="role_arn is required when external_id is provided")
    elif _role_required():
        raise HTTPException(status_code=400, detail="role_arn and external_id are required on this server")


def _assume_role_session(
    role_arn: str,
    external_id: str,
    *,
    session_name: str = _ASSUME_SESSION_NAME,
) -> boto3.Session:
    """AssumeRole into the customer's account; return a session bound to the temporary credentials.

    Error bodies never echo the ExternalId. Billing uses ``session_name="sofe-billing"``
    so CloudTrail distinguishes analytical queries from evaluations.
    """
    try:
        creds = boto3.client("sts").assume_role(
            RoleArn=role_arn,
            RoleSessionName=session_name,
            ExternalId=external_id,
            DurationSeconds=_ASSUME_SESSION_SECONDS,
        )["Credentials"]
    except ClientError as e:
        code = e.response.get("Error", {}).get("Code", "")
        if code in ("AccessDenied", "AccessDeniedException"):
            raise HTTPException(
                status_code=403,
                detail=(
                    "Could not assume the role. Check that it exists in the target account and that the "
                    "ExternalId in its trust policy matches the one shown in your SOFE account page."
                ),
            )
        raise HTTPException(status_code=502, detail=f"AssumeRole failed ({code or 'ClientError'})")
    except BotoCoreError:
        raise HTTPException(status_code=502, detail="AssumeRole failed (could not reach STS)")
    return boto3.Session(
        aws_access_key_id=creds["AccessKeyId"],
        aws_secret_access_key=creds["SecretAccessKey"],
        aws_session_token=creds["SessionToken"],
    )


# --- Cost status (S111 Phase B) ---------------------------------------------
#
# The engine reports WHY there is (or is not) per-resource cost data, on the
# synthetic `aws.account` resource. Clients (platform, CLI) use it instead of
# guessing from `estimated_savings`.
#   cost_status          ok | partial | access_denied | not_enabled | no_data | error | unknown
#   cost_detail          short, ARN-free reason
#   cost_coverage        matched resources / inventoried resources
#   cost_coverage_usd    matched spend / the account's Cost Explorer spend
#   cost_account_monthly Cost Explorer monthly spend of the evaluated account (7-day sample x 30/7)
#   cost_matched_monthly the part of it attributed to inventoried resources (== total_monthly_cost)
# A resource with no Cost Explorer match has monthly_cost = null: UNKNOWN, never 0 or a share.
_COST_FIELDS = (
    "cost_status", "cost_detail", "cost_coverage", "cost_coverage_usd",
    "cost_account_monthly", "cost_matched_monthly",
)


def _cost_summary(resources) -> dict:
    """Cost fields for the response; `unknown` when the engine predates S111 Phase B."""
    for r in resources:
        if r.resource_type == "aws.account" and "cost_status" in (r.properties or {}):
            return {k: r.properties.get(k) for k in _COST_FIELDS}
    return {
        "cost_status": "unknown",
        "cost_detail": "the evaluation engine does not report cost status",
        **{k: None for k in _COST_FIELDS if k not in ("cost_status", "cost_detail")},
    }


@app.post("/evaluate")
async def evaluate_endpoint(req: EvaluateRequest):
    _check_credential_source(req)  # 400/501 before anything else; no AWS call yet

    policies = load_policies(req.policies_dir)
    if not policies:
        raise HTTPException(status_code=422, detail="No policies found")

    if req.role_arn:
        session = _assume_role_session(req.role_arn, req.external_id)
        evaluated_via = "assumed_role"
        resources = collect_all(
            resource_types=req.resource_types,
            regions=req.regions,
            session=session,  # `profile` is ignored when a role is given
        )
    else:
        evaluated_via = "profile" if req.profile else "default_credentials"
        resources = collect_all(
            profile=req.profile,
            resource_types=req.resource_types,
            regions=req.regions,
        )

    # Which account was actually read (from the synthetic account resource).
    account_id = next((r.account_id for r in resources if r.resource_type == "aws.account"), None)
    # One log line, never the ExternalId.
    print(f"evaluating account={account_id} via={evaluated_via} role={req.role_arn or '-'}", file=sys.stderr, flush=True)

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

    # Build cost lookup map from resources
    cost_by_resource: dict[str, float] = {}
    for r in resources:
        mc = r.metrics.get("monthly_cost")
        if mc and mc > 0:
            cost_by_resource[r.resource_id] = mc

    # S083 — account-level savings metrics (from synthetic aws.account resource)
    account_metrics: dict = {}
    for r in resources:
        if r.resource_type == "aws.account":
            account_metrics = dict(r.metrics)
            break
    account_metrics.setdefault("potential_savings_monthly", insights.get("potential_savings_monthly", 0))

    return {
        "evaluation_id": str(uuid.uuid4()),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "policies_evaluated": len(policies),
        "account_id": account_id,
        "evaluated_via": evaluated_via,
        "evaluated_role_arn": req.role_arn,
        "resources_scanned": len(resources),
        "findings_count": len(findings),
        "total_estimated_savings": total_savings,
        "total_monthly_cost": round(sum(cost_by_resource.values()), 2),
        **_cost_summary(resources),
        "account_metrics": account_metrics,
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
                "monthly_cost": cost_by_resource.get(f.resource_id),
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


def _validate_role_arn(role_arn: str) -> None:
    """Only allow AWS IAM role ARNs (prevents abuse of the STS proxy)."""
    if not isinstance(role_arn, str) or not role_arn.startswith("arn:aws:iam::"):
        raise HTTPException(status_code=400, detail="role_arn must be an AWS IAM role ARN")
    if "/" not in role_arn.split("arn:aws:iam::")[1]:
        raise HTTPException(status_code=400, detail="role_arn must be a role ARN (arn:aws:iam::ACCOUNT:role/NAME)")


@app.post("/connect/test")
async def test_connection(body: dict):
    """Test STS AssumeRole — verifies the user's IAM role works."""
    import boto3
    role_arn = body.get("role_arn")
    external_id = body.get("external_id")

    if not role_arn or not external_id:
        raise HTTPException(status_code=400, detail="role_arn and external_id required")
    _validate_role_arn(role_arn)

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


# --- Bedrock User-Account Invoke (SoW-S059) ---

# --- Bedrock User-Account Invoke (SoW-S059) ---

# Allow by FAMILY (text models only) instead of hardcoded model IDs — Bedrock
# retires model versions frequently (e.g. claude-3-haiku EOL), so the user's
# account discovery (ListFoundationModels) drives which models are selectable.
BEDROCK_TEXT_PREFIXES = (
    "anthropic.claude",
    "amazon.titan-text",
    "amazon.nova",
    "meta.llama",
    "mistral.",
    "cohere.command",
    "ai21.jamba",
)

# Block expensive / non-text / retired families that break SOFE prompts or cost too much.
BEDROCK_BLOCK_PATTERNS = (
    "opus",           # expensive (5-10x sonnet)
    "image",          # non-text
    "embed",          # non-text
    "stability",      # image
    "titan-image",
    "titan-video",
    "nova-canvas",
    "video",
)

def _is_allowed_bedrock_model(model: str) -> bool:
    # Normalize: us./global. prefixes are inference profiles (Anthropic gen 4+)
    normalized = model
    for prefix in ("us.", "global."):
        if model.startswith(prefix):
            normalized = model[len(prefix):]
            break
    if not normalized.startswith(BEDROCK_TEXT_PREFIXES):
        return False
    return not any(p in normalized for p in BEDROCK_BLOCK_PATTERNS)


def _normalize_bedrock_model(model: str) -> str:
    """Strip us./global. inference-profile prefixes for family detection."""
    for prefix in ("us.", "global."):
        if model.startswith(prefix):
            return model[len(prefix):]
    return model


def _build_bedrock_body(model: str, prompt: str, system_prompt: str) -> bytes:
    """Build the InvokeModel request body for each model family."""
    import json
    model = _normalize_bedrock_model(model)
    if model.startswith("anthropic.claude"):
        body = {
            "anthropic_version": "bedrock-2023-05-31",
            "max_tokens": 400,
            "temperature": 0.3,
            "system": system_prompt,
            "messages": [{"role": "user", "content": prompt}],
        }
    elif model.startswith("amazon.titan-text"):
        body = {
            "inputText": f"{system_prompt}\n\n{prompt}",
            "textGenerationConfig": {
                "maxTokenCount": 400,
                "temperature": 0.3,
                "topP": 0.9,
            },
        }
    elif model.startswith("amazon.nova"):
        body = {
            "system": [{"text": system_prompt}],
            "messages": [{"role": "user", "content": [{"text": prompt}]}],
            "inferenceConfig": {"maxNewTokens": 400, "temperature": 0.3, "topP": 0.9},
        }
    elif model.startswith("meta.llama"):
        body = {
            "prompt": f"<|begin_of_text|><|start_header_id|>system<|end_header_id|>\n\n{system_prompt}<|eot_id|><|start_header_id|>user<|end_header_id|>\n\n{prompt}<|eot_id|><|start_header_id|>assistant<|end_header_id|>",
            "max_gen_len": 400,
            "temperature": 0.3,
            "top_p": 0.9,
        }
    elif model.startswith("mistral."):
        body = {
            "prompt": f"<s>[INST] {system_prompt}\n\n{prompt} [/INST]",
            "max_tokens": 400,
            "temperature": 0.3,
            "top_p": 0.9,
        }
    elif model.startswith("cohere.command"):
        body = {
            "prompt": f"{system_prompt}\n\n{prompt}",
            "max_tokens": 400,
            "temperature": 0.3,
        }
    elif model.startswith("ai21.jamba"):
        body = {
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": prompt},
            ],
            "max_tokens": 400,
            "temperature": 0.3,
        }
    else:
        raise HTTPException(status_code=400, detail=f"Model {model} not supported")
    return json.dumps(body).encode("utf-8")


def _parse_bedrock_response(model: str, raw: bytes) -> str:
    """Extract text from InvokeModel response for each model family."""
    import json
    data = json.loads(raw)
    model = _normalize_bedrock_model(model)
    if model.startswith("anthropic.claude"):
        content = data.get("content", [])
        return "".join(block.get("text", "") for block in content if isinstance(block, dict))
    if model.startswith("amazon.titan-text"):
        results = data.get("results", [])
        return results[0].get("outputText", "") if results else ""
    if model.startswith("amazon.nova"):
        out = data.get("output", {})
        return out.get("message", {}).get("content", [{}])[0].get("text", "")
    if model.startswith("meta.llama"):
        return data.get("generation", "")
    if model.startswith("mistral."):
        outputs = data.get("outputs", [])
        return outputs[0].get("text", "") if outputs else ""
    if model.startswith("cohere.command"):
        return data.get("text", "")
    if model.startswith("ai21.jamba"):
        return data.get("text", "")
    return ""


class BedrockInvokeRequest(BaseModel):
    role_arn: str
    external_id: str
    model: str
    prompt: str
    system_prompt: str = ""


class BedrockListModelsRequest(BaseModel):
    role_arn: str
    external_id: str


def _bedrock_client_with_role(role_arn: str, external_id: str, service: str = "bedrock"):
    """AssumeRole in user's account and return a boto3 client for the given service."""
    import boto3
    sts = boto3.client("sts")
    assumed = sts.assume_role(
        RoleArn=role_arn,
        RoleSessionName="sofe-ai-invoke",
        ExternalId=external_id,
        DurationSeconds=900,  # 15 min max
    )
    creds = assumed["Credentials"]
    return boto3.client(
        service,
        aws_access_key_id=creds["AccessKeyId"],
        aws_secret_access_key=creds["SecretAccessKey"],
        aws_session_token=creds["SessionToken"],
    )


@app.post("/bedrock/models")
async def bedrock_list_models(req: BedrockListModelsRequest):
    """List text foundation models available in the user's account (discovery, SoW-S059).

    Uses ListFoundationModels through the sofe-ai-invoke role. Returns only
    text-capable models in allowed families, excluding expensive/retired ones.
    """
    _validate_role_arn(req.role_arn)
    try:
        client = _bedrock_client_with_role(req.role_arn, req.external_id)
        resp = client.list_foundation_models()
        summaries = resp.get("modelSummaries", [])
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"ListFoundationModels failed: {str(e)}")

    models = []
    for m in summaries:
        model_id = m.get("modelId", "")
        if not _is_allowed_bedrock_model(model_id):
            continue
        modalities = m.get("outputModalities") or []
        if "TEXT" not in modalities:
            continue
        lifecycle = (m.get("modelLifecycle") or {}).get("status", "ACTIVE")
        # Anthropic gen 4+ can only be invoked via an inference profile (us.<model>).
        # Keep the raw ID for display but the invoke path auto-retries with the us. prefix.
        models.append({
            "id": model_id,
            "name": m.get("modelName", model_id),
            "provider": m.get("providerName", ""),
            "status": lifecycle,  # ACTIVE | LEGACY | DEPRECATED
        })

    models.sort(key=lambda x: (x["provider"], x["id"]))
    return {"success": True, "models": models, "total": len(models)}


@app.post("/bedrock/invoke")
async def bedrock_invoke(req: BedrockInvokeRequest):
    """AssumeRole in user's account → bedrock:InvokeModel (SoW-S059).

    The role must be the `sofe-ai-invoke` role deployed by the user
    (sofe-ai-invoke-role.yaml). Costs are billed to the user's AWS account.
    """
    if not _is_allowed_bedrock_model(req.model):
        raise HTTPException(
            status_code=400,
            detail=f"Model {req.model} not allowed. SOFE only allows text models in families: {', '.join(BEDROCK_TEXT_PREFIXES)}",
        )
    _validate_role_arn(req.role_arn)

    try:
        client = _bedrock_client_with_role(req.role_arn, req.external_id, service="bedrock-runtime")
        # Anthropic gen 4+ models require an inference profile (us.<model>), not the raw model ID.
        # Try direct first; on ValidationException suggesting a profile, retry with the us. prefix.
        candidates = [req.model]
        if req.model.startswith("anthropic.claude"):
            candidates.append(f"us.{req.model}")

        last_err: Exception | None = None
        for model_id in candidates:
            try:
                body = _build_bedrock_body(model_id, req.prompt, req.system_prompt)
                resp = client.invoke_model(modelId=model_id, body=body, contentType="application/json", accept="application/json")
                raw = resp["body"].read()
                text = _parse_bedrock_response(model_id, raw)
                if not text:
                    raise HTTPException(status_code=502, detail="Bedrock returned empty response")
                return {"success": True, "text": text, "model": model_id}
            except HTTPException:
                raise
            except Exception as e:
                last_err = e
                if "inference profile" not in str(e).lower() and "inference profile" not in str(e).lower():
                    # Non-profile error — don't retry with the profile prefix unless it's specifically about profiles
                    break
        raise HTTPException(status_code=400, detail=f"Bedrock InvokeModel failed: {last_err}")
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Bedrock InvokeModel failed: {str(e)}")
