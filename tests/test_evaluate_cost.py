"""POST /evaluate — cost status fields (S111 Phase B).

The engine decides whether per-resource cost data exists; the server only relays it.
What matters to clients: `cost_status` explains the absence of data, an unmatched resource
has `monthly_cost = null` (unknown, never 0 or a share), and `total_monthly_cost` is the sum
of what was matched.
"""

from datetime import datetime, timezone

import pytest

import sofe_server.app as appmod
from sofe.models import Finding, Resource, Severity
from tests.conftest import EXTERNAL_ID, ROLE_ARN

ACCT = ROLE_ARN.split(":")[4]
SUMMARY = {
    "cost_status": "partial",
    "cost_detail": "part of the spend belongs to services/resources SOFE does not inventory",
    "cost_coverage": 0.0909,
    "cost_coverage_usd": 0.0297,
    "cost_account_monthly": 26.92,
    "cost_matched_monthly": 0.8,
}
BODY = {"role_arn": ROLE_ARN, "external_id": EXTERNAL_ID}


def _account(props=None) -> Resource:
    return Resource(resource_id=f"account-{ACCT}", resource_type="aws.account", region="us-east-1", account_id=ACCT, properties=props or {})


def _fn(name, cost=None) -> Resource:
    return Resource(resource_id=name, resource_type="aws.lambda", region="us-east-1", account_id=ACCT, metrics={"monthly_cost": cost} if cost is not None else {})


def _finding(resource_id) -> Finding:
    return Finding(
        id="f", policy_name="p", severity=Severity.high, resource_id=resource_id, resource_type="aws.lambda",
        region="us-east-1", account_id=ACCT, message="m", metric_name="m", metric_value=1, threshold=0,
        timestamp=datetime.now(timezone.utc),
    )


@pytest.fixture
def serve(monkeypatch, client):
    """Make the (faked) engine return these resources / findings."""

    def _serve(resources, findings=()):
        monkeypatch.setattr(appmod, "collect_all", lambda **kw: resources)
        monkeypatch.setattr(appmod, "evaluate_architecture", lambda policies, res: {"findings": list(findings), "insights": {}})
        return client

    return _serve


def test_cost_summary_from_the_engine_is_returned(serve):
    r = serve([_fn("a", 0.4), _account(dict(SUMMARY))]).post("/evaluate", json=BODY)

    assert r.status_code == 200
    body = r.json()
    assert {k: body[k] for k in SUMMARY} == SUMMARY


@pytest.mark.parametrize("status", ["ok", "access_denied", "not_enabled", "no_data", "error"])
def test_every_status_is_relayed_untouched(serve, status):
    props = {**SUMMARY, "cost_status": status, "cost_detail": "why", "cost_coverage": None, "cost_coverage_usd": None, "cost_account_monthly": None}

    body = serve([_account(props)]).post("/evaluate", json=BODY).json()

    assert body["cost_status"] == status
    assert body["cost_detail"] == "why"
    assert body["cost_coverage"] is None


def test_an_engine_that_predates_the_cost_summary_says_unknown_instead_of_pretending(serve):
    body = serve([_fn("a", 0.4), _account({})]).post("/evaluate", json=BODY).json()

    assert body["cost_status"] == "unknown"
    assert body["cost_detail"]
    assert body["cost_coverage"] is None and body["cost_account_monthly"] is None


def test_unmatched_resource_has_a_null_monthly_cost_not_zero(serve):
    findings = [_finding("known"), _finding("unknown")]

    body = serve([_fn("known", 12.5), _fn("unknown"), _account(dict(SUMMARY))], findings).post("/evaluate", json=BODY).json()

    by_id = {f["resource_id"]: f for f in body["findings"]}
    assert by_id["known"]["monthly_cost"] == 12.5
    assert by_id["unknown"]["monthly_cost"] is None


def test_total_monthly_cost_is_the_sum_of_matched_resources_only(serve):
    body = serve([_fn("a", 10.0), _fn("b", 2.5), _fn("c"), _account(dict(SUMMARY))]).post("/evaluate", json=BODY).json()

    assert body["total_monthly_cost"] == 12.5
    # the account's real spend is a separate, explicit number
    assert body["cost_account_monthly"] == 26.92


def test_profile_path_reports_cost_too(serve):
    body = serve([_account(dict(SUMMARY))]).post("/evaluate", json={"profile": "dev"}).json()

    assert body["evaluated_via"] == "profile"
    assert body["cost_status"] == "partial"


def test_existing_response_fields_are_all_still_there(serve):
    body = serve([_account(dict(SUMMARY))]).post("/evaluate", json=BODY).json()

    for key in (
        "evaluation_id", "timestamp", "policies_evaluated", "account_id", "evaluated_via", "evaluated_role_arn",
        "resources_scanned", "findings_count", "total_estimated_savings", "total_monthly_cost", "account_metrics",
        "failed", "resources_by_type", "resources_detail", "findings", "insights",
    ):
        assert key in body, key
