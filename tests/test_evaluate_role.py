"""Tests for POST /evaluate credential selection — S111.

Hosted mode evaluates a CUSTOMER's account through AssumeRole. Self-hosted/OSS
mode must keep working exactly as before (profile or default credentials).
"""

import pytest
from botocore.exceptions import BotoCoreError, ClientError

import sofe_server.app as appmod
from tests.conftest import EXTERNAL_ID, HOST_ACCOUNT, ROLE_ARN


def _role_body(**extra):
    return {"role_arn": ROLE_ARN, "external_id": EXTERNAL_ID, **extra}


def _client_error(code):
    return ClientError({"Error": {"Code": code, "Message": f"denied for {EXTERNAL_ID}"}}, "AssumeRole")


# --------------------------------------------------------------------------
# Role path: the customer's account is evaluated with temporary credentials
# --------------------------------------------------------------------------

def test_role_path_assumes_role_and_evaluates_that_account(client, calls):
    r = client.post("/evaluate", json=_role_body())

    assert r.status_code == 200
    # One AssumeRole with the documented parameters.
    assert len(calls["assume_role"]) == 1
    assume = calls["assume_role"][0]
    assert assume["RoleArn"] == ROLE_ARN
    assert assume["ExternalId"] == EXTERNAL_ID
    assert assume["RoleSessionName"] == "sofe-evaluate"
    assert assume["DurationSeconds"] == 900
    # The session is built from the temporary credentials and handed to the engine.
    assert calls["sessions"][0].creds["aws_session_token"] == "temp-token"
    collect = calls["collect_all"][0]
    assert collect["session"] is calls["sessions"][0]
    # The response says which account/credential source was really used.
    body = r.json()
    assert body["account_id"] == "222233334444"
    assert body["account_id"] != HOST_ACCOUNT
    assert body["evaluated_via"] == "assumed_role"
    assert body["evaluated_role_arn"] == ROLE_ARN


def test_role_takes_precedence_over_profile(client, calls):
    r = client.post("/evaluate", json=_role_body(profile="some-profile"))

    assert r.status_code == 200
    assert "profile" not in calls["collect_all"][0]  # a profile can never override the role
    assert r.json()["evaluated_via"] == "assumed_role"


def test_filters_are_forwarded_with_the_role(client, calls):
    client.post("/evaluate", json=_role_body(resource_types=["aws.s3"], regions=["us-west-2"]))

    collect = calls["collect_all"][0]
    assert collect["resource_types"] == ["aws.s3"]
    assert collect["regions"] == ["us-west-2"]


# --------------------------------------------------------------------------
# Validation happens BEFORE any AWS call
# --------------------------------------------------------------------------

@pytest.mark.parametrize(
    "body, fragment",
    [
        ({"role_arn": ROLE_ARN}, "external_id is required"),
        ({"external_id": EXTERNAL_ID}, "role_arn is required"),
        ({"role_arn": "not-an-arn", "external_id": EXTERNAL_ID}, "role ARN"),
        ({"role_arn": "arn:aws:iam::222233334444", "external_id": EXTERNAL_ID}, "role ARN"),
        ({"role_arn": ROLE_ARN, "external_id": "x"}, "invalid format"),
        ({"role_arn": ROLE_ARN, "external_id": "has space inside"}, "invalid format"),
        ({"role_arn": ROLE_ARN, "external_id": "a" * 1225}, "invalid format"),
    ],
)
def test_invalid_credential_requests_are_400_and_touch_nothing(client, calls, body, fragment):
    r = client.post("/evaluate", json=body)

    assert r.status_code == 400
    assert fragment in r.json()["detail"]
    assert calls["assume_role"] == []
    assert calls["collect_all"] == []


def test_engine_without_session_support_is_501_before_aws(client, calls, monkeypatch):
    monkeypatch.setattr(appmod, "_ENGINE_SUPPORTS_SESSION", False)

    r = client.post("/evaluate", json=_role_body())

    assert r.status_code == 501
    assert "upgrade the 'sofe' package" in r.json()["detail"]
    assert calls["assume_role"] == [] and calls["collect_all"] == []


# --------------------------------------------------------------------------
# STS failures map to clear errors and never echo the ExternalId
# --------------------------------------------------------------------------

@pytest.mark.parametrize("code", ["AccessDenied", "AccessDeniedException"])
def test_access_denied_is_403_with_actionable_message(client, calls, sts_behavior, code):
    sts_behavior["raise"] = _client_error(code)

    r = client.post("/evaluate", json=_role_body())

    assert r.status_code == 403
    assert "ExternalId" in r.json()["detail"]  # tells the user what to check…
    assert EXTERNAL_ID not in r.text           # …without leaking the value
    assert calls["collect_all"] == []          # nothing is evaluated after a failed assume


def test_other_sts_errors_are_502_without_secret(client, calls, sts_behavior):
    sts_behavior["raise"] = _client_error("ServiceUnavailable")

    r = client.post("/evaluate", json=_role_body())

    assert r.status_code == 502
    assert "ServiceUnavailable" in r.json()["detail"]
    assert EXTERNAL_ID not in r.text
    assert calls["collect_all"] == []


def test_botocore_errors_are_502(client, calls, sts_behavior):
    sts_behavior["raise"] = BotoCoreError()

    r = client.post("/evaluate", json=_role_body())

    assert r.status_code == 502
    assert EXTERNAL_ID not in r.text
    assert calls["collect_all"] == []


# --------------------------------------------------------------------------
# Hosted guard: SOFE_REQUIRE_ROLE=true => never read the host's own account
# --------------------------------------------------------------------------

@pytest.mark.parametrize("value", ["1", "true", "TRUE", " yes ", "on"])
def test_guard_truthy_values(monkeypatch, value):
    monkeypatch.setenv("SOFE_REQUIRE_ROLE", value)
    assert appmod._role_required() is True


@pytest.mark.parametrize("value", ["", "0", "false", "no", "off", "random"])
def test_guard_falsy_values(monkeypatch, value):
    monkeypatch.setenv("SOFE_REQUIRE_ROLE", value)
    assert appmod._role_required() is False


@pytest.mark.parametrize("body", [{}, {"profile": "dev"}, {"resource_types": ["aws.s3"]}])
def test_guard_rejects_requests_without_a_role_and_makes_zero_aws_calls(client, calls, monkeypatch, body):
    monkeypatch.setenv("SOFE_REQUIRE_ROLE", "true")

    r = client.post("/evaluate", json=body)

    assert r.status_code == 400
    assert "role_arn and external_id are required" in r.json()["detail"]
    assert calls["assume_role"] == []
    assert calls["collect_all"] == []  # the host's own account is never read


def test_guard_still_allows_role_requests(client, calls, monkeypatch):
    monkeypatch.setenv("SOFE_REQUIRE_ROLE", "true")

    r = client.post("/evaluate", json=_role_body())

    assert r.status_code == 200
    assert r.json()["account_id"] == "222233334444"


# --------------------------------------------------------------------------
# Self-hosted / OSS behavior is unchanged
# --------------------------------------------------------------------------

def test_default_credentials_path_is_unchanged(client, calls):
    r = client.post("/evaluate", json={})

    assert r.status_code == 200
    # Exactly the original engine call shape — no `session` key at all (older engines keep working).
    assert calls["collect_all"] == [{"profile": None, "resource_types": None, "regions": None}]
    assert calls["assume_role"] == []
    body = r.json()
    assert body["evaluated_via"] == "default_credentials"
    assert body["evaluated_role_arn"] is None
    assert body["account_id"] == HOST_ACCOUNT


def test_profile_path_is_unchanged(client, calls):
    r = client.post("/evaluate", json={"profile": "dev"})

    assert r.status_code == 200
    assert calls["collect_all"] == [{"profile": "dev", "resource_types": None, "regions": None}]
    assert calls["assume_role"] == []
    assert r.json()["evaluated_via"] == "profile"


def test_existing_response_contract_is_preserved(client):
    body = client.post("/evaluate", json={}).json()

    for key in (
        "evaluation_id", "timestamp", "policies_evaluated", "resources_scanned", "findings_count",
        "total_estimated_savings", "total_monthly_cost", "account_metrics", "failed",
        "resources_by_type", "resources_detail", "findings", "insights",
    ):
        assert key in body, f"missing existing field: {key}"


def test_auth_is_still_enforced_when_a_secret_is_configured(client, monkeypatch):
    monkeypatch.setattr(appmod, "SOFE_INTERNAL_SECRET", "s3cret")

    assert client.post("/evaluate", json={}).status_code == 401
    assert client.post("/evaluate", json={}, headers={"x-sofe-internal-secret": "s3cret"}).status_code == 200


# --------------------------------------------------------------------------
# Secret hygiene
# --------------------------------------------------------------------------

def test_log_line_identifies_account_and_role_but_never_the_external_id(client, capsys):
    client.post("/evaluate", json=_role_body())

    err = capsys.readouterr().err
    assert "evaluating account=222233334444" in err
    assert f"role={ROLE_ARN}" in err
    assert "via=assumed_role" in err
    assert EXTERNAL_ID not in err
