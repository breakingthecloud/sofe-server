"""S116-B2 — Billing endpoints with AssumeRole + normalized Cost Explorer results."""

from __future__ import annotations

import pytest
from botocore.exceptions import ClientError
from fastapi.testclient import TestClient

import sofe_server.app as appmod

ROLE_ARN = "arn:aws:iam::111122223333:role/sofe-read-only"
EXTERNAL_ID = "billing-test-external-id"
ACCOUNT = "111122223333"


def page(rows: dict[str, str], token: str | None = None) -> dict:
    payload = {
        "ResultsByTime": [
            {
                "TimePeriod": {"Start": "2026-10-01", "End": "2026-11-01"},
                "Groups": [
                    {"Keys": [key], "Metrics": {"UnblendedCost": {"Amount": amount, "Unit": "USD"}}}
                    for key, amount in rows.items()
                ]
            }
        ]
    }
    if token:
        payload["NextPageToken"] = token
    return payload


class FakeCE:
    def __init__(self, error: Exception | None = None):
        self.error = error
        self.calls: list[tuple[str, dict]] = []

    def _answer(self, name: str, kwargs: dict, rows: dict[str, str]):
        self.calls.append((name, kwargs))
        if self.error:
            raise self.error
        return page(rows)

    def get_cost_and_usage(self, **kwargs):
        return self._answer("get_cost_and_usage", kwargs, {"Amazon EC2": "12.34"})

    def get_cost_and_usage_with_resources(self, **kwargs):
        return self._answer("get_cost_and_usage_with_resources", kwargs, {"arn:aws:s3:::bucket": "7.00"})

    def get_dimension_values(self, **kwargs):
        self.calls.append(("get_dimension_values", kwargs))
        return {"DimensionValues": [{"Value": "Amazon EC2"}, {"Value": "Amazon S3"}]}

    def get_tags(self, **kwargs):
        self.calls.append(("get_tags", kwargs))
        return {"Tags": [{"Key": "env", "Values": ["prod", "dev"]}]}


class FakeOrg:
    def describe_organization(self):
        return {"Organization": {"Id": "o-test", "MasterAccountId": ACCOUNT}}

    def list_accounts(self, **kwargs):
        return {
            "Accounts": [
                {"Id": ACCOUNT, "Name": "Production", "Email": "prod@example.com", "Status": "ACTIVE", "JoinedMethod": "CREATED"},
                {"Id": "222233334444", "Name": "Data", "Email": "data@example.com", "Status": "ACTIVE", "JoinedMethod": "INVITED"},
            ]
        }

    def list_parents(self, ChildId):
        return {"Parents": [{"Id": "r-test", "Type": "ROOT"}]}


class FakeIAM:
    def list_account_aliases(self):
        return {"AccountAliases": ["prod-alias"]}


class FakeSTS:
    def get_caller_identity(self):
        return {"Account": ACCOUNT}


class FakeSession:
    def __init__(self, ce: FakeCE | None = None):
        self.ce = ce or FakeCE()
        self.services: list[str] = []

    def client(self, service: str, **kwargs):
        self.services.append(service)
        if service == "ce":
            return self.ce
        if service == "organizations":
            return FakeOrg()
        if service == "iam":
            return FakeIAM()
        if service == "sts":
            return FakeSTS()
        raise AssertionError(f"unexpected service {service}")


@pytest.fixture
def assume(monkeypatch):
    """Record AssumeRole calls and return a fake boto3 session with CE/Organizations."""
    calls: list[dict] = []
    session = FakeSession()

    def fake_assume(role_arn, external_id, *, session_name="sofe-evaluate"):
        calls.append({"role_arn": role_arn, "external_id": external_id, "session_name": session_name})
        return session

    monkeypatch.setattr(appmod, "SOFE_API_KEY", "")
    monkeypatch.setattr(appmod, "SOFE_INTERNAL_SECRET", "")
    monkeypatch.setattr(appmod, "_assume_role_session", fake_assume)
    return calls, session


@pytest.fixture
def client(assume):
    return TestClient(appmod.app)


def body(**extra):
    return {"role_arn": ROLE_ARN, "external_id": EXTERNAL_ID, "from": "2026-10-01", "to": "2026-11-01", **extra}


def test_query_assumes_billing_session_and_returns_cents_as_decimal(assume, client):
    calls, session = assume
    r = client.post(
        "/billing/query",
        json=body(account_id=ACCOUNT, granularity="daily", metric="unblended", group_by=[{"Type": "DIMENSION", "Key": "SERVICE"}]),
    )

    assert r.status_code == 200
    assert calls[0]["session_name"] == "sofe-billing"
    assert session.services[0] == "ce"
    payload = r.json()
    assert payload["cost_status"] == "ok"
    assert payload["total"] == "12.34"
    assert payload["groups"] == [
        {"keys": ["Amazon EC2"], "amount": "12.34", "unit": "USD", "period": "2026-10-01"}
    ]
    ce_call = session.ce.calls[0]
    assert ce_call[0] == "get_cost_and_usage"
    assert ce_call[1]["GroupBy"] == [{"Type": "DIMENSION", "Key": "SERVICE"}]
    assert {"Dimensions": {"Key": "LINKED_ACCOUNT", "Values": [ACCOUNT]}} in ce_call[1]["Filter"]["And"]


def test_query_rejects_three_group_by_before_aws(assume, client):
    r = client.post(
        "/billing/query",
        json=body(group_by=[
            {"Type": "DIMENSION", "Key": "LINKED_ACCOUNT"},
            {"Type": "DIMENSION", "Key": "SERVICE"},
            {"Type": "DIMENSION", "Key": "REGION"},
        ]),
    )
    assert r.status_code == 422
    assert assume[0] == []


def test_resources_are_limited_to_fourteen_days(assume, client):
    r = client.post("/billing/resources", json={"role_arn": ROLE_ARN, "external_id": EXTERNAL_ID, "from": "2026-10-01", "to": "2026-10-20"})
    assert r.status_code == 400
    assert "14 days" in r.json()["detail"]

    r = client.post("/billing/resources", json={"role_arn": ROLE_ARN, "external_id": EXTERNAL_ID, "from": "2026-10-01", "to": "2026-10-15"})
    assert r.status_code == 200
    assert r.json()["total"] == "7.00"
    assert assume[1].ce.calls[0][0] == "get_cost_and_usage_with_resources"


def test_organization_returns_accounts_and_ou(assume, client):
    r = client.post("/billing/organization", json={"role_arn": ROLE_ARN, "external_id": EXTERNAL_ID})
    assert r.status_code == 200
    payload = r.json()
    assert payload["available"] is True
    assert payload["is_payer"] is True
    assert [account["id"] for account in payload["accounts"]] == [ACCOUNT, "222233334444"]


def test_dimensions_and_tags(assume, client):
    r = client.post(
        "/billing/dimensions",
        json={"role_arn": ROLE_ARN, "external_id": EXTERNAL_ID, "from": "2026-10-01", "to": "2026-11-01", "dimension": "SERVICE"},
    )
    assert r.status_code == 200
    assert r.json()["values"] == ["Amazon EC2", "Amazon S3"]

    r = client.post(
        "/billing/dimensions",
        json={"role_arn": ROLE_ARN, "external_id": EXTERNAL_ID, "from": "2026-10-01", "to": "2026-11-01", "tag_key": "env"},
    )
    assert r.status_code == 200
    assert r.json() == {"type": "tag", "key": "env", "values": ["prod", "dev"]}


def test_invalid_credentials_are_rejected_before_aws(assume, client):
    r = client.post("/billing/query", json=body() | {"external_id": "has space"})
    assert r.status_code == 400
    assert assume[0] == []


def test_ce_access_denied_is_visible_in_the_result(assume, client):
    _, session = assume
    session.ce.error = ClientError(
        {"Error": {"Code": "AccessDeniedException", "Message": "not authorized to perform: ce:GetCostAndUsage"}},
        "GetCostAndUsage",
    )
    r = client.post("/billing/query", json=body())
    assert r.status_code == 200
    assert r.json()["cost_status"] == "access_denied"
    assert "ce:GetCostAndUsage" in r.json()["cost_detail"]
