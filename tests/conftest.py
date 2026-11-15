"""Shared fixtures for sofe-server tests.

Nothing here touches AWS: STS and the engine are replaced by recording fakes, so
the tests can assert exactly which credentials a request would have used.
"""

from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

import sofe_server.app as appmod
from sofe.models import Resource

ROLE_ARN = "arn:aws:iam::222233334444:role/sofe-read-only"
HOST_ACCOUNT = "999999999999"  # the account the server itself runs in
EXTERNAL_ID = "9f4efdb3-test-external-id"


@pytest.fixture
def calls():
    """Everything the server asked AWS / the engine to do during a request."""
    return {"assume_role": [], "sessions": [], "collect_all": []}


@pytest.fixture
def sts_behavior():
    """Mutable switch: tests set ``sts_behavior['raise']`` to simulate STS failures."""
    return {"raise": None}


@pytest.fixture
def client(monkeypatch, calls, sts_behavior):
    # Open ("local") mode: the module reads auth secrets at import time.
    monkeypatch.setattr(appmod, "SOFE_API_KEY", "")
    monkeypatch.setattr(appmod, "SOFE_INTERNAL_SECRET", "")
    monkeypatch.delenv("SOFE_REQUIRE_ROLE", raising=False)

    # --- STS / boto3 fakes -------------------------------------------------
    class FakeSTS:
        def assume_role(self, **kw):
            calls["assume_role"].append(kw)
            if sts_behavior["raise"] is not None:
                raise sts_behavior["raise"]
            return {
                "Credentials": {
                    "AccessKeyId": "ASIATEMP",
                    "SecretAccessKey": "temp-secret",
                    "SessionToken": "temp-token",
                }
            }

    def fake_client(service, *a, **kw):
        assert service == "sts", f"unexpected boto3 client {service!r}"
        return FakeSTS()

    def fake_session(**kw):
        # Account is derived from the role the credentials were issued for.
        sess = SimpleNamespace(creds=kw, account_id=ROLE_ARN.split(":")[4])
        calls["sessions"].append(sess)
        return sess

    monkeypatch.setattr(appmod.boto3, "client", fake_client)
    monkeypatch.setattr(appmod.boto3, "Session", fake_session)

    # --- engine fakes ------------------------------------------------------
    monkeypatch.setattr(appmod, "load_policies", lambda d: [object()])
    monkeypatch.setattr(
        appmod, "evaluate_architecture", lambda policies, resources: {"findings": [], "insights": {}}
    )

    def fake_collect_all(**kw):
        calls["collect_all"].append(kw)
        session = kw.get("session")
        account = session.account_id if session is not None else HOST_ACCOUNT
        return [
            Resource(
                resource_id=f"account-{account}",
                resource_type="aws.account",
                region="us-east-1",
                account_id=account,
                tags={},
                properties={},
                metrics={},
            )
        ]

    monkeypatch.setattr(appmod, "collect_all", fake_collect_all)
    monkeypatch.setattr(appmod, "_ENGINE_SUPPORTS_SESSION", True)

    return TestClient(appmod.app)
