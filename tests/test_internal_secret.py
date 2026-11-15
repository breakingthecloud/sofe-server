"""Internal-secret rotation (S114 Phase B).

The Lambda accepts SOFE_INTERNAL_SECRET and, only while a rotation is in progress,
SOFE_INTERNAL_SECRET_PREVIOUS. That lets the two Cloudflare Workers switch to the new secret
one after the other without a single rejected request. No test prints a secret.
"""

import pytest
from fastapi.testclient import TestClient

import sofe_server.app as appmod

NEW = "new-secret-value-0123456789abcdef"
OLD = "old-secret-value-fedcba9876543210"


@pytest.fixture
def secrets(monkeypatch):
    """Configure the module-level secrets (they are read at import time) and return an HTTP client."""

    def configure(current="", previous="", api_key=""):
        monkeypatch.setattr(appmod, "SOFE_INTERNAL_SECRET", current)
        monkeypatch.setattr(appmod, "SOFE_INTERNAL_SECRET_PREVIOUS", previous)
        monkeypatch.setattr(appmod, "SOFE_API_KEY", api_key)
        # Only authentication is under test: an allowed request may fail later (no policies dir), which is not a 401.
        return TestClient(appmod.app, raise_server_exceptions=False)

    return configure


def status(client, secret=None, api_key=None, path="/policies"):
    headers = {}
    if secret is not None:
        headers["x-sofe-internal-secret"] = secret
    if api_key is not None:
        headers["x-api-key"] = api_key
    return client.get(path, headers=headers).status_code


# --- the rotation window ------------------------------------------------------------------------


def test_during_rotation_both_the_new_and_the_previous_secret_are_accepted(secrets):
    client = secrets(current=NEW, previous=OLD)
    assert status(client, NEW) != 401
    assert status(client, OLD) != 401


def test_a_secret_that_is_neither_is_rejected(secrets):
    client = secrets(current=NEW, previous=OLD)
    assert status(client, "something-else") == 401
    assert status(client, NEW + "x") == 401
    assert status(client, NEW[:-1]) == 401


def test_after_rotation_the_previous_secret_no_longer_works(secrets):
    client = secrets(current=NEW, previous="")
    assert status(client, NEW) != 401
    assert status(client, OLD) == 401


def test_without_any_rotation_behaviour_is_unchanged(secrets):
    client = secrets(current=NEW)
    assert status(client, NEW) != 401
    assert status(client) == 401
    assert status(client, "") == 401


# --- fail closed --------------------------------------------------------------------------------


def test_only_a_previous_secret_configured_is_still_enforced_not_open(secrets):
    """A half-finished rotation must never turn the public endpoint into open local mode."""
    client = secrets(current="", previous=OLD)
    assert status(client) == 401
    assert status(client, "anything") == 401
    assert status(client, OLD) != 401


def test_an_empty_header_never_matches_an_empty_secret(secrets):
    client = secrets(current=NEW, previous="")
    assert status(client, "") == 401
    assert status(client) == 401


def test_a_non_ascii_header_is_rejected_without_crashing(secrets):
    client = secrets(current=NEW, previous=OLD)
    # On the wire headers are bytes (latin-1); the server must reject them, not crash.
    assert status(client, "s\xe9cret-\xf1".encode("latin-1")) == 401


def test_health_stays_open(secrets):
    client = secrets(current=NEW, previous=OLD)
    assert status(client, path="/health") == 200


# --- unchanged paths ----------------------------------------------------------------------------


def test_no_secrets_at_all_is_still_open_local_mode(secrets):
    client = secrets()
    assert status(client) != 401


def test_the_api_key_path_is_unchanged(secrets):
    client = secrets(current=NEW, previous=OLD, api_key="api-key-value")
    assert status(client, api_key="api-key-value") != 401
    assert status(client, api_key="wrong") == 401
    assert status(client, api_key="") == 401


# --- comparison ---------------------------------------------------------------------------------


def test_secrets_are_compared_in_constant_time():
    """The comparison must go through hmac.compare_digest, not ==."""
    import inspect

    source = inspect.getsource(appmod)
    assert "compare_digest" in source
    assert "x_internal == SOFE_INTERNAL_SECRET" not in source
