"""Billing & Cost Explorer endpoints (S116-B2).

These endpoints are the only place where the server talks to Cost Explorer and
Organizations. They always AssumeRole into the customer account (S111) and reuse
the engine's typed helpers from ``sofe.billing`` (S116-B1).
"""

from __future__ import annotations

import uuid
from datetime import date, timedelta
from typing import Any, Literal

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from sofe.billing.ce import account_cost_filter, classify_ce_error, query_costs, query_resources
from sofe.billing.credits import get_credit_allocations, get_credits
from sofe.billing.models import CostQuery, Granularity, GroupBy, Metric, OrganizationResult
from sofe.billing.organization import build_organization

router = APIRouter(tags=["billing"])

BILLING_SESSION_NAME = "sofe-billing"
MAX_RESOURCE_DAYS = 14
MAX_CREDIT_BALANCE_DAYS = 365
MAX_CREDIT_HISTORY_DAYS = 731

_METRIC_ALIASES = {
    "unblended": Metric.unblended,
    "amortized": Metric.amortized,
    "net_amortized": Metric.net_amortized,
    "net_unblended": Metric.net_unblended,
    "blended": Metric.blended,
}


class BillingCredentials(BaseModel):
    role_arn: str
    external_id: str


class BillingGroupBy(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="forbid")

    type: Literal["DIMENSION", "TAG", "COST_CATEGORY"] = Field(alias="Type")
    key: str = Field(alias="Key")

    def to_engine(self) -> GroupBy:
        return GroupBy(type=self.type, key=self.key)


class BillingInclude(BaseModel):
    credits: bool = False
    refunds: bool = False
    taxes: bool = True


class BillingQueryRequest(BillingCredentials):
    model_config = ConfigDict(populate_by_name=True, extra="forbid")

    account_id: str | None = None
    from_date: date = Field(alias="from")
    to_date: date = Field(alias="to")
    granularity: Granularity = Granularity.monthly
    metric: Metric = Metric.unblended
    group_by: list[BillingGroupBy] = Field(default_factory=list, max_length=2)
    filter: dict[str, Any] | None = None
    include: BillingInclude = Field(default_factory=BillingInclude)

    @field_validator("granularity", mode="before")
    @classmethod
    def _granularity(cls, value: Any) -> Any:
        return value.upper() if isinstance(value, str) else value

    @field_validator("metric", mode="before")
    @classmethod
    def _metric(cls, value: Any) -> Any:
        if isinstance(value, str):
            return _METRIC_ALIASES.get(value.lower(), value)
        return value

    @model_validator(mode="after")
    def _dates(self) -> "BillingQueryRequest":
        if self.to_date <= self.from_date:
            raise ValueError("to must be after from")
        return self

    def to_engine_query(self) -> CostQuery:
        if self.filter is not None:
            ce_filter = self.filter
        else:
            # Build the record-type exclusion even when no account is scoped: an
            # org-wide payer query must not include credits, or a fully
            # credit-covered bill nets to ~$0 and looks like ``no_data``.
            ce_filter = account_cost_filter(
                self.account_id,
                exclude_credits=not self.include.credits,
                exclude_refunds=not self.include.refunds,
                exclude_taxes=not self.include.taxes,
            )
        return CostQuery(
            start=self.from_date,
            end=self.to_date,
            granularity=self.granularity,
            metric=self.metric,
            group_by=[group.to_engine() for group in self.group_by],
            filter=ce_filter,
        )


class BillingDimensionsRequest(BillingCredentials):
    model_config = ConfigDict(populate_by_name=True, extra="forbid")

    from_date: date = Field(alias="from")
    to_date: date = Field(alias="to")
    dimension: str | None = None
    tag_key: str | None = None
    search: str | None = None

    @model_validator(mode="after")
    def _dates(self) -> "BillingDimensionsRequest":
        if self.to_date <= self.from_date:
            raise ValueError("to must be after from")
        return self


class BillingCreditsRequest(BillingCredentials):
    model_config = ConfigDict(populate_by_name=True, extra="forbid")

    account_id: str = Field(pattern=r"^[0-9]{12}$")
    payer_account_flag: bool = False
    from_date: date | None = Field(default=None, alias="from")
    to_date: date | None = Field(default=None, alias="to")

    @model_validator(mode="after")
    def _dates(self) -> "BillingCreditsRequest":
        if self.from_date and self.to_date and self.to_date <= self.from_date:
            raise ValueError("to must be after from")
        return self

    def period(self, *, max_days: int, clamp_end: bool = False) -> tuple[date, date]:
        today = date.today()
        end = self.to_date or today
        if clamp_end:
            # GetCredits rejects a future endDate.
            end = min(end, today)
        start = self.from_date or (today - timedelta(days=max_days))
        # The Billing API caps lookback by "today" (not by the requested end),
        # so a period that ends long ago still fails unless it is recent.
        if (today - start).days > max_days or (end - start).days > max_days + 31:
            raise HTTPException(
                status_code=400,
                detail=f"the requested period is limited to {max_days} days",
            )
        return start, end


def _billing_session(role_arn: str, external_id: str):
    # Imported lazily so this module never imports app.py at import time.
    from .app import _EXTERNAL_ID_RE, _assume_role_session, _validate_role_arn

    if not role_arn or not external_id:
        raise HTTPException(status_code=400, detail="role_arn and external_id are required")
    if not _EXTERNAL_ID_RE.match(external_id):
        raise HTTPException(status_code=400, detail="external_id has an invalid format")
    _validate_role_arn(role_arn)
    return _assume_role_session(role_arn, external_id, session_name=BILLING_SESSION_NAME)


def _amount(cents: int) -> str:
    return f"{cents / 100:.2f}"


def _result_body(result, query: CostQuery) -> dict[str, Any]:
    return {
        "request_id": str(uuid.uuid4()),
        "period": {"start": query.start.isoformat(), "end": query.end.isoformat()},
        "granularity": query.granularity.value,
        "metric": query.metric.value,
        "groups": [
            {
                "keys": group.keys,
                "amount": _amount(group.amount_cents),
                "unit": group.unit,
                "period": group.period,
            }
            for group in result.groups
        ],
        "total": _amount(result.total_cents),
        "requests": result.requests,
        "cost_status": result.status.value,
        "cost_detail": result.detail,
    }


def _ce_error(exc: Exception) -> HTTPException:
    status, detail = classify_ce_error(exc)
    code = 403 if status.value in ("access_denied", "not_enabled") else 502
    return HTTPException(status_code=code, detail=f"{status.value}: {detail}")


def _credits_body(result) -> dict[str, Any]:
    return {
        "request_id": str(uuid.uuid4()),
        "period": {"start": result.period_start.isoformat(), "end": result.period_end.isoformat()},
        "currency": "USD",
        "totals": {
            "initial": _amount(result.total_initial_cents),
            "remaining": _amount(result.total_remaining_cents),
            "estimated": _amount(result.total_estimated_cents),
        },
        "by_account": {account: _amount(cents) for account, cents in sorted(result.by_account.items())},
        "credits": [
            {
                "credit_id": credit.credit_id,
                "account_id": credit.account_id,
                "credit_type": credit.credit_type,
                "description": credit.description,
                "initial": _amount(credit.initial_cents),
                "remaining": _amount(credit.remaining_cents),
                "estimated": _amount(credit.estimated_cents) if credit.estimated_cents is not None else None,
                "start_date": credit.start_date.isoformat() if credit.start_date else None,
                "end_date": credit.end_date.isoformat() if credit.end_date else None,
                "exhaust_date": credit.exhaust_date.isoformat() if credit.exhaust_date else None,
                "status": credit.status,
                "products": credit.products,
            }
            for credit in result.credits
        ],
        "requests": result.requests,
        "cost_status": result.status.value,
        "cost_detail": result.detail,
    }


def _credit_history_body(result) -> dict[str, Any]:
    return {
        "request_id": str(uuid.uuid4()),
        "period": {"start": result.period_start.isoformat(), "end": result.period_end.isoformat()},
        "currency": "USD",
        "entries": [
            {
                "billing_month": entry.billing_month,
                "account_id": entry.account_id,
                "service": entry.service,
                "credit_id": entry.credit_id,
                "amount": _amount(entry.amount_cents),
                "description": entry.description,
                "estimated": entry.estimated,
            }
            for entry in result.entries
        ],
        "total": _amount(result.total_cents),
        "by_month": {month: _amount(cents) for month, cents in sorted(result.by_month.items())},
        "by_account": {account: _amount(cents) for account, cents in sorted(result.by_account.items())},
        "by_service": {
            service: _amount(cents)
            for service, cents in sorted(result.by_service.items(), key=lambda item: item[1], reverse=True)
        },
        "partial_results": result.partial,
        "failed_months": result.failed_months,
        "requests": result.requests,
        "cost_status": result.status.value,
        "cost_detail": result.detail,
    }


@router.post("/billing/credits")
async def billing_credits(req: BillingCreditsRequest) -> dict[str, Any]:
    start, end = req.period(max_days=MAX_CREDIT_BALANCE_DAYS, clamp_end=True)
    session = _billing_session(req.role_arn, req.external_id)
    result = get_credits(
        session.get_credentials(),
        account_id=req.account_id,
        start=start,
        end=end,
        payer_account_flag=req.payer_account_flag,
    )
    return _credits_body(result)


@router.post("/billing/credits/history")
async def billing_credit_history(req: BillingCreditsRequest) -> dict[str, Any]:
    start, end = req.period(max_days=MAX_CREDIT_HISTORY_DAYS)
    session = _billing_session(req.role_arn, req.external_id)
    result = get_credit_allocations(
        session.get_credentials(),
        account_id=req.account_id,
        start=start,
        end=end,
    )
    return _credit_history_body(result)


@router.post("/billing/query")
async def billing_query(req: BillingQueryRequest):
    session = _billing_session(req.role_arn, req.external_id)
    query = req.to_engine_query()
    ce = session.client("ce", region_name="us-east-1")
    return _result_body(query_costs(ce, query), query)


@router.post("/billing/resources")
async def billing_resources(req: BillingQueryRequest):
    session = _billing_session(req.role_arn, req.external_id)
    if (req.to_date - req.from_date).days > MAX_RESOURCE_DAYS:
        raise HTTPException(
            status_code=400,
            detail=f"resource-level Cost Explorer data is limited to {MAX_RESOURCE_DAYS} days",
        )
    query = req.to_engine_query()
    ce = session.client("ce", region_name="us-east-1")
    return _result_body(query_resources(ce, query), query)


@router.post("/billing/organization")
async def billing_organization(req: BillingCredentials) -> dict[str, Any]:
    session = _billing_session(req.role_arn, req.external_id)
    org = session.client("organizations", region_name="us-east-1")
    iam = session.client("iam", region_name="us-east-1")
    caller = session.client("sts").get_caller_identity().get("Account")
    result: OrganizationResult = build_organization(org, caller, iam=iam)
    return result.model_dump()


@router.post("/billing/dimensions")
async def billing_dimensions(req: BillingDimensionsRequest) -> dict[str, Any]:
    session = _billing_session(req.role_arn, req.external_id)
    ce = session.client("ce", region_name="us-east-1")
    period = {"Start": req.from_date.isoformat(), "End": req.to_date.isoformat()}
    try:
        if not req.tag_key and not req.dimension:
            response = ce.get_tags(TimePeriod=period)
            tags = response.get("Tags", []) or []
            return {"type": "tag_keys", "keys": [tag.get("Key") for tag in tags if tag.get("Key")]}
        if req.tag_key:
            response = ce.get_tags(TimePeriod=period, TagKey=req.tag_key)
            tags = response.get("Tags", []) or []
            values = [
                value
                for tag in tags
                for value in (tag.get("Values", []) if tag.get("Key") == req.tag_key else [])
            ]
            return {"type": "tag", "key": req.tag_key, "values": values}
        response = ce.get_dimension_values(
            TimePeriod=period,
            Dimension=req.dimension,
            **({"SearchString": req.search} if req.search else {}),
        )
        values = [str(item.get("Value")) for item in response.get("DimensionValues", []) if item.get("Value")]
        return {"type": "dimension", "dimension": req.dimension, "values": values}
    except Exception as exc:  # noqa: BLE001 - normalize CE errors
        raise _ce_error(exc) from exc
