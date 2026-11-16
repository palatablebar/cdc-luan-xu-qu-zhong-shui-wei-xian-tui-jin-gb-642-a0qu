"""M8 入口：擦除客户姓名/手机号/地址原值，保留稳定关联标记。

- `POST /api/redactions`：对当前（或指定）批次执行一次擦除；
- `GET /api/redactions`：看擦除历史、版本与标记；`GET /api/redactions/{id}`：单条；
- `POST /api/redactions/{id}/resume`：中断/失败后从断点续跑；
- 页面 `/redactions`。
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, Request

from ... import errors, redaction
from ...web import Ctx, get_ctx, render
from . import plan, service

router = APIRouter(tags=["M8 敏感值擦除"])


def _run(ctx: Ctx, batch_id: str | None, actor: str) -> dict:
    key, fingerprint = service.resolve_key(ctx.settings)
    outcome = service.redact(store=ctx.store, batch_id=batch_id, key=key,
                             key_fingerprint=fingerprint, actor=actor)
    payload = outcome.as_dict()
    payload["batch"] = _batch_brief(ctx.store, outcome.batch_id)
    return payload


def _batch_brief(store, batch_id: str) -> dict:
    batch = store.get_batch(batch_id) or {}
    return {"batch_id": batch.get("batch_id"),
            "redaction_version": int(batch.get("redaction_version") or 0),
            "redaction_id": batch.get("redaction_id"),
            "watermark_utc": batch.get("watermark_utc")}


@router.post("/api/redactions")
def api_redact(payload: dict | None = None, ctx: Ctx = Depends(get_ctx)) -> dict:
    body = payload or {}
    batch_id = str(body.get("batch_id") or "").strip() or None
    actor = str(body.get("actor") or "").strip()
    return _run(ctx, batch_id, actor)


@router.get("/api/redactions")
def api_redactions(batch_id: str | None = None,
                   ctx: Ctx = Depends(get_ctx)) -> dict:
    return {
        **service.list_for_batch(ctx.store, batch_id),
        "policy_version": redaction.POLICY_VERSION,
        "token_prefix": redaction.TOKEN_PREFIX,
        "stages": list(plan.STAGES),
        "stage_labels": plan.STAGE_LABELS,
    }


@router.post("/api/redactions/{redaction_id}/resume")
def api_resume(redaction_id: str, ctx: Ctx = Depends(get_ctx)) -> dict:
    record = ctx.store.get_redaction(redaction_id)
    if record is None:
        raise errors.NotFound(f"擦除记录 {redaction_id} 不存在", code="E_NOT_FOUND")
    return _run(ctx, record["batch_id"], f"resume:{redaction_id}")


@router.get("/redactions")
def page_redactions(request: Request, batch_id: str | None = None,
                    ctx: Ctx = Depends(get_ctx)):
    batch = ctx.current_batch(batch_id)
    data = service.list_for_batch(ctx.store, batch["batch_id"] if batch else None)
    return render(request, "redactions.html", batch=batch, page="redactions",
                  redaction_data=data, policy_version=redaction.POLICY_VERSION,
                  token_prefix=redaction.TOKEN_PREFIX,
                  stages=plan.STAGES, stage_labels=plan.STAGE_LABELS,
                  page_title="敏感值擦除")
