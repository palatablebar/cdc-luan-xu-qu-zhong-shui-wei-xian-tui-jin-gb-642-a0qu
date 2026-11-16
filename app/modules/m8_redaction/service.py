"""擦除编排：暂存 → 校验 → 单事务落库，可重入、可续跑、失败保留旧版。

规则：

1. **不整笔抹去证据**。事件行与快照行一条不删，只把敏感原值换成稳定标记；
   行号引用、表、版本、操作、时刻、金额、数量、分类、原因码、四账全部不动；
2. **一次擦除覆盖三层回看**：事件证据（采信与去重明细的原文）、隔离证据
   （原值/明细/原始文本）、快照（payload 与强敏感主键）一起替换；
3. **同一次擦除重跑不重复计数**：请求摘要相同且已完成 → 直接返回原记录；
   中断/失败后重跑 → 复用同一条记录与同一个版本号，从断点继续；
4. **中断可恢复**：暂存区落库，恢复时按 `source_hash` 判断暂存是否仍对应当前
   线上行，对应就复用，不再重新计数；
5. **失败保留旧版**：校验失败不落库；落库是单事务，任何一步失败整体回滚，
   批次的擦除版本、事件、快照、清单、合计仍停在上一次成功的结果；
6. **不丢记录**：暂存行数与线上行数必须逐类相等，结构性列必须逐行相等。
"""
from __future__ import annotations

import datetime as dt
import hashlib
import hmac
import json
from dataclasses import dataclass, field

from ... import config, errors, manifest as manifest_mod, redaction
from . import plan


@dataclass
class Outcome:
    redaction_id: str
    batch_id: str
    status: str
    version: int
    stage: str
    idempotent_replay: bool
    resumed: bool
    stats: dict = field(default_factory=dict)
    problems: list[str] = field(default_factory=list)
    detail: str = ""

    def as_dict(self) -> dict:
        return {
            "redaction_id": self.redaction_id, "batch_id": self.batch_id,
            "status": self.status, "version": self.version,
            "policy_version": redaction.POLICY_VERSION,
            "stage": self.stage, "stage_label": plan.STAGE_LABELS.get(self.stage,
                                                                     self.stage),
            "idempotent_replay": self.idempotent_replay,
            "resumed": self.resumed, "stats": self.stats,
            "problems": self.problems, "detail": self.detail,
            "marker": f"{redaction.TOKEN_PREFIX}…]",
        }


def _now() -> str:
    return dt.datetime.now(config.UTC).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def _fingerprint(key: bytes, parts: dict) -> str:
    """带密钥的指纹：暂存区与线上行的一致性凭据。

    用 HMAC 而不是裸 sha256：指纹覆盖敏感原值，裸摘要可能被字典反推。
    """
    body = json.dumps(parts, sort_keys=True, ensure_ascii=False, default=str)
    return hmac.new(key, body.encode("utf-8"), hashlib.sha256).hexdigest()


def _event_fingerprint(row: dict, key: bytes) -> str:
    return _fingerprint(key, {
        "pk": row.get("pk"), "payload": row.get("payload"),
        "raw_value": row.get("raw_value"), "detail": row.get("detail"),
        "raw_text": row.get("raw_text"),
    })


def _snapshot_fingerprint(row: dict, key: bytes) -> str:
    return _fingerprint(key, {"pk": row.get("pk"), "payload": row.get("payload")})


def _snapshot_key(row: dict) -> str:
    return f"{row['table_name']}:{row['row_ref']}:{row['version']}"


# ---------------------------------------------------------------- 暂存

def build_stage(store, batch_id: str, key: bytes) -> tuple[list[dict], dict]:
    """把线上事件与快照逐行擦除到暂存区；不写任何线上结果。"""
    staged: list[dict] = []
    problems: list[str] = []

    for row in store.load_events(batch_id):
        original = dict(row)
        new, stats = redaction.redact_event_row(original, key)
        broken = redaction.verify_event(original, new)
        if broken:
            problems.append(f"{row['row_ref']}: " + "；".join(broken))
        changed = any(new.get(name) != original.get(name)
                      for name in ("pk", "payload", "raw_value", "detail", "raw_text"))
        staged.append({
            "kind": "event", "row_key": row["row_ref"], "batch_id": batch_id,
            "table_name": row["table_name"], "seq": row["seq"],
            "new_pk": new.get("pk"),
            "payload": new.get("payload"), "raw_value": new.get("raw_value"),
            "detail": new.get("detail"), "raw_text": new.get("raw_text"),
            "row_ref": row["row_ref"], "changed": changed,
            "cells": stats.cells,
            "tokens": sorted(stats.values),
            "source_hash": _event_fingerprint(original, key),
        })

    for row in store.load_snapshot(batch_id):
        original = dict(row)
        new, stats = redaction.redact_snapshot_row(original, key)
        broken = redaction.verify_snapshot(original, new)
        if broken:
            problems.append(f"snapshot {original['table_name']}/{original['pk']}: "
                            + "；".join(broken))
        changed = any(new.get(name) != original.get(name)
                      for name in ("pk", "payload"))
        staged.append({
            "kind": "snapshot", "row_key": _snapshot_key(original),
            "batch_id": batch_id, "table_name": original["table_name"],
            "seq": original["version"],
            "new_pk": new.get("pk"), "payload": new.get("payload"),
            "raw_value": None, "detail": None, "raw_text": None,
            "row_ref": original["row_ref"], "changed": changed,
            "cells": stats.cells,
            "tokens": sorted(stats.values),
            "source_hash": _snapshot_fingerprint(original, key),
        })
    return staged, _aggregate(staged, problems)


def _aggregate(staged: list[dict], problems: list[str]) -> dict:
    by_kind: dict[str, dict] = {}
    tokens: set[str] = set()
    for row in staged:
        bucket = by_kind.setdefault(row["kind"], {"rows": 0, "changed": 0, "cells": 0})
        bucket["rows"] += 1
        bucket["changed"] += 1 if row["changed"] else 0
        bucket["cells"] += row["cells"]
        tokens.update(row["tokens"])
    total_cells = sum(b["cells"] for b in by_kind.values())
    total_changed = sum(b["changed"] for b in by_kind.values())
    return {
        "rows": sum(b["rows"] for b in by_kind.values()),
        "changed": total_changed,
        "cells": total_cells,
        "values": len(tokens),
        "by_kind": by_kind,
        "problems": problems,
    }


# ---------------------------------------------------------------- 校验

def _residual(staged: list[dict], key: bytes) -> list[str]:
    """对暂存结果再擦一遍：仍能命中敏感值说明第一遍没擦干净。

    注意检查的是暂存区（准备落库的内容），不是尚未提交的线上行。
    """
    hits: list[str] = []
    for row in staged:
        if row["kind"] == "event":
            _, stats = redaction.redact_event_row(
                {"pk": row["new_pk"], "payload": row["payload"],
                 "raw_value": row["raw_value"], "detail": row["detail"],
                 "raw_text": row["raw_text"]}, key)
        else:
            _, stats = redaction.redact_snapshot_row(
                {"pk": row["new_pk"], "payload": row["payload"]}, key)
        if stats.cells:
            hits.append(f"{row['kind']} {row['row_key']}: {stats.cells} 处残留")
    return hits


def verify_stage(store, batch_id: str, redaction_id: str, key: bytes,
                 staged: list[dict]) -> list[str]:
    """行数逐类相等、暂存指纹对得上线上、暂存内容无敏感残留。"""
    problems: list[str] = []
    counts = store.count_stage(redaction_id)
    live = {
        "event": len(store.load_events(batch_id)),
        "snapshot": len(store.load_snapshot(batch_id)),
    }
    for kind, expected in live.items():
        got = counts.get(kind, {}).get("rows", 0)
        if got != expected:
            problems.append(f"{kind} 行数 {got} ≠ 线上 {expected}")

    live_events = {row["row_ref"]: row for row in store.load_events(batch_id)}
    live_snapshots = {_snapshot_key(row): row
                      for row in store.load_snapshot(batch_id)}
    for row in staged:
        if row["kind"] == "event":
            current = live_events.get(row["row_key"])
            fingerprint = _event_fingerprint(current, key) if current else None
        else:
            current = live_snapshots.get(row["row_key"])
            fingerprint = _snapshot_fingerprint(current, key) if current else None
        if current is None:
            problems.append(f"{row['kind']} {row['row_key']} 在线上已消失")
        elif fingerprint != row["source_hash"]:
            problems.append(f"{row['kind']} {row['row_key']} 暂存已过期")

    problems.extend(_residual(staged, key))
    return problems


# ---------------------------------------------------------------- 主流程

def resolve_key(settings) -> tuple[bytes, str]:
    """读取擦除密钥与其指纹；未显式配置时在数据目录生成并持久化。"""
    key = redaction.resolve_key(settings.redaction_key,
                                settings.redaction_key_path)
    return key, redaction.key_id(key)


def redact(*, store, batch_id: str | None, key: bytes, key_fingerprint: str,
           actor: str = "") -> Outcome:
    batch = store.get_batch(batch_id) if batch_id else store.latest_batch()
    if batch is None:
        raise errors.NotFound("还没有批次，先采信一次", code="E_NO_BATCH")
    if batch.get("status") != "done":
        raise errors.BadRequest(
            f"批次 {batch['batch_id']} 尚未完成（{batch.get('status')}），先续跑到完成再擦除",
            code="R_BATCH_NOT_DONE")
    batch_id = batch["batch_id"]
    digest = plan.request_digest(batch_id, redaction.POLICY_VERSION, key_fingerprint)

    done = store.find_redaction(batch_id, digest, status="done")
    if done is not None:
        return Outcome(redaction_id=done["redaction_id"], batch_id=batch_id,
                       status="done", version=done["version"], stage="done",
                       idempotent_replay=True, resumed=False,
                       stats=done.get("stats", {}),
                       detail="同一擦除请求已完成，复用原结果、不重复计数")

    record = store.find_redaction(batch_id, digest)
    resumed = record is not None
    if record is None:
        version = plan.next_version(batch)
        record = {
            "redaction_id": manifest_mod.new_run_id("RED"),
            "batch_id": batch_id, "requested_at": _now(),
            "started_at": _now(), "finished_at": None, "status": "running",
            "stage": "prepare", "policy_version": redaction.POLICY_VERSION,
            "key_id": key_fingerprint, "request_digest": digest,
            "replay_of": None, "version": version, "stats": {},
            "detail": actor,
        }
        store.insert_redaction(record)
    else:
        store.update_redaction(record["redaction_id"], status="running",
                              detail=actor or record.get("detail", ""))
        record = store.get_redaction(record["redaction_id"]) or record

    redaction_id = record["redaction_id"]
    version = int(record["version"])

    # ---- prepare：暂存 ----
    staged = store.load_stage(redaction_id)
    reuse = (resumed and staged
             and not verify_stage(store, batch_id, redaction_id, key, staged))
    if not reuse:
        store.update_redaction(redaction_id, stage="prepare")
        staged, stats = build_stage(store, batch_id, key)
        if stats["problems"]:
            return _fail(store, redaction_id, batch_id, version, stats,
                         stats["problems"], "改动越过结构列，未落库")
        store.replace_stage(redaction_id, staged)
        store.update_redaction(redaction_id, stage="staged", stats=stats)
    else:
        stats = record.get("stats") or _aggregate(staged, [])

    # ---- verified：行账与残留 ----
    store.update_redaction(redaction_id, stage="staged")
    problems = verify_stage(store, batch_id, redaction_id, key, staged)
    if problems:
        return _fail(store, redaction_id, batch_id, version, stats, problems,
                     "暂存校验未通过，保留旧版结果")
    store.update_redaction(redaction_id, version=version, stage="verified",
                           stats=stats)

    # ---- committed：单事务落库 ----
    store.update_redaction(redaction_id, stage="committed")
    finished_at = _now()
    manifest = _redacted_manifest(store, batch_id, record=record, version=version,
                                  stats=stats, finished_at=finished_at)
    totals = _merged_totals(store, batch_id, stats, version)
    marks = [{"table_name": row["table_name"], "token": token,
              "row_ref": row["row_ref"], "seq": row["seq"] or 0}
             for row in staged if row["changed"] for token in row["tokens"]]
    try:
        store.apply_redaction(
            redaction_id=redaction_id, batch_id=batch_id, version=version,
            manifest=manifest, totals=totals, marks=marks, stats=stats,
            finished_at=finished_at, policy_version=redaction.POLICY_VERSION,
            key_id=key_fingerprint)
    except Exception as exc:  # noqa: BLE001 - 落库失败按失败记录，线上保持旧版
        store.update_redaction(redaction_id, status="failed", stage="committed",
                              detail=f"落库失败：{exc}", finished_at=_now())
        raise errors.Conflict(f"擦除落库失败，已保留旧版结果：{exc}",
                              code="R_REDACT_COMMIT_FAILED") from exc

    return Outcome(redaction_id=redaction_id, batch_id=batch_id, status="done",
                   version=version, stage="done", idempotent_replay=False,
                   resumed=resumed, stats=stats,
                   detail="已擦除；结构性列与合计未变")


def _fail(store, redaction_id: str, batch_id: str, version: int, stats: dict,
          problems: list[str], detail: str) -> Outcome:
    store.update_redaction(redaction_id, status="failed", stage="failed",
                          detail=detail, stats=stats, finished_at=_now())
    return Outcome(redaction_id=redaction_id, batch_id=batch_id, status="failed",
                   version=version, stage="failed", idempotent_replay=False,
                   resumed=True, stats=stats, problems=problems, detail=detail)


def _merged_totals(store, batch_id: str, stats: dict, version: int) -> dict:
    """合计只增加擦除元信息；四个金额位与全部计数原样保留。"""
    totals = dict(store.load_totals(batch_id))
    totals["redaction_version"] = version
    totals["redaction_cells"] = int(stats.get("cells", 0))
    totals["redaction_changed_rows"] = int(stats.get("changed", 0))
    totals["redaction_values"] = int(stats.get("values", 0))
    totals["redaction_policy"] = redaction.POLICY_VERSION
    return totals


def _redacted_manifest(store, batch_id: str, *, record: dict, version: int,
                       stats: dict, finished_at: str) -> dict:
    doc = dict(store.load_manifest(batch_id) or {})
    doc["redaction"] = {
        "version": version,
        "redaction_id": record["redaction_id"],
        "policy_version": redaction.POLICY_VERSION,
        "key_id": record["key_id"],
        "finished_at": finished_at,
        "marker": "不可还原的稳定关联标记",
        "stats": stats,
    }
    return doc


def list_for_batch(store, batch_id: str | None) -> dict:
    batch = store.get_batch(batch_id) if batch_id else store.latest_batch()
    if batch is None:
        return {"batch_id": None, "current_version": 0, "redactions": []}
    rows = store.list_redactions(batch["batch_id"])
    out = []
    for row in rows:
        out.append({
            "redaction_id": row["redaction_id"], "status": row["status"],
            "stage": plan.STAGE_LABELS.get(row["stage"], row["stage"]),
            "version": row["version"], "policy_version": row["policy_version"],
            "key_id": row["key_id"], "requested_at": row["requested_at"],
            "finished_at": row.get("finished_at"),
            "stats": row.get("stats", {}), "detail": row.get("detail", ""),
            "resumable": row["status"] in ("running", "failed"),
        })
    return {
        "batch_id": batch["batch_id"],
        "current_version": int(batch.get("redaction_version") or 0),
        "redaction_id": batch.get("redaction_id"),
        "redactions": out,
        "marks": store.load_redaction_marks(batch["batch_id"]),
    }
