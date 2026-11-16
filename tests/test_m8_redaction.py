"""M8 敏感值擦除：识别、稳定标记、三层覆盖、幂等、续跑、失败保留旧版。

样例 `events_pii.jsonl` 含姓名 / 手机 / 地址，且混有已应用、隔离两种来源，
用来验证一次擦除同时覆盖采信、去重明细、隔离证据与快照。
"""
from __future__ import annotations

import json
from dataclasses import replace

import pytest

from app import config, redaction
from app.modules.m6_batches import service as batch_service
from app.modules.m7_export import service as export_service
from app.modules.m8_redaction import plan, service
from app.store import Store

PII_FILE = "events_pii.jsonl"
RAW_VALUES = ("张三", "李四", "王五", "13812345678", "13987654321", "13800138000",
              "上海市浦东新区", "北京市朝阳区", "广州市天河区")

FULL_WIDTH = "Ａ"  # 全角 A，验证 NFKC 归一会落到同一标记


def _key(tmp_path) -> tuple[bytes, str]:
    key = redaction.load_or_create_key(tmp_path / "red.key")
    return key, redaction.key_id(key)


def _pii_run(settings, store):
    return batch_service.run(settings=settings, store=store, source=PII_FILE)


def _blob(store, batch_id: str) -> str:
    """把页面上能看到的一切拼起来：证据行、隔离原值、分组、快照、导出。"""
    chunks = []
    for row in store.load_events(batch_id):
        chunks.append(json.dumps(row, ensure_ascii=False, default=str))
    for row in store.load_snapshot(batch_id):
        chunks.append(json.dumps(row, ensure_ascii=False, default=str))
    for kind in ("events", "quarantine", "conflicts", "snapshot"):
        data, _ = export_service.render_csv(store, batch_id, kind)
        chunks.append(data.decode("utf-8-sig"))
    chunks.append(export_service.render_manifest(store, batch_id)[0].decode("utf-8"))
    chunks.append(export_service.render_snapshot_json(store, batch_id)[0].decode("utf-8"))
    return "\n".join(chunks)


def _leaks(store, batch_id: str) -> list[str]:
    blob = _blob(store, batch_id)
    return [value for value in RAW_VALUES if value in blob]


# ---------------------------------------------------------------- 纯策略

def test_sensitive_keys_and_strong_patterns():
    assert redaction.is_sensitive_key("customer_name")
    assert redaction.is_sensitive_key("收货地址")
    assert not redaction.is_sensitive_key("status")
    assert redaction.strong_pii("13812345678")
    assert redaction.strong_pii("+86 138-1234-5678") is False  # 分隔写法要在归一后判定
    assert redaction.strong_pii("010-12345678")
    assert redaction.strong_pii("11010519491231002X")
    assert not redaction.strong_pii("orders")


def test_token_is_stable_across_spellings_and_keys():
    key = b"k" * 32
    same = {
        redaction.token_for("13812345678", key),
        redaction.token_for("+8613812345678", key),
        redaction.token_for("138-1234-5678", key),
        redaction.token_for("１３８１２３４５６７８", key),
    }
    assert len(same) == 1
    assert redaction.token_for("张三", key) == redaction.token_for(" 张三 ", key)
    assert redaction.token_for("张三", b"other" * 8) != redaction.token_for("张三", key)


def test_redact_string_keeps_existing_tokens_idempotent():
    key = b"z" * 32
    once, stats = redaction.redact_string("联系人 13987654321", key)
    assert stats.cells == 1
    assert raw_marker(once) == 1
    twice, again = redaction.redact_string(once, key)
    assert twice == once
    assert again.cells == 0


def raw_marker(text: str) -> int:
    return text.count(redaction.TOKEN_PREFIX)


def test_redact_object_handles_nested_values():
    key = b"n" * 32
    payload = {
        "status": "新建", "amount": "1.00",
        "customer": {"name": "张三", "phone": "13812345678"},
        "items": [{"recipient": "李四", "addr": "上海市浦东新区张江路88号"}],
    }
    out, stats = redaction.redact_object(payload, key)
    assert out["status"] == "新建" and out["amount"] == "1.00"
    assert redaction.is_token(out["customer"]["name"])
    assert redaction.is_token(out["customer"]["phone"])
    assert redaction.is_token(out["items"][0]["recipient"])
    assert redaction.is_token(out["items"][0]["addr"])
    assert stats.cells >= 4


# ---------------------------------------------------------------- 一次擦除覆盖三层

def test_redaction_removes_pii_from_all_surfaces(settings, store):
    run = _pii_run(settings, store)
    batch_id = run["batch"]["batch_id"]
    assert _leaks(store, batch_id), "样例应当先含原值，否则测试本身失效"

    key, fingerprint = _key(store_dir(store))
    outcome = service.redact(store=store, batch_id=batch_id, key=key,
                             key_fingerprint=fingerprint)
    assert outcome.status == "done"
    assert _leaks(store, batch_id) == []

    applied = store.load_events(batch_id, "applied")
    quarantine = store.load_events(batch_id, "quarantine")
    assert any(redaction.is_token(row["pk"]) for row in applied + quarantine
               if row["row_class"] == "applied")
    assert any("REDACTED" in (row["raw_text"] or "") for row in quarantine)
    assert all("name=" not in (row["raw_value"] or "") for row in quarantine)


def test_structural_columns_and_totals_are_preserved(settings, store):
    run = _pii_run(settings, store)
    batch_id = run["batch"]["batch_id"]
    before_events = store.load_events(batch_id)
    before_snapshot = store.load_snapshot(batch_id)
    before_totals = store.load_totals(batch_id)

    key, fingerprint = _key(store_dir(store))
    outcome = service.redact(store=store, batch_id=batch_id, key=key,
                             key_fingerprint=fingerprint)
    after_events = store.load_events(batch_id)
    after_snapshot = store.load_snapshot(batch_id)
    after_totals = store.load_totals(batch_id)

    assert outcome.problems == []
    for key_rows in ("amount_snapshot", "amount_pending", "amount_drift",
                     "amount_applied", "applied", "raw_lines", "conflicts",
                     "quarantine", "snapshot_keys"):
        assert before_totals[key_rows] == after_totals[key_rows], key_rows

    structural = ("row_ref", "seq", "table_name", "version", "op",
                  "event_time_utc", "event_time_raw", "schema_version",
                  "amount", "qty", "row_class", "reason_code", "field", "late")
    by_ref = {row["row_ref"]: row for row in after_events}
    for original in before_events:
        current = by_ref[original["row_ref"]]
        for name in structural:
            assert original[name] == current[name], (original["row_ref"], name)
    assert len(before_snapshot) == len(after_snapshot)


def test_same_value_gets_same_marker_across_rows(settings, store):
    _pii_run(settings, store)
    batch_id = store.latest_batch()["batch_id"]
    key, fingerprint = _key(store_dir(store))
    service.redact(store=store, batch_id=batch_id, key=key,
                   key_fingerprint=fingerprint)
    # 张三 / 13812345678 在 v1、v2 两条隔离证据里出现，手机号还有 +86 写法。
    # 它们是契约外列，原值只留在证据原文里；两条原文必须共享姓名与手机标记。
    customers = [row for row in store.load_events(batch_id)
                 if row["table_name"] == "customers"]
    assert len(customers) == 2
    first = set(redaction.TOKEN_RE.findall(customers[0]["raw_text"]))
    second = set(redaction.TOKEN_RE.findall(customers[1]["raw_text"]))
    assert len(first) == 3 and len(second) == 2   # v1 还有地址，v2 只有姓名+手机
    assert second <= first, "同一姓名/手机在两条证据里必须得到同一标记"
    assert len(first - second) == 1, "多出来的标记只应是地址"


def test_marker_values_are_unique_per_value(settings, store):
    _pii_run(settings, store)
    batch_id = store.latest_batch()["batch_id"]
    key, fingerprint = _key(store_dir(store))
    first = service.redact(store=store, batch_id=batch_id, key=key,
                           key_fingerprint=fingerprint)
    marks = store.load_redaction_marks(batch_id)
    distinct = {mark["token"] for mark in marks}
    assert len(marks) >= len(distinct)
    assert len(distinct) == first.stats["values"]


def test_pii_primary_key_replaced_but_normal_keys_kept(settings, store):
    _pii_run(settings, store)
    batch_id = store.latest_batch()["batch_id"]
    key, fingerprint = _key(store_dir(store))
    service.redact(store=store, batch_id=batch_id, key=key,
                   key_fingerprint=fingerprint)
    applied = store.load_events(batch_id, "applied")
    keys = {row["pk"] for row in applied}
    assert any(redaction.is_token(pk) for pk in keys)          # 手机号主键
    assert "3101" in keys and "3103" in keys                    # 普通主键不动
    marks = store.load_redaction_marks(batch_id)
    assert any(mark["table_name"] == "orders" for mark in marks)


# ---------------------------------------------------------------- 幂等与续跑

def test_same_redaction_rerun_does_not_double_count(settings, store):
    _pii_run(settings, store)
    batch_id = store.latest_batch()["batch_id"]
    key, fingerprint = _key(store_dir(store))

    first = service.redact(store=store, batch_id=batch_id, key=key,
                           key_fingerprint=fingerprint)
    second = service.redact(store=store, batch_id=batch_id, key=key,
                            key_fingerprint=fingerprint)
    assert first.version == 1
    assert second.idempotent_replay is True
    assert second.version == first.version
    assert second.stats == first.stats
    assert len(store.list_redactions(batch_id)) == 1
    distinct = {mark["token"] for mark in store.load_redaction_marks(batch_id)}
    assert len(distinct) == first.stats["values"]


def test_interrupted_redaction_resumes_without_new_record(settings, store,
                                                          monkeypatch):
    _pii_run(settings, store)
    batch_id = store.latest_batch()["batch_id"]
    key, fingerprint = _key(store_dir(store))

    def boom(**kwargs):
        raise RuntimeError("disk full")

    monkeypatch.setattr(store, "apply_redaction", boom)
    with pytest.raises(Exception):
        service.redact(store=store, batch_id=batch_id, key=key,
                       key_fingerprint=fingerprint)
    monkeypatch.undo()

    failed = store.list_redactions(batch_id)
    assert len(failed) == 1 and failed[0]["status"] == "failed"
    assert store.get_batch(batch_id)["redaction_version"] == 0
    assert _leaks(store, batch_id), "落库失败时必须保留旧版原值"

    outcome = service.redact(store=store, batch_id=batch_id, key=key,
                             key_fingerprint=fingerprint)
    assert outcome.resumed is True
    assert outcome.version == failed[0]["version"]
    assert len(store.list_redactions(batch_id)) == 1
    assert _leaks(store, batch_id) == []


def test_verify_failure_keeps_old_version(settings, store, monkeypatch):
    _pii_run(settings, store)
    batch_id = store.latest_batch()["batch_id"]
    key, fingerprint = _key(store_dir(store))
    before = store.load_totals(batch_id)

    def bad_verify(*args, **kwargs):
        return ["人为制造的校验失败"]

    monkeypatch.setattr(service, "verify_stage", bad_verify)
    outcome = service.redact(store=store, batch_id=batch_id, key=key,
                             key_fingerprint=fingerprint)
    assert outcome.status == "failed"
    assert "人为制造的校验失败" in outcome.problems
    assert store.load_totals(batch_id).get("redaction_version") in (None, "0")
    assert before["applied"] == store.load_totals(batch_id)["applied"]
    assert _leaks(store, batch_id)


def test_new_policy_version_creates_next_version(settings, store, monkeypatch):
    _pii_run(settings, store)
    batch_id = store.latest_batch()["batch_id"]
    key, fingerprint = _key(store_dir(store))
    service.redact(store=store, batch_id=batch_id, key=key,
                   key_fingerprint=fingerprint)
    monkeypatch.setattr(redaction, "POLICY_VERSION", "pii-redaction/2.0")
    second = service.redact(store=store, batch_id=batch_id, key=key,
                            key_fingerprint=fingerprint)
    assert second.idempotent_replay is False
    assert second.version == 2
    assert len(store.list_redactions(batch_id)) == 2
    assert store.get_batch(batch_id)["redaction_version"] == 2


def test_every_row_is_marked_covered_by_this_redaction(settings, store):
    """没命中敏感值的行也打上版本，否则和「漏擦」无法区分。"""
    _pii_run(settings, store)
    batch_id = store.latest_batch()["batch_id"]
    key, fingerprint = _key(store_dir(store))
    service.redact(store=store, batch_id=batch_id, key=key,
                   key_fingerprint=fingerprint)
    assert store.uncovered_rows(batch_id, 1) == {"events": 0, "snapshots": 0}
    assert all(row["redaction_version"] == 1 for row in store.load_events(batch_id))
    assert all(row["redaction_version"] == 1 for row in store.load_snapshot(batch_id))


def test_unfinished_batch_cannot_be_redacted(settings, store):
    store.save_attempt(batch={
        "batch_id": "B-failed02", "batch_key": "failed02", "run_id": "CDC-y",
        "source": "all", "status": "failed", "created_at": "2026-11-15T09:00:00Z",
        "input_digest": "digest", "params": {},
    }, inputs=[])
    key, fingerprint = _key(store_dir(store))
    with pytest.raises(Exception) as info:
        service.redact(store=store, batch_id="B-failed02", key=key,
                       key_fingerprint=fingerprint)
    assert getattr(info.value, "code", "") == "R_BATCH_NOT_DONE"


def test_redacted_batch_refuses_raw_overwrite(settings, store):
    """已擦除批次不能再被原始行覆盖，否则原值会借重跑回来。"""
    _pii_run(settings, store)
    batch_id = store.latest_batch()["batch_id"]
    key, fingerprint = _key(store_dir(store))
    service.redact(store=store, batch_id=batch_id, key=key,
                   key_fingerprint=fingerprint)

    replay = batch_service.run(settings=settings, store=store, source=PII_FILE)
    assert replay["idempotent_replay"] is True
    assert _leaks(store, batch_id) == []

    # 即便有人绕过幂等重放直接 save_run，也必须被拦下
    with pytest.raises(RuntimeError) as info:
        store.save_run(batch={"batch_id": batch_id, "batch_key": "k",
                              "run_id": "CDC-z", "source": PII_FILE,
                              "status": "done",
                              "created_at": "2026-11-15T10:00:00Z",
                              "input_digest": "d", "params": {}},
                       inputs=[], events=[], snapshots=[], watermarks=[],
                       stages=[], totals={}, manifest={})
    assert "已擦除" in str(info.value)


# ---------------------------------------------------------------- 回看与 API

def test_snapshot_rebuild_after_redaction_stays_redacted(settings, store):
    _pii_run(settings, store)
    batch_id = store.latest_batch()["batch_id"]
    from app.modules.m5_snapshot import service as snapshot_service
    key, fingerprint = _key(store_dir(store))
    service.redact(store=store, batch_id=batch_id, key=key,
                   key_fingerprint=fingerprint)
    snapshot_service.rebuild(store, batch_id)
    assert _leaks(store, batch_id) == []
    assert all(row["redaction_version"] >= 1 for row in store.load_snapshot(batch_id))


def test_redaction_api_surface(client):
    listed = client.get("/api/redactions").json()
    assert listed["policy_version"] == redaction.POLICY_VERSION
    assert listed["stages"] == list(plan.STAGES)

    result = client.post("/api/redactions", json={}).json()
    assert result["status"] == "done"
    assert result["version"] == 1
    again = client.post("/api/redactions", json={}).json()
    assert again["idempotent_replay"] is True
    assert again["version"] == result["version"]

    detail = client.get("/api/redactions").json()
    assert detail["current_version"] == 1
    assert len(detail["redactions"]) == 1
    assert client.get("/redactions").status_code == 200
    health = client.get("/api/health").json()
    assert health["redaction_version"] == 1


def test_pii_beyond_first_400_chars_is_redacted(tmp_path, store):
    """原文不能只留前 400 字符：截断会留下半截手机号，也无法按 JSON 结构擦。"""
    samples = tmp_path / "samples"
    samples.mkdir()
    filler = "x" * 500
    (samples / "long.jsonl").write_text(
        '{"table":"orders","pk":"9001","version":1,"op":"upsert",'
        '"event_time":"2026-11-15T08:00:00Z","schema":"v2",'
        f'"payload":{{"status":"新建","amount":"1.00","note":"{filler}",'
        '"phone":"13812345678"}}\n', encoding="utf-8")
    settings = config.Settings(db_path=store.path, sample_dir=str(samples))
    batch_service.run(settings=settings, store=store, source="long.jsonl")
    batch_id = store.latest_batch()["batch_id"]
    key, fingerprint = _key(store_dir(store))
    service.redact(store=store, batch_id=batch_id, key=key,
                   key_fingerprint=fingerprint)
    blob = _blob(store, batch_id)
    assert "13812345678" not in blob
    assert "1381" not in blob
    assert filler in blob, "非敏感长文本不能被误伤"


def test_redaction_page_renders(client):
    client.post("/api/redactions", json={})
    response = client.get("/redactions")
    assert response.status_code == 200
    assert "敏感值擦除" in response.text
    assert "擦除记录" in response.text


def test_request_digest_changes_with_policy_and_key():
    base = plan.request_digest("B-1", "pii-redaction/1.0", "abcd1234")
    assert base == plan.request_digest("B-1", "pii-redaction/1.0", "abcd1234")
    assert base != plan.request_digest("B-1", "pii-redaction/2.0", "abcd1234")
    assert base != plan.request_digest("B-1", "pii-redaction/1.0", "ffff0000")
    assert base != plan.request_digest("B-2", "pii-redaction/1.0", "abcd1234")


def store_dir(store: Store):
    from pathlib import Path
    return Path(store.path).resolve().parent
