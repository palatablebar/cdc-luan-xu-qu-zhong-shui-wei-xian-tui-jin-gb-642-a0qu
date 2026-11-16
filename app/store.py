"""SQLite 存储：批次、输入文件、事件、快照、水位序列、阶段、合计、运行清单。

约定：

- 金额列一律 TEXT（Decimal 字符串），不落 float；主键 pk 一律 TEXT，前导零与
  超过 2^53 的整数都按原样保存；
- 一次运行的所有行在同一个事务里「先删后插」，失败整体回滚，不留半批数据；
- 页面永远只展示一个批次，所有查询都带 batch_id。
"""
from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from decimal import Decimal
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS batches (
    batch_id TEXT PRIMARY KEY,
    batch_key TEXT NOT NULL,
    run_id TEXT NOT NULL,
    source TEXT NOT NULL,
    status TEXT NOT NULL,
    created_at TEXT NOT NULL,
    finished_at TEXT,
    input_digest TEXT NOT NULL,
    watermark_utc TEXT,
    max_event_time TEXT,
    params_json TEXT NOT NULL DEFAULT '{}',
    note TEXT NOT NULL DEFAULT '',
    replay_of TEXT,
    redaction_version INTEGER NOT NULL DEFAULT 0,
    redaction_id TEXT
);
CREATE INDEX IF NOT EXISTS idx_batches_key ON batches(batch_key, status);
CREATE TABLE IF NOT EXISTS inputs (
    batch_id TEXT NOT NULL, seq INTEGER NOT NULL, name TEXT NOT NULL,
    bytes INTEGER NOT NULL, sha256 TEXT NOT NULL, declared_rows INTEGER,
    encoding TEXT, declared TEXT, kind TEXT, status TEXT NOT NULL, code TEXT,
    note TEXT, lines INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS events (
    batch_id TEXT NOT NULL, row_ref TEXT NOT NULL, seq INTEGER NOT NULL,
    table_name TEXT NOT NULL, pk TEXT NOT NULL, version INTEGER,
    op TEXT, event_time_utc TEXT, event_time_raw TEXT, schema_version TEXT,
    payload_json TEXT NOT NULL DEFAULT '{}', amount TEXT, qty INTEGER,
    row_class TEXT NOT NULL, reason_code TEXT, field TEXT, raw_value TEXT,
    detail TEXT, late INTEGER NOT NULL DEFAULT 0, flags_json TEXT NOT NULL DEFAULT '[]',
    raw_text TEXT NOT NULL DEFAULT '',
    columns_json TEXT NOT NULL DEFAULT '[]',
    redaction_version INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_events_class ON events(batch_id, row_class);
CREATE TABLE IF NOT EXISTS snapshots (
    batch_id TEXT NOT NULL, table_name TEXT NOT NULL, pk TEXT NOT NULL,
    version INTEGER NOT NULL, op TEXT NOT NULL, amount TEXT, qty INTEGER,
    event_time_utc TEXT NOT NULL, row_ref TEXT NOT NULL,
    late INTEGER NOT NULL DEFAULT 0, pending INTEGER NOT NULL DEFAULT 0,
    payload_json TEXT NOT NULL DEFAULT '{}',
    redaction_version INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS watermarks (
    batch_id TEXT NOT NULL, seq INTEGER NOT NULL, row_ref TEXT NOT NULL,
    event_time_utc TEXT NOT NULL, watermark_utc TEXT NOT NULL,
    late INTEGER NOT NULL DEFAULT 0, behind_seconds INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS stages (
    batch_id TEXT NOT NULL, stage TEXT NOT NULL, in_count INTEGER NOT NULL,
    out_count INTEGER NOT NULL, quarantine_count INTEGER NOT NULL,
    status TEXT NOT NULL, elapsed_ms INTEGER NOT NULL, note TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS totals (
    batch_id TEXT NOT NULL, key TEXT NOT NULL, value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS manifests (
    batch_id TEXT PRIMARY KEY, json TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS redactions (
    redaction_id TEXT PRIMARY KEY,
    batch_id TEXT NOT NULL,
    requested_at TEXT NOT NULL,
    started_at TEXT,
    finished_at TEXT,
    status TEXT NOT NULL,
    stage TEXT NOT NULL DEFAULT 'prepare',
    policy_version TEXT NOT NULL,
    key_id TEXT NOT NULL,
    request_digest TEXT NOT NULL,
    replay_of TEXT,
    version INTEGER NOT NULL DEFAULT 0,
    stats_json TEXT NOT NULL DEFAULT '{}',
    detail TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_redactions_batch ON redactions(batch_id, requested_at);
CREATE UNIQUE INDEX IF NOT EXISTS idx_redactions_request
    ON redactions(batch_id, request_digest);
CREATE TABLE IF NOT EXISTS redaction_stages (
    redaction_id TEXT NOT NULL, kind TEXT NOT NULL, row_key TEXT NOT NULL,
    batch_id TEXT NOT NULL, table_name TEXT NOT NULL DEFAULT '',
    seq INTEGER, new_pk TEXT, payload_json TEXT,
    raw_value TEXT, detail TEXT, raw_text TEXT,
    row_ref TEXT NOT NULL DEFAULT '', changed INTEGER NOT NULL DEFAULT 0,
    cells INTEGER NOT NULL DEFAULT 0, tokens_json TEXT NOT NULL DEFAULT '[]',
    source_hash TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (redaction_id, kind, row_key)
);
CREATE INDEX IF NOT EXISTS idx_stage_batch ON redaction_stages(redaction_id, batch_id);
CREATE TABLE IF NOT EXISTS redaction_marks (
    redaction_id TEXT NOT NULL, batch_id TEXT NOT NULL,
    table_name TEXT NOT NULL, token TEXT NOT NULL,
    row_ref TEXT NOT NULL DEFAULT '', seq INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_marks_token ON redaction_marks(token);
"""

# 老库升级：新列在这里登记，缺列就补，避免升级后 500
_MIGRATED_COLUMNS = {
    "batches": {"redaction_version": "INTEGER NOT NULL DEFAULT 0",
                "redaction_id": "TEXT"},
    "events": {"redaction_version": "INTEGER NOT NULL DEFAULT 0",
               "columns_json": "TEXT NOT NULL DEFAULT '[]'"},
    "snapshots": {"redaction_version": "INTEGER NOT NULL DEFAULT 0"},
}


class Store:
    def __init__(self, path: str):
        self.path = str(path)
        Path(self.path).resolve().parent.mkdir(parents=True, exist_ok=True)
        with self.connect() as conn:
            conn.executescript(SCHEMA)
            self._ensure_columns(conn)

    @staticmethod
    def _ensure_columns(conn) -> None:
        """轻量迁移：老库缺列时补上，避免升级后 500。"""
        wanted = {"inputs": {"declared": "TEXT"}, **_MIGRATED_COLUMNS}
        for table, columns in wanted.items():
            existing = {row["name"] for row in conn.execute(
                f"PRAGMA table_info({table})").fetchall()}
            for column, ddl in columns.items():
                if column not in existing:
                    conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {ddl}")

    @contextmanager
    def connect(self):
        conn = sqlite3.connect(self.path, timeout=15.0)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    # ---------- 批次 ----------
    def get_batch(self, batch_id: str) -> dict | None:
        rows = self._all("SELECT * FROM batches WHERE batch_id=?", (batch_id,))
        return rows[0] if rows else None

    def find_done_by_key(self, batch_key: str) -> dict | None:
        rows = self._all(
            "SELECT * FROM batches WHERE batch_key=? AND status='done' "
            "ORDER BY created_at LIMIT 1", (batch_key,))
        return rows[0] if rows else None

    def latest_batch(self, status: str = "done") -> dict | None:
        rows = self._all(
            "SELECT * FROM batches WHERE status=? ORDER BY created_at DESC, rowid DESC LIMIT 1",
            (status,))
        if not rows:
            rows = self._all("SELECT * FROM batches ORDER BY created_at DESC, rowid DESC LIMIT 1",
                             ())
        return rows[0] if rows else None

    def list_batches(self, limit: int = 30) -> list[dict]:
        return self._all(
            "SELECT * FROM batches ORDER BY created_at DESC, rowid DESC LIMIT ?", (limit,))

    def watermark_high(self) -> str | None:
        rows = self._all(
            "SELECT watermark_utc FROM batches WHERE status='done' "
            "AND watermark_utc IS NOT NULL ORDER BY watermark_utc DESC LIMIT 1", ())
        return rows[0]["watermark_utc"] if rows else None

    # ---------- 一次运行落库（单事务替换） ----------
    def save_run(self, *, batch: dict, inputs: list[dict], events: list[dict],
                 snapshots: list[dict], watermarks: list[dict], stages: list[dict],
                 totals: dict, manifest: dict) -> None:
        with self.connect() as conn:
            # 最后一道防线：已擦除批次绝不能用原始数据覆盖（否则原值会回来）
            existing = conn.execute(
                "SELECT redaction_version FROM batches WHERE batch_id=?",
                (batch["batch_id"],)).fetchone()
            if existing is not None and int(existing["redaction_version"] or 0) > 0:
                raise RuntimeError(
                    f"批次 {batch['batch_id']} 已擦除（v{existing['redaction_version']}），"
                    "拒绝用原始数据覆盖")
            for table in ("inputs", "events", "snapshots", "watermarks", "stages", "totals"):
                conn.execute(f"DELETE FROM {table} WHERE batch_id=?", (batch["batch_id"],))
            for i, item in enumerate(inputs, 1):
                conn.execute(
                    """INSERT INTO inputs (batch_id,seq,name,bytes,sha256,declared_rows,
                        encoding,declared,kind,status,code,note,lines)
                       VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                    (batch["batch_id"], i, item["name"], item["bytes"], item["sha256"],
                     item.get("declared_rows"), item.get("encoding"),
                     item.get("declared"), item.get("kind"), item["status"],
                     item.get("code"), item.get("note", ""), item.get("lines", 0)))
            for row in events:
                conn.execute(
                    """INSERT INTO events (batch_id,row_ref,seq,table_name,pk,version,op,
                        event_time_utc,event_time_raw,schema_version,payload_json,amount,qty,
                        row_class,reason_code,field,raw_value,detail,late,flags_json,raw_text,
                        columns_json,redaction_version)
                       VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                    (batch["batch_id"], row["row_ref"], row["seq"], row["table"], row["pk"],
                     row.get("version"), row.get("op"), row.get("event_time"),
                     row.get("event_time_raw"), row.get("schema"),
                     json.dumps(row.get("payload", {}), ensure_ascii=False,
                                default=str),
                     None if row.get("amount") is None else str(row["amount"]),
                     row.get("qty"), row["row_class"], row.get("reason_code"),
                     row.get("field"), row.get("raw_value"), row.get("detail"),
                     1 if row.get("late") else 0,
                     json.dumps(row.get("flags", []), ensure_ascii=False),
                     row.get("raw_text", ""),
                     json.dumps(row.get("columns", []), ensure_ascii=False),
                     int(row.get("redaction_version", 0))))
            for s in snapshots:
                conn.execute(
                    """INSERT INTO snapshots (batch_id,table_name,pk,version,op,amount,qty,
                        event_time_utc,row_ref,late,pending,payload_json,redaction_version)
                       VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                    (batch["batch_id"], s["table"], s["pk"], s["version"], s["op"],
                     None if s.get("amount") is None else str(s["amount"]), s.get("qty"),
                     s["event_time"], s["row_ref"], 1 if s.get("late") else 0,
                     1 if s.get("pending") else 0,
                     json.dumps(s.get("payload", {}), ensure_ascii=False, default=str),
                     int(s.get("redaction_version", 0))))
            for w in watermarks:
                conn.execute(
                    """INSERT INTO watermarks (batch_id,seq,row_ref,event_time_utc,
                        watermark_utc,late,behind_seconds) VALUES (?,?,?,?,?,?,?)""",
                    (batch["batch_id"], w["seq"], w["row_ref"], w["event_time"],
                     w["watermark"], 1 if w.get("late") else 0, w.get("behind_seconds", 0)))
            for s in stages:
                conn.execute(
                    """INSERT INTO stages (batch_id,stage,in_count,out_count,
                        quarantine_count,status,elapsed_ms,note) VALUES (?,?,?,?,?,?,?,?)""",
                    (batch["batch_id"], s["stage"], s["in_count"], s["out_count"],
                     s["quarantine_count"], s["status"], s["elapsed_ms"], s.get("note", "")))
            for key, value in totals.items():
                conn.execute("INSERT INTO totals (batch_id,key,value) VALUES (?,?,?)",
                             (batch["batch_id"], key, str(value)))
            conn.execute(
                "INSERT INTO manifests (batch_id,json) VALUES (?,?) "
                "ON CONFLICT(batch_id) DO UPDATE SET json=excluded.json",
                (batch["batch_id"], json.dumps(manifest, ensure_ascii=False, default=str)))
            conn.execute(
                """INSERT INTO batches (batch_id,batch_key,run_id,source,status,created_at,
                        finished_at,input_digest,watermark_utc,max_event_time,params_json,
                        note,replay_of,redaction_version,redaction_id)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                   ON CONFLICT(batch_id) DO UPDATE SET
                     status=excluded.status, finished_at=excluded.finished_at,
                     note=excluded.note, input_digest=excluded.input_digest,
                     watermark_utc=excluded.watermark_utc,
                     max_event_time=excluded.max_event_time,
                     redaction_version=MAX(batches.redaction_version,
                                           excluded.redaction_version)""",
                (batch["batch_id"], batch["batch_key"], batch["run_id"], batch["source"],
                 batch["status"], batch["created_at"], batch.get("finished_at"),
                 batch["input_digest"], batch.get("watermark_utc"),
                 batch.get("max_event_time"),
                 json.dumps(batch.get("params", {}), ensure_ascii=False),
                 batch.get("note", ""), batch.get("replay_of"),
                 int(batch.get("redaction_version", 0)), batch.get("redaction_id")))


    # ---------- 快照（可重复物化） ----------
    def replace_snapshot(self, batch_id: str, rows: list[dict], totals: dict,
                         redaction_version: int = 0) -> None:
        """按同一 as_of 重算快照：先删后插，不新增事件行。

        已擦除批次重算时沿用批次当前的擦除版本，新行直接标记为已擦除。
        """
        with self.connect() as conn:
            conn.execute("DELETE FROM snapshots WHERE batch_id=?", (batch_id,))
            for s in rows:
                conn.execute(
                    """INSERT INTO snapshots (batch_id,table_name,pk,version,op,amount,qty,
                        event_time_utc,row_ref,late,pending,payload_json,redaction_version)
                       VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                    (batch_id, s["table"], s["pk"], s["version"], s["op"],
                     None if s.get("amount") is None else str(s["amount"]), s.get("qty"),
                     s["event_time"], s["row_ref"], 1 if s.get("late") else 0,
                     1 if s.get("pending") else 0,
                     json.dumps(s.get("payload", {}), ensure_ascii=False, default=str),
                     int(s.get("redaction_version", redaction_version))))
            for key, value in totals.items():
                conn.execute("DELETE FROM totals WHERE batch_id=? AND key=?",
                             (batch_id, key))
                conn.execute("INSERT INTO totals (batch_id,key,value) VALUES (?,?,?)",
                             (batch_id, key, str(value)))

    def save_attempt(self, *, batch: dict, inputs: list[dict], note: str = "") -> None:
        """失败尝试：只写批次与输入，不动任何已存在批次的结果行。"""
        with self.connect() as conn:
            conn.execute(
                """INSERT INTO batches (batch_id,batch_key,run_id,source,status,created_at,
                        finished_at,input_digest,watermark_utc,max_event_time,params_json,
                        note,replay_of)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)
                   ON CONFLICT(batch_id) DO UPDATE SET
                     status=excluded.status, finished_at=excluded.finished_at,
                     note=excluded.note""",
                (batch["batch_id"], batch["batch_key"], batch["run_id"], batch["source"],
                 batch["status"], batch["created_at"], batch.get("finished_at"),
                 batch["input_digest"], batch.get("watermark_utc"),
                 batch.get("max_event_time"),
                 json.dumps(batch.get("params", {}), ensure_ascii=False),
                 note or batch.get("note", ""), batch.get("replay_of")))
            conn.execute("DELETE FROM inputs WHERE batch_id=?", (batch["batch_id"],))
            for i, item in enumerate(inputs, 1):
                conn.execute(
                    """INSERT INTO inputs (batch_id,seq,name,bytes,sha256,declared_rows,
                        encoding,declared,kind,status,code,note,lines)
                       VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                    (batch["batch_id"], i, item["name"], item["bytes"], item["sha256"],
                     item.get("declared_rows"), item.get("encoding"),
                     item.get("declared"), item.get("kind"), item["status"],
                     item.get("code"), item.get("note", ""), item.get("lines", 0)))

    # ---------- 擦除作业 ----------
    def insert_redaction(self, record: dict) -> None:
        with self.connect() as conn:
            conn.execute(
                """INSERT INTO redactions (redaction_id,batch_id,requested_at,started_at,
                        finished_at,status,stage,policy_version,key_id,request_digest,
                        replay_of,version,stats_json,detail)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (record["redaction_id"], record["batch_id"], record["requested_at"],
                 record.get("started_at"), record.get("finished_at"),
                 record["status"], record.get("stage", "prepare"),
                 record["policy_version"], record["key_id"], record["request_digest"],
                 record.get("replay_of"), int(record.get("version", 0)),
                 json.dumps(record.get("stats", {}), ensure_ascii=False),
                 record.get("detail", "")))

    def update_redaction(self, redaction_id: str, **fields) -> None:
        allowed = ("started_at", "finished_at", "status", "stage", "version",
                   "detail", "replay_of")
        sets, args = [], []
        for name in allowed:
            if name in fields:
                sets.append(f"{name}=?")
                args.append(fields[name])
        if "stats" in fields:
            sets.append("stats_json=?")
            args.append(json.dumps(fields["stats"], ensure_ascii=False))
        if not sets:
            return
        args.append(redaction_id)
        with self.connect() as conn:
            conn.execute(f"UPDATE redactions SET {', '.join(sets)} "
                         "WHERE redaction_id=?", tuple(args))

    def get_redaction(self, redaction_id: str) -> dict | None:
        rows = self._all("SELECT * FROM redactions WHERE redaction_id=?",
                         (redaction_id,))
        return self._redaction_row(rows[0]) if rows else None

    def list_redactions(self, batch_id: str | None = None,
                        limit: int = 50) -> list[dict]:
        if batch_id:
            rows = self._all(
                "SELECT * FROM redactions WHERE batch_id=? "
                "ORDER BY requested_at DESC, rowid DESC LIMIT ?", (batch_id, limit))
        else:
            rows = self._all(
                "SELECT * FROM redactions ORDER BY requested_at DESC, rowid DESC LIMIT ?",
                (limit,))
        return [self._redaction_row(row) for row in rows]

    def find_redaction(self, batch_id: str, request_digest: str,
                       status: str | None = None) -> dict | None:
        if status:
            rows = self._all(
                "SELECT * FROM redactions WHERE batch_id=? AND request_digest=? "
                "AND status=? ORDER BY requested_at LIMIT 1",
                (batch_id, request_digest, status))
        else:
            rows = self._all(
                "SELECT * FROM redactions WHERE batch_id=? AND request_digest=? "
                "ORDER BY requested_at LIMIT 1", (batch_id, request_digest))
        return self._redaction_row(rows[0]) if rows else None

    @staticmethod
    def _redaction_row(row: dict) -> dict:
        row["stats"] = json.loads(row.pop("stats_json") or "{}")
        return row

    def replace_stage(self, redaction_id: str, rows: list[dict]) -> None:
        """写入暂存区；只动该擦除作业自己的行，不碰线上结果。

        暂存区只保存擦除后的内容与带密钥的指纹/行键，不保存原始敏感值。
        """
        with self.connect() as conn:
            conn.execute("DELETE FROM redaction_stages WHERE redaction_id=?",
                         (redaction_id,))
            for row in rows:
                conn.execute(
                    """INSERT INTO redaction_stages (redaction_id,kind,row_key,batch_id,
                        table_name,seq,new_pk,payload_json,raw_value,detail,
                        raw_text,row_ref,changed,cells,tokens_json,source_hash)
                       VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                    (redaction_id, row["kind"], row["row_key"], row["batch_id"],
                     row.get("table_name", ""), row.get("seq"),
                     row.get("new_pk"),
                     None if row.get("payload") is None
                     else json.dumps(row["payload"], ensure_ascii=False, default=str),
                     row.get("raw_value"), row.get("detail"), row.get("raw_text"),
                     row.get("row_ref", ""), 1 if row.get("changed") else 0,
                     int(row.get("cells", 0)),
                     json.dumps(row.get("tokens", []), ensure_ascii=False),
                     row.get("source_hash", "")))

    def load_stage(self, redaction_id: str) -> list[dict]:
        rows = self._all(
            "SELECT * FROM redaction_stages WHERE redaction_id=? ORDER BY kind, seq",
            (redaction_id,))
        for row in rows:
            raw = row.pop("payload_json")
            row["payload"] = None if raw is None else json.loads(raw)
            row["tokens"] = json.loads(row.pop("tokens_json") or "[]")
            row["changed"] = bool(row["changed"])
        return rows

    def count_stage(self, redaction_id: str) -> dict:
        rows = self._all(
            "SELECT kind, COUNT(*) AS n, SUM(changed) AS changed FROM redaction_stages "
            "WHERE redaction_id=? GROUP BY kind", (redaction_id,))
        return {row["kind"]: {"rows": row["n"], "changed": row["changed"] or 0}
                for row in rows}

    def apply_redaction(self, *, redaction_id: str, batch_id: str, version: int,
                        manifest: dict, totals: dict, marks: list[dict],
                        stats: dict, finished_at: str, policy_version: str,
                        key_id: str) -> None:
        """单事务落库：证据行、快照、清单、合计、批次版本、标记一起提交。

        任一步失败整个事务回滚，调用方看到的仍是上一次成功的结果。
        """
        staged = self.load_stage(redaction_id)
        with self.connect() as conn:
            for row in staged:
                if row["kind"] == "event":
                    if row["changed"]:
                        conn.execute(
                            """UPDATE events SET pk=?, payload_json=?, raw_value=?,
                                   detail=?, raw_text=?, redaction_version=?
                               WHERE batch_id=? AND row_ref=?""",
                            (row["new_pk"],
                             json.dumps(row["payload"], ensure_ascii=False, default=str),
                             row["raw_value"], row["detail"], row["raw_text"],
                             version, batch_id, row["row_key"]))
                    else:
                        # 未命中敏感值也要标记「已覆盖本次擦除」，否则无法与漏擦区分
                        conn.execute(
                            "UPDATE events SET redaction_version=? "
                            "WHERE batch_id=? AND row_ref=?",
                            (version, batch_id, row["row_key"]))
                elif row["kind"] == "snapshot":
                    if row["changed"]:
                        conn.execute(
                            """UPDATE snapshots SET pk=?, payload_json=?,
                                   redaction_version=?
                               WHERE batch_id=? AND row_ref=? AND version=?""",
                            (row["new_pk"],
                             json.dumps(row["payload"], ensure_ascii=False, default=str),
                             version, batch_id, row["row_ref"], row["seq"]))
                    else:
                        conn.execute(
                            "UPDATE snapshots SET redaction_version=? "
                            "WHERE batch_id=? AND row_ref=? AND version=?",
                            (version, batch_id, row["row_ref"], row["seq"]))
            conn.execute(
                "INSERT INTO manifests (batch_id,json) VALUES (?,?) "
                "ON CONFLICT(batch_id) DO UPDATE SET json=excluded.json",
                (batch_id, json.dumps(manifest, ensure_ascii=False, default=str)))
            for key, value in totals.items():
                conn.execute("DELETE FROM totals WHERE batch_id=? AND key=?",
                             (batch_id, key))
                conn.execute("INSERT INTO totals (batch_id,key,value) VALUES (?,?,?)",
                             (batch_id, key, str(value)))
            conn.execute(
                "UPDATE batches SET redaction_version=?, redaction_id=? WHERE batch_id=?",
                (version, redaction_id, batch_id))
            conn.execute("DELETE FROM redaction_marks WHERE redaction_id=?",
                         (redaction_id,))
            for item in marks:
                conn.execute(
                    """INSERT INTO redaction_marks (redaction_id,batch_id,table_name,
                        token,row_ref,seq) VALUES (?,?,?,?,?,?)""",
                    (redaction_id, batch_id, item["table_name"], item["token"],
                     item.get("row_ref", ""), int(item.get("seq") or 0)))
            conn.execute(
                """UPDATE redactions SET status='done', stage='done', finished_at=?,
                        version=?, stats_json=?, policy_version=?, key_id=?
                   WHERE redaction_id=?""",
                (finished_at, version,
                 json.dumps(stats, ensure_ascii=False), policy_version, key_id,
                 redaction_id))
            # 覆盖自检：仍在旧版本的行必须为 0，否则整体回滚（不丢行、不留半批）
            for table in ("events", "snapshots"):
                left = conn.execute(
                    f"SELECT COUNT(*) AS n FROM {table} "
                    f"WHERE batch_id=? AND redaction_version < ?",
                    (batch_id, version)).fetchone()
                if left and left["n"]:
                    raise RuntimeError(
                        f"{table} 仍有 {left['n']} 行未被本次擦除覆盖")

    def load_redaction_marks(self, batch_id: str) -> list[dict]:
        return self._all(
            "SELECT * FROM redaction_marks WHERE batch_id=? ORDER BY seq",
            (batch_id,))

    def uncovered_rows(self, batch_id: str, version: int) -> dict:
        """本次擦除覆盖后仍未打标的行（应为 0）：审计用。"""
        out = {}
        for table in ("events", "snapshots"):
            rows = self._all(
                f"SELECT COUNT(*) AS n FROM {table} "
                f"WHERE batch_id=? AND redaction_version < ?", (batch_id, version))
            out[table] = rows[0]["n"] if rows else 0
        return out

    # ---------- 读取 ----------
    def load_inputs(self, batch_id: str) -> list[dict]:
        return self._all("SELECT * FROM inputs WHERE batch_id=? ORDER BY seq", (batch_id,))

    def load_events(self, batch_id: str, row_class: str | None = None) -> list[dict]:
        if row_class:
            rows = self._all(
                "SELECT * FROM events WHERE batch_id=? AND row_class=? ORDER BY seq",
                (batch_id, row_class))
        else:
            rows = self._all("SELECT * FROM events WHERE batch_id=? ORDER BY seq", (batch_id,))
        for r in rows:
            r["payload"] = json.loads(r.pop("payload_json") or "{}")
            r["flags"] = json.loads(r.pop("flags_json") or "[]")
            r["columns"] = json.loads(r.pop("columns_json", "[]") or "[]")
            r["amount"] = None if r["amount"] is None else Decimal(r["amount"])
            r["late"] = bool(r["late"])
        return rows

    def load_snapshot(self, batch_id: str) -> list[dict]:
        rows = self._all(
            "SELECT * FROM snapshots WHERE batch_id=? ORDER BY table_name, pk", (batch_id,))
        for r in rows:
            r["payload"] = json.loads(r.pop("payload_json") or "{}")
            r["amount"] = None if r["amount"] is None else Decimal(r["amount"])
            r["late"] = bool(r["late"])
            r["pending"] = bool(r["pending"])
        return rows

    def load_watermarks(self, batch_id: str) -> list[dict]:
        return self._all(
            "SELECT * FROM watermarks WHERE batch_id=? ORDER BY seq", (batch_id,))

    def load_stages(self, batch_id: str) -> list[dict]:
        from . import config
        rows = self._all("SELECT * FROM stages WHERE batch_id=? ORDER BY rowid", (batch_id,))
        for row in rows:
            row["label"] = config.STAGE_LABELS.get(row["stage"], row["stage"])
        return rows

    def load_totals(self, batch_id: str) -> dict:
        rows = self._all("SELECT key, value FROM totals WHERE batch_id=?", (batch_id,))
        return {r["key"]: r["value"] for r in rows}

    def load_manifest(self, batch_id: str) -> dict | None:
        rows = self._all("SELECT json FROM manifests WHERE batch_id=?", (batch_id,))
        return json.loads(rows[0]["json"]) if rows else None

    def count_rows(self, batch_id: str) -> dict:
        out = {}
        for table in ("inputs", "events", "snapshots", "watermarks", "stages"):
            out[table] = self._all(
                f"SELECT COUNT(*) AS n FROM {table} WHERE batch_id=?", (batch_id,))[0]["n"]
        return out

    def _all(self, sql: str, args: tuple) -> list[dict]:
        with self.connect() as conn:
            return [dict(r) for r in conn.execute(sql, args).fetchall()]
