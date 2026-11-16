"""擦除计划：请求摘要、擦除版本与阶段顺序。

一个擦除请求由 `(batch_id, 策略版本, 密钥指纹)` 唯一确定：

- 同一请求重跑命中已完成的擦除 → 幂等重放，不重复计数；
- 同一请求中断/失败后重跑 → 复用同一条擦除记录、同一个版本号，从断点继续；
- 换策略版本或换密钥 → 新请求，版本号 +1，用于区分「哪一次擦除生效」。

阶段严格有序：prepare → staged → verified → committed。
"""
from __future__ import annotations

import hashlib
import json

from ... import config

STAGES = config.REDACT_STAGES
STAGE_LABELS = config.REDACT_STAGE_LABELS
STATUSES = ("running", "done", "failed")


def request_digest(batch_id: str, policy_version: str, key_fingerprint: str) -> str:
    body = json.dumps({"batch_id": batch_id, "policy_version": policy_version,
                       "key_id": key_fingerprint}, sort_keys=True,
                      ensure_ascii=False)
    return hashlib.sha256(body.encode("utf-8")).hexdigest()


def next_version(batch: dict) -> int:
    try:
        return int(batch.get("redaction_version") or 0) + 1
    except (TypeError, ValueError):
        return 1
