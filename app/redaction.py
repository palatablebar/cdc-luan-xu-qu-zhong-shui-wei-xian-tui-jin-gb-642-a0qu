"""脱敏策略：识别姓名、手机号、地址，替换成不可还原但稳定的标记。

取舍（见 docs/DATA-DICTIONARY.md 第 10 节）：

- 不整笔删除证据行。行号引用、表、主键、版本、操作、时刻、金额、数量、分类、
  原因码、对账关系全部保留，所以受影响订单、金额与四账仍然可复核；
- 只把敏感原值替换成「按值派生的稳定标记」：`[REDACTED:<16 hex>]`。同一个值在
  事件原文、隔离证据、去重明细与快照里得到同一个标记，因此重复仍能认出重复、
  冲突两边的差异仍能对齐，跨表/跨批次的关联不丢；
- 标记是 HMAC-SHA256（密钥不在数据里）截断，没有密钥无法反推原值；
- 标记可重复识别：已经擦过的值再擦一次不会变、也不会重复计数。

检测分三层：

1. 结构化键名：`name/full_name/customer_name`、`phone/mobile/tel`、
   `address/addr` 以及对应中文键；
2. 强模式：中国大陆手机号、带区号座机、18 位身份证号（作为主键时同样擦除）；
3. 弱模式：整串地址（至少两个地址标记且含数字）、自由文本中内嵌的强模式、
   `key=value` 形式的带标签值。

局限：没有键名、没有强模式、也不像地址的孤立中文姓名无法可靠识别；这类需要
在导出端补列名或提供敏感值清单，不在这里猜。
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import secrets
import unicodedata
from dataclasses import dataclass, field
from pathlib import Path

POLICY_VERSION = "pii-redaction/1.0"
TOKEN_PREFIX = "[REDACTED:"
TOKEN_HEX_LEN = 16
TOKEN_RE = re.compile(r"\[REDACTED:[0-9a-f]{%d}\]" % TOKEN_HEX_LEN)

_PHONE_FULL = re.compile(r"^(?:\+?86[-\s]?)?1[3-9]\d{9}$")
_PHONE_IN_TEXT = re.compile(r"(?<!\d)(?:\+?86[-\s]?)?1[3-9]\d{9}(?!\d)")
_LANDLINE_FULL = re.compile(r"^0\d{2,3}[-\s]?\d{7,8}$")
_LANDLINE_IN_TEXT = re.compile(r"(?<!\d)0\d{2,3}[-\s]?\d{7,8}(?!\d)")
_ID_FULL = re.compile(r"^\d{17}[0-9Xx]$")
_ID_IN_TEXT = re.compile(r"(?<![0-9A-Za-z])\d{17}[0-9Xx](?![0-9A-Za-z])")

# 结构化键名：比较前统一小写并去掉分隔符
_SENSITIVE_KEYS = {
    "name", "fullname", "customername", "realname", "contactname", "recipient",
    "phone", "mobile", "tel", "telephone", "contactphone", "phonenumber",
    "address", "addr", "contactaddress", "shippingaddress", "deliveryaddress",
    "客户姓名", "姓名", "真实姓名", "联系人", "收货人", "手机", "手机号",
    "电话", "联系电话", "联系方式", "地址", "收货地址", "详细地址", "住址",
}

_ADDRESS_MARKERS = ("省", "市", "区", "县", "镇", "乡", "街道", "路", "街",
                    "巷", "弄", "号", "栋", "单元", "室", "楼", "院")
_ADDRESS_HOUSE = ("号", "栋", "单元", "室", "楼", "院")
# 出现这些说明是叙述性文本（备注/说明），不能整段当成地址
_PROSE = re.compile(r"联系|备注|说明|请|已|待|取消|核对|发货|支付|新建|"
                    r"[；;]|。")

# 自由文本里的 key=value / key: value（只在无法按 JSON/CSV 解析时使用）
_LABELED = re.compile(
    r"(?i)(name|full_name|customer_name|real_name|phone|mobile|tel|telephone|"
    r"address|addr|客户姓名|姓名|联系人|收货人|手机号|手机|联系电话|电话|"
    r"收货地址|详细地址|地址)\s*[:=：]\s*"
    r"(\"[^\"]*\"|'[^']*'|[^,;&\s]+)"
)

_STRUCTURAL_EVENT = ("row_ref", "table_name", "version", "op", "event_time_utc",
                     "row_class", "amount", "qty", "reason_code")
_STRUCTURAL_SNAPSHOT = ("table_name", "version", "op", "amount", "qty",
                        "event_time_utc", "row_ref", "late", "pending")


# ---------------------------------------------------------------- 密钥

def key_bytes(value: str | bytes | None) -> bytes | None:
    """把配置里的密钥文本转成字节；64 位十六进制按原样解释，否则做一次摘要。"""
    if value is None:
        return None
    if isinstance(value, bytes):
        return value
    text = str(value).strip()
    if not text:
        return None
    if re.fullmatch(r"[0-9a-fA-F]{64}", text):
        return bytes.fromhex(text)
    return hashlib.sha256(text.encode("utf-8")).digest()


def load_or_create_key(path: Path) -> bytes:
    """读取本机擦除密钥；首次使用时生成并落盘（0600）。密钥从不进数据行。"""
    path = Path(path)
    try:
        text = path.read_text(encoding="ascii").strip()
        if text:
            return bytes.fromhex(text)
    except (FileNotFoundError, ValueError):
        pass
    path.parent.mkdir(parents=True, exist_ok=True)
    key = secrets.token_bytes(32)
    try:
        fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        # 并发首次启动：谁先写谁赢，后到者读现成密钥
        return bytes.fromhex(path.read_text(encoding="ascii").strip())
    with os.fdopen(fd, "w", encoding="ascii") as handle:
        handle.write(key.hex())
    return key


def resolve_key(explicit: str | bytes | None, path: Path) -> bytes:
    return key_bytes(explicit) or load_or_create_key(path)


def key_id(key: bytes) -> str:
    """密钥指纹：只用于说明两次擦除是否同一把钥匙，不能反推密钥。"""
    return hashlib.sha256(key).hexdigest()[:8]


# ---------------------------------------------------------------- 归一与标记

def normalize_key(name) -> str:
    return re.sub(r"[\s_\-]+", "", str(name or "")).lower()


def is_sensitive_key(name) -> bool:
    return normalize_key(name) in _SENSITIVE_KEYS


def normalize_value(value) -> str:
    """把同一个值的不同写法归到同一字符串，保证标记稳定。

    - NFKC：全角/半角等价；
    - 手机号去掉 +86、空格、连字符、括号；
    - 姓名/地址折叠空白、大小写不敏感。
    """
    text = unicodedata.normalize("NFKC", str(value)).strip()
    text = re.sub(r"\s+", " ", text)
    digits = re.sub(r"[\s\-()+]", "", text)
    if re.fullmatch(r"(?:86)?1[3-9]\d{9}", digits):
        return "phone:" + (digits[2:] if len(digits) == 13 else digits)
    if re.fullmatch(r"0\d{9,11}", digits):
        return "tel:" + digits
    if _ID_FULL.match(text):
        return "id:" + text.upper()
    return "text:" + text.casefold()


def token_for(value, key: bytes) -> str:
    digest = hmac.new(key, normalize_value(value).encode("utf-8"),
                      hashlib.sha256).hexdigest()[:TOKEN_HEX_LEN]
    return f"{TOKEN_PREFIX}{digest}]"


def is_token(text) -> bool:
    return isinstance(text, str) and TOKEN_RE.fullmatch(text.strip()) is not None


def strong_pii(value) -> bool:
    """整串就是手机号/座机/身份证号。主键只在强模式命中时替换。"""
    if value is None:
        return False
    text = str(value).strip()
    return bool(_PHONE_FULL.match(text) or _LANDLINE_FULL.match(text)
                or _ID_FULL.match(text))


def looks_address(text) -> bool:
    """整串像一个地址：含门牌类标记、行政区划、数字，且不是叙述性备注。"""
    if not isinstance(text, str):
        return False
    body = text.strip()
    if len(body) < 6 or len(body) > 120:
        return False
    if body.lower().startswith(("http://", "https://")) or _PROSE.search(body):
        return False
    markers = sum(1 for marker in _ADDRESS_MARKERS if marker in body)
    house = sum(1 for marker in _ADDRESS_HOUSE if marker in body)
    return markers >= 2 and house >= 1 and bool(re.search(r"\d", body))


# ---------------------------------------------------------------- 文本/对象擦除

@dataclass
class Stats:
    cells: int = 0
    keys: int = 0
    values: set[str] = field(default_factory=set)

    def merge(self, other: "Stats") -> None:
        self.cells += other.cells
        self.keys += other.keys
        self.values.update(other.values)

    def as_dict(self) -> dict:
        return {"cells": self.cells, "keys": self.keys,
                "values": len(self.values)}


def _replace_plain(segment: str, key: bytes, stats: Stats, *,
                   whole_address: bool = True) -> str:
    """处理一段不含既有标记的文本。

    `whole_address` 只对「单个字段值」打开：整串像一个地址才整体替换；
    对 CSV 原始行 / 明细句这类复合文本必须关掉，否则一行证据会被并成一个标记。
    """
    if not segment:
        return segment
    stripped = segment.strip()
    if stripped and (strong_pii(stripped)
                     or (whole_address and looks_address(stripped))):
        token = token_for(stripped, key)
        stats.cells += 1
        stats.values.add(token)
        # 保留段首尾空白，便于拼接后仍然可读
        left = segment[: len(segment) - len(segment.lstrip())]
        right = segment[len(segment.rstrip()):]
        return f"{left}{token}{right}"

    def swap(match: re.Match) -> str:
        token = token_for(match.group(0), key)
        stats.cells += 1
        stats.values.add(token)
        return token

    text = _PHONE_IN_TEXT.sub(swap, segment)
    text = _LANDLINE_IN_TEXT.sub(swap, text)
    text = _ID_IN_TEXT.sub(swap, text)

    def labeled(match: re.Match) -> str:
        raw = match.group(2)
        quote = raw[0] if raw[:1] in ("'", '"') else ""
        value = raw[1:-1] if quote and raw[-1:] == quote else raw
        token = token_for(value, key)
        stats.cells += 1
        stats.values.add(token)
        return f"{match.group(1)}={token}"

    return _LABELED.sub(labeled, text)


def redact_string(text, key: bytes, *, whole_address: bool = True
                  ) -> tuple[object, Stats]:
    """擦除自由文本中的敏感值；已是标记的片段原样保留（幂等）。"""
    stats = Stats()
    if not isinstance(text, str) or not text:
        return text, stats
    if is_token(text):
        return text, stats
    pieces: list[str] = []
    cursor = 0
    for match in TOKEN_RE.finditer(text):
        pieces.append(_replace_plain(text[cursor:match.start()], key, stats,
                                     whole_address=whole_address))
        pieces.append(match.group(0))
        cursor = match.end()
    pieces.append(_replace_plain(text[cursor:], key, stats,
                                 whole_address=whole_address))
    return "".join(pieces), stats


def redact_object(value, key: bytes) -> tuple[object, Stats]:
    """递归擦除 dict/list 中的敏感键与敏感值。已有的标记原样保留（幂等）。"""
    stats = Stats()
    if isinstance(value, dict):
        out = {}
        for name, item in value.items():
            if is_sensitive_key(name) and item not in (None, "", [], {}):
                if isinstance(item, str) and is_token(item):
                    out[name] = item
                    continue
                if isinstance(item, (dict, list)):
                    token = token_for(json.dumps(item, ensure_ascii=False,
                                                 sort_keys=True, default=str), key)
                else:
                    token = token_for(item, key)
                out[name] = token
                stats.cells += 1
                stats.values.add(token)
                continue
            out[name], child = redact_object(item, key)
            stats.merge(child)
        return out, stats
    if isinstance(value, list):
        out = []
        for item in value:
            new_item, child = redact_object(item, key)
            out.append(new_item)
            stats.merge(child)
        return out, stats
    if isinstance(value, str):
        new_text, child = redact_string(value, key)
        return new_text, child
    return value, stats


def redact_json_text(text, key: bytes) -> tuple[str, Stats]:
    """对 JSON/JSONL 单行优先按结构擦除；解析失败再按自由文本处理。"""
    if not isinstance(text, str) or not text:
        return text, Stats()
    stripped = text.strip()
    if stripped[:1] in ("{", "["):
        try:
            parsed = json.loads(stripped)
        except (ValueError, TypeError):
            parsed = None
        if parsed is not None:
            new_obj, stats = redact_object(parsed, key)
            if not stats.cells:
                return text, stats
            return json.dumps(new_obj, ensure_ascii=False, separators=(",", ":")), stats
    return redact_string(text, key, whole_address=False)


def redact_csv_row(cells: list[str], headers: list[str], key: bytes) -> tuple[str, Stats]:
    """CSV 行：有表头时按敏感列名擦整列，其余单元格按自由文本擦。"""
    stats = Stats()
    out: list[str] = []
    for index, cell in enumerate(cells):
        header = headers[index] if index < len(headers) else ""
        if header and is_sensitive_key(header) and str(cell).strip():
            token = token_for(cell, key)
            out.append(token)
            stats.cells += 1
            stats.values.add(token)
            continue
        new_cell, child = redact_string(cell, key, whole_address=False)
        out.append(new_cell)
        stats.merge(child)
    return ",".join(out), stats


# ---------------------------------------------------------------- 行级擦除

def redact_event_row(row: dict, key: bytes) -> tuple[dict, Stats]:
    """事件行：只改证据文本列与主键（仅强模式），结构列不动。"""
    out = dict(row)
    stats = Stats()
    pk = out.get("pk")
    if strong_pii(pk):
        token = token_for(pk, key)
        out["pk"] = token
        stats.keys += 1
        stats.cells += 1
        stats.values.add(token)

    payload = out.get("payload")
    if isinstance(payload, dict):
        new_payload, child = redact_object(payload, key)
        out["payload"] = new_payload
        stats.merge(child)

    for name in ("raw_value", "detail"):
        value = out.get(name)
        if isinstance(value, str) and value:
            new_text, child = redact_string(value, key)
            out[name] = new_text
            stats.merge(child)

    raw = out.get("raw_text")
    if isinstance(raw, str) and raw:
        columns = out.get("columns") or []
        if columns and "," in raw:
            new_raw, child = redact_csv_row(raw.split(","), list(columns), key)
        else:
            new_raw, child = redact_json_text(raw, key)
        out["raw_text"] = new_raw
        stats.merge(child)
    return out, stats


def redact_snapshot_row(row: dict, key: bytes) -> tuple[dict, Stats]:
    out = dict(row)
    stats = Stats()
    pk = out.get("pk")
    if strong_pii(pk):
        token = token_for(pk, key)
        out["pk"] = token
        stats.keys += 1
        stats.cells += 1
        stats.values.add(token)
    payload = out.get("payload")
    if isinstance(payload, dict):
        new_payload, child = redact_object(payload, key)
        out["payload"] = new_payload
        stats.merge(child)
    return out, stats


def verify_event(original: dict, redacted: dict) -> list[str]:
    """擦除只允许改证据文本与（强模式命中的）主键，结构列必须完全一致。"""
    problems = []
    for name in _STRUCTURAL_EVENT:
        if original.get(name) != redacted.get(name):
            problems.append(f"{name} 被改变")
    if original.get("pk") != redacted.get("pk") and not strong_pii(original.get("pk")):
        problems.append("pk 被改变但不是强模式敏感值")
    return problems


def verify_snapshot(original: dict, redacted: dict) -> list[str]:
    problems = []
    for name in _STRUCTURAL_SNAPSHOT:
        if original.get(name) != redacted.get(name):
            problems.append(f"{name} 被改变")
    if original.get("pk") != redacted.get("pk") and not strong_pii(original.get("pk")):
        problems.append("pk 被改变但不是强模式敏感值")
    return problems
