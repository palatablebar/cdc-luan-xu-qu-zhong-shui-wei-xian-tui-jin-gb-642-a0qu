# 运行手册 cdcwater

## 1 启动与自检

```bash
docker compose config --quiet
docker compose up -d --build
curl -s http://127.0.0.1:18201/api/health
curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:18201/
docker compose exec -T app python -m pytest -q
```

首次启动会用 `sample_data/` 的三个文件跑一次采信（`app/bootstrap.py`），页面直接有数据；
重复启动命中批次键，走幂等重放。

## 2 主流程（页面）

1. `/` 水位时间轴 → 选来源 → 点「采信」；
2. `/events` 按分类筛选，确认每行的行号引用与原因码；
3. `/conflicts` 看冲突分组与隔离区，导出隔离 CSV；
4. `/snapshot` 点「物化」，核对三条对账；
5. `/batches` 看 `run_id`、输入 sha256 与阶段耗时，导出运行清单。

## 3 主流程（命令）

```bash
BASE=http://127.0.0.1:18201
curl -s -X POST $BASE/api/events/import -H 'content-type: application/json' -d '{"source":"all"}' | head -c 600
curl -s "$BASE/api/conflicts" | python3 -c 'import json,sys; d=json.load(sys.stdin); print(d["counters"])'
curl -s "$BASE/api/watermark"  | python3 -c 'import json,sys; d=json.load(sys.stdin); print(d["watermark"])'
curl -s -X POST $BASE/api/snapshot | python3 -c 'import json,sys; d=json.load(sys.stdin); print(d["rows"], d["amounts"])'
curl -s -o /tmp/events.csv      "$BASE/api/export/events.csv"
curl -s -o /tmp/quarantine.csv  "$BASE/api/export/quarantine.csv"
curl -s -o /tmp/conflicts.csv   "$BASE/api/export/conflicts.csv"
curl -s -o /tmp/snapshot.csv    "$BASE/api/export/snapshot.csv"
curl -s -o /tmp/manifest.json   "$BASE/api/export/manifest.json"
```

判定看数字：行账 42 = 27 + 2 + 3 + 10；键账 19 = 18 + 1；金额 1552.51 + 200.00 + 0.00 = 1752.51。

## 4 失败处置

| 现象 | 原因码 | 处置 |
|---|---|---|
| 采信后页面无数据 | — | 看 `/events` 的「输入文件」表，文件状态 `failed` 说明编码链全失败 |
| 隔离区大量同名行 | `E_COLUMN_COUNT` / `E_BAD_JSON` | 导出端截断或多分隔符，重新导出 |
| 冲突表出现同键同版本 | `C_VERSION_CONFLICT` | 两条都不应用，回源确认版本号 |
| 导入报 409 | `C_STALE_BATCH` | 拿到的是旧导出，重新导出后再跑 |
| 快照键比预期少 | `W_PENDING_WINDOW` | 事件落在水位之后，等下一轮水位推过 |
| 水位不前进 | `W_WATERMARK_REGRESS` | 检查导出端时钟与文件版本 |

## 5 重建数据库

```bash
docker compose down -v          # 删掉命名卷 cdcwater-data
docker compose up -d --build    # 重新初始化并跑一次首次采信
```

本地直接跑（不用 Docker）：

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
CDCWATER_DB=./var/cdcwater.sqlite CDCWATER_SAMPLE_DIR=./sample_data \
  uvicorn app.main:create_app --factory --port 18201
python -m pytest -q
```

## 6 导出复核

- `events.csv`：42 行，含 `行号引用`、`原因码`、`分类`、`迟到`；
- `quarantine.csv`：10 行，含 `字段`、`原值`、`原始文本`；
- `conflicts.csv`：3 行，含两条证据行引用；
- `snapshot.csv` / `snapshot.json`：18 键，活跃 16、墓碑 2；
- `manifest.json`：`run_id`、每个输入的 sha256、阶段耗时、四账。

## 7 敏感值擦除

```bash
BASE=http://127.0.0.1:18201
curl -s -X POST $BASE/api/redactions -H 'content-type: application/json' -d '{}' \
  | python3 -c 'import json,sys; d=json.load(sys.stdin); print(d["version"], d["stats"])'
curl -s $BASE/api/redactions | python3 -c 'import json,sys; d=json.load(sys.stdin); print(d["current_version"], len(d["redactions"]))'
```

判定看数字：

- `stats.cells` = 本次替换的敏感单元格数，`stats.values` = 去重后的标记数；
- `idempotent_replay=true` 表示同一擦除重跑，版本号与统计都不变；
- 擦除后 `events.csv` / `quarantine.csv` / `snapshot.csv` / `manifest.json` 均无原值，
  但行数、`金额`、四账与擦除前逐项相同。

失败处置：

| 现象 | 原因码 | 处置 |
|---|---|---|
| 擦除返回 409 | `R_REDACT_COMMIT_FAILED` | 落库失败，旧版仍在；查磁盘/权限后重跑同一请求或点「续跑」 |
| 擦除记录 `失败 / failed` | — | 暂存校验未通过；看 `problems`，修复后重跑 |
| 页面仍有原值 | — | 检查该值是否有敏感列名或强模式；孤立姓名需导出端补列名 |
| 两次擦除产生两个版本 | — | 策略版本或密钥变了；属预期，旧标记仍可关联 |

密钥：默认在数据目录生成 `redaction.key`（0600），可用
`CDCWATER_REDACTION_KEY`（64 位十六进制）或 `CDCWATER_REDACTION_KEY_FILE`
指定。换密钥后同一原值会得到不同标记，跨版本关联会断，按需保留旧密钥。
