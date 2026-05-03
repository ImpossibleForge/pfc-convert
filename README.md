# pfc-convert

Convert legacy log and data formats to [PFC](https://github.com/ImpossibleForge/pfc-jsonl) — the high-performance cold storage format for JSONL data.

```
Apache CLF · nginx · CSV/TSV · NDJSON  →  JSONL  →  .pfc
gzip · zstd · bzip2 · lz4 · xz        →  auto-decompressed transparently
```

**Part of the [PFC Ecosystem](https://github.com/ImpossibleForge/pfc-jsonl).**  
For pure compression-format migration (gzip/zstd → .pfc, content unchanged) see [pfc-migrate](https://github.com/ImpossibleForge/pfc-migrate).

---

## What it does

pfc-convert is a schema converter: it reads old log/data formats line by line, rewrites them as structured JSONL with a proper timestamp field, and compresses the result as `.pfc` — including a block-level timestamp index for fast time-range queries.

| Input | What happens |
|---|---|
| `access.log.gz` (Apache CLF) | decompress → parse fields → JSONL → `.pfc` |
| `data.csv` | detect delimiter → header as keys → JSONL → `.pfc` |
| `events.jsonl.gz` | decompress → compress as `.pfc` |
| `s3://bucket/logs/` | in-region conversion, no data egress |

---

## Installation

```bash
pip install pfc-convert
```

Requires the `pfc_jsonl` binary on your system. Set `PFC_JSONL_BINARY=/path/to/pfc_jsonl` if it is not in `$PATH`.

Optional extras:

```bash
pip install "pfc-convert[s3]"    # S3 support
pip install "pfc-convert[all]"   # all cloud backends + compression formats
```

---

## Quick Start

```bash
# Single file — auto-detect schema and compression
pfc-convert convert access.log.gz

# Explicit schema
pfc-convert convert access.log.gz --schema apache --out archive.pfc

# CSV with specific timestamp column
pfc-convert convert events.csv --schema csv --timestamp-field event_time

# Output JSONL instead of .pfc (inspect before compressing)
pfc-convert convert access.log --schema apache --output-format jsonl

# Convert all logs in a directory
pfc-convert convert --dir /var/log/apache/ --schema apache --out-dir /archive/pfc/

# S3 in-region conversion
pfc-convert s3 --bucket my-logs --prefix apache/2024/ --schema apache
```

---

## Supported Input Formats

### Log formats (CLF family)

| Schema flag | Format | Auto-detected |
|---|---|---|
| `apache` | Apache Common / Combined Log Format | ✓ |
| `nginx` | nginx CLF (structurally identical to Apache) | ✓ |
| `nginx-json` | nginx JSON log mode (already JSONL) | ✓ |

Example Apache CLF line and its JSONL output:
```
192.168.1.1 - alice [29/Apr/2026:10:30:00 +0200] "GET /api HTTP/1.1" 200 4523 "https://ref.example.com" "curl/7.88"
```
```json
{"timestamp": "2026-04-29T10:30:00+02:00", "ip": "192.168.1.1", "user": "alice", "method": "GET", "path": "/api", "protocol": "HTTP/1.1", "status": 200, "bytes": 4523, "referer": "https://ref.example.com", "user_agent": "curl/7.88"}
```

### Tabular formats

| Schema flag | Format | Notes |
|---|---|---|
| `csv` | CSV / TSV | Header row → JSON keys, delimiter auto-detected |
| `ndjson` | NDJSON / JSONL | No schema change, compress only |

### Compression (auto-detected, no flag needed)

| Format | Magic bytes |
|---|---|
| gzip | `\x1f\x8b` |
| zstd | `\x28\xb5\x2f\xfd` |
| bzip2 | `BZh` |
| lz4 | `\x04\x22\x4d\x18` |
| xz | `\xfd7zXZ\x00` |

Magic bytes are checked first — file extension is ignored. A file named `.log` that is actually gzip-compressed will be decompressed correctly.

> **Parquet / Avro / ORC?**  
> These formats have their own SDK dependencies and are handled by dedicated tools:  
> [pfc-migrate-parquet](https://github.com/ImpossibleForge/pfc-migrate-parquet) · [pfc-migrate-avro](https://github.com/ImpossibleForge/pfc-migrate-avro)

---

## Three Usage Modes

### Mode 1 — One-Shot (most common)

```bash
pfc-convert convert server_logs.gz --schema apache --out archive.pfc
# gzip detected → decompress → CLF → JSONL → .pfc  (no temp files)
```

### Mode 2 — Step by step (inspect before compressing)

```bash
pfc-convert convert server_logs.gz --schema apache --output-format jsonl --out archive.jsonl
# → inspect archive.jsonl, verify it looks correct
pfc-migrate convert archive.jsonl --out archive.pfc
# → compress once verified
```

### Mode 3 — Pipe / stream (no disk overhead)

```bash
pfc-convert convert server_logs.gz --schema apache --stdout \
  | pfc-migrate convert --stdin --out archive.pfc
# streams directly, no intermediate file
```

---

## CSV Details

- **Delimiter:** auto-detected (comma, semicolon, tab, pipe)
- **Header:** first row becomes JSON keys; BOM (`﻿`) stripped automatically
- **Timestamp:** auto-detected from column named `timestamp`, `time`, `ts`, `@timestamp`, `datetime`, `date`, or `event_time`; override with `--timestamp-field`
- **Encoding:** UTF-8 with optional BOM; legacy Latin-1 files handled gracefully via `errors='replace'`

---

## Dirty Data Handling

Production logs are never clean. Use `--on-error` to control behaviour:

| Flag | Behaviour |
|---|---|
| `--on-error skip` | Skip unparseable lines, continue (default) |
| `--on-error fail` | Stop on first error |
| `--on-error log` | Skip + write errors to `<input>.convert_errors.log` |

---

## Timestamp Index

The `.pfc` block index (`.bidx` sidecar file) stores the timestamp range per block.  
This enables pfc-gateway and DuckDB to answer time-range queries **without decompressing** any data.

pfc-convert sets timestamps automatically:

| Schema | Source |
|---|---|
| Apache / nginx CLF | `[29/Apr/2026:10:30:00 +0200]` → ISO 8601 |
| nginx-json | `time_local` or `time_iso8601` field |
| NDJSON | `timestamp`, `ts`, `time`, or `@timestamp` field |
| CSV | `--timestamp-field` or auto-detected column |
| Fallback | Processing time (with warning — reduces query efficiency) |

---

## Audit Log

Every converted file can be recorded to a JSONL audit log:

```bash
pfc-convert convert --dir /var/log/ --schema apache --audit-log migration.log
```

Each entry contains: `logged_at`, `input`, `output`, `schema`, `compression`, `rows_ok`, `rows_err`, `input_mb`, `output_mb`, `ratio_pct`, `duration_s`.

---

## S3 In-Region Conversion

```bash
pfc-convert s3 \
  --bucket my-logs \
  --prefix apache-logs/2024/ \
  --out-bucket my-pfc-archive \
  --out-prefix pfc/2024/ \
  --schema apache \
  --region eu-central-1
```

Data stays in-region — no egress costs. Both `.pfc` and `.bidx` files are uploaded.

AWS credentials are read from environment variables, IAM roles, or `~/.aws/credentials` (standard boto3 chain). Explicit credentials via `--access-key` / `--secret-key`.

---

## Python API

For programmatic use and integration with [pfc-ingest-watchdog](https://github.com/ImpossibleForge/pfc-ingest-watchdog):

```python
from pfc_convert import ConvertPipeline

pipeline = ConvertPipeline(
    source      = "/var/log/apache/access.log.gz",
    destination = "/archive/access.pfc",
    schema      = "auto",
    on_error    = "log",
)
result = pipeline.run()
# result: {'rows_ok': 84231, 'rows_err': 3, 'output_mb': 2.14, 'ratio_pct': 8.7, 'duration_s': 1.2, ...}
```

---

## Ecosystem

```
Legacy data                pfc-convert              PFC Ecosystem
─────────────────────────────────────────────────────────────────────
access.log.gz   ───────►  schema convert           ►  .pfc archive
data.csv        ───────►  + compress               ►  pfc-gateway (query)
events.jsonl    ───────►                           ►  pfc-duckdb  (SQL)

s3://legacy/    ───────►  in-region, no egress     ►  s3://archive/
```

After conversion, use:
- **[pfc-duckdb](https://github.com/ImpossibleForge/pfc-duckdb)** — `SELECT * FROM read_pfc_jsonl('archive.pfc') WHERE status = 500`
- **[pfc-gateway](https://github.com/ImpossibleForge/pfc-gateway)** — REST API with time-range filter
- **[pfc-grafana](https://github.com/ImpossibleForge/pfc-grafana)** — Grafana data source plugin

---

## Output Naming

| Input | Output |
|---|---|
| `access.log.gz` | `access.pfc` |
| `data.csv` | `data.pfc` |
| `events.jsonl.gz` | `events.pfc` |

Use `--out` to specify an explicit output path.

---

## Part of the PFC Ecosystem

**[→ View all PFC tools & integrations](https://github.com/ImpossibleForge/pfc-jsonl#ecosystem)**

| Direct integration | Why |
|---|---|
| [pfc-migrate](https://github.com/ImpossibleForge/pfc-migrate) | Pipe partner — `pfc-convert --stdout \| pfc-migrate --stdin` for streaming compression |
| [pfc-ingest-watchdog](https://github.com/ImpossibleForge/pfc-ingest-watchdog) | Calls pfc-convert automatically when new files arrive in folder or S3 |

---

## License

MIT — © ImpossibleForge. See [LICENSE](LICENSE).
