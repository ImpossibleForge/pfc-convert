# pfc-convert Changelog

## v0.1.0 — 2026-04-29

Initial release.

### Supported input schemas
- `apache` / `nginx` — CLF (Common Log Format) + Combined Log Format
- `nginx-json` — nginx JSON log mode (already JSONL, compress only)
- `csv` — CSV/TSV with header row → JSON keys
- `ndjson` — plain NDJSON/JSONL (compress only)
- `auto` — auto-detect from magic bytes + first content line

### Compression detection
- Auto-detection via magic bytes (gzip · zstd · bzip2 · lz4 · xz)
- Magic bytes take priority over file extension

### Features
- Three usage modes: One-Shot / Schrittweise (`--output-format jsonl`) / Pipe (`--stdout`)
- `--stdin` mode for pipe destination (JSONL → .pfc compress)
- Dirty-data handling: `--on-error skip|fail|log`
- Timestamp auto-detection for CLF and NDJSON
- `--timestamp-field` for CSV
- Audit log: `--audit-log path` (JSONL record per file)
- Directory batch mode: `--dir`
- S3 support: `pfc-convert s3 --bucket ...`
- Python API: `from pfc_convert import ConvertPipeline`
