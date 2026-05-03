#!/usr/bin/env python3
"""
pfc-convert — Convert legacy log/data formats to PFC (JSONL) format.

Supported input schemas:
  auto        — auto-detect from file content (default)
  apache      — Apache Common / Combined Log Format (CLF)
  nginx       — nginx CLF (structurally identical to apache)
  nginx-json  — nginx JSON log format (already JSONL → compress only)
  csv         — CSV / TSV (header row becomes JSON keys)
  ndjson      — Plain NDJSON / JSONL (compress only, no schema conversion)

Compression (Magic Bytes — auto-detected, no flag needed):
  gzip · zstd · bzip2 · lz4 · xz → decompressed transparently before conversion

Usage:
  pfc-convert convert access.log.gz
  pfc-convert convert access.log.gz --schema apache --out archive.pfc
  pfc-convert convert data.csv --schema csv --timestamp-field event_time
  pfc-convert convert data.csv --output-format jsonl --out data.jsonl
  pfc-convert convert access.log.gz --stdout | pfc-migrate convert --stdin archive.pfc
  pfc-convert convert --dir /var/log/apache/ --schema apache --out-dir /var/log/pfc/
  pfc-convert s3 --bucket my-logs --prefix apache/2024/ --schema apache
"""

__version__ = "0.1.0"

import argparse
import csv
import gzip
import bz2
import io
import json
import lzma
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from datetime import datetime
from pathlib import Path


# ---------------------------------------------------------------------------
# PFC binary detection
# ---------------------------------------------------------------------------

def find_pfc_binary(override=None):
    """Locate the pfc_jsonl binary. Returns path or raises."""
    if override:
        if os.path.isfile(override) and os.access(override, os.X_OK):
            return override
        raise FileNotFoundError(f"pfc_jsonl binary not found at: {override}")
    env = os.environ.get("PFC_JSONL_BINARY")
    if env and os.path.isfile(env) and os.access(env, os.X_OK):
        return env
    default = "/usr/local/bin/pfc_jsonl"
    if os.path.isfile(default) and os.access(default, os.X_OK):
        return default
    found = shutil.which("pfc_jsonl")
    if found:
        return found
    return None


# ---------------------------------------------------------------------------
# Magic byte compression detection (content beats extension)
# ---------------------------------------------------------------------------

_MAGIC = [
    (b'\x1f\x8b',         'gz'),
    (b'\x28\xb5\x2f\xfd', 'zst'),
    (b'BZh',              'bz2'),
    (b'\x04\x22\x4d\x18', 'lz4'),
    (b'\xfd7zXZ\x00',     'xz'),
]

def detect_compression(path) -> str:
    """Detect compression format from magic bytes. Returns format string or 'plain'."""
    try:
        with open(path, 'rb') as f:
            header = f.read(8)
    except OSError:
        return 'plain'
    for magic, fmt in _MAGIC:
        if header[:len(magic)] == magic:
            return fmt
    return 'plain'


# ---------------------------------------------------------------------------
# Decompressed stream opener
# ---------------------------------------------------------------------------

def open_input(path, compression: str):
    """Return an encoding-safe text stream for the (possibly compressed) input file."""
    kwargs = dict(encoding='utf-8', errors='replace')
    if compression == 'gz':
        return gzip.open(path, 'rt', **kwargs)
    if compression == 'bz2':
        return bz2.open(path, 'rt', **kwargs)
    if compression == 'zst':
        try:
            import zstandard as zstd
        except ImportError:
            raise ImportError("pip install zstandard  (required for .zst files)")
        raw = zstd.ZstdDecompressor().stream_reader(open(path, 'rb'))
        return io.TextIOWrapper(raw, **kwargs)
    if compression == 'lz4':
        try:
            import lz4.frame
        except ImportError:
            raise ImportError("pip install lz4  (required for .lz4 files)")
        return lz4.frame.open(path, 'rt', **kwargs)
    if compression == 'xz':
        return lzma.open(path, 'rt', **kwargs)
    return open(path, 'r', **kwargs)


# ---------------------------------------------------------------------------
# Schema auto-detection (from first non-empty line)
# ---------------------------------------------------------------------------

_CLF_DETECT = re.compile(
    r'^\S+ \S+ \S+ \[\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2} [+-]\d{4}\]'
)

def detect_schema(first_line: str) -> str:
    """Infer schema from first non-empty content line."""
    line = first_line.strip()
    if not line:
        return 'ndjson'
    if line.startswith('{'):
        try:
            json.loads(line)
            return 'ndjson'
        except json.JSONDecodeError:
            pass
    if _CLF_DETECT.match(line):
        return 'apache'
    return 'csv'


# ---------------------------------------------------------------------------
# Output path derivation
# ---------------------------------------------------------------------------

_COMP_EXTS  = {'.gz', '.zst', '.bz2', '.lz4', '.xz'}
_DATA_EXTS  = {'.jsonl', '.json', '.ndjson', '.log', '.csv', '.tsv', '.txt'}

def output_path_for(input_path: Path, output_dir=None) -> Path:
    """Derive the output .pfc (or .jsonl) path from the input path."""
    name = input_path.name
    if Path(name).suffix.lower() in _COMP_EXTS:
        name = Path(name).stem
    if Path(name).suffix.lower() in _DATA_EXTS:
        name = Path(name).stem + '.pfc'
    elif not name.endswith('.pfc'):
        name = name + '.pfc'
    base = Path(output_dir) if output_dir else input_path.parent
    return base / name


def output_jsonl_path_for(input_path: Path, output_dir=None) -> Path:
    """Derive the .jsonl output path (for --output-format jsonl)."""
    p = output_path_for(input_path, output_dir)
    return p.with_suffix('.jsonl')


# ---------------------------------------------------------------------------
# CLF parser  (Apache CLF / Combined + nginx CLF)
# ---------------------------------------------------------------------------

_CLF_COMBINED = re.compile(
    r'(?P<ip>\S+) \S+ (?P<user>\S+) \[(?P<time>[^\]]+)\] '
    r'"(?P<method>\S+) (?P<path>\S+) (?P<protocol>[^"]*)" '
    r'(?P<status>\d+) (?P<bytes>\S+) '
    r'"(?P<referer>[^"]*)" "(?P<user_agent>[^"]*)"'
)
_CLF_COMMON = re.compile(
    r'(?P<ip>\S+) \S+ (?P<user>\S+) \[(?P<time>[^\]]+)\] '
    r'"(?P<method>\S+) (?P<path>\S+) (?P<protocol>[^"]*)" '
    r'(?P<status>\d+) (?P<bytes>\S+)'
)
_CLF_TIME = '%d/%b/%Y:%H:%M:%S %z'


def _clf_time_to_iso(timestr: str) -> str:
    try:
        return datetime.strptime(timestr, _CLF_TIME).isoformat()
    except ValueError:
        return timestr


def parse_clf_line(line: str):
    """Parse one CLF/Combined log line → dict, or None if unparseable."""
    line = line.strip()
    if not line or line.startswith('#'):
        return None
    m = _CLF_COMBINED.match(line) or _CLF_COMMON.match(line)
    if not m:
        return None
    d = m.groupdict()
    rec = {
        'timestamp': _clf_time_to_iso(d['time']),
        'ip':        d['ip'],
        'method':    d['method'],
        'path':      d['path'],
        'protocol':  d['protocol'].strip(),
        'status':    int(d['status']),
    }
    if d['user'] != '-':
        rec['user'] = d['user']
    if d['bytes'] != '-':
        try:
            rec['bytes'] = int(d['bytes'])
        except ValueError:
            rec['bytes'] = d['bytes']
    if 'referer' in d and d['referer'] not in ('-', ''):
        rec['referer'] = d['referer']
    if 'user_agent' in d and d['user_agent'] not in ('-', ''):
        rec['user_agent'] = d['user_agent']
    return rec


# ---------------------------------------------------------------------------
# CSV converter
# ---------------------------------------------------------------------------

_TS_CANDIDATES = ('timestamp', 'time', 'ts', '@timestamp', 'datetime', 'date',
                  'event_time', 'created_at', 'logged_at')

def _sniff_delimiter(lines: list) -> str:
    sample = ''.join(lines[:20])
    try:
        return csv.Sniffer().sniff(sample, delimiters=',;\t|').delimiter
    except csv.Error:
        return ','


def convert_csv_stream(fh, timestamp_field=None, on_error='skip', error_log=None):
    """
    Generator: reads CSV from fh, yields dicts with 'timestamp' first if found.
    Handles header detection, delimiter sniffing, BOM stripping, type inference.
    """
    # Collect peek lines for sniffing + header
    peek = []
    for _, line in zip(range(20), fh):
        peek.append(line)
    if not peek:
        return

    delimiter = _sniff_delimiter(peek)

    def _all_lines():
        yield from peek
        yield from fh

    reader = csv.reader(_all_lines(), delimiter=delimiter)
    try:
        raw_headers = next(reader)
    except StopIteration:
        return

    headers = [h.strip().lstrip('﻿') for h in raw_headers]

    ts_field = timestamp_field
    if not ts_field:
        for cand in _TS_CANDIDATES:
            if cand in headers:
                ts_field = cand
                break

    for lineno, row in enumerate(reader, start=2):
        if not row:
            continue
        try:
            if len(row) != len(headers):
                raise ValueError(f"Line {lineno}: {len(row)} columns, expected {len(headers)}")
            d = dict(zip(headers, (v.strip() for v in row)))
            if ts_field and ts_field in d:
                ts_val = d.pop(ts_field)
                rec = {'timestamp': ts_val}
                rec.update(d)
            else:
                rec = d
            yield rec
        except Exception as exc:
            if on_error == 'fail':
                raise
            if error_log is not None:
                error_log.append({'line': lineno, 'error': str(exc)})


# ---------------------------------------------------------------------------
# NDJSON passthrough
# ---------------------------------------------------------------------------

def passthrough_ndjson(fh, on_error='skip', error_log=None):
    """Generator: yields valid JSON lines from an NDJSON stream."""
    for lineno, line in enumerate(fh, start=1):
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
            yield obj
        except json.JSONDecodeError as exc:
            if on_error == 'fail':
                raise
            if error_log is not None:
                error_log.append({'line': lineno, 'error': str(exc)})


# ---------------------------------------------------------------------------
# Core convert_file()
# ---------------------------------------------------------------------------

def convert_file(
    input_path,
    output_path,
    pfc_binary=None,
    schema='auto',
    output_format='pfc',
    timestamp_field=None,
    on_error='skip',
    stdout_mode=False,
    verbose=False,
    audit_log_path=None,
) -> dict:
    """
    Convert a single file to PFC or JSONL.

    Args:
        input_path    : source file (local path)
        output_path   : destination .pfc or .jsonl (ignored when stdout_mode=True)
        pfc_binary    : path to pfc_jsonl binary (required for output_format='pfc')
        schema        : 'auto' | 'apache' | 'nginx' | 'nginx-json' | 'csv' | 'ndjson'
        output_format : 'pfc' (default) | 'jsonl'
        timestamp_field: CSV column name to use as timestamp (auto-detected if None)
        on_error      : 'skip' | 'fail' | 'log'
        stdout_mode   : write JSONL to stdout instead of file (for pipe mode)
        verbose       : print progress
        audit_log_path: path to append JSONL audit record

    Returns dict with: input, output, schema, compression, rows_ok, rows_err,
                       input_mb, output_mb, ratio_pct, duration_s
    """
    t0 = time.time()
    input_path  = Path(input_path)
    if output_path:
        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)

    compression = detect_compression(input_path)

    # Detect schema from first non-empty line if auto
    resolved_schema = schema
    first_line_buf = None
    if schema == 'auto':
        with open_input(input_path, compression) as fh:
            for line in fh:
                if line.strip():
                    first_line_buf = line
                    break
        resolved_schema = detect_schema(first_line_buf or '')
        # Clear first_line_buf — file is re-opened from start, no injection needed
        first_line_buf = None

    if verbose:
        comp_label = f" [{compression}]" if compression != 'plain' else ''
        print(f"  -> {input_path.name}{comp_label}  schema={resolved_schema}")

    # Reject binary columnar formats with clear message
    if resolved_schema == 'parquet':
        raise ValueError(
            f"'{input_path.name}' appears to be Parquet — use pfc-migrate-parquet instead."
        )

    error_log = [] if on_error == 'log' else None
    error_counter = [0]  # mutable counter shared with generator for rows_err
    rows_ok = rows_err = 0

    # Choose output sink
    if stdout_mode:
        out_sink = sys.stdout
        tmp_jsonl = None

        with open_input(input_path, compression) as fh:
            records = _records_from_schema(
                fh, resolved_schema, first_line_buf, timestamp_field, on_error, error_log,
                error_counter,
            )
            for rec in records:
                try:
                    out_sink.write(json.dumps(rec, ensure_ascii=False) + '\n')
                    rows_ok += 1
                except Exception:
                    error_counter[0] += 1
                    if on_error == 'fail':
                        raise

        rows_err = error_counter[0]
        duration = time.time() - t0
        return _build_result(
            input_path, None, resolved_schema, compression,
            rows_ok, rows_err, duration, stdout_mode=True
        )

    # Normal mode: write to temp JSONL, then compress (or save as JSONL)
    tmp_fd, tmp_jsonl = tempfile.mkstemp(suffix='.jsonl')
    os.close(tmp_fd)

    try:
        with open_input(input_path, compression) as fh:
            records = _records_from_schema(
                fh, resolved_schema, first_line_buf, timestamp_field, on_error, error_log,
                error_counter,
            )
            with open(tmp_jsonl, 'w', encoding='utf-8') as out:
                for rec in records:
                    try:
                        out.write(json.dumps(rec, ensure_ascii=False) + '\n')
                        rows_ok += 1
                    except Exception:
                        error_counter[0] += 1
                        if on_error == 'fail':
                            raise

        if output_format == 'pfc':
            if not pfc_binary:
                raise RuntimeError(
                    "pfc_jsonl binary not found. Set PFC_JSONL_BINARY env var or use --pfc-binary."
                )
            result = subprocess.run(
                [pfc_binary, 'compress', tmp_jsonl, str(output_path)],
                capture_output=True, text=True,
            )
            if result.returncode != 0:
                raise RuntimeError(
                    f"pfc_jsonl compress failed (exit {result.returncode}):\n{result.stderr.strip()}"
                )
        else:
            shutil.copy2(tmp_jsonl, output_path)

        rows_err = error_counter[0]
        duration = time.time() - t0
        stats = _build_result(
            input_path, output_path, resolved_schema, compression,
            rows_ok, rows_err, duration
        )

        if verbose:
            skipped = f"  [{rows_err} skipped]" if rows_err else ''
            print(
                f"     {rows_ok} rows  {stats['output_mb']:.2f} MB"
                f"  ({stats['ratio_pct']:.1f}%)  OK {output_path.name}{skipped}"
            )

        if error_log:
            _write_error_log(input_path, error_log)

        if audit_log_path:
            _append_audit(audit_log_path, stats)

        return stats

    finally:
        if tmp_jsonl and os.path.exists(tmp_jsonl):
            os.unlink(tmp_jsonl)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _records_from_schema(fh, schema, first_line_buf, timestamp_field, on_error, error_log,
                         error_counter=None):
    """Return an iterator of dicts for the given schema, injecting first_line_buf if set."""
    if error_counter is None:
        error_counter = [0]

    if schema in ('apache', 'nginx'):
        def _clf_iter():
            if first_line_buf:
                rec = parse_clf_line(first_line_buf)
                if rec:
                    yield rec
                elif on_error == 'fail':
                    raise ValueError(f"Cannot parse CLF line: {first_line_buf[:100]!r}")
                else:
                    error_counter[0] += 1
                    if error_log is not None:
                        error_log.append({'line': 1, 'error': 'CLF parse failed', 'raw': first_line_buf[:120]})
            for line in fh:
                rec = parse_clf_line(line)
                if rec:
                    yield rec
                elif line.strip():
                    if on_error == 'fail':
                        raise ValueError(f"Cannot parse CLF line: {line[:100]!r}")
                    error_counter[0] += 1
                    if error_log is not None:
                        error_log.append({'error': 'CLF parse failed', 'raw': line[:120]})
        return _clf_iter()

    elif schema in ('ndjson', 'nginx-json'):
        def _ndjson_iter():
            if first_line_buf:
                line = first_line_buf.strip()
                if line:
                    try:
                        yield json.loads(line)
                    except json.JSONDecodeError as exc:
                        if on_error == 'fail':
                            raise
                        error_counter[0] += 1
                        if error_log is not None:
                            error_log.append({'line': 1, 'error': str(exc)})
            yield from passthrough_ndjson(fh, on_error=on_error, error_log=error_log)
        return _ndjson_iter()

    elif schema == 'csv':
        def _csv_fh():
            if first_line_buf:
                yield first_line_buf
            yield from fh
        wrapped = _IterFH(_csv_fh())
        return convert_csv_stream(wrapped, timestamp_field, on_error, error_log)

    else:
        raise ValueError(f"Unknown schema: {schema!r}")


class _IterFH:
    """Wraps a generator to look like a file handle (iterable + readline)."""
    def __init__(self, gen):
        self._gen = gen
        self._buf = []

    def __iter__(self):
        return self

    def __next__(self):
        return next(self._gen)

    def readline(self):
        try:
            return next(self._gen)
        except StopIteration:
            return ''


def _build_result(input_path, output_path, schema, compression,
                  rows_ok, rows_err, duration, stdout_mode=False):
    input_mb = input_path.stat().st_size / 1_048_576
    output_mb = 0.0
    ratio_pct = 0.0
    if output_path and output_path.exists():
        output_mb = output_path.stat().st_size / 1_048_576
        if input_mb > 0:
            ratio_pct = output_mb / input_mb * 100
    return {
        'input':       str(input_path),
        'output':      str(output_path) if output_path else 'stdout',
        'schema':      schema,
        'compression': compression,
        'rows_ok':     rows_ok,
        'rows_err':    rows_err,
        'input_mb':    round(input_mb, 3),
        'output_mb':   round(output_mb, 3),
        'ratio_pct':   round(ratio_pct, 2),
        'duration_s':  round(duration, 2),
    }


def _write_error_log(input_path, errors):
    log_path = Path(str(input_path) + '.convert_errors.log')
    with open(log_path, 'w', encoding='utf-8') as f:
        for e in errors:
            f.write(json.dumps(e, ensure_ascii=False) + '\n')
    print(f"  WARN {len(errors)} parse errors -> {log_path.name}", file=sys.stderr)


def _append_audit(audit_log_path, stats):
    record = {'logged_at': datetime.utcnow().isoformat() + 'Z', **stats}
    with open(audit_log_path, 'a', encoding='utf-8') as f:
        f.write(json.dumps(record, ensure_ascii=False) + '\n')


# ---------------------------------------------------------------------------
# Python API  (for pfc-ingest-watchdog and programmatic use)
# ---------------------------------------------------------------------------

class ConvertPipeline:
    """
    High-level Python API for pfc-convert.

    Usage:
        from pfc_convert import ConvertPipeline

        pipeline = ConvertPipeline(
            source      = "/var/log/apache/access.log.gz",
            destination = "/archive/access.pfc",
            schema      = "auto",
            on_error    = "log",
        )
        result = pipeline.run()
        # result: {rows_ok, rows_err, input_mb, output_mb, ratio_pct, duration_s, ...}
    """

    def __init__(
        self,
        source,
        destination,
        schema='auto',
        output_format='pfc',
        timestamp_field=None,
        on_error='skip',
        pfc_binary=None,
        verbose=False,
        audit_log=None,
    ):
        self.source          = source
        self.destination     = destination
        self.schema          = schema
        self.output_format   = output_format
        self.timestamp_field = timestamp_field
        self.on_error        = on_error
        self.pfc_binary      = pfc_binary or find_pfc_binary()
        self.verbose         = verbose
        self.audit_log       = audit_log

    def run(self) -> dict:
        return convert_file(
            input_path      = self.source,
            output_path     = self.destination,
            pfc_binary      = self.pfc_binary,
            schema          = self.schema,
            output_format   = self.output_format,
            timestamp_field = self.timestamp_field,
            on_error        = self.on_error,
            verbose         = self.verbose,
            audit_log_path  = self.audit_log,
        )


# ---------------------------------------------------------------------------
# Batch directory conversion
# ---------------------------------------------------------------------------

_INPUT_PATTERNS = [
    '*.log.gz', '*.log.zst', '*.log.bz2', '*.log.lz4', '*.log',
    '*.csv.gz', '*.csv',
    '*.jsonl.gz', '*.jsonl.zst', '*.jsonl',
    '*.ndjson.gz', '*.ndjson',
]


def convert_dir(
    input_dir,
    output_dir=None,
    schema='auto',
    output_format='pfc',
    timestamp_field=None,
    on_error='skip',
    pfc_binary=None,
    recursive=False,
    verbose=False,
    audit_log_path=None,
) -> tuple:
    """Convert all matching files in a directory. Returns (success, failed)."""
    input_dir = Path(input_dir)
    files = []
    for pattern in _INPUT_PATTERNS:
        fn = input_dir.rglob if recursive else input_dir.glob
        for f in fn(pattern):
            if f not in files:
                files.append(f)
    files = sorted(set(files))

    if not files:
        print(f"No convertible files found in {input_dir}")
        return 0, 0

    print(f"Found {len(files)} file(s) to convert\n")
    success = failed = 0
    total_rows = 0

    for f in files:
        if output_format == 'jsonl':
            out = output_jsonl_path_for(f, output_dir)
        else:
            out = output_path_for(f, output_dir)
        try:
            stats = convert_file(
                f, out, pfc_binary=pfc_binary, schema=schema,
                output_format=output_format, timestamp_field=timestamp_field,
                on_error=on_error, verbose=verbose, audit_log_path=audit_log_path,
            )
            total_rows += stats['rows_ok']
            success += 1
        except Exception as exc:
            print(f"  ERROR {f.name}: {exc}", file=sys.stderr)
            failed += 1

    print(f"\nDone: {success} converted, {failed} failed — {total_rows:,} rows total")
    return success, failed


# ---------------------------------------------------------------------------
# S3 support
# ---------------------------------------------------------------------------

def _s3_client(args):
    try:
        import boto3
    except ImportError:
        print("ERROR: pip install boto3  (required for S3 support)", file=sys.stderr)
        sys.exit(1)
    kwargs = dict(region_name=getattr(args, 'region', None))
    if getattr(args, 'endpoint_url', None):
        kwargs['endpoint_url'] = args.endpoint_url
    if getattr(args, 'access_key', None):
        kwargs['aws_access_key_id']     = args.access_key
        kwargs['aws_secret_access_key'] = args.secret_key
    return boto3.client('s3', **kwargs)


def s3_convert_prefix(
    s3, bucket, prefix, out_bucket, out_prefix,
    pfc_binary, schema='auto', output_format='pfc',
    timestamp_field=None, on_error='skip',
    verbose=False, delete_original=False, audit_log_path=None,
) -> tuple:
    """Convert all matching objects under s3://bucket/prefix. Returns (success, failed)."""
    keys = []
    paginator = s3.get_paginator('list_objects_v2')
    for page in paginator.paginate(Bucket=bucket, Prefix=prefix):
        for obj in page.get('Contents', []):
            k = obj['Key']
            if any(k.endswith(ext) for ext in
                   ('.log', '.log.gz', '.log.zst', '.log.bz2',
                    '.csv', '.csv.gz', '.jsonl', '.jsonl.gz', '.ndjson', '.ndjson.gz')):
                keys.append(k)

    if not keys:
        print(f"No convertible objects found under s3://{bucket}/{prefix}")
        return 0, 0

    print(f"Found {len(keys)} object(s) to convert\n")
    success = failed = 0

    for key in keys:
        src = Path(key)
        if output_format == 'jsonl':
            out_name = output_jsonl_path_for(src).name
        else:
            out_name = output_path_for(src).name
        out_key = (out_prefix.rstrip('/') + '/' + out_name) if out_prefix else out_name

        if verbose:
            print(f"  -> s3://{bucket}/{key}")

        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_in  = Path(tmpdir) / src.name
            tmp_out = Path(tmpdir) / out_name

            s3.download_file(bucket, key, str(tmp_in))
            try:
                stats = convert_file(
                    tmp_in, tmp_out, pfc_binary=pfc_binary, schema=schema,
                    output_format=output_format, timestamp_field=timestamp_field,
                    on_error=on_error, verbose=verbose, audit_log_path=audit_log_path,
                )
                s3.upload_file(str(tmp_out), out_bucket, out_key)

                bidx = Path(str(tmp_out) + '.bidx')
                if bidx.exists():
                    s3.upload_file(str(bidx), out_bucket, out_key + '.bidx')

                if delete_original:
                    s3.delete_object(Bucket=bucket, Key=key)

                success += 1
                if verbose:
                    print(f"     {stats['rows_ok']} rows -> s3://{out_bucket}/{out_key}  OK")

            except Exception as exc:
                print(f"  ERROR {key}: {exc}", file=sys.stderr)
                failed += 1

    print(f"\nDone: {success} converted, {failed} failed")
    return success, failed


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _add_common_args(p):
    p.add_argument('--schema', default='auto',
                   choices=['auto', 'apache', 'nginx', 'nginx-json', 'csv', 'ndjson'],
                   help='Input schema (default: auto-detect)')
    p.add_argument('--output-format', default='pfc', choices=['pfc', 'jsonl'],
                   help='Output format (default: pfc)')
    p.add_argument('--timestamp-field', default=None,
                   help='CSV column to use as timestamp (auto-detected if omitted)')
    p.add_argument('--on-error', default='skip', choices=['skip', 'fail', 'log'],
                   help='Behaviour on unparseable lines (default: skip)')
    p.add_argument('--pfc-binary', default=None, metavar='PATH',
                   help='Path to pfc_jsonl binary (or set PFC_JSONL_BINARY env var)')
    p.add_argument('--audit-log', default=None, metavar='FILE',
                   help='Append JSONL audit record per file to this path')
    p.add_argument('-v', '--verbose', action='store_true')


def build_parser():
    parser = argparse.ArgumentParser(
        prog='pfc-convert',
        description='Convert legacy log/data formats to PFC format.',
        epilog=(
            'For Parquet/Avro/ORC use the dedicated pfc-migrate-parquet / '
            'pfc-migrate-avro tools.\n'
            'Schema conversion details: https://github.com/ImpossibleForge/pfc-convert'
        ),
    )
    parser.add_argument('--version', action='version', version=f'pfc-convert {__version__}')
    sub = parser.add_subparsers(dest='command', required=True)

    # ── convert (single file or directory) ──────────────────────────────────
    p_conv = sub.add_parser('convert', help='Convert local file(s)')
    p_conv.add_argument('input', nargs='?', help='Input file path')
    p_conv.add_argument('--out', default=None, metavar='PATH',
                        help='Output path (default: same dir, .pfc suffix)')
    p_conv.add_argument('--dir', default=None, metavar='DIR',
                        help='Convert all matching files in DIR')
    p_conv.add_argument('--out-dir', default=None, metavar='DIR',
                        help='Output directory for --dir mode')
    p_conv.add_argument('--recursive', action='store_true',
                        help='Recurse into subdirectories (--dir mode)')
    p_conv.add_argument('--stdout', action='store_true',
                        help='Write JSONL to stdout (pipe mode)')
    p_conv.add_argument('--stdin', action='store_true',
                        help='Read JSONL from stdin and compress to .pfc (pass-through compress)')
    _add_common_args(p_conv)

    # ── s3 ──────────────────────────────────────────────────────────────────
    p_s3 = sub.add_parser('s3', help='Convert objects in S3 bucket')
    p_s3.add_argument('--bucket',       required=True)
    p_s3.add_argument('--prefix',       default='')
    p_s3.add_argument('--out-bucket',   default=None,
                      help='Destination bucket (default: same as --bucket)')
    p_s3.add_argument('--out-prefix',   default=None,
                      help='Destination prefix (default: same as --prefix)')
    p_s3.add_argument('--delete-original', action='store_true')
    p_s3.add_argument('--region',       default=None)
    p_s3.add_argument('--endpoint-url', default=None)
    p_s3.add_argument('--access-key',   default=None)
    p_s3.add_argument('--secret-key',   default=None)
    _add_common_args(p_s3)

    return parser


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)

    pfc_bin = find_pfc_binary(args.pfc_binary)
    if args.output_format == 'pfc' and not pfc_bin:
        print(
            "ERROR: pfc_jsonl binary not found.\n"
            "  Set PFC_JSONL_BINARY=/path/to/pfc_jsonl  or use --pfc-binary.\n"
            "  To output plain JSONL: --output-format jsonl",
            file=sys.stderr,
        )
        sys.exit(1)

    if args.command == 'convert':
        # ── stdin compress mode ──────────────────────────────────────────
        if getattr(args, 'stdin', False):
            if not args.out:
                print("ERROR: --stdin requires --out <output.pfc>", file=sys.stderr)
                sys.exit(1)
            tmp_fd, tmp_path = tempfile.mkstemp(suffix='.jsonl')
            try:
                with os.fdopen(tmp_fd, 'wb') as f:
                    shutil.copyfileobj(sys.stdin.buffer, f)
                result = subprocess.run(
                    [pfc_bin, 'compress', tmp_path, args.out],
                    capture_output=True, text=True,
                )
                if result.returncode != 0:
                    print(f"ERROR: pfc_jsonl failed:\n{result.stderr}", file=sys.stderr)
                    sys.exit(result.returncode)
                if args.verbose:
                    print(f"  OK stdin -> {args.out}")
            finally:
                if os.path.exists(tmp_path):
                    os.unlink(tmp_path)
            return

        # ── directory mode ───────────────────────────────────────────────
        if args.dir:
            convert_dir(
                args.dir,
                output_dir    = args.out_dir,
                schema        = args.schema,
                output_format = args.output_format,
                timestamp_field = args.timestamp_field,
                on_error      = args.on_error,
                pfc_binary    = pfc_bin,
                recursive     = args.recursive,
                verbose       = args.verbose,
                audit_log_path= args.audit_log,
            )
            return

        # ── single file mode ─────────────────────────────────────────────
        if not args.input:
            parser.error("Provide an input file, --dir, or --stdin.")

        input_path = Path(args.input)
        if not input_path.exists():
            print(f"ERROR: File not found: {input_path}", file=sys.stderr)
            sys.exit(1)

        if args.stdout:
            convert_file(
                input_path, None,
                pfc_binary      = pfc_bin,
                schema          = args.schema,
                output_format   = 'jsonl',
                timestamp_field = args.timestamp_field,
                on_error        = args.on_error,
                stdout_mode     = True,
                verbose         = args.verbose,
                audit_log_path  = args.audit_log,
            )
            return

        if args.output_format == 'jsonl':
            out = Path(args.out) if args.out else output_jsonl_path_for(input_path)
        else:
            out = Path(args.out) if args.out else output_path_for(input_path)

        stats = convert_file(
            input_path, out,
            pfc_binary      = pfc_bin,
            schema          = args.schema,
            output_format   = args.output_format,
            timestamp_field = args.timestamp_field,
            on_error        = args.on_error,
            verbose         = args.verbose,
            audit_log_path  = args.audit_log,
        )
        if not args.verbose:
            skipped = f"  ({stats['rows_err']} skipped)" if stats['rows_err'] else ''
            print(
                f"  OK {input_path.name}  [{stats['schema']}]"
                f"  {stats['rows_ok']:,} rows  {stats['output_mb']:.2f} MB{skipped}"
            )

    elif args.command == 's3':
        s3 = _s3_client(args)
        out_bucket = args.out_bucket or args.bucket
        out_prefix = args.out_prefix if args.out_prefix is not None else args.prefix
        s3_convert_prefix(
            s3, args.bucket, args.prefix, out_bucket, out_prefix,
            pfc_binary      = pfc_bin,
            schema          = args.schema,
            output_format   = args.output_format,
            timestamp_field = args.timestamp_field,
            on_error        = args.on_error,
            verbose         = args.verbose,
            delete_original = args.delete_original,
            audit_log_path  = args.audit_log,
        )


if __name__ == '__main__':
    main()
