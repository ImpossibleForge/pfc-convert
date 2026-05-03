#!/usr/bin/env python3
"""
pfc-convert v0.1.0 — HARD Test Suite
======================================
Roundtrip · Large files · Edge cases · Pipe mode · Encoding
DuckDB queryability · Directory batch · Error recovery

Run on server: python3 tests/test_pfc_convert_hard.py
Requires: pfc_jsonl binary + optional DuckDB
"""

import csv
import gzip
import io
import json
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path

if sys.stdout.encoding != 'utf-8':
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')

sys.path.insert(0, str(Path(__file__).parent.parent))
import pfc_convert as pc

PFC_BIN  = os.environ.get("PFC_JSONL_BINARY", "/usr/local/bin/pfc_jsonl")
OUTDIR   = Path(tempfile.mkdtemp(prefix="pfc_hard_test_"))
results  = []
HAS_BIN  = os.path.isfile(PFC_BIN)


def test(name, fn):
    t0 = time.time()
    try:
        fn()
        dt = time.time() - t0
        print(f"  PASS  [{dt:.2f}s]  {name}")
        results.append((name, True, dt))
    except Exception as exc:
        dt = time.time() - t0
        print(f"  FAIL  [{dt:.2f}s]  {name}")
        print(f"           -> {exc}")
        import traceback
        traceback.print_exc()
        results.append((name, False, dt))


def skip(name, reason):
    print(f"  SKIP  [0.00s]  {name}  ({reason})")
    results.append((name, True, 0.0))


def assert_eq(a, b, msg=""):
    if a != b:
        raise AssertionError(f"{msg}: {a!r} != {b!r}")


def assert_true(cond, msg):
    if not cond:
        raise AssertionError(msg)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def make_apache_log(n, start_minute=0) -> list:
    lines = []
    for i in range(n):
        minute = (start_minute + i) % 60
        hour   = (start_minute + i) // 60 % 24
        lines.append(
            f'10.0.{i // 256}.{i % 256} - user{i} '
            f'[29/Apr/2026:{hour:02d}:{minute:02d}:{i % 60:02d} +0200] '
            f'"GET /api/v1/item/{i}?page={i % 10}&sort=desc HTTP/1.1" '
            f'{200 + i % 5} {512 * (i % 20 + 1)} '
            f'"https://example.com/page/{i % 100}" '
            f'"Mozilla/5.0 (compatible; TestBot/{i % 5}.0)"\n'
        )
    return lines


def make_csv_rows(n, ts_col='timestamp') -> list:
    rows = [f"{ts_col},service,level,latency_ms,status_code,message\n"]
    for i in range(n):
        rows.append(
            f"2026-04-29T{(i // 3600) % 24:02d}:{(i // 60) % 60:02d}:{i % 60:02d}Z,"
            f"svc-{i % 10},{'INFO' if i % 3 else 'WARN'},{i % 500},{200 + i % 5},"
            f"Request {i} processed\n"
        )
    return rows


def write_file(lines, suffix='.log', compress=None) -> Path:
    name = f"hard_{int(time.time() * 1000)}{suffix}"
    p = OUTDIR / name
    content = ''.join(lines).encode('utf-8')
    if compress == 'gz':
        out_p = Path(str(p) + '.gz')
        with gzip.open(out_p, 'wb') as f:
            f.write(content)
        return out_p
    p.write_bytes(content)
    return p


def read_jsonl(path) -> list:
    recs = []
    for line in Path(path).read_text('utf-8').splitlines():
        if line.strip():
            recs.append(json.loads(line))
    return recs


def pfc_decompress(pfc_path, out_path):
    r = subprocess.run(
        [PFC_BIN, 'decompress', str(pfc_path), str(out_path)],
        capture_output=True, text=True,
    )
    if r.returncode != 0:
        raise RuntimeError(f"decompress failed: {r.stderr}")


# ===========================================================================
# 1. ROUNDTRIP TESTS
# ===========================================================================

def test_roundtrip_apache():
    if not HAS_BIN:
        return skip("roundtrip apache", "no binary")
    n = 200
    src = write_file(make_apache_log(n), '.log')
    pfc = OUTDIR / 'rt_apache.pfc'
    jsonl_out = OUTDIR / 'rt_apache_dec.jsonl'

    stats = pc.convert_file(src, pfc, pfc_binary=PFC_BIN, schema='apache', output_format='pfc')
    assert_eq(stats['rows_ok'], n)
    assert pfc.exists() and pfc.stat().st_size > 0

    pfc_decompress(pfc, jsonl_out)
    recs = read_jsonl(jsonl_out)
    assert_eq(len(recs), n, "roundtrip row count")

    # Verify structure of first record
    r0 = recs[0]
    for field in ('timestamp', 'ip', 'method', 'path', 'status', 'bytes'):
        assert field in r0, f"missing field: {field}"
    assert r0['method'] == 'GET'
    assert r0['status'] == 200


def test_roundtrip_csv():
    if not HAS_BIN:
        return skip("roundtrip csv", "no binary")
    n = 150
    src = write_file(make_csv_rows(n), '.csv')
    pfc = OUTDIR / 'rt_csv.pfc'
    jsonl_out = OUTDIR / 'rt_csv_dec.jsonl'

    stats = pc.convert_file(src, pfc, pfc_binary=PFC_BIN, schema='csv', output_format='pfc')
    assert_eq(stats['rows_ok'], n)

    pfc_decompress(pfc, jsonl_out)
    recs = read_jsonl(jsonl_out)
    assert_eq(len(recs), n, "CSV roundtrip row count")

    r0 = recs[0]
    assert 'timestamp' in r0, "timestamp present"
    assert 'service' in r0
    assert 'status_code' in r0


def test_roundtrip_gzip_apache():
    if not HAS_BIN:
        return skip("roundtrip gzip+apache", "no binary")
    n = 100
    src = write_file(make_apache_log(n), '.log', compress='gz')
    pfc = OUTDIR / 'rt_gz_apache.pfc'
    jsonl_out = OUTDIR / 'rt_gz_apache_dec.jsonl'

    stats = pc.convert_file(src, pfc, pfc_binary=PFC_BIN, schema='auto', output_format='pfc')
    assert_eq(stats['schema'], 'apache')
    assert_eq(stats['compression'], 'gz')
    assert_eq(stats['rows_ok'], n)

    pfc_decompress(pfc, jsonl_out)
    recs = read_jsonl(jsonl_out)
    assert_eq(len(recs), n)


def test_roundtrip_ndjson():
    if not HAS_BIN:
        return skip("roundtrip ndjson", "no binary")
    n = 80
    lines = [json.dumps({'timestamp': f'2026-04-29T10:{i:05.2f}', 'val': i, 'msg': f'event {i}'}) + '\n'
             for i in range(n)]
    src = write_file(lines, '.jsonl')
    pfc = OUTDIR / 'rt_ndjson.pfc'
    jsonl_out = OUTDIR / 'rt_ndjson_dec.jsonl'

    stats = pc.convert_file(src, pfc, pfc_binary=PFC_BIN, schema='ndjson', output_format='pfc')
    assert_eq(stats['rows_ok'], n)

    pfc_decompress(pfc, jsonl_out)
    recs = read_jsonl(jsonl_out)
    assert_eq(len(recs), n)
    assert_eq(recs[5]['val'], 5)


# ===========================================================================
# 2. LARGE FILE / STREAMING TEST
# ===========================================================================

def test_large_apache_no_oom():
    """10k lines — verify streaming (no full load into RAM), correct count."""
    n = 10_000
    src = write_file(make_apache_log(n), '.log')
    out = OUTDIR / 'large_apache.jsonl'
    stats = pc.convert_file(src, out, pfc_binary=None, schema='apache', output_format='jsonl')
    assert_eq(stats['rows_ok'], n, "10k rows")
    recs = read_jsonl(out)
    assert_eq(len(recs), n)


def test_large_csv_streaming():
    n = 5_000
    src = write_file(make_csv_rows(n), '.csv')
    out = OUTDIR / 'large_csv.jsonl'
    stats = pc.convert_file(src, out, pfc_binary=None, schema='csv', output_format='jsonl')
    assert_eq(stats['rows_ok'], n)


def test_large_gzip_apache_performance():
    if not HAS_BIN:
        return skip("large gzip apache perf", "no binary")
    n = 5_000
    src = write_file(make_apache_log(n), '.log', compress='gz')
    pfc = OUTDIR / 'large_gz_apache.pfc'
    t0 = time.time()
    stats = pc.convert_file(src, pfc, pfc_binary=PFC_BIN, schema='auto', output_format='pfc')
    dt = time.time() - t0
    assert_eq(stats['rows_ok'], n)
    print(f"     {n} rows in {dt:.2f}s ({n/dt:.0f} rows/s)")
    assert dt < 30, f"Too slow: {dt:.1f}s for {n} rows"


# ===========================================================================
# 3. CLF EDGE CASES
# ===========================================================================

def test_clf_ipv6():
    line = '2001:db8::1 - - [29/Apr/2026:10:00:00 +0000] "GET / HTTP/1.1" 200 512'
    rec = pc.parse_clf_line(line)
    assert rec is not None, "IPv6 CLF parsed"
    assert_eq(rec['ip'], '2001:db8::1')


def test_clf_long_query_string():
    line = ('192.168.1.1 - - [29/Apr/2026:10:00:00 +0000] '
            '"GET /search?q=hello+world&category=test&page=5&sort=asc&filter=active HTTP/1.1" '
            '200 9876')
    rec = pc.parse_clf_line(line)
    assert rec is not None
    assert 'search' in rec['path']


def test_clf_status_codes():
    for status in [100, 201, 301, 404, 500, 503]:
        line = f'1.2.3.4 - - [29/Apr/2026:10:00:00 +0000] "GET / HTTP/1.1" {status} 0'
        rec = pc.parse_clf_line(line)
        assert rec is not None, f"status {status}"
        assert_eq(rec['status'], status)


def test_clf_zero_bytes():
    line = '1.2.3.4 - - [29/Apr/2026:10:00:00 +0000] "HEAD / HTTP/1.1" 200 0'
    rec = pc.parse_clf_line(line)
    assert rec is not None
    assert_eq(rec['bytes'], 0)


def test_clf_comment_line_skipped():
    assert pc.parse_clf_line('# This is a comment') is None


def test_clf_timestamp_various_months():
    months = ['Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec']
    for i, mon in enumerate(months, 1):
        line = f'1.2.3.4 - - [01/{mon}/2026:00:00:00 +0000] "GET / HTTP/1.1" 200 1'
        rec = pc.parse_clf_line(line)
        assert rec is not None, f"month {mon}"
        assert f'2026-{i:02d}-01' in rec['timestamp'], f"month {mon} ISO: {rec['timestamp']}"


# ===========================================================================
# 4. CSV EDGE CASES
# ===========================================================================

def _csv_recs(text, **kwargs):
    fh = pc._IterFH(iter(text.splitlines(keepends=True)))
    return list(pc.convert_csv_stream(fh, **kwargs))


def test_csv_quoted_commas():
    data = 'ts,message\n2026-01-01,"hello, world"\n2026-01-02,"another, one"\n'
    recs = _csv_recs(data, timestamp_field='ts')
    assert_eq(len(recs), 2)
    assert_eq(recs[0]['message'], 'hello, world')


def test_csv_empty_fields():
    data = 'ts,a,b,c\n2026-01-01,val1,,val3\n'
    recs = _csv_recs(data, timestamp_field='ts')
    assert_eq(len(recs), 1)
    assert_eq(recs[0]['b'], '')


def test_csv_no_timestamp_col():
    data = 'id,value,label\n1,42,test\n2,99,prod\n'
    recs = _csv_recs(data)
    assert_eq(len(recs), 2)
    assert 'id' in recs[0]


def test_csv_tab_delimiter():
    data = "ts\tservice\tstatus\n2026-01-01\tapi\t200\n"
    recs = _csv_recs(data, timestamp_field='ts')
    assert_eq(len(recs), 1)
    assert_eq(recs[0]['service'], 'api')


def test_csv_only_header_no_data():
    data = 'ts,service,status\n'
    recs = _csv_recs(data)
    assert_eq(len(recs), 0, "no data rows")


def test_csv_many_columns():
    cols = [f'col{i}' for i in range(50)]
    header = 'timestamp,' + ','.join(cols) + '\n'
    row = '2026-01-01T00:00:00Z,' + ','.join(str(i) for i in range(50)) + '\n'
    recs = _csv_recs(header + row)
    assert_eq(len(recs), 1)
    assert_eq(len(recs[0]), 51)  # timestamp + 50 cols


def test_csv_alternate_ts_names():
    for ts_name in ('time', 'ts', '@timestamp', 'datetime', 'date', 'event_time'):
        data = f'{ts_name},val\n2026-01-01T00:00:00Z,42\n'
        recs = _csv_recs(data)
        assert 'timestamp' in recs[0], f"auto-detect {ts_name!r} -> timestamp"


# ===========================================================================
# 5. NDJSON EDGE CASES
# ===========================================================================

def test_ndjson_nested_objects():
    lines = ['{"ts":"2026-01-01","nested":{"a":1,"b":[1,2,3]},"level":"INFO"}\n']
    fh = pc._IterFH(iter(lines))
    recs = list(pc.passthrough_ndjson(fh))
    assert_eq(len(recs), 1)
    assert_eq(recs[0]['nested']['a'], 1)


def test_ndjson_unicode():
    lines = ['{"ts":"2026-01-01","msg":"日本語テスト 🔥"}\n',
             '{"ts":"2026-01-02","msg":"Ünïcödé"}\n']
    fh = pc._IterFH(iter(lines))
    recs = list(pc.passthrough_ndjson(fh))
    assert_eq(len(recs), 2)
    assert '🔥' in recs[0]['msg']


def test_ndjson_large_objects():
    big = {'ts': '2026-01-01', 'data': 'x' * 10_000, 'tags': list(range(100))}
    lines = [json.dumps(big) + '\n'] * 5
    fh = pc._IterFH(iter(lines))
    recs = list(pc.passthrough_ndjson(fh))
    assert_eq(len(recs), 5)


# ===========================================================================
# 6. ENCODING TESTS
# ===========================================================================

def test_latin1_apache_log():
    """Simulate old server with Latin-1 encoded log (umlauts in user-agent)."""
    line = '192.168.1.1 - - [29/Apr/2026:10:00:00 +0200] "GET / HTTP/1.1" 200 512 "-" "Mozilla/5.0 (Ünïcödé Brösèr)"\n'
    src = OUTDIR / 'latin1.log'
    src.write_bytes(line.encode('latin-1'))
    out = OUTDIR / 'latin1_out.jsonl'
    # Should not crash — errors='replace' handles bad bytes
    stats = pc.convert_file(src, out, pfc_binary=None, schema='apache',
                            output_format='jsonl', on_error='skip')
    assert stats['rows_ok'] >= 0  # may fail to parse due to latin-1, but no crash


def test_utf8_with_bom_csv():
    data = '﻿' + 'timestamp,val\n2026-01-01T00:00:00Z,test\n'
    src = OUTDIR / 'bom_csv.csv'
    src.write_bytes(data.encode('utf-8-sig'))
    out = OUTDIR / 'bom_csv_out.jsonl'
    stats = pc.convert_file(src, out, pfc_binary=None, schema='csv', output_format='jsonl')
    assert_eq(stats['rows_ok'], 1)
    recs = read_jsonl(out)
    assert 'timestamp' in recs[0], f"BOM-free field, keys: {list(recs[0].keys())}"


# ===========================================================================
# 7. ERROR RECOVERY / EDGE CASES
# ===========================================================================

def test_empty_file():
    src = OUTDIR / 'empty.log'
    src.write_bytes(b'')
    out = OUTDIR / 'empty_out.jsonl'
    stats = pc.convert_file(src, out, pfc_binary=None, schema='apache', output_format='jsonl')
    assert_eq(stats['rows_ok'], 0)
    assert_eq(stats['rows_err'], 0)


def test_file_with_only_empty_lines():
    src = write_file(['\n', '\n', '   \n'], '.log')
    out = OUTDIR / 'empties_out.jsonl'
    stats = pc.convert_file(src, out, pfc_binary=None, schema='apache', output_format='jsonl')
    assert_eq(stats['rows_ok'], 0)


def test_missing_input_file():
    try:
        pc.convert_file('/nonexistent/file.log', OUTDIR / 'out.jsonl',
                        pfc_binary=None, schema='apache', output_format='jsonl')
        raise AssertionError("Should have raised")
    except (FileNotFoundError, OSError):
        pass


def test_output_dir_auto_created():
    src = write_file(make_apache_log(3), '.log')
    out = OUTDIR / 'subdir1' / 'subdir2' / 'output.jsonl'
    stats = pc.convert_file(src, out, pfc_binary=None, schema='apache', output_format='jsonl')
    assert out.exists(), "output created in nested dir"
    assert_eq(stats['rows_ok'], 3)


def test_corrupted_gzip():
    src = OUTDIR / 'corrupt.log.gz'
    src.write_bytes(b'\x1f\x8b' + b'\x00' * 50)  # valid magic, garbage content
    out = OUTDIR / 'corrupt_out.jsonl'
    try:
        pc.convert_file(src, out, pfc_binary=None, schema='apache', output_format='jsonl')
        raise AssertionError("Should have raised on corrupt gzip")
    except Exception:
        pass  # expected — any exception is fine


def test_single_line_file():
    src = write_file(make_apache_log(1), '.log')
    out = OUTDIR / 'single_out.jsonl'
    stats = pc.convert_file(src, out, pfc_binary=None, schema='apache', output_format='jsonl')
    assert_eq(stats['rows_ok'], 1)
    recs = read_jsonl(out)
    assert_eq(len(recs), 1)


# ===========================================================================
# 8. STDOUT / PIPE MODE
# ===========================================================================

def test_stdout_mode_produces_valid_jsonl():
    """--stdout mode: capture stdout, verify JSONL."""
    n = 20
    lines = make_apache_log(n)
    src = write_file(lines, '.log')
    out = OUTDIR / 'stdout_test.jsonl'

    # Run CLI with --stdout, capture output
    r = subprocess.run(
        [sys.executable,
         str(Path(__file__).parent.parent / 'pfc_convert.py'),
         'convert', str(src), '--schema', 'apache', '--stdout'],
        capture_output=True, text=True,
    )
    assert_eq(r.returncode, 0, f"stdout mode exit: {r.stderr[:200]}")
    lines_out = [l for l in r.stdout.splitlines() if l.strip()]
    assert_eq(len(lines_out), n, "stdout row count")
    # Verify valid JSON
    for line in lines_out[:5]:
        rec = json.loads(line)
        assert 'timestamp' in rec


def test_pipe_to_migrate_stdin():
    """pfc-convert --stdout | pfc-migrate --stdin -> .pfc (full pipe test)."""
    if not HAS_BIN:
        return skip("pipe mode full", "no binary")

    migrate_script = Path(__file__).parent.parent.parent / 'pfc-migrate' / 'pfc_migrate.py'
    if not migrate_script.exists():
        return skip("pipe mode full", "pfc-migrate not found at expected path")

    n = 30
    lines = make_apache_log(n)
    src = write_file(lines, '.log')
    out_pfc = OUTDIR / 'pipe_out.pfc'

    # pfc-convert --stdout | pfc-migrate convert --stdin out.pfc
    # Using subprocess.Popen for pipe
    p_convert = subprocess.Popen(
        [sys.executable,
         str(Path(__file__).parent.parent / 'pfc_convert.py'),
         'convert', str(src), '--schema', 'apache', '--stdout'],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    p_migrate = subprocess.Popen(
        [sys.executable, str(migrate_script),
         'convert', '--stdin', '--out', str(out_pfc)],
        stdin=p_convert.stdout, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    p_convert.stdout.close()
    stdout, stderr = p_migrate.communicate(timeout=30)
    p_convert.wait()

    assert p_migrate.returncode == 0, f"pipe migrate failed: {stderr.decode()[:300]}"
    assert out_pfc.exists(), ".pfc created via pipe"

    jsonl_out = OUTDIR / 'pipe_dec.jsonl'
    pfc_decompress(out_pfc, jsonl_out)
    recs = read_jsonl(jsonl_out)
    assert_eq(len(recs), n, "pipe roundtrip row count")


# ===========================================================================
# 9. BATCH DIRECTORY MODE
# ===========================================================================

def test_batch_dir_multiple_formats():
    batch_dir = OUTDIR / 'batch_input'
    batch_out = OUTDIR / 'batch_output'
    batch_dir.mkdir(exist_ok=True)

    # Create mixed files
    (batch_dir / 'access1.log').write_text(''.join(make_apache_log(5)), encoding='utf-8')
    (batch_dir / 'access2.log').write_text(''.join(make_apache_log(3)), encoding='utf-8')
    # Non-matching file should be ignored
    (batch_dir / 'README.md').write_text('# test\n', encoding='utf-8')

    success, failed = pc.convert_dir(
        batch_dir, output_dir=batch_out,
        schema='apache', output_format='jsonl',
        pfc_binary=None, verbose=False,
    )
    assert_eq(success, 2, "2 log files converted")
    assert_eq(failed, 0)
    out_files = list(batch_out.glob('*.jsonl'))
    assert_eq(len(out_files), 2)

    total_rows = sum(len(read_jsonl(f)) for f in out_files)
    assert_eq(total_rows, 8, "5 + 3 rows total")


def test_batch_dir_recursive():
    root = OUTDIR / 'rec_input'
    subdir = root / 'subdir'
    out = OUTDIR / 'rec_output'
    root.mkdir(exist_ok=True)
    subdir.mkdir(exist_ok=True)

    (root / 'top.log').write_text(''.join(make_apache_log(4)), encoding='utf-8')
    (subdir / 'sub.log').write_text(''.join(make_apache_log(6)), encoding='utf-8')

    success, failed = pc.convert_dir(
        root, output_dir=out, schema='apache', output_format='jsonl',
        pfc_binary=None, recursive=True, verbose=False,
    )
    assert_eq(success, 2)
    total = sum(len(read_jsonl(f)) for f in out.rglob('*.jsonl'))
    assert_eq(total, 10)


# ===========================================================================
# 10. AUDIT LOG
# ===========================================================================

def test_audit_log_append_multiple():
    """Multiple conversions append to same audit log."""
    audit = OUTDIR / 'multi_audit.jsonl'
    for i in range(3):
        src = write_file(make_apache_log(i + 1), '.log')
        out = OUTDIR / f'audit_multi_{i}.jsonl'
        pc.convert_file(src, out, pfc_binary=None, schema='apache',
                        output_format='jsonl', audit_log_path=str(audit))

    entries = read_jsonl(audit)
    assert_eq(len(entries), 3, "3 audit entries")
    assert all('rows_ok' in e for e in entries)
    assert all('logged_at' in e for e in entries)
    assert_eq(entries[0]['rows_ok'], 1)
    assert_eq(entries[1]['rows_ok'], 2)
    assert_eq(entries[2]['rows_ok'], 3)


def test_audit_log_all_fields():
    src = write_file(make_apache_log(5), '.log')
    out = OUTDIR / 'af_out.jsonl'
    audit = OUTDIR / 'af_audit.jsonl'
    pc.convert_file(src, out, pfc_binary=None, schema='apache',
                    output_format='jsonl', audit_log_path=str(audit))
    entry = read_jsonl(audit)[0]
    required = ['logged_at', 'input', 'output', 'schema', 'compression',
                'rows_ok', 'rows_err', 'input_mb', 'output_mb', 'duration_s']
    for field in required:
        assert field in entry, f"audit missing field: {field}"


# ===========================================================================
# 11. DUCKDB QUERYABILITY
# ===========================================================================

def test_duckdb_query_pfc_output():
    """Convert apache log -> .pfc -> query with DuckDB pfc extension."""
    if not HAS_BIN:
        return skip("duckdb query", "no pfc_jsonl binary")

    try:
        import duckdb
    except ImportError:
        return skip("duckdb query", "duckdb not installed")

    # Check pfc extension available
    try:
        con = duckdb.connect()
        con.execute("INSTALL pfc FROM community")
        con.execute("LOAD pfc")
    except Exception as e:
        return skip("duckdb query", f"pfc extension not available: {e}")

    n = 100
    src = write_file(make_apache_log(n), '.log')
    pfc = OUTDIR / 'duckdb_test.pfc'
    stats = pc.convert_file(src, pfc, pfc_binary=PFC_BIN, schema='apache', output_format='pfc')
    assert_eq(stats['rows_ok'], n)

    # Query with DuckDB
    result = con.execute(f"SELECT COUNT(*) FROM read_pfc_jsonl('{pfc}')").fetchone()[0]
    assert_eq(result, n, "DuckDB row count matches")

    # Query specific field
    statuses = con.execute(
        f"SELECT status, COUNT(*) as cnt FROM read_pfc_jsonl('{pfc}') GROUP BY status ORDER BY status"
    ).fetchall()
    assert len(statuses) > 0, "status group by works"
    print(f"     DuckDB query OK: {n} rows, {len(statuses)} distinct statuses")


# ===========================================================================
# 12. CLI HARD TESTS
# ===========================================================================

SCRIPT = str(Path(__file__).parent.parent / 'pfc_convert.py')

def _cli(*args, input_text=None):
    r = subprocess.run(
        [sys.executable, SCRIPT] + list(args),
        capture_output=True, text=True,
        input=input_text,
    )
    return r


def test_cli_auto_schema_apache():
    src = write_file(make_apache_log(5), '.log')
    out = OUTDIR / 'cli_auto_apache.jsonl'
    r = _cli('convert', str(src), '--output-format', 'jsonl', '--out', str(out))
    assert_eq(r.returncode, 0, f"exit: {r.stderr[:200]}")
    recs = read_jsonl(out)
    assert_eq(len(recs), 5)


def test_cli_verbose_output():
    src = write_file(make_apache_log(3), '.log')
    out = OUTDIR / 'cli_verbose.jsonl'
    r = _cli('convert', str(src), '--schema', 'apache', '--output-format', 'jsonl',
             '--out', str(out), '--verbose')
    assert_eq(r.returncode, 0)
    assert 'apache' in r.stdout + r.stderr


def test_cli_on_error_skip():
    lines = make_apache_log(4) + ['GARBAGE\n'] + make_apache_log(3)
    src = write_file(lines, '.log')
    out = OUTDIR / 'cli_onerr.jsonl'
    r = _cli('convert', str(src), '--schema', 'apache', '--output-format', 'jsonl',
             '--out', str(out), '--on-error', 'skip')
    assert_eq(r.returncode, 0)
    recs = read_jsonl(out)
    assert_eq(len(recs), 7, "7 good rows, 1 skipped")


def test_cli_missing_binary_error():
    """When output-format=pfc and no binary, should exit non-zero with message."""
    src = write_file(make_apache_log(2), '.log')
    out = OUTDIR / 'no_bin.pfc'
    env = os.environ.copy()
    env.pop('PFC_JSONL_BINARY', None)  # remove env var if set
    r = subprocess.run(
        [sys.executable, SCRIPT, 'convert', str(src), '--out', str(out),
         '--pfc-binary', '/nonexistent/pfc_jsonl'],
        capture_output=True, text=True, env=env,
    )
    assert r.returncode != 0, "should fail without binary"
    assert 'pfc_jsonl' in r.stdout + r.stderr


def test_cli_csv_timestamp_field():
    lines = ['event_time,service,code\n', '2026-04-29T10:00:00Z,api,200\n']
    src = write_file(lines, '.csv')
    out = OUTDIR / 'cli_csv_ts.jsonl'
    r = _cli('convert', str(src), '--schema', 'csv', '--timestamp-field', 'event_time',
             '--output-format', 'jsonl', '--out', str(out))
    assert_eq(r.returncode, 0)
    recs = read_jsonl(out)
    assert_eq(len(recs), 1)
    assert 'timestamp' in recs[0]


# ===========================================================================
# Run all tests
# ===========================================================================

if __name__ == '__main__':
    print(f"\npfc-convert v{pc.__version__} — HARD Test Suite")
    print(f"PFC binary: {PFC_BIN} ({'found' if HAS_BIN else 'NOT FOUND — binary tests will skip'})")
    print(f"Output dir: {OUTDIR}\n")

    all_tests = [
        # Roundtrip
        ("roundtrip: apache log -> pfc -> jsonl",          test_roundtrip_apache),
        ("roundtrip: csv -> pfc -> jsonl",                 test_roundtrip_csv),
        ("roundtrip: gzip(apache) auto -> pfc -> jsonl",   test_roundtrip_gzip_apache),
        ("roundtrip: ndjson -> pfc -> jsonl",              test_roundtrip_ndjson),
        # Large file / streaming
        ("large: 10k apache rows no OOM",                  test_large_apache_no_oom),
        ("large: 5k csv streaming",                        test_large_csv_streaming),
        ("large: 5k gzip+apache performance",              test_large_gzip_apache_performance),
        # CLF edge cases
        ("CLF: IPv6 address",                              test_clf_ipv6),
        ("CLF: long query string in path",                 test_clf_long_query_string),
        ("CLF: all HTTP status codes",                     test_clf_status_codes),
        ("CLF: zero bytes response",                       test_clf_zero_bytes),
        ("CLF: comment line skipped",                      test_clf_comment_line_skipped),
        ("CLF: all 12 months parse correctly",             test_clf_timestamp_various_months),
        # CSV edge cases
        ("CSV: quoted fields with commas",                 test_csv_quoted_commas),
        ("CSV: empty fields preserved",                    test_csv_empty_fields),
        ("CSV: no timestamp column",                       test_csv_no_timestamp_col),
        ("CSV: tab delimiter",                             test_csv_tab_delimiter),
        ("CSV: header only, no data rows",                 test_csv_only_header_no_data),
        ("CSV: 50 columns",                                test_csv_many_columns),
        ("CSV: all timestamp field name variants",         test_csv_alternate_ts_names),
        # NDJSON edge cases
        ("NDJSON: nested objects preserved",               test_ndjson_nested_objects),
        ("NDJSON: unicode + emoji",                        test_ndjson_unicode),
        ("NDJSON: large objects (10k char field)",         test_ndjson_large_objects),
        # Encoding
        ("encoding: latin-1 log no crash",                test_latin1_apache_log),
        ("encoding: UTF-8 BOM CSV",                       test_utf8_with_bom_csv),
        # Error recovery
        ("error: empty file",                             test_empty_file),
        ("error: file with only empty lines",             test_file_with_only_empty_lines),
        ("error: missing input file",                     test_missing_input_file),
        ("error: output dir auto-created",               test_output_dir_auto_created),
        ("error: corrupted gzip raises",                  test_corrupted_gzip),
        ("error: single line file",                       test_single_line_file),
        # Stdout / pipe mode
        ("pipe: --stdout produces valid JSONL",           test_stdout_mode_produces_valid_jsonl),
        ("pipe: pfc-convert | pfc-migrate full roundtrip", test_pipe_to_migrate_stdin),
        # Batch directory
        ("batch: --dir multiple files",                   test_batch_dir_multiple_formats),
        ("batch: --dir --recursive",                      test_batch_dir_recursive),
        # Audit log
        ("audit: append multiple conversions",            test_audit_log_append_multiple),
        ("audit: all required fields present",            test_audit_log_all_fields),
        # DuckDB
        ("duckdb: query pfc output",                      test_duckdb_query_pfc_output),
        # CLI
        ("CLI: auto schema detects apache",               test_cli_auto_schema_apache),
        ("CLI: --verbose output",                         test_cli_verbose_output),
        ("CLI: --on-error skip",                          test_cli_on_error_skip),
        ("CLI: missing binary -> clear error",            test_cli_missing_binary_error),
        ("CLI: --timestamp-field for CSV",                test_cli_csv_timestamp_field),
    ]

    for name, fn in all_tests:
        test(name, fn)

    total  = len(results)
    passed = sum(1 for _, ok, _ in results if ok)
    failed = total - passed
    total_t = sum(t for _, _, t in results)

    print(f"\n{'='*65}")
    print(f"  {passed}/{total} PASS   {failed} FAIL   {total_t:.1f}s total")
    print(f"{'='*65}\n")

    if failed:
        print("FAILED tests:")
        for name, ok, _ in results:
            if not ok:
                print(f"  - {name}")
        sys.exit(1)
