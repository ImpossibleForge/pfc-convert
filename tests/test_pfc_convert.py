#!/usr/bin/env python3
"""
pfc-convert v0.1.0 — Test Suite
================================
Tests: CLF parsing · CSV conversion · NDJSON passthrough
       Magic byte detection · Schema auto-detect · Python API
       Dirty data · Encoding · Output modes

Run on server: python3 tests/test_pfc_convert.py
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

# Force UTF-8 output on Windows
if sys.stdout.encoding != 'utf-8':
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')

# Resolve pfc_convert.py from parent dir
sys.path.insert(0, str(Path(__file__).parent.parent))
import pfc_convert as pc

PFC_BIN  = os.environ.get("PFC_JSONL_BINARY", "/usr/local/bin/pfc_jsonl")
OUTDIR   = Path(tempfile.mkdtemp(prefix="pfc_convert_test_"))
results  = []


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

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
        results.append((name, False, dt))


def assert_eq(a, b, msg=""):
    if a != b:
        raise AssertionError(f"{msg}: {a!r} != {b!r}")


def make_apache_log(n=10) -> list:
    lines = []
    for i in range(n):
        lines.append(
            f'192.168.0.{i % 255} - user{i} [29/Apr/2026:10:{i:02d}:00 +0200] '
            f'"GET /api/v1/resource/{i} HTTP/1.1" {200 + i % 5} {1024 * (i + 1)} '
            f'"https://example.com" "Mozilla/5.0 (test)"\n'
        )
    return lines


def make_csv(n=10, timestamp_col='timestamp') -> list:
    rows = [f"{timestamp_col},level,service,message\n"]
    for i in range(n):
        rows.append(f"2026-04-29T10:{i:02d}:00Z,INFO,svc-{i % 3},Request processed {i}\n")
    return rows


def write_tmp(lines, suffix='.log', compress=None) -> Path:
    p = OUTDIR / f"input_{int(time.time()*1000)}{suffix}"
    content = ''.join(lines).encode()
    if compress == 'gz':
        with gzip.open(str(p) + '.gz', 'wb') as f:
            f.write(content)
        return Path(str(p) + '.gz')
    with open(p, 'wb') as f:
        f.write(content)
    return p


# ---------------------------------------------------------------------------
# 1. Magic byte detection
# ---------------------------------------------------------------------------

def test_magic_gz():
    p = write_tmp(["test\n"], compress='gz')
    assert_eq(pc.detect_compression(p), 'gz', "gzip magic")

def test_magic_plain():
    p = write_tmp(["test\n"], suffix='.log')
    assert_eq(pc.detect_compression(p), 'plain', "plain magic")

def test_magic_beats_extension():
    # gzip content with .log extension — magic bytes win
    content = gzip.compress(b"test\n")
    p = OUTDIR / "fake.log"
    p.write_bytes(content)
    assert_eq(pc.detect_compression(p), 'gz', "magic > extension")


# ---------------------------------------------------------------------------
# 2. Schema auto-detection
# ---------------------------------------------------------------------------

def test_detect_schema_apache():
    line = '127.0.0.1 - frank [29/Apr/2026:10:30:00 +0200] "GET / HTTP/1.1" 200 1234'
    assert_eq(pc.detect_schema(line), 'apache')

def test_detect_schema_ndjson():
    line = '{"timestamp": "2026-04-29T10:00:00", "level": "INFO", "msg": "ok"}'
    assert_eq(pc.detect_schema(line), 'ndjson')

def test_detect_schema_csv():
    line = 'timestamp,level,service,message'
    assert_eq(pc.detect_schema(line), 'csv')


# ---------------------------------------------------------------------------
# 3. CLF parser
# ---------------------------------------------------------------------------

def test_clf_combined():
    line = ('192.168.1.1 - alice [29/Apr/2026:14:30:00 +0200] '
            '"POST /api/data HTTP/1.1" 201 512 '
            '"https://ref.example.com" "curl/7.88"')
    rec = pc.parse_clf_line(line)
    assert rec is not None, "combined CLF parsed"
    assert_eq(rec['ip'], '192.168.1.1')
    assert_eq(rec['method'], 'POST')
    assert_eq(rec['status'], 201)
    assert_eq(rec['bytes'], 512)
    assert 'referer' in rec
    assert 'user_agent' in rec
    assert 'timestamp' in rec

def test_clf_common():
    line = '10.0.0.1 - - [29/Apr/2026:09:00:00 +0000] "GET /health HTTP/1.0" 200 42'
    rec = pc.parse_clf_line(line)
    assert rec is not None, "common CLF parsed"
    assert_eq(rec['status'], 200)
    assert 'user_agent' not in rec

def test_clf_timestamp_iso():
    line = '1.2.3.4 - - [15/Jan/2024:08:30:00 +0100] "GET / HTTP/1.1" 200 100'
    rec = pc.parse_clf_line(line)
    assert rec['timestamp'].startswith('2024-01-15'), f"ISO timestamp: {rec['timestamp']}"

def test_clf_dash_user_omitted():
    line = '1.2.3.4 - - [29/Apr/2026:10:00:00 +0000] "GET / HTTP/1.1" 200 100'
    rec = pc.parse_clf_line(line)
    assert 'user' not in rec, "dash user should be omitted"

def test_clf_dash_bytes_omitted():
    line = '1.2.3.4 - - [29/Apr/2026:10:00:00 +0000] "HEAD / HTTP/1.1" 204 -'
    rec = pc.parse_clf_line(line)
    assert 'bytes' not in rec, "dash bytes should be omitted"

def test_clf_empty_line():
    assert pc.parse_clf_line('') is None
    assert pc.parse_clf_line('   \n') is None

def test_clf_garbage_line():
    assert pc.parse_clf_line('this is not a log line') is None


# ---------------------------------------------------------------------------
# 4. CSV converter
# ---------------------------------------------------------------------------

def _csv_to_list(rows_str, timestamp_field=None, on_error='skip'):
    fh = pc._IterFH(iter(rows_str.splitlines(keepends=True)))
    return list(pc.convert_csv_stream(fh, timestamp_field=timestamp_field, on_error=on_error))

def test_csv_header_to_keys():
    data = "ts,level,msg\n2026-01-01T00:00:00Z,INFO,hello\n"
    recs = _csv_to_list(data, timestamp_field='ts')
    assert_eq(len(recs), 1)
    assert_eq(recs[0]['level'], 'INFO')
    assert_eq(recs[0]['timestamp'], '2026-01-01T00:00:00Z')

def test_csv_timestamp_auto_detect():
    data = "timestamp,service,status\n2026-04-29T12:00:00Z,api,200\n"
    recs = _csv_to_list(data)
    assert recs[0].get('timestamp') == '2026-04-29T12:00:00Z', "auto-detect timestamp"

def test_csv_semicolon_delimiter():
    data = "time;value;label\n2026-01-01;42;test\n"
    recs = _csv_to_list(data, timestamp_field='time')
    assert_eq(recs[0]['value'], '42')

def test_csv_bom_stripped():
    data = "﻿timestamp,msg\n2026-01-01T00:00:00Z,hello\n"
    recs = _csv_to_list(data)
    assert 'timestamp' in recs[0], f"BOM stripped, keys: {list(recs[0].keys())}"

def test_csv_skip_bad_rows():
    data = "ts,val\n2026-01-01T00:00:00Z,good\nbad_row_only_one_col\n2026-01-02T00:00:00Z,good2\n"
    recs = _csv_to_list(data, on_error='skip')
    assert_eq(len(recs), 2, "bad row skipped")


# ---------------------------------------------------------------------------
# 5. NDJSON passthrough
# ---------------------------------------------------------------------------

def test_ndjson_valid():
    lines = ['{"ts":"2026-01-01","val":1}\n', '{"ts":"2026-01-02","val":2}\n']
    fh = pc._IterFH(iter(lines))
    recs = list(pc.passthrough_ndjson(fh))
    assert_eq(len(recs), 2)
    assert_eq(recs[0]['val'], 1)

def test_ndjson_skip_invalid():
    lines = ['{"ok":1}\n', 'NOT JSON\n', '{"ok":2}\n']
    fh = pc._IterFH(iter(lines))
    recs = list(pc.passthrough_ndjson(fh, on_error='skip'))
    assert_eq(len(recs), 2, "invalid line skipped")

def test_ndjson_empty_lines_skipped():
    lines = ['{"a":1}\n', '\n', '  \n', '{"a":2}\n']
    fh = pc._IterFH(iter(lines))
    recs = list(pc.passthrough_ndjson(fh))
    assert_eq(len(recs), 2)


# ---------------------------------------------------------------------------
# 6. Output path derivation
# ---------------------------------------------------------------------------

def test_output_path_gz():
    p = pc.output_path_for(Path('access.log.gz'))
    assert_eq(p.name, 'access.pfc')

def test_output_path_csv():
    p = pc.output_path_for(Path('data.csv'))
    assert_eq(p.name, 'data.pfc')

def test_output_path_jsonl_gz():
    p = pc.output_path_for(Path('events.jsonl.gz'))
    assert_eq(p.name, 'events.pfc')

def test_output_jsonl_path():
    p = pc.output_jsonl_path_for(Path('data.csv'))
    assert_eq(p.name, 'data.jsonl')


# ---------------------------------------------------------------------------
# 7. convert_file — JSONL output mode (no pfc_jsonl binary needed)
# ---------------------------------------------------------------------------

def test_convert_apache_to_jsonl():
    lines = make_apache_log(5)
    src = write_tmp(lines, suffix='.log')
    out = OUTDIR / 'apache_out.jsonl'
    stats = pc.convert_file(src, out, pfc_binary=None, schema='apache',
                            output_format='jsonl', verbose=False)
    assert_eq(stats['rows_ok'], 5, "row count")
    assert_eq(stats['rows_err'], 0)
    recs = [json.loads(l) for l in out.read_text().splitlines() if l.strip()]
    assert_eq(len(recs), 5)
    assert 'timestamp' in recs[0]
    assert 'ip' in recs[0]
    assert 'status' in recs[0]

def test_convert_apache_gz_to_jsonl():
    lines = make_apache_log(10)
    src = write_tmp(lines, suffix='.log', compress='gz')
    out = OUTDIR / 'apache_gz_out.jsonl'
    stats = pc.convert_file(src, out, pfc_binary=None, schema='auto',
                            output_format='jsonl', verbose=False)
    assert_eq(stats['schema'], 'apache', "auto-detected apache")
    assert_eq(stats['rows_ok'], 10)
    assert_eq(stats['compression'], 'gz')

def test_convert_csv_to_jsonl():
    lines = make_csv(8)
    src = write_tmp(lines, suffix='.csv')
    out = OUTDIR / 'csv_out.jsonl'
    stats = pc.convert_file(src, out, pfc_binary=None, schema='csv',
                            output_format='jsonl', verbose=False)
    assert_eq(stats['rows_ok'], 8)
    recs = [json.loads(l) for l in out.read_text().splitlines() if l.strip()]
    assert 'timestamp' in recs[0], "timestamp field present"
    assert 'level' in recs[0]

def test_convert_ndjson_to_jsonl():
    lines = ['{"timestamp":"2026-04-29T10:00:00Z","val":' + str(i) + '}\n'
             for i in range(6)]
    src = write_tmp(lines, suffix='.jsonl')
    out = OUTDIR / 'ndjson_out.jsonl'
    stats = pc.convert_file(src, out, pfc_binary=None, schema='ndjson',
                            output_format='jsonl', verbose=False)
    assert_eq(stats['rows_ok'], 6)

def test_convert_auto_ndjson():
    lines = ['{"ts":"2026-04-29T10:00:00Z","msg":"hello"}\n'] * 4
    src = write_tmp(lines, suffix='.jsonl')
    out = OUTDIR / 'auto_ndjson_out.jsonl'
    stats = pc.convert_file(src, out, pfc_binary=None, schema='auto',
                            output_format='jsonl', verbose=False)
    assert_eq(stats['schema'], 'ndjson')
    assert_eq(stats['rows_ok'], 4)


# ---------------------------------------------------------------------------
# 8. Dirty data — on_error modes
# ---------------------------------------------------------------------------

def test_dirty_clf_skip():
    lines = make_apache_log(3) + ["NOT A LOG LINE\n"] + make_apache_log(2)
    src = write_tmp(lines, suffix='.log')
    out = OUTDIR / 'dirty_skip.jsonl'
    stats = pc.convert_file(src, out, pfc_binary=None, schema='apache',
                            output_format='jsonl', on_error='skip')
    assert_eq(stats['rows_ok'], 5, "5 good rows")
    assert stats['rows_err'] >= 1, "at least 1 error"

def test_dirty_clf_fail():
    lines = make_apache_log(2) + ["GARBAGE\n"]
    src = write_tmp(lines, suffix='.log')
    out = OUTDIR / 'dirty_fail.jsonl'
    try:
        pc.convert_file(src, out, pfc_binary=None, schema='apache',
                        output_format='jsonl', on_error='fail')
        raise AssertionError("Should have raised on dirty line")
    except ValueError:
        pass  # expected

def test_dirty_clf_log():
    lines = make_apache_log(3) + ["BAD\n"] + make_apache_log(2)
    src = write_tmp(lines, suffix='.log')
    out = OUTDIR / 'dirty_log.jsonl'
    stats = pc.convert_file(src, out, pfc_binary=None, schema='apache',
                            output_format='jsonl', on_error='log')
    assert_eq(stats['rows_ok'], 5)
    error_log = Path(str(src) + '.convert_errors.log')
    assert error_log.exists(), "error log created"


# ---------------------------------------------------------------------------
# 9. Audit log
# ---------------------------------------------------------------------------

def test_audit_log():
    lines = make_apache_log(4)
    src = write_tmp(lines, suffix='.log')
    out = OUTDIR / 'audit_test.jsonl'
    audit = OUTDIR / 'audit.jsonl'
    pc.convert_file(src, out, pfc_binary=None, schema='apache',
                    output_format='jsonl', audit_log_path=str(audit))
    assert audit.exists(), "audit log created"
    rec = json.loads(audit.read_text().splitlines()[0])
    assert 'rows_ok' in rec
    assert 'logged_at' in rec
    assert_eq(rec['rows_ok'], 4)


# ---------------------------------------------------------------------------
# 10. Python API (ConvertPipeline)
# ---------------------------------------------------------------------------

def test_convert_pipeline_api():
    lines = make_apache_log(5)
    src = write_tmp(lines, suffix='.log')
    out = OUTDIR / 'pipeline_out.jsonl'
    pipeline = pc.ConvertPipeline(
        source=str(src), destination=str(out),
        schema='apache', output_format='jsonl', on_error='skip',
    )
    result = pipeline.run()
    assert_eq(result['rows_ok'], 5)
    assert result['duration_s'] >= 0


# ---------------------------------------------------------------------------
# 11. Full pipeline with pfc_jsonl binary (if available)
# ---------------------------------------------------------------------------

def test_convert_apache_to_pfc():
    if not os.path.isfile(PFC_BIN):
        print(f"     (skipped — pfc_jsonl binary not found at {PFC_BIN})")
        return

    lines = make_apache_log(50)
    src = write_tmp(lines, suffix='.log')
    out = OUTDIR / 'apache_full.pfc'
    stats = pc.convert_file(src, out, pfc_binary=PFC_BIN, schema='apache',
                            output_format='pfc', verbose=True)
    assert out.exists(), ".pfc file created"
    assert out.stat().st_size > 0, ".pfc not empty"
    assert_eq(stats['rows_ok'], 50)

    bidx = Path(str(out) + '.bidx')
    assert bidx.exists(), ".bidx index created alongside .pfc"

def test_convert_csv_gz_to_pfc():
    if not os.path.isfile(PFC_BIN):
        print(f"     (skipped — pfc_jsonl binary not found)")
        return

    lines = make_csv(30)
    src = write_tmp(lines, suffix='.csv', compress='gz')
    out = OUTDIR / 'csv_full.pfc'
    stats = pc.convert_file(src, out, pfc_binary=PFC_BIN, schema='auto',
                            output_format='pfc', verbose=True)
    assert_eq(stats['schema'], 'csv')
    assert_eq(stats['rows_ok'], 30)
    assert out.exists()


# ---------------------------------------------------------------------------
# 12. CLI smoke test
# ---------------------------------------------------------------------------

def test_cli_version():
    r = subprocess.run(
        [sys.executable, str(Path(__file__).parent.parent / 'pfc_convert.py'), '--version'],
        capture_output=True, text=True,
    )
    assert 'pfc-convert' in r.stdout + r.stderr, f"version output: {r.stdout}{r.stderr}"

def test_cli_convert_jsonl_mode():
    lines = make_apache_log(5)
    src = write_tmp(lines, suffix='.log')
    out = OUTDIR / 'cli_out.jsonl'
    r = subprocess.run(
        [sys.executable, str(Path(__file__).parent.parent / 'pfc_convert.py'),
         'convert', str(src), '--schema', 'apache', '--output-format', 'jsonl',
         '--out', str(out)],
        capture_output=True, text=True,
    )
    assert r.returncode == 0, f"CLI exit {r.returncode}: {r.stderr}"
    assert out.exists()
    recs = [json.loads(l) for l in out.read_text().splitlines() if l.strip()]
    assert_eq(len(recs), 5)


# ---------------------------------------------------------------------------
# Run all tests
# ---------------------------------------------------------------------------

if __name__ == '__main__':
    print(f"\npfc-convert v{pc.__version__} — Test Suite")
    print(f"Output dir: {OUTDIR}\n")

    tests = [
        # Magic bytes
        ("magic byte: gzip detected",           test_magic_gz),
        ("magic byte: plain detected",          test_magic_plain),
        ("magic byte beats extension",          test_magic_beats_extension),
        # Schema detection
        ("schema auto: apache CLF",             test_detect_schema_apache),
        ("schema auto: ndjson",                 test_detect_schema_ndjson),
        ("schema auto: csv fallback",           test_detect_schema_csv),
        # CLF parser
        ("CLF combined format",                 test_clf_combined),
        ("CLF common format",                   test_clf_common),
        ("CLF timestamp → ISO 8601",            test_clf_timestamp_iso),
        ("CLF dash user omitted",               test_clf_dash_user_omitted),
        ("CLF dash bytes omitted",              test_clf_dash_bytes_omitted),
        ("CLF empty line → None",               test_clf_empty_line),
        ("CLF garbage line → None",             test_clf_garbage_line),
        # CSV
        ("CSV header → JSON keys",              test_csv_header_to_keys),
        ("CSV timestamp auto-detect",           test_csv_timestamp_auto_detect),
        ("CSV semicolon delimiter",             test_csv_semicolon_delimiter),
        ("CSV BOM stripped",                    test_csv_bom_stripped),
        ("CSV skip bad rows",                   test_csv_skip_bad_rows),
        # NDJSON
        ("NDJSON valid records",                test_ndjson_valid),
        ("NDJSON skip invalid",                 test_ndjson_skip_invalid),
        ("NDJSON empty lines skipped",          test_ndjson_empty_lines_skipped),
        # Output paths
        ("output path .log.gz → .pfc",         test_output_path_gz),
        ("output path .csv → .pfc",            test_output_path_csv),
        ("output path .jsonl.gz → .pfc",       test_output_path_jsonl_gz),
        ("output jsonl path derivation",        test_output_jsonl_path),
        # convert_file JSONL mode
        ("convert apache → jsonl",              test_convert_apache_to_jsonl),
        ("convert apache.gz → jsonl (auto)",   test_convert_apache_gz_to_jsonl),
        ("convert csv → jsonl",                 test_convert_csv_to_jsonl),
        ("convert ndjson → jsonl",              test_convert_ndjson_to_jsonl),
        ("convert auto ndjson detection",       test_convert_auto_ndjson),
        # Dirty data
        ("dirty CLF: on_error=skip",            test_dirty_clf_skip),
        ("dirty CLF: on_error=fail raises",     test_dirty_clf_fail),
        ("dirty CLF: on_error=log file",        test_dirty_clf_log),
        # Audit log
        ("audit log written",                   test_audit_log),
        # Python API
        ("ConvertPipeline API",                 test_convert_pipeline_api),
        # Full pipeline (needs binary)
        ("convert apache → .pfc + .bidx",      test_convert_apache_to_pfc),
        ("convert csv.gz → .pfc (auto)",       test_convert_csv_gz_to_pfc),
        # CLI
        ("CLI --version",                       test_cli_version),
        ("CLI convert --output-format jsonl",   test_cli_convert_jsonl_mode),
    ]

    for name, fn in tests:
        test(name, fn)

    total  = len(results)
    passed = sum(1 for _, ok, _ in results if ok)
    failed = total - passed
    total_t = sum(t for _, _, t in results)

    print(f"\n{'='*60}")
    print(f"  {passed}/{total} PASS   {failed} FAIL   {total_t:.1f}s total")
    print(f"{'='*60}")

    if failed:
        sys.exit(1)
