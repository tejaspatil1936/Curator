"""Unit tests for challenge.py query translation layer — no model, no DB required."""
import sys
sys.path.insert(0, '/app')

from curator.ai.challenge import query_filters_to_sql

def test_empty_filters():
    sql, params = query_filters_to_sql({})
    assert "FROM events e" in sql
    assert "LIMIT" in sql
    assert "WHERE" not in sql
    print("PASS: empty filters")

def test_event_codes():
    sql, params = query_filters_to_sql({"event_codes": ["4688", "1"]})
    assert "e.event_code = ANY(:event_codes)" in sql
    assert params["event_codes"] == ["4688", "1"]
    print("PASS: event_codes")

def test_hosts():
    sql, params = query_filters_to_sql({"hosts": ["SCRANTON", "NASHUA"]})
    assert "LOWER(e.host) = ANY(:hosts)" in sql
    assert "scranton" in params["hosts"]
    print("PASS: hosts (lowercased)")

def test_process_names():
    sql, params = query_filters_to_sql({"process_names": ["explorer.exe"]})
    assert "LOWER(COALESCE(e.process_name,'')) LIKE :pname_0" in sql
    assert params["pname_0"] == "%explorer.exe"
    print("PASS: process_names (suffix match)")

def test_command_line_contains():
    sql, params = query_filters_to_sql({"command_line_contains": ["powershell", "encoded"]})
    assert "LOWER(COALESCE(e.command_line,'')) LIKE :cl_0" in sql
    assert params["cl_0"] == "%powershell%"
    assert params["cl_1"] == "%encoded%"
    print("PASS: command_line_contains")

def test_time_range():
    sql, params = query_filters_to_sql({
        "time_after": "2019-06-21T02:50:00",
        "time_before": "2019-06-21T03:00:00",
    })
    assert "e.ts >= :time_after" in sql
    assert "e.ts <= :time_before" in sql
    print("PASS: time range")

def test_incident_id_scope():
    sql, params = query_filters_to_sql({}, incident_id=803)
    assert "e.incident_id = :incident_id" in sql
    assert params["incident_id"] == 803
    print("PASS: incident_id scope")

def test_sql_injection_rejected():
    try:
        query_filters_to_sql({"hosts": ["SCRANTON; DROP TABLE events--"]})
        print("FAIL: should have raised ValueError")
    except ValueError as e:
        print(f"PASS: SQL injection rejected: {e}")

def test_combined_filters():
    sql, params = query_filters_to_sql({
        "event_codes": ["1"],
        "hosts": ["scranton"],
        "process_names": ["powershell.exe"],
        "time_after": "2019-06-21T02:00:00",
    }, incident_id=803, max_rows=25)
    assert "WHERE" in sql
    assert "AND" in sql
    assert params["max_rows"] == 25
    print("PASS: combined filters with incident scope")

if __name__ == "__main__":
    tests = [
        test_empty_filters,
        test_event_codes,
        test_hosts,
        test_process_names,
        test_command_line_contains,
        test_time_range,
        test_incident_id_scope,
        test_sql_injection_rejected,
        test_combined_filters,
    ]
    failures = 0
    for t in tests:
        try:
            t()
        except Exception as ex:
            print(f"FAIL: {t.__name__}: {ex}")
            failures += 1
    print(f"\n{'All tests passed!' if not failures else f'{failures} test(s) failed.'}")
    sys.exit(failures)
