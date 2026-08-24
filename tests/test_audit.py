from __future__ import annotations

import contextlib
import json

import pytest

from dataweir import AccessDenied, Guardrail, Monitor, guard
from dataweir.audit import (
    GENESIS_HASH,
    JsonlAuditSink,
    MemoryAuditSink,
    read_records,
    record_hash,
    redact_params,
    verify_chain,
)


def test_chain_links_each_record_to_the_last(tmp_path):
    sink = JsonlAuditSink(tmp_path / "a.jsonl")
    first = sink.write({"event": "decision", "agent_id": "a"})
    second = sink.write({"event": "decision", "agent_id": "b"})
    assert first["prev_hash"] == GENESIS_HASH
    assert second["prev_hash"] == first["hash"]
    assert second["seq"] == 1


def test_verify_passes_on_an_untouched_log(tmp_path):
    path = tmp_path / "a.jsonl"
    sink = JsonlAuditSink(path)
    for i in range(5):
        sink.write({"event": "decision", "agent_id": f"agent-{i}"})
    report = verify_chain(path)
    assert report.ok
    assert report.checked == 5


def test_verify_catches_an_edited_record(tmp_path):
    path = tmp_path / "a.jsonl"
    sink = JsonlAuditSink(path)
    for i in range(4):
        sink.write({"event": "decision", "agent_id": f"agent-{i}", "rows_returned": i})

    lines = path.read_text().splitlines()
    tampered = json.loads(lines[2])
    tampered["rows_returned"] = 0  # hide a large read
    lines[2] = json.dumps(tampered, sort_keys=True, separators=(",", ":"))
    path.write_text("\n".join(lines) + "\n")

    report = verify_chain(path)
    assert not report.ok
    assert report.broken_at == 2
    assert "does not match its hash" in report.message


def test_verify_catches_a_deleted_record(tmp_path):
    path = tmp_path / "a.jsonl"
    sink = JsonlAuditSink(path)
    for i in range(4):
        sink.write({"event": "decision", "agent_id": f"agent-{i}"})

    lines = path.read_text().splitlines()
    del lines[1]
    path.write_text("\n".join(lines) + "\n")

    report = verify_chain(path)
    assert not report.ok
    assert report.broken_at == 1


def test_verify_catches_reordering(tmp_path):
    path = tmp_path / "a.jsonl"
    sink = JsonlAuditSink(path)
    for i in range(3):
        sink.write({"event": "decision", "agent_id": f"agent-{i}"})

    lines = path.read_text().splitlines()
    lines[0], lines[1] = lines[1], lines[0]
    path.write_text("\n".join(lines) + "\n")

    assert not verify_chain(path).ok


def test_appending_to_an_existing_file_continues_the_chain(tmp_path):
    path = tmp_path / "a.jsonl"
    first = JsonlAuditSink(path)
    first.write({"event": "decision", "agent_id": "a"})
    first.write({"event": "decision", "agent_id": "b"})

    reopened = JsonlAuditSink(path)
    third = reopened.write({"event": "decision", "agent_id": "c"})

    assert third["seq"] == 2
    assert verify_chain(path).ok


def test_hash_is_order_independent():
    a = {"b": 2, "a": 1, "hash": "ignored"}
    b = {"a": 1, "b": 2}
    assert record_hash(a) == record_hash(b)


def test_unchained_sink_writes_no_hashes(tmp_path):
    path = tmp_path / "a.jsonl"
    sink = JsonlAuditSink(path, hash_chain=False)
    record = sink.write({"event": "decision"})
    assert "hash" not in record
    assert not verify_chain(path).ok  # nothing to verify against


def test_malformed_json_is_reported_with_a_line_number(tmp_path):
    path = tmp_path / "a.jsonl"
    path.write_text('{"seq":0}\nnot json\n')
    with pytest.raises(ValueError, match="malformed JSON"):
        list(read_records(path))


@pytest.mark.parametrize(
    ("params", "expected"),
    [
        (None, None),
        (("ana", 42), ["<redacted>", "<redacted>"]),
        ({"owner": "ana"}, {"owner": "<redacted>"}),
        ("ana", "<redacted>"),
    ],
)
def test_redaction_keeps_shape_not_values(params, expected):
    assert redact_params(params) == expected


def test_redaction_can_be_switched_off():
    assert redact_params(("ana",), enabled=False) == ("ana",)


def test_end_to_end_log_survives_verification(tmp_path, policy, db):
    import dataclasses

    from dataweir.policy import AuditConfig

    path = tmp_path / "audit.jsonl"
    audited = dataclasses.replace(policy, audit=AuditConfig(enabled=True, path=str(path)))
    guardrail = Guardrail(audited, monitor=Monitor())
    conn = guard(db, audited, agent="support", guardrail=guardrail)

    conn.execute("SELECT id FROM tickets LIMIT 5").fetchall()
    with contextlib.suppress(AccessDenied):
        conn.execute("SELECT amount FROM payroll")

    report = verify_chain(path)
    assert report.ok
    records = list(read_records(path))
    assert any(r["action"] == "blocked" for r in records)
    assert all("hash" in r for r in records)


def test_memory_sink_chains_too():
    sink = MemoryAuditSink()
    sink.write({"event": "a"})
    second = sink.write({"event": "b"})
    assert second["prev_hash"] == sink.records[0]["hash"]
