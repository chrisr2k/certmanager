"""LocalDB offline buffer tests — PSK-derived encryption of any
private_key_pem field before it touches the plaintext-JSON buffer table.

Only relevant when deliver_key_to_central produced a result carrying a
key (AD CS issue/renew); ordinary discovery results are untouched.
"""

from __future__ import annotations

import sqlite3

from certmanager.agent.local_db import LocalDB


def _result_with_key(pem: str = "-----BEGIN PRIVATE KEY-----\nSECRET\n-----END PRIVATE KEY-----"):
    return {
        "total_checked": 1,
        "certificates": [
            {
                "common_name": "www.example.com",
                "private_key_pem": pem,
            }
        ],
        "errors": [],
    }


def test_private_key_is_not_plaintext_on_disk(tmp_path):
    db = LocalDB(str(tmp_path / "agent.db"), psk="test-agent-psk")
    db.buffer_result("job-1", _result_with_key())

    conn = sqlite3.connect(str(tmp_path / "agent.db"))
    raw = conn.execute("SELECT result_json FROM pending_results").fetchone()[0]
    conn.close()

    assert "SECRET" not in raw, "the raw PEM must not be recoverable from the DB file as-is"
    assert "BEGIN PRIVATE KEY" not in raw


def test_buffered_key_round_trips_through_get_pending_results(tmp_path):
    db = LocalDB(str(tmp_path / "agent.db"), psk="test-agent-psk")
    db.buffer_result("job-1", _result_with_key())

    pending = db.get_pending_results()
    assert len(pending) == 1
    cert = pending[0]["result"]["certificates"][0]
    assert cert["private_key_pem"] == (
        "-----BEGIN PRIVATE KEY-----\nSECRET\n-----END PRIVATE KEY-----"
    )
    assert "_private_key_encrypted" not in cert


def test_different_psk_cannot_decrypt(tmp_path):
    db_path = str(tmp_path / "agent.db")
    writer = LocalDB(db_path, psk="correct-psk")
    writer.buffer_result("job-1", _result_with_key())

    reader = LocalDB(db_path, psk="wrong-psk")
    try:
        reader.get_pending_results()
        raised = False
    except Exception:
        raised = True
    assert raised, "a different PSK must not be able to decrypt another agent's buffered key"


def test_no_psk_means_no_encryption_but_still_functions(tmp_path):
    db = LocalDB(str(tmp_path / "agent.db"))  # no psk configured
    db.buffer_result("job-1", _result_with_key())

    conn = sqlite3.connect(str(tmp_path / "agent.db"))
    raw = conn.execute("SELECT result_json FROM pending_results").fetchone()[0]
    conn.close()
    assert "SECRET" in raw  # unavoidable without a PSK; discovery-only results are unaffected

    pending = db.get_pending_results()
    assert pending[0]["result"]["certificates"][0]["private_key_pem"] == (
        "-----BEGIN PRIVATE KEY-----\nSECRET\n-----END PRIVATE KEY-----"
    )


def test_discovery_results_without_a_key_are_unaffected(tmp_path):
    db = LocalDB(str(tmp_path / "agent.db"), psk="test-agent-psk")
    plain_result = {
        "total_checked": 1,
        "certificates": [{"common_name": "svc.internal.test", "thumbprint": "aa" * 32}],
        "errors": [],
    }
    db.buffer_result("job-1", plain_result)

    pending = db.get_pending_results()
    cert = pending[0]["result"]["certificates"][0]
    assert cert == {"common_name": "svc.internal.test", "thumbprint": "aa" * 32}


def test_mark_result_submitted_removes_row(tmp_path):
    db = LocalDB(str(tmp_path / "agent.db"), psk="test-agent-psk")
    row_id = db.buffer_result("job-1", _result_with_key())
    assert db.get_pending_count() == 1

    db.mark_result_submitted(row_id)
    assert db.get_pending_count() == 0


def test_json_dumps_default_str_still_applies(tmp_path):
    """Regression guard: _encrypt_private_keys must not break the existing
    default=str serialization fallback for non-JSON-native values."""
    import datetime

    db = LocalDB(str(tmp_path / "agent.db"), psk="test-agent-psk")
    result = {
        "total_checked": 1,
        "certificates": [{"common_name": "x", "seen_at": datetime.datetime(2026, 1, 1)}],
        "errors": [],
    }
    db.buffer_result("job-1", result)
    pending = db.get_pending_results()
    assert "2026-01-01" in pending[0]["result"]["certificates"][0]["seen_at"]
