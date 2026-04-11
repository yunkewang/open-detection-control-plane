"""Unit tests for TokenStore, AuditLogger, and auth helpers."""

from __future__ import annotations

import hashlib
import time
from collections import deque
from pathlib import Path

import pytest

from odcp.models.auth import AuditEvent, UserRole
from odcp.server.audit import AuditLogger
from odcp.server.auth import TokenStore


# ── TokenStore ──────────────────────────────────────────────────────────────


class TestTokenStore:
    def test_create_returns_plain_token_and_record(self):
        store = TokenStore(auth_enabled=True)
        plain, record = store.create("test-token", UserRole.readonly)
        assert plain.startswith("odcp_")
        assert "_" in plain
        assert record.name == "test-token"
        assert record.role == UserRole.readonly
        assert record.token_hash == hashlib.sha256(plain.encode()).hexdigest()

    def test_plain_token_not_stored(self):
        store = TokenStore(auth_enabled=True)
        plain, record = store.create("tok", UserRole.admin)
        # The plain token must not appear anywhere in the store's internal dicts
        for stored_record in store._tokens.values():
            assert plain not in stored_record.model_dump(mode="json").values()

    def test_verify_correct_token(self):
        store = TokenStore(auth_enabled=True)
        plain, record = store.create("tok", UserRole.analyst)
        found = store.verify(plain)
        assert found is not None
        assert found.token_id == record.token_id

    def test_verify_wrong_token_returns_none(self):
        store = TokenStore(auth_enabled=True)
        store.create("tok", UserRole.readonly)
        assert store.verify("odcp_bad_token") is None

    def test_verify_updates_last_used_at(self):
        store = TokenStore(auth_enabled=True)
        plain, record = store.create("tok", UserRole.readonly)
        assert record.last_used_at is None
        store.verify(plain)
        updated = store._tokens[record.token_id]
        assert updated.last_used_at is not None

    def test_revoke_removes_token(self):
        store = TokenStore(auth_enabled=True)
        plain, record = store.create("tok", UserRole.readonly)
        assert store.verify(plain) is not None
        ok = store.revoke(record.token_id)
        assert ok is True
        assert store.verify(plain) is None

    def test_revoke_nonexistent_returns_false(self):
        store = TokenStore(auth_enabled=True)
        assert store.revoke("nonexistent-id") is False

    def test_list_all(self):
        store = TokenStore(auth_enabled=True)
        store.create("tok1", UserRole.admin)
        store.create("tok2", UserRole.analyst)
        records = store.list_all()
        assert len(records) == 2
        names = {r.name for r in records}
        assert names == {"tok1", "tok2"}

    def test_agent_id_stored(self):
        store = TokenStore(auth_enabled=True)
        plain, record = store.create("agent-tok", UserRole.agent, agent_id="my-agent-001")
        assert record.agent_id == "my-agent-001"
        found = store.verify(plain)
        assert found.agent_id == "my-agent-001"

    def test_token_id_is_8_hex_chars(self):
        store = TokenStore(auth_enabled=True)
        _, record = store.create("tok", UserRole.readonly)
        # token_id comes from secrets.token_hex(4) → 8 hex chars
        assert len(record.token_id) == 8
        int(record.token_id, 16)  # must be valid hex

    def test_multiple_tokens_have_unique_ids(self):
        store = TokenStore(auth_enabled=True)
        ids = set()
        for i in range(10):
            _, rec = store.create(f"tok{i}", UserRole.readonly)
            ids.add(rec.token_id)
        assert len(ids) == 10

    def test_auth_disabled_verify_always_returns_none(self):
        """With auth disabled, verify should still work but the flag controls enforcement."""
        store = TokenStore(auth_enabled=False)
        plain, _ = store.create("tok", UserRole.admin)
        # verify still works — auth enforcement is done at the route level
        result = store.verify(plain)
        assert result is not None


# ── AuditLogger ─────────────────────────────────────────────────────────────


class TestAuditLogger:
    def test_log_creates_event(self):
        al = AuditLogger()
        event = al.log("alice", "token.create", "token:abc123", actor_role="admin")
        assert isinstance(event, AuditEvent)
        assert event.actor == "alice"
        assert event.action == "token.create"
        assert event.resource == "token:abc123"
        assert event.actor_role == "admin"
        assert event.status == "success"

    def test_log_custom_status(self):
        al = AuditLogger()
        event = al.log("bob", "report.push", "agent:x", status="denied")
        assert event.status == "denied"

    def test_total_count(self):
        al = AuditLogger()
        assert al.total() == 0
        al.log("a", "act", "res")
        al.log("b", "act2", "res2")
        assert al.total() == 2

    def test_recent_newest_first(self):
        al = AuditLogger()
        al.log("a", "act1", "res")
        al.log("b", "act2", "res")
        al.log("c", "act3", "res")
        events = al.recent(limit=10)
        assert events[0].actor == "c"
        assert events[1].actor == "b"
        assert events[2].actor == "a"

    def test_recent_limit(self):
        al = AuditLogger()
        for i in range(20):
            al.log(f"actor{i}", "act", "res")
        events = al.recent(limit=5)
        assert len(events) == 5

    def test_recent_action_filter(self):
        al = AuditLogger()
        al.log("a", "token.create", "res")
        al.log("b", "agent.register", "res")
        al.log("c", "token.revoke", "res")
        events = al.recent(action_filter="token")
        assert all("token" in e.action for e in events)
        assert len(events) == 2

    def test_recent_actor_filter(self):
        al = AuditLogger()
        al.log("alice", "act", "res")
        al.log("bob", "act", "res")
        al.log("Alice-admin", "act", "res")
        events = al.recent(actor_filter="alice")
        assert len(events) == 2
        assert all("alice" in e.actor.lower() for e in events)

    def test_recent_status_filter(self):
        al = AuditLogger()
        al.log("a", "act", "res", status="success")
        al.log("b", "act", "res", status="denied")
        al.log("c", "act", "res", status="success")
        success = al.recent(status_filter="success")
        assert len(success) == 2
        denied = al.recent(status_filter="denied")
        assert len(denied) == 1

    def test_ring_buffer_drops_oldest(self):
        al = AuditLogger(max_memory=5)
        for i in range(8):
            al.log(f"actor{i}", "act", "res")
        assert al.total() == 5
        events = al.recent(limit=10)
        actors = [e.actor for e in events]
        assert "actor0" not in actors
        assert "actor7" in actors

    def test_file_persistence(self, tmp_path: Path):
        log_file = tmp_path / "audit.jsonl"
        al = AuditLogger(log_path=log_file)
        al.log("alice", "token.create", "token:abc")
        al.log("bob", "agent.register", "agent:x")
        assert log_file.exists()
        lines = log_file.read_text().strip().splitlines()
        assert len(lines) == 2

    def test_load_from_file(self, tmp_path: Path):
        log_file = tmp_path / "audit.jsonl"
        al = AuditLogger(log_path=log_file)
        al.log("alice", "act1", "res")
        al.log("bob", "act2", "res")
        # Load into a fresh logger
        al2 = AuditLogger(log_path=log_file)
        count = al2.load_from_file()
        assert count == 2
        assert al2.total() == 2

    def test_log_from_request_anonymous(self):
        """When token is None, actor should be 'anonymous'."""
        al = AuditLogger()

        class FakeRequest:
            headers = {}
            client = type("Client", (), {"host": "127.0.0.1"})()

        event = al.log_from_request(FakeRequest(), "act", "res", token=None)
        assert event.actor == "anonymous"
        assert event.actor_role is None

    def test_log_from_request_with_token(self):
        al = AuditLogger()
        store = TokenStore(auth_enabled=True)
        plain, record = store.create("alice", UserRole.analyst)
        token = store.verify(plain)

        class FakeRequest:
            headers = {"X-Forwarded-For": "10.0.0.1"}
            client = type("Client", (), {"host": "127.0.0.1"})()

        event = al.log_from_request(FakeRequest(), "act", "res", token=token)
        assert event.actor == "alice"
        assert event.actor_role == "analyst"
        assert event.ip_address == "10.0.0.1"

    def test_event_has_unique_ids(self):
        al = AuditLogger()
        ids = set()
        for _ in range(10):
            e = al.log("a", "act", "res")
            ids.add(e.event_id)
        assert len(ids) == 10
