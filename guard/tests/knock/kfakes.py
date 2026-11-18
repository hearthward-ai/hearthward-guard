"""Helpers for Knock tests (stdlib only)."""
from __future__ import annotations

import sys
import types
from unittest import mock

from tests.unit import fakes
from tests.unit.fakes import OWNER

GATE_OK = lambda: (True, "")          # noqa: E731
GATE_NO = lambda: (False, "test")     # noqa: E731
APPROVER_OK = lambda platform: (True, "")     # noqa: E731  (approvals.approvers names owners only)


NO_CARD_LIMIT = lambda platform: None    # noqa: E731  (tests of other logic: the card shows everything)


def make(knock=None, gate=GATE_OK, approver=APPROVER_OK, card_limit=NO_CARD_LIMIT, **settings):
    """card_limit: per-platform card budget (fix round 3). Older tests use the fake "chatapp"
    platform for logic other than card length, so they keep an unlimited card; pass None for
    Knock's real budgets (policy.default_card_limit)."""
    s = dict(settings)
    if knock is not None:
        s["knock"] = knock
    g = fakes.make_guard(s)
    g.knock.gate_check = gate
    g.knock.approver_check = approver
    if card_limit is not None:
        g.knock.card_limit = card_limit
    return g, g.knock


def turn(k, sid="s1", plat="chatapp", sender=OWNER, msg="hello", first=True, hist=None, task="", parent=""):
    return k.on_pre_llm_call(session_id=sid, user_message=msg, conversation_history=hist or [],
                             is_first_turn=first, model="m", platform=plat, sender_id=sender, task_id=task,
                             parent_session_id=parent)


def call(k, tool, args=None, sid="s1", conv="", task=""):
    return k.on_pre_tool_call(tool_name=tool, args={} if args is None else args, task_id=task, session_id=sid,
                              tool_call_id="tc", turn_id="t", conversation_id=conv)


def is_block(r) -> bool:
    return isinstance(r, dict) and r.get("action") == "block" and isinstance(r.get("message"), str) and \
        bool(r["message"])


def is_ask(r) -> bool:
    return isinstance(r, dict) and r.get("action") == "approve" and bool(r.get("rule_key")) and bool(r.get("message"))


def hermes_modules(yolo_session=False, unattended=False, room=None):
    """Fake public Hermes modules used by the default gate check."""
    tools_pkg = types.ModuleType("tools")
    appr = types.ModuleType("tools.approval")
    appr.is_current_session_yolo_enabled = lambda: yolo_session
    gw = types.ModuleType("gateway")
    fin = types.ModuleType("gateway.session_finite")
    fin.unattended_turn = lambda: unattended
    hr = types.ModuleType("gateway.hosted_room_execution_policy")
    hr.current_room_execution_policy = lambda: room
    return mock.patch.dict(sys.modules, {"tools": tools_pkg, "tools.approval": appr, "gateway": gw,
                                         "gateway.session_finite": fin,
                                         "gateway.hosted_room_execution_policy": hr})
