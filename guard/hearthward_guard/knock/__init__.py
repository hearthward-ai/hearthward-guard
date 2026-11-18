"""Knock: a never-allowed list, taint (Rule of Two) and tool allowlists on top of Hermes's own
tool approvals, through the documented pre_tool_call hook. See policy.py."""
KNOCK_VERSION = "1.4.1"      # 1.0.0 = job 8 (2026-11-16); 1.1.0 = review fix round (2026-11-17);
                             # 1.2.0 = re-check fix round 2 (2026-11-17);
                             # 1.3.0 = lab re-test fix round 3 (2026-11-17);
                             # 1.4.0 = decision review fix round 4 (2026-11-17)
                             # 1.4.1 = lab re-test 2 fix round 5 (2026-11-17)

from .policy import Knock  # noqa: E402

__all__ = ["Knock", "KNOCK_VERSION"]
