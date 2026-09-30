"""Unit tests for log sanitization."""

from __future__ import annotations

from bernstein.core.sanitize import sanitize_log


def test_sanitize_replaces_newline() -> None:
    assert sanitize_log("a\nb") == "a\\nb"


def test_sanitize_replaces_carriage_return() -> None:
    assert sanitize_log("a\rb") == "a\\rb"


def test_sanitize_replaces_both() -> None:
    assert sanitize_log("a\r\nb") == "a\\r\\nb"


def test_sanitize_passthrough_for_safe_content() -> None:
    value = "safe content 123"
    assert sanitize_log(value) == value


# ---------------------------------------------------------------------------
# One escaper, not three (#5749)
# ---------------------------------------------------------------------------
#
# Three independent character classes used to escape log-bound values:
# sla_store._single_line, and one copy each in spawner_core and
# spawner_merge under the name _sanitise_for_log. All three are gone: the
# spawner call sites call sanitize_log directly, and sla_store's call sites
# call log_safe.for_log, which is sanitize_log plus a length cap. This pins
# that the SLA store's log tokens still agree with sanitize_log on the record
# boundaries.


def test_sla_store_log_token_agrees_with_sanitize_log_on_record_boundaries() -> None:
    from bernstein.core.log_safe import for_log

    # CR, LF, U+2028 LINE SEPARATOR, and U+0085 NEL (a C1 control). Built
    # with chr() rather than an embedded literal so the boundary character
    # stays a visible codepoint reference in source, not an invisible byte.
    raw = "a\rb\nc" + chr(0x2028) + "d" + chr(0x85) + "z"
    assert for_log(raw, limit=256) == sanitize_log(raw)
