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
# spawner_merge under the name _sanitise_for_log. The two spawner copies are
# gone now -- every call site in both modules was rewritten to call
# sanitize_log directly, landed by a parallel consolidation on this same
# issue -- leaving sla_store._single_line as the one remaining wrapper, kept
# because it adds a length cap sanitize_log does not have. This pins that
# its escaping still agrees with sanitize_log's on the record boundaries, and
# additionally escapes non-printable format characters (bidi, zero-width).


def test_single_line_agrees_with_sanitize_log_on_every_boundary_character() -> None:
    from bernstein.core.planning.sla_store import _single_line

    # CR, LF, U+2028 LINE SEPARATOR, and U+0085 NEL (a C1 control). Built
    # with chr() rather than an embedded literal so the boundary character
    # stays a visible codepoint reference in source, not an invisible byte.
    raw = "a\rb\nc" + chr(0x2028) + "d" + chr(0x85) + "z"
    assert _single_line(raw) == sanitize_log(raw)

    # Non-printable format characters sanitize_log leaves alone: escaped here.
    fmt = "a" + chr(0x202E) + "b" + chr(0x200B) + "c"
    out = _single_line(fmt)
    assert chr(0x202E) not in out
    assert chr(0x200B) not in out
    assert "\\u202e" in out
    assert "\\u200b" in out
