"""The ``allowed_files`` axis on ``DelegationScope`` (#5351, #5418).

``allowed_files`` is a glob field: a pattern is not a path prefix, so it cannot
be decided by the ancestry primitive ``path_prefixes`` uses.  #5418 adds
glob-subsumption grading via :func:`~bernstein.core.path_scope.glob_subsumes`:
the child's patterns must be subsumed by the parent's.  The axis is now in
:data:`SCOPE_BODY_KEYS` and is graded as a narrowing check rather than reported
``comparison_axis_unsupported``.

The compatibility group pins the axis against the implementation exactly as it
stood at the commit this change is written on top of.  ``scope_ref()`` digests
the canonical bytes of ``to_body()``, so emitting a new key unconditionally
would move every stored reference and stop sealed records from replaying
byte-identically.  The literals below were computed on the pre-change class and
are the oracle: a scope that does not use the axis must still produce these
exact bytes and this exact digest.

The presence matrix records what the module actually produces for the three
ways two hops can carry the axis.  Grading keys off each hop's OWN recorded
body, so the three cases are not symmetric, and the asymmetry is recorded here
rather than engineered away.
"""

from __future__ import annotations

from dataclasses import replace

from bernstein.core.identity import delegation
from bernstein.core.identity.delegation_scope import (
    REASON_COMPARISON_AXIS_UNSUPPORTED,
    REASON_ROOT_STRUCTURAL_ONLY,
    VERDICT_FAIL,
    VERDICT_PASS,
    VERDICT_UNPROVEN,
    ChainVerdict,
    DelegationScope,
    HopVerdict,
    grade_chain,
)
from bernstein.core.security.agent_card_signer import canonicalize_jcs

#: A scope exercising every axis that existed before ``allowed_files`` did.
REPRESENTATIVE = DelegationScope(
    permissions=frozenset({"repo.read"}),
    duties=frozenset({"spawn"}),
    task_ids=frozenset({"t1"}),
    path_prefixes=frozenset({"src"}),
    not_after=1.0,
    max_uses=2,
    max_depth=3,
)

#: ``REPRESENTATIVE.to_body()`` on the pre-change class.
PRE_CHANGE_BODY = {
    "duties": ["spawn"],
    "max_depth": 3,
    "max_uses": 2,
    "not_after": 1.0,
    "path_prefixes": ["src"],
    "permissions": ["repo.read"],
    "task_ids": ["t1"],
}

#: The canonical bytes ``scope_ref()`` hashes, on the pre-change class.
#:
#: Frozen under ``JCS_CANONICALIZATION_VERSION`` 3. The literal moved once, when
#: #5494 made integral floats follow RFC 8785 3.2.2.3 (`not_after` serialises as
#: ``1``, not ``1.0``); that bump is versioned and deliberate. If these two
#: literals fail, decide which happened before touching them: a member was added
#: to the body, which is the thing this group exists to catch, or the number
#: grammar moved again, which shows up only in a payload carrying a float.
PRE_CHANGE_JCS = (
    b'{"duties":["spawn"],"max_depth":3,"max_uses":2,"not_after":1,'
    b'"path_prefixes":["src"],"permissions":["repo.read"],"task_ids":["t1"]}'
)

#: ``REPRESENTATIVE.scope_ref()`` on the pre-change class.
PRE_CHANGE_REF = "sha256:82809a0d877bc91da391c41b349a8a5ec405fdb1bc92613adf5a4654b1af6d58"

#: ``DelegationScope().scope_ref()`` on the pre-change class.
PRE_CHANGE_EMPTY_REF = "sha256:0215f133c471eb217982555a27f131a3d94f1b3764ee4679a79c5a2021e875b1"


def _receipt(
    index: int,
    *,
    scope: DelegationScope | None = None,
) -> delegation.DelegationReceipt:
    """Build one receipt directly; the reference is the body's own address."""
    return delegation.DelegationReceipt(
        run_id="run",
        hop_index=index,
        issuer=f"p{index}",
        subject=f"p{index}",
        audience=f"p{index + 1}",
        act="task.delegate",
        created=1_700_000_000 + index,
        hmac=f"{index + 1:064x}",
        scope_ref=None if scope is None else scope.scope_ref(),
        scope=None if scope is None else scope.to_body(),
    )


def _rows(verdict: ChainVerdict) -> dict[int, HopVerdict]:
    return {row.hop_index: row for row in verdict.hops}


CEILING_WITH = DelegationScope(task_ids=frozenset({"t1", "t2"}), allowed_files=frozenset({"src/**"}))
CEILING_WITHOUT = DelegationScope(task_ids=frozenset({"t1", "t2"}))
CHILD_WITH = DelegationScope(task_ids=frozenset({"t1"}), allowed_files=frozenset({"src/core"}))
CHILD_WITHOUT = DelegationScope(task_ids=frozenset({"t1"}))


class TestAScopeThatDoesNotUseTheAxisHashesUnchanged:
    """The trap: a new key that is always emitted re-addresses every scope."""

    def test_the_body_carries_no_allowed_files_key(self):
        assert "allowed_files" not in REPRESENTATIVE.to_body()
        assert REPRESENTATIVE.to_body() == PRE_CHANGE_BODY

    def test_the_canonical_bytes_are_byte_identical(self):
        assert canonicalize_jcs(REPRESENTATIVE.to_body()) == PRE_CHANGE_JCS

    def test_the_reference_is_the_literal_pre_change_digest(self):
        assert REPRESENTATIVE.scope_ref() == PRE_CHANGE_REF

    def test_the_default_scope_reference_is_unchanged_too(self):
        assert "allowed_files" not in DelegationScope().to_body()
        assert DelegationScope().scope_ref() == PRE_CHANGE_EMPTY_REF

    def test_using_the_axis_is_serialized_and_moves_the_reference(self):
        used = replace(REPRESENTATIVE, allowed_files=frozenset({"x"}))
        assert used.to_body()["allowed_files"] == ["x"]
        assert used.scope_ref() != PRE_CHANGE_REF


class TestTheAxisSurvivesTheRoundTrip:
    """``from_body`` is an explicit constructor: an unlisted key is dropped."""

    def test_a_present_value_comes_back(self):
        scope = replace(REPRESENTATIVE, allowed_files=frozenset({"src/**", "docs/*.md"}))
        assert DelegationScope.from_body(scope.to_body()).allowed_files == scope.allowed_files
        assert DelegationScope.from_body(scope.to_body()) == scope

    def test_an_absent_key_reads_as_the_widest_value(self):
        assert DelegationScope.from_body(REPRESENTATIVE.to_body()).allowed_files is None

    def test_the_round_trip_reproduces_the_reference(self):
        """What a dropped key would cost: the grader re-derives the body's address.

        A recorded reference that is not the content address of the inline scope
        is read as one signed body contradicting itself, which fails the hop -
        so a receipt recording this axis would grade ``fail`` rather than
        ``pass`` if the constructor could not read the key back.  A root hop
        with ``allowed_files`` is structural-only and grades ``pass`` (the axis
        is now in SCOPE_BODY_KEYS and REASON_ROOT_STRUCTURAL_ONLY is a PASS reason).
        """
        scope = replace(REPRESENTATIVE, allowed_files=frozenset({"src/**"}))
        assert DelegationScope.from_body(scope.to_body()).scope_ref() == scope.scope_ref()
        assert grade_chain([_receipt(0, scope=scope)]).hops[0].verdict == VERDICT_PASS


class TestPresenceMatrix:
    """What the module produces when one, both, or neither hop records the axis.

    After #5418 the axis is graded via glob-subsumption: child patterns must be
    subsumed by parent patterns.  Root hops are structural-only and grade PASS
    (REASON_ROOT_STRUCTURAL_ONLY is in PASS_REASONS, not UNPROVEN_REASONS).
    Non-root hops that successfully narrow on this axis also grade PASS.
    A non-root hop that widens grades FAIL.
    """

    def test_both_sides_record_it_and_child_is_subsumed(self):
        """Child scope src/core is inside parent scope src/**, so narrowing holds.

        Both hops grade PASS: hop 0 is structural-only (PASS), hop 1 narrows
        correctly because ``src/core`` is subsumed by ``src/**``.
        """
        verdict = grade_chain([_receipt(0, scope=CEILING_WITH), _receipt(1, scope=CHILD_WITH)])
        rows = _rows(verdict)
        assert verdict.verdict == VERDICT_PASS
        assert verdict.unproven_hops == 0
        assert rows[0].verdict == VERDICT_PASS
        assert rows[0].axes == ()  # allowed_files IS in SCOPE_BODY_KEYS now
        assert REASON_ROOT_STRUCTURAL_ONLY in rows[0].reasons
        assert REASON_COMPARISON_AXIS_UNSUPPORTED not in rows[0].reasons
        assert rows[1].verdict == VERDICT_PASS
        assert rows[1].axes == ()

    def test_the_child_records_it_and_the_ceiling_does_not(self):
        """Parent carries no ``allowed_files`` restriction; child adding one narrows.

        ``None`` on the parent means unconstrained (admits everything), so a child
        claiming any non-empty pattern is strictly narrower.  Both hops grade PASS:
        root is structural-only (PASS), child narrows a None ceiling (PASS).
        """
        verdict = grade_chain([_receipt(0, scope=CEILING_WITHOUT), _receipt(1, scope=CHILD_WITH)])
        rows = _rows(verdict)
        assert verdict.verdict == VERDICT_PASS
        assert verdict.unproven_hops == 0
        assert rows[0].verdict == VERDICT_PASS
        assert rows[0].axes == ()
        assert rows[1].verdict == VERDICT_PASS
        assert rows[1].axes == ()

    def test_the_ceiling_records_it_and_the_child_does_not(self):
        """Child carries no ``allowed_files``; parent does.  ``None`` child is always a subset.

        A child that claims nothing is narrower than any parent restriction.  Both
        hops grade PASS: root is structural-only (PASS), child with None allowed_files
        passes because ``None`` child ⊆ any parent.
        """
        verdict = grade_chain([_receipt(0, scope=CEILING_WITH), _receipt(1, scope=CHILD_WITHOUT)])
        rows = _rows(verdict)
        assert verdict.verdict == VERDICT_PASS
        assert verdict.unproven_hops == 0
        assert rows[0].verdict == VERDICT_PASS
        assert rows[0].axes == ()
        assert rows[1].verdict == VERDICT_PASS
        assert rows[1].axes == ()
        assert rows[1].reasons == ()

    def test_child_wider_than_parent_reports_allowed_files_violation(self):
        """A child pattern outside the parent scope is a widening on this axis.

        Widening is in FAIL_REASONS, so the non-root hop grades FAIL.
        """
        wider_child = DelegationScope(task_ids=frozenset({"t1"}), allowed_files=frozenset({"other/**"}))
        verdict = grade_chain([_receipt(0, scope=CEILING_WITH), _receipt(1, scope=wider_child)])
        rows = _rows(verdict)
        assert rows[1].verdict == VERDICT_FAIL
        assert "allowed_files" in rows[1].axes
