"""Unit tests for the CoSAI evidence-pack control map (Issue #5945).

Covers:
* Registration: ``cosai`` is in ``SUPPORTED_STANDARDS`` and resolves via
  ``get_standard_map``.
* Shape: every control carries the required keys and a valid status.
* Completeness: every mapped control resolves to exactly one of ``mapped``
  / ``partial`` / ``todo`` and status counts sum to ``len(CONTROLS)``.
* Honesty: at least one control is marked ``"partial"`` and at least one
  is marked ``"todo"`` (the map is not all-green).
* Grounding: every ``selector`` event-type token cited by the map is a
  literal ``event_type`` string emitted by an audit writer in the Bernstein source tree.
* End-to-end: ``build_evidence_pack`` produces a well-formed pack for
  ``cosai`` whose ``controls.json`` matches the map and whose manifest
  counts match the actual status distribution.
* Risk Map ID integrity: every cited upstream Risk Map identifier exists in
  the pinned upstream CoSAI catalogue.
* Map-to-page drift guard: ``test_cosai_mapping_page_and_map_stay_in_sync``
  validates 1:1 parity between ``cosai.CONTROLS`` and ``docs/compliance/cosai-mapping.md``
  for control IDs, statuses, Risk Map IDs, and artefacts, and ensures module/test
  links exist and exercise their targets.
"""

from __future__ import annotations

import ast
import functools
import hashlib
import json
import re
import zipfile
from collections import Counter
from pathlib import Path
from typing import Any

import pytest

from bernstein.compliance import cosai
from bernstein.compliance.evidence_pack import (
    SUPPORTED_STANDARDS,
    build_evidence_pack,
    get_standard_map,
)

pytestmark = pytest.mark.whole_tree_guard

# Selector tokens that are legitimate evidence but are not themselves
# ``event_type`` literals (lineage / cost-ledger fields or the "n/a" placeholder).
_NON_EVENT_SELECTOR_TOKENS: frozenset[str] = frozenset(
    {
        "content_hash",
        "parent_hashes",
        "spent_usd",
        "budget_usd",
        "n/a",
    }
)

_VALID_STATUSES: frozenset[str] = frozenset({"mapped", "partial", "todo"})

# Pinned upstream identifiers from cosai-oasis/secure-ai-tooling risk-map/yaml/controls.yaml
_PINNED_RISK_MAP_IDS: frozenset[str] = frozenset(
    {
        "controlAgentPluginUserControl",
        "controlAgentIntegrityManagement",
        "controlAgentPluginPermissions",
        "controlAgentExecutionBounds",
        "controlAgentObservability",
        "controlModelAndDataIntegrityManagement",
        "controlInputValidationAndSanitization",
    }
)


def _source_event_types() -> set[str]:
    """Collect every literal ``event_type`` string actively emitted in ``src/bernstein``.

    Uses an AST walk over ``src/bernstein`` only (ignoring tests and docstrings).
    Collects string literals passed as ``event_type=...`` keyword arguments,
    as well as ``EVENT_*`` / ``*_EVENT_*`` constant definitions whose symbols
    are referenced in executable code.
    """
    repo_root = Path(__file__).resolve().parents[3]
    src_root = repo_root / "src" / "bernstein"
    assert src_root.is_dir(), src_root

    emitted_events: set[str] = set()
    constants: dict[str, str] = {}
    name_usages: Counter[str] = Counter()

    for path in src_root.rglob("*.py"):
        try:
            tree = ast.parse(path.read_bytes(), filename=str(path))
        except (SyntaxError, OSError):
            continue

        for node in ast.walk(tree):
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if (
                        isinstance(target, ast.Name)
                        and ("EVENT" in target.id or target.id.startswith("EVENT_"))
                        and isinstance(node.value, ast.Constant)
                        and isinstance(node.value.value, str)
                    ):
                        constants[target.id] = node.value.value

            elif isinstance(node, ast.Call):
                for kw in node.keywords:
                    if kw.arg != "event_type":
                        continue
                    if isinstance(kw.value, ast.Constant) and isinstance(kw.value.value, str):
                        emitted_events.add(kw.value.value)
                    elif isinstance(kw.value, ast.Name):
                        name_usages[kw.value.id] += 1
                    elif isinstance(kw.value, ast.Attribute):
                        name_usages[kw.value.attr] += 1

            elif isinstance(node, ast.Name):
                name_usages[node.id] += 1

    # Include constants whose identifier is referenced outside its own assignment
    for cname, cval in constants.items():
        if name_usages[cname] >= 2:
            emitted_events.add(cval)

    return emitted_events


@pytest.fixture(scope="module")
def source_event_types() -> set[str]:
    return _source_event_types()


def test_standard_is_registered() -> None:
    assert "cosai" in SUPPORTED_STANDARDS
    mapping = get_standard_map("cosai")
    assert mapping["regulation"]
    assert mapping["controls"]


def test_every_control_has_required_keys_and_valid_status() -> None:
    mapping = get_standard_map("cosai")
    for control in mapping["controls"]:
        for key in ("control_id", "requirement", "artefact", "selector", "status"):
            assert key in control, (control.get("control_id"), key)
            assert control[key] != "", (control.get("control_id"), key)
        assert control["status"] in _VALID_STATUSES, control


def test_every_cosai_control_is_counted_exactly_once() -> None:
    mapping = get_standard_map("cosai")
    controls = mapping["controls"]
    counted = sum(1 for c in controls if c["status"] in _VALID_STATUSES)
    assert counted == len(controls)

    statuses = [c["status"] for c in controls]
    mapped = statuses.count("mapped")
    partial = statuses.count("partial")
    todo = statuses.count("todo")
    assert mapped + partial + todo == len(controls)
    assert mapped == 7
    assert partial == 16
    assert todo == 2


def test_map_honesty_declares_partial_and_todo() -> None:
    mapping = get_standard_map("cosai")
    statuses = {c["control_id"]: c["status"] for c in mapping["controls"]}
    assert "partial" in statuses.values(), statuses
    assert "todo" in statuses.values(), statuses


def test_todo_controls_carry_no_chain_selector() -> None:
    mapping = get_standard_map("cosai")
    for control in mapping["controls"]:
        if control["status"] == "todo":
            assert control["selector"] == "n/a", control
            assert control["artefact"] == "n/a", control


def test_selectors_reference_real_event_types(source_event_types: set[str]) -> None:
    mapping = get_standard_map("cosai")
    unknown: list[tuple[str, str]] = []
    for control in mapping["controls"]:
        for token in str(control["selector"]).split(","):
            token = token.strip()
            if not token or token in _NON_EVENT_SELECTOR_TOKENS:
                continue
            if token not in source_event_types:
                unknown.append((control["control_id"], token))
    assert not unknown, f"cosai cites event types not found in src: {unknown}"


def test_risk_map_ids_exist_upstream() -> None:
    mapping = get_standard_map("cosai")
    for control in mapping["controls"]:
        req = control["requirement"]
        match = re.search(r"Risk Map:\s*([A-Za-z0-9_]+)", req)
        if match:
            risk_id = match.group(1)
            assert risk_id in _PINNED_RISK_MAP_IDS, (
                f"Unknown Risk Map ID {risk_id} in {control['control_id']}; expected one of {_PINNED_RISK_MAP_IDS}"
            )


def test_control_map_returns_copy() -> None:
    first = cosai.control_map()
    first["controls"][0]["status"] = "MUTATED"
    second = cosai.control_map()
    assert second["controls"][0]["status"] != "MUTATED"


# ---------------------------------------------------------------------------
# End-to-end pack build
# ---------------------------------------------------------------------------


def _seed_sdd(tmp_path: Path) -> Path:
    sdd = tmp_path / ".sdd"
    audit = sdd / "audit"
    audit.mkdir(parents=True)
    (audit / "log.jsonl").write_text(
        json.dumps(
            {
                "timestamp": "2026-01-05T10:00:00+00:00",
                "event_type": "task.transition",
                "actor": "agent",
                "resource_type": "task",
                "resource_id": "T-1",
                "hmac": "a" * 64,
            },
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    return sdd


def test_build_evidence_pack_wellformed(tmp_path: Path) -> None:
    sdd = _seed_sdd(tmp_path)
    out = tmp_path / "pack.zip"
    pack = build_evidence_pack(
        sdd_dir=sdd,
        standard="cosai",
        output_path=out,
        write=True,
    )
    assert pack.standard == "cosai"
    assert pack.event_count == 1

    mapping = get_standard_map("cosai")
    n_controls = len(mapping["controls"])
    assert (
        pack.controls_mapped + pack.controls_partial + pack.controls_organisational + pack.controls_todo == n_controls
    )
    assert pack.controls_mapped == 7
    assert pack.controls_partial == 16
    assert pack.controls_todo == 2
    assert out.is_file()

    with zipfile.ZipFile(out) as zf:
        names = set(zf.namelist())
        for required in (
            "manifest.json",
            "controls.json",
            "audit-chain/events.jsonl",
            "lineage/log.jsonl",
            "costs/cost_history.jsonl",
            "README.md",
        ):
            assert required in names, required

        controls = json.loads(zf.read("controls.json"))
        assert controls["standard"] == "cosai"
        assert len(controls["controls"]) == n_controls

        manifest = json.loads(zf.read("manifest.json"))
        assert manifest["controls_mapped"] == pack.controls_mapped
        assert manifest["controls_partial"] == pack.controls_partial
        assert manifest["controls_todo"] == pack.controls_todo
        assert pack.to_dict()["controls_todo"] == pack.controls_todo
        for name, digest in manifest["artefacts"].items():
            if name == "manifest.json":
                continue
            assert hashlib.sha256(zf.read(name)).hexdigest() == digest, name


def test_build_evidence_pack_is_deterministic(tmp_path: Path) -> None:
    sdd = _seed_sdd(tmp_path)
    a = build_evidence_pack(sdd_dir=sdd, standard="cosai", output_path=tmp_path / "a.zip")
    b = build_evidence_pack(sdd_dir=sdd, standard="cosai", output_path=tmp_path / "b.zip")
    assert a.sha256 == b.sha256
    assert (tmp_path / "a.zip").read_bytes() == (tmp_path / "b.zip").read_bytes()


def test_cosai_mapping_page_and_map_stay_in_sync() -> None:
    """Validate 1:1 correspondence between docs/compliance/cosai-mapping.md and cosai.py.

    Guards against drift across control IDs, statuses, Risk Map IDs, artefacts,
    and checks that implementation and test paths exist and exercise cited modules.
    """
    repo_root = Path(__file__).resolve().parents[3]
    doc_path = repo_root / "docs" / "compliance" / "cosai-mapping.md"
    assert doc_path.is_file(), f"Missing docs file: {doc_path}"

    text = doc_path.read_text(encoding="utf-8")

    control_prefixes = (
        "human-governed-accountable.",
        "bounded-resilient.",
        "transparent-verifiable.",
        "mcp-threats.",
    )
    page_rows: dict[str, dict[str, Any]] = {}
    for line in text.splitlines():
        line = line.strip()
        if not line.startswith("|") or not line.endswith("|"):
            continue
        cells = [c.strip().strip("`") for c in line.strip("|").split("|")]
        if len(cells) >= 7 and any(cells[0].startswith(p) for p in control_prefixes):
            ctrl_id = cells[0]
            page_rows[ctrl_id] = {
                "risk_map_id": cells[1],
                "req_short": cells[2],
                "module_path": cells[3],
                "test_path": cells[4],
                "artefact": cells[5],
                "status": cells[6],
            }

    mapping = get_standard_map("cosai")
    map_controls = {c["control_id"]: c for c in mapping["controls"]}

    # Exact control ID match
    assert set(page_rows.keys()) == set(map_controls.keys()), (
        f"Drift in control IDs between page and map: {set(page_rows.keys()) ^ set(map_controls.keys())}"
    )

    # Validate count summary sentence on the doc page
    assert "7 `mapped`, 16 `partial`, 2 `todo` - 25 of 25 controls counted" in text, (
        "Status count summary line in cosai-mapping.md does not match expected 7/16/2"
    )

    missing_paths: list[str] = []
    unrelated_tests: list[tuple[str, str, str]] = []

    for ctrl_id, page_data in page_rows.items():
        map_c = map_controls[ctrl_id]

        # Status match
        assert page_data["status"] == map_c["status"], (
            f"Status drift on {ctrl_id}: page={page_data['status']}, map={map_c['status']}"
        )

        # Artefact match
        assert page_data["artefact"] == map_c["artefact"], (
            f"Artefact drift on {ctrl_id}: page={page_data['artefact']}, map={map_c['artefact']}"
        )

        # Risk Map ID match
        risk_match = re.search(r"Risk Map:\s*([A-Za-z0-9_]+)", map_c["requirement"])
        expected_risk_id = risk_match.group(1) if risk_match else "n/a"
        assert page_data["risk_map_id"] == expected_risk_id, (
            f"Risk Map ID drift on {ctrl_id}: page={page_data['risk_map_id']}, map={expected_risk_id}"
        )

        if expected_risk_id != "n/a":
            assert expected_risk_id in _PINNED_RISK_MAP_IDS, (
                f"Page cites unpinned Risk Map ID {expected_risk_id} for {ctrl_id}"
            )

        # Path integrity for non-todo rows
        if page_data["status"] == "todo":
            assert page_data["module_path"] == "n/a", f"Todo row {ctrl_id} must have n/a module"
            assert page_data["test_path"] == "n/a", f"Todo row {ctrl_id} must have n/a test"
        else:
            assert page_data["module_path"] != "n/a", f"Non-todo row {ctrl_id} has n/a module"
            assert page_data["test_path"] != "n/a", f"Non-todo row {ctrl_id} has n/a test"

            full_mod = repo_root / page_data["module_path"]
            full_test = repo_root / page_data["test_path"]

            if not full_mod.exists():
                missing_paths.append(page_data["module_path"])
            if not full_test.exists():
                missing_paths.append(page_data["test_path"])

            if full_mod.exists() and full_test.exists():
                test_content = full_test.read_text(encoding="utf-8")
                mod_stem = full_mod.stem
                mod_import = page_data["module_path"].replace("src/", "").replace(".py", "").replace("/", ".")
                if mod_stem not in test_content and mod_import not in test_content:
                    unrelated_tests.append((ctrl_id, page_data["module_path"], page_data["test_path"]))

    assert not missing_paths, f"cosai-mapping.md cites paths that do not exist: {missing_paths}"
    assert not unrelated_tests, f"cosai-mapping.md cites tests that do not reference module: {unrelated_tests}"


# ---------------------------------------------------------------------------
# MCP threat classes (#6217): the twelve classes of the CoSAI MCP security paper
# ---------------------------------------------------------------------------

#: The paper's own class titles, MCP-T1 to MCP-T12. A row quotes its class title, so a
#: reworded title is a different claim about which class the row answers.
_MCP_CLASS_TITLES: dict[int, str] = {
    1: "Improper Authentication and Identity Management",
    2: "Missing or Improper Access Control",
    3: "Input Validation / Sanitization Failures",
    4: "Input / Instruction Boundary Distinction Failure",
    5: "Inadequate Data Protection and Confidentiality Controls",
    6: "Missing Integrity / Verification Controls",
    7: "Session and Transport Security Failures",
    8: "Network Binding / Isolation Failures",
    9: "Trust Boundary and Privilege Design Failures",
    10: "Resource Management / Rate-Limiting Absence",
    11: "Supply Chain and Lifecycle Security Failures",
    12: "Insufficient Logging, Monitoring, and Auditability",
}

#: MCP chain events and the recorder that writes each. A row may cite one only while a
#: non-test module outside ``audit_chain.py`` calls its recorder: an event type that
#: exists but is never emitted is not evidence.
_MCP_EVENT_RECORDERS: dict[str, str] = {
    "mcp.stateless_call": "record_mcp_stateless_call",
    "mcp.capability_drift": "record_mcp_capability_drift",
    "mcp.task_handle": "record_mcp_task_handle",
}


def _mcp_rows() -> list[dict[str, Any]]:
    return [c for c in get_standard_map("cosai")["controls"] if str(c["control_id"]).startswith("mcp-threats.")]


@functools.cache
def _production_callers(function_name: str) -> tuple[str, ...]:
    """Files under ``src/bernstein`` (other than ``audit_chain.py``) that call *function_name*."""
    src_root = Path(__file__).resolve().parents[3] / "src" / "bernstein"
    callers: list[str] = []
    for path in src_root.rglob("*.py"):
        if path.name == "audit_chain.py":
            continue
        try:
            tree = ast.parse(path.read_bytes(), filename=str(path))
        except (SyntaxError, OSError):
            continue
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            name = func.id if isinstance(func, ast.Name) else func.attr if isinstance(func, ast.Attribute) else ""
            if name == function_name:
                callers.append(path.relative_to(src_root).as_posix())
                break
    return tuple(callers)


def test_mcp_paper_is_recorded_with_its_version_and_date() -> None:
    """The paper may renumber, so the rows say which revision they follow."""
    for key in ("title", "publisher", "version", "date", "status", "announced", "url"):
        assert cosai.MCP_PAPER.get(key), key

    page = (Path(__file__).resolve().parents[3] / "docs" / "compliance" / "cosai-mapping.md").read_text(
        encoding="utf-8"
    )
    assert cosai.MCP_PAPER["version"] in page
    assert cosai.MCP_PAPER["date"] in page


def test_every_mcp_threat_class_has_exactly_one_row() -> None:
    numbers = []
    for row in _mcp_rows():
        match = re.fullmatch(r"mcp-threats\.t(\d+)-[a-z-]+", str(row["control_id"]))
        assert match, row["control_id"]
        numbers.append(int(match.group(1)))
    assert sorted(numbers) == list(range(1, 13)), numbers


def test_each_mcp_row_quotes_the_papers_class_title() -> None:
    for row in _mcp_rows():
        number = int(re.search(r"\.t(\d+)-", str(row["control_id"])).group(1))  # type: ignore[union-attr]
        expected = f"MCP-T{number} {_MCP_CLASS_TITLES[number]}:"
        assert str(row["requirement"]).startswith(expected), (row["control_id"], expected)


def test_no_mcp_row_claims_more_than_the_chain_records() -> None:
    """A ``mapped`` row needs a chained event, and none of the twelve is ``mapped`` today.

    The signing and scan verdicts, transport authentication decisions and refused inputs are
    not written to the audit chain, so every class that rests on them is ``partial``. If a
    row is promoted this test asks for the event that justifies it.
    """
    for row in _mcp_rows():
        assert row["status"] in {"partial", "todo"}, row["control_id"]
        if row["status"] == "mapped":
            assert row["selector"] != "n/a", row["control_id"]


def test_mcp_rows_cite_only_events_that_production_code_emits() -> None:
    for row in _mcp_rows():
        for token in str(row["selector"]).split(","):
            recorder = _MCP_EVENT_RECORDERS.get(token.strip())
            if recorder is None:
                continue
            assert _production_callers(recorder), (
                f"{row['control_id']} cites {token}, but {recorder} has no production caller"
            )


def test_mcp_task_handle_is_not_cited_while_nothing_emits_it() -> None:
    """``mcp.task_handle`` exists as an event type but ``record_mcp_task_handle`` is never called."""
    cited = {t.strip() for row in _mcp_rows() for t in str(row["selector"]).split(",")}
    if _production_callers("record_mcp_task_handle"):
        return  # it is emitted now; a row may cite it
    assert "mcp.task_handle" not in cited
