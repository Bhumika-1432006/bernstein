"""The AI Act application dates live in one table and the report reads from it (#6215)."""

from __future__ import annotations

import re
from datetime import date
from pathlib import Path

import pytest

from bernstein.compliance import ai_act_dates
from bernstein.compliance.ai_act_dates import AI_ACT_DATES, DATES_AS_OF, Obligation, applicable_dates
from bernstein.compliance.eu_ai_act import (
    ComplianceEngine,
    RiskCategory,
    SystemDescriptor,
    _AnnexIIIClassifier,  # pyright: ignore[reportPrivateUsage]
)

REPO = Path(__file__).resolve().parents[2]

# Typed out from the Official Journal text, deliberately not derived from the table under test.
# Regulation (EU) 2024/1689, Article 113 (OJ L, 2024/1689, 12.7.2024) as amended by
# Regulation (EU) 2026/1744 (OJ L, 2026/1744, 24.7.2026).
EXPECTED: dict[Obligation, tuple[date, str]] = {
    Obligation.ARTICLE_50: (date(2026, 8, 2), "Article 113, second paragraph"),
    Obligation.ARTICLE_50_2_EXISTING_SYSTEMS: (date(2026, 12, 2), "Article 111(4)"),
    Obligation.ANNEX_III_HIGH_RISK: (date(2027, 12, 2), "Article 113, third paragraph, point (c)(i)"),
    Obligation.ANNEX_I_HIGH_RISK: (date(2028, 8, 2), "Article 113, third paragraph, point (c)(ii)"),
    Obligation.HIGH_RISK_PUBLIC_AUTHORITIES: (date(2030, 8, 2), "Article 111(2)"),
    Obligation.GPAI: (date(2025, 8, 2), "Article 113, third paragraph, point (b)"),
    Obligation.GPAI_EXISTING_MODELS: (date(2027, 8, 2), "Article 111(3)"),
}


def _descriptor(**overrides: object) -> SystemDescriptor:
    base: dict[str, object] = {
        "name": "sys",
        "version": "1.0.0",
        "description": "d",
        "intended_use": "i",
        "deployment_context": "c",
    }
    base.update(overrides)
    return SystemDescriptor(**base)  # type: ignore[arg-type]


def _summary(**overrides: object) -> dict[str, object]:
    return ComplianceEngine().run(_descriptor(**overrides), include_tech_doc=False)["compliance_summary"]


class TestTable:
    def test_every_obligation_has_exactly_one_row(self) -> None:
        assert set(AI_ACT_DATES) == set(Obligation) == set(EXPECTED)

    @pytest.mark.parametrize("obligation", list(Obligation))
    def test_row_pins_its_date_and_provision(self, obligation: Obligation) -> None:
        expected_date, provision = EXPECTED[obligation]
        row = AI_ACT_DATES[obligation]
        assert row.applies_from == expected_date
        assert provision in row.reference

    @pytest.mark.parametrize("obligation", list(Obligation))
    def test_row_quotes_the_text_its_date_comes_from(self, obligation: Obligation) -> None:
        """A date edited on its own, without the quoted wording, no longer matches the source."""
        row = AI_ACT_DATES[obligation]
        assert row.long_date in row.source_text

    def test_amended_rows_name_the_amending_regulation(self) -> None:
        for obligation in (
            Obligation.ARTICLE_50_2_EXISTING_SYSTEMS,
            Obligation.ANNEX_III_HIGH_RISK,
            Obligation.ANNEX_I_HIGH_RISK,
            Obligation.HIGH_RISK_PUBLIC_AUTHORITIES,
        ):
            assert "Regulation (EU) 2026/1744" in AI_ACT_DATES[obligation].reference

    def test_the_two_high_risk_dates_differ(self) -> None:
        assert (
            AI_ACT_DATES[Obligation.ANNEX_III_HIGH_RISK].applies_from
            < AI_ACT_DATES[Obligation.ANNEX_I_HIGH_RISK].applies_from
        )

    def test_the_table_records_the_day_it_was_checked(self) -> None:
        assert date(2026, 7, 27) <= DATES_AS_OF  # the amending regulation's entry into force


class TestSelection:
    def test_annex_iii_selects_only_its_row(self) -> None:
        rows = applicable_dates(annex_iii_high_risk=True)
        assert [r.obligation for r in rows] == [Obligation.ANNEX_III_HIGH_RISK]

    def test_both_routes_are_listed_earliest_first(self) -> None:
        rows = applicable_dates(annex_i_high_risk=True, annex_iii_high_risk=True)
        assert [r.obligation for r in rows] == [Obligation.ANNEX_III_HIGH_RISK, Obligation.ANNEX_I_HIGH_RISK]

    def test_the_existing_system_period_needs_synthetic_content(self) -> None:
        assert Obligation.ARTICLE_50_2_EXISTING_SYSTEMS not in {r.obligation for r in applicable_dates(article_50=True)}
        rows = applicable_dates(article_50=True, synthetic_content=True)
        assert [r.obligation for r in rows] == [Obligation.ARTICLE_50, Obligation.ARTICLE_50_2_EXISTING_SYSTEMS]

    def test_nothing_applies_without_a_trigger(self) -> None:
        assert applicable_dates() == []
        assert applicable_dates(synthetic_content=True) == []


class TestReport:
    def test_annex_iii_and_annex_i_systems_print_different_dates(self) -> None:
        annex_iii = _summary(used_in_employment=True)
        annex_i = _summary(annex_i_product_component=True)
        assert "2 December 2027" in str(annex_iii["deadline"])
        assert "2 August 2028" in str(annex_i["deadline"])
        assert annex_iii["deadline"] != annex_i["deadline"]

    def test_the_headline_names_the_provision_that_sets_the_date(self) -> None:
        deadline = str(_summary(used_in_employment=True)["deadline"])
        assert "Article 113, third paragraph, point (c)(i)" in deadline
        assert "Regulation (EU) 2026/1744" in deadline

    def test_article_111_2_is_no_longer_presented_as_the_application_date(self) -> None:
        summary = _summary(used_in_employment=True)
        assert "111(2)" not in str(summary["deadline"])
        assert not any("111(2)" in step for step in summary["next_steps"])  # type: ignore[attr-defined]

    def test_a_system_with_both_routes_leads_with_the_earlier_date(self) -> None:
        summary = _summary(used_in_employment=True, annex_i_product_component=True)
        assert "2 December 2027" in str(summary["deadline"])
        listed = [row["obligation"] for row in summary["application_dates"]]  # type: ignore[attr-defined]
        assert listed == ["annex_iii_high_risk", "annex_i_high_risk"]

    def test_article_50_is_listed_for_any_risk_category(self) -> None:
        limited = _summary(is_chatbot_or_conversational=True)
        assert limited["risk_category"] == RiskCategory.LIMITED.value
        assert "2 August 2026" in str(limited["deadline"])
        high = _summary(used_in_employment=True, is_chatbot_or_conversational=True)
        listed = {row["obligation"] for row in high["application_dates"]}  # type: ignore[attr-defined]
        assert listed == {"annex_iii_high_risk", "article_50"}

    def test_synthetic_content_adds_the_existing_system_period(self) -> None:
        summary = _summary(generates_synthetic_media=True)
        listed = {row["obligation"] for row in summary["application_dates"]}  # type: ignore[attr-defined]
        assert listed == {"article_50", "article_50_2_existing_systems"}

    def test_a_minimal_or_prohibited_system_has_no_date(self) -> None:
        for flags in ({}, {"social_scoring_public": True}):
            summary = _summary(**flags)
            assert summary["deadline"] == "N/A"
            assert summary["application_dates"] == []

    def test_the_report_records_the_day_and_source_the_dates_were_checked_against(self) -> None:
        summary = _summary(used_in_employment=True)
        assert summary["application_dates_as_of"] == DATES_AS_OF.isoformat()
        assert "OJ L, 2026/1744, 24.7.2026" in str(summary["application_dates_source"])

    def test_every_listed_row_round_trips_the_table(self) -> None:
        summary = _summary(used_in_employment=True, generates_synthetic_media=True)
        for row in summary["application_dates"]:  # type: ignore[attr-defined]
            assert row == AI_ACT_DATES[Obligation(row["obligation"])].to_dict()

    def test_the_annex_iv_conformity_section_reads_from_the_table(self) -> None:
        report = ComplianceEngine().run(_descriptor(used_in_employment=True))
        text = str(report["tech_doc"])
        assert "2 December 2027" in text
        assert "August 2027" not in text


class TestClassification:
    def test_the_annex_i_flag_makes_a_system_high_risk(self) -> None:
        result = _AnnexIIIClassifier().classify(_descriptor(annex_i_product_component=True))
        assert result.risk_category == RiskCategory.HIGH
        assert result.annex_i_product is True
        assert "Annex I" in result.justification

    def test_without_the_flag_a_system_is_not_an_annex_i_product(self) -> None:
        assert _AnnexIIIClassifier().classify(_descriptor(used_in_employment=True)).annex_i_product is False

    def test_a_prohibited_system_stays_prohibited_whatever_else_applies(self) -> None:
        result = _AnnexIIIClassifier().classify(_descriptor(social_scoring_public=True, annex_i_product_component=True))
        assert result.risk_category == RiskCategory.UNACCEPTABLE

    def test_hashes_recorded_before_the_flag_existed_still_match(self) -> None:
        """Computed on the commit before ``annex_i_product_component`` was added."""
        classified = _AnnexIIIClassifier().classify(
            _descriptor(name="pin", used_in_employment=True),
        )
        assert classified.classification_hash == "5bd479d9d4c203d22a146d75eed00d31810daaf529402335d455f9a72486185b"

    def test_the_flag_changes_the_hash_when_set(self) -> None:
        plain = _AnnexIIIClassifier().classify(_descriptor(used_in_employment=True))
        flagged = _AnnexIIIClassifier().classify(_descriptor(used_in_employment=True, annex_i_product_component=True))
        assert plain.classification_hash != flagged.classification_hash


def _date_patterns() -> list[re.Pattern[str]]:
    """Every spelling of a table date a module might write instead of reading the table."""
    patterns: list[re.Pattern[str]] = []
    for row in AI_ACT_DATES.values():
        month = row.applies_from.strftime("%B")
        year = row.applies_from.year
        patterns.append(re.compile(rf"\b{month} {year}\b"))
        patterns.append(re.compile(re.escape(row.applies_from.isoformat())))
    return patterns


class TestOneSourceOfTruth:
    def test_no_other_module_writes_an_application_date(self) -> None:
        table = Path(ai_act_dates.__file__).resolve()
        offenders: list[str] = []
        patterns = _date_patterns()
        for path in sorted((REPO / "src" / "bernstein").rglob("*.py")):
            if path.resolve() == table:
                continue
            for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
                if any(p.search(line) for p in patterns):
                    offenders.append(f"{path.relative_to(REPO)}:{number}: {line.strip()}")
        assert offenders == []

    def test_the_search_would_catch_a_date_literal(self) -> None:
        """The scan is only worth anything if it flags the string this issue was about."""
        assert any(p.search('deadline = "August 2027 (Article 111(2))"') for p in _date_patterns())
        assert any(p.search('deadline = "December 2027"') for p in _date_patterns())

    def test_the_operator_docs_do_not_state_the_old_deadline(self) -> None:
        for relative in ("docs/operations/compliance.md", "docs/compliance/eu-ai-act-article-12-bundle.md"):
            text = (REPO / relative).read_text(encoding="utf-8")
            assert "August 2027 compliance deadline" not in text
            assert "August 2027 deadline" not in text
            assert "(`Article 111(2)`)" not in text

    def test_the_operator_docs_carry_the_as_of_line_and_the_journal_reference(self) -> None:
        text = (REPO / "docs/operations/compliance.md").read_text(encoding="utf-8")
        assert f"Dates as of {DATES_AS_OF.isoformat()}" in text
        assert "OJ L, 2026/1744, 24.7.2026" in text
        assert "OJ L, 2024/1689, 12.7.2024" in text
        for row in AI_ACT_DATES.values():
            if row.obligation is not Obligation.HIGH_RISK_PUBLIC_AUTHORITIES:
                assert row.long_date in text, row.obligation


class TestCli:
    def test_assess_prints_the_dates_source_only_when_a_date_applies(self, tmp_path: Path) -> None:
        from click.testing import CliRunner

        from bernstein.cli.commands.compliance_cmd import compliance_group

        minimal = CliRunner().invoke(compliance_group, ["assess", "--workdir", str(tmp_path)])
        assert minimal.exit_code == 0, minimal.output
        assert "Deadline: N/A" in minimal.output
        assert "Dates as of" not in minimal.output

    def test_report_prints_the_source_line_for_a_high_risk_package(self, tmp_path: Path) -> None:
        import json

        from click.testing import CliRunner

        from bernstein.cli.commands.compliance_cmd import compliance_group

        report = ComplianceEngine().run(_descriptor(used_in_employment=True), include_tech_doc=False)
        package = tmp_path / "evidence_package.json"
        package.write_text(json.dumps({"report": report}), encoding="utf-8")

        result = CliRunner().invoke(compliance_group, ["report", "--evidence-package", str(package)])
        assert result.exit_code == 0, result.output
        assert "Deadline: 2 December 2027" in result.output
        assert f"Dates as of {DATES_AS_OF.isoformat()}" in result.output

    def test_report_reads_a_package_written_before_the_date_table_existed(self, tmp_path: Path) -> None:
        import json

        from click.testing import CliRunner

        from bernstein.cli.commands.compliance_cmd import compliance_group

        package = tmp_path / "evidence_package.json"
        package.write_text(
            json.dumps({"report": {"compliance_summary": {"deadline": "August 2027 (Article 111(2))"}}}),
            encoding="utf-8",
        )
        result = CliRunner().invoke(compliance_group, ["report", "--evidence-package", str(package)])
        assert result.exit_code == 0, result.output
        assert "Dates as of" not in result.output
