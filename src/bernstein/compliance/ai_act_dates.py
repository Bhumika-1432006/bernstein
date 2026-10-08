"""Application dates of the EU AI Act, kept in one place.

Every date the compliance engine prints comes from :data:`AI_ACT_DATES`. No
other module carries one (``tests/unit/test_ai_act_dates.py`` greps for it), so
the next amendment is a one-file change.

Sources, both read from the Official Journal text on :data:`DATES_AS_OF`:

* Regulation (EU) 2024/1689, ``OJ L, 2024/1689, 12.7.2024`` - the AI Act.
* Regulation (EU) 2026/1744, ``OJ L, 2026/1744, 24.7.2026`` - the "Digital
  Omnibus on AI", which replaced Article 113, third paragraph, points (a) and
  (c), added point (d), replaced Article 111(2) and added Article 111(4).

Each row quotes the operative words of the Official Journal text next to the
date, so a reviewer can check the date against the source without leaving this
file. Nothing here is legal advice; when the Official Journal changes, the row
and :data:`DATES_AS_OF` change together.

What a row means. ``applies_from`` is the day the obligation starts to apply,
not a deadline to be met "by" some later point: Article 111 grace periods are
separate rows. A high-risk system placed on the market *before* its
``applies_from`` date is only caught if it later undergoes a significant design
change (Article 111(2)); that grandfathering is not a date and is not modelled.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date
from enum import StrEnum

DATES_AS_OF = date(2026, 10, 8)
"""Day the table was last checked against the Official Journal."""

AI_ACT = "Regulation (EU) 2024/1689 (OJ L, 2024/1689, 12.7.2024)"
AMENDING_ACT = "Regulation (EU) 2026/1744 (OJ L, 2026/1744, 24.7.2026)"
AMENDING_ACT_URL = "https://eur-lex.europa.eu/legal-content/EN/TXT/HTML/?uri=OJ:L_202601744"
"""Official Journal text of the amending regulation the dates were read from."""


class Obligation(StrEnum):
    """What an application date is for."""

    ARTICLE_50 = "article_50"
    ARTICLE_50_2_EXISTING_SYSTEMS = "article_50_2_existing_systems"
    ANNEX_III_HIGH_RISK = "annex_iii_high_risk"
    ANNEX_I_HIGH_RISK = "annex_i_high_risk"
    HIGH_RISK_PUBLIC_AUTHORITIES = "high_risk_public_authorities"
    GPAI = "gpai"
    GPAI_EXISTING_MODELS = "gpai_existing_models"


@dataclass(frozen=True)
class AiActDate:
    """One obligation, the day it applies from, and where that is written.

    Attributes:
        obligation: Which obligation the date is for.
        label: Short human-readable name, used in reports.
        applies_from: First day the obligation applies.
        reference: Provision that sets the date, including the amending act
            where the current text comes from one.
        source_text: The operative words of that provision, as printed in the
            Official Journal.
    """

    obligation: Obligation
    label: str
    applies_from: date
    reference: str
    source_text: str

    @property
    def long_date(self) -> str:
        """The date as the Official Journal writes it, e.g. ``2 December 2027``."""
        return f"{self.applies_from.day} {self.applies_from.strftime('%B %Y')}"

    def describe(self) -> str:
        """One line for a report: date, what it is for, and the provision."""
        return f"{self.long_date} - {self.label} ({self.reference})"

    def to_dict(self) -> dict[str, str]:
        """JSON-ready form, with the date as ISO 8601."""
        return {
            "obligation": self.obligation.value,
            "label": self.label,
            "applies_from": self.applies_from.isoformat(),
            "reference": self.reference,
            "source_text": self.source_text,
        }


AI_ACT_DATES: dict[Obligation, AiActDate] = {
    row.obligation: row
    for row in (
        AiActDate(
            obligation=Obligation.ARTICLE_50,
            label="Article 50 transparency obligations",
            applies_from=date(2026, 8, 2),
            reference=(
                "Regulation (EU) 2024/1689, Article 113, second paragraph; not amended by Regulation (EU) 2026/1744"
            ),
            source_text="It shall apply from 2 August 2026.",
        ),
        AiActDate(
            obligation=Obligation.ARTICLE_50_2_EXISTING_SYSTEMS,
            label="Article 50(2) marking, for generative systems already on the market",
            applies_from=date(2026, 12, 2),
            reference="Regulation (EU) 2024/1689, Article 111(4), added by Regulation (EU) 2026/1744, Article 1(39)(b)",
            source_text=(
                "Providers of AI systems, including general-purpose AI systems, generating synthetic audio, "
                "image, video or text content, that have been placed on the market before 2 August 2026 shall "
                "take the necessary steps in order to comply with Article 50(2) by 2 December 2026."
            ),
        ),
        AiActDate(
            obligation=Obligation.ANNEX_III_HIGH_RISK,
            label="high-risk obligations, Annex III (stand-alone) systems",
            applies_from=date(2027, 12, 2),
            reference=(
                "Regulation (EU) 2024/1689, Article 113, third paragraph, point (c)(i), "
                "as replaced by Regulation (EU) 2026/1744, Article 1(40)(b)"
            ),
            source_text=(
                "Chapter III, Sections 1, 2, and 3, with the exception of Article 6(5), shall apply from: "
                "2 December 2027 as regards AI systems classified as high-risk pursuant to Article 6(2) "
                "and Annex III"
            ),
        ),
        AiActDate(
            obligation=Obligation.ANNEX_I_HIGH_RISK,
            label="high-risk obligations, Annex I (product-embedded) systems",
            applies_from=date(2028, 8, 2),
            reference=(
                "Regulation (EU) 2024/1689, Article 113, third paragraph, point (c)(ii), "
                "as replaced by Regulation (EU) 2026/1744, Article 1(40)(b)"
            ),
            source_text=(
                "Chapter III, Sections 1, 2, and 3, with the exception of Article 6(5), shall apply from: "
                "2 August 2028 as regards AI systems classified as high-risk pursuant to Article 6(1) "
                "and Annex I"
            ),
        ),
        AiActDate(
            obligation=Obligation.HIGH_RISK_PUBLIC_AUTHORITIES,
            label="long-stop for high-risk systems already on the market and intended for public authorities",
            applies_from=date(2030, 8, 2),
            reference=(
                "Regulation (EU) 2024/1689, Article 111(2), as replaced by Regulation (EU) 2026/1744, Article 1(39)(a)"
            ),
            source_text=(
                "In any case, the providers and deployers of high-risk AI systems intended to be used by "
                "public authorities shall take the necessary steps to comply with the requirements and "
                "obligations laid down in this Regulation by 2 August 2030."
            ),
        ),
        AiActDate(
            obligation=Obligation.GPAI,
            label="general-purpose AI model obligations",
            applies_from=date(2025, 8, 2),
            reference=(
                "Regulation (EU) 2024/1689, Article 113, third paragraph, point (b); "
                "not amended by Regulation (EU) 2026/1744"
            ),
            source_text=(
                "Chapter III Section 4, Chapter V, Chapter VII and Chapter XII and Article 78 shall apply "
                "from 2 August 2025, with the exception of Article 101"
            ),
        ),
        AiActDate(
            obligation=Obligation.GPAI_EXISTING_MODELS,
            label="general-purpose AI models already on the market before 2 August 2025",
            applies_from=date(2027, 8, 2),
            reference="Regulation (EU) 2024/1689, Article 111(3); not amended by Regulation (EU) 2026/1744",
            source_text=(
                "Providers of general-purpose AI models that have been placed on the market before "
                "2 August 2025 shall take the necessary steps in order to comply with the obligations laid "
                "down in this Regulation by 2 August 2027."
            ),
        ),
    )
}


def applicable_dates(
    *,
    annex_iii_high_risk: bool = False,
    annex_i_high_risk: bool = False,
    article_50: bool = False,
    synthetic_content: bool = False,
) -> list[AiActDate]:
    """Return the rows that apply to a system, earliest first.

    Args:
        annex_iii_high_risk: High-risk under Article 6(2) and Annex III.
        annex_i_high_risk: High-risk under Article 6(1) and Annex I.
        article_50: Any Article 50 transparency obligation applies.
        synthetic_content: The system generates synthetic audio, image, video
            or text, so the Article 50(2) marking obligation applies and the
            Article 111(4) period for systems already on the market is
            relevant.

    Returns:
        The matching rows ordered by ``applies_from``, then by obligation name,
        so the output is stable.
    """
    wanted: list[Obligation] = []
    if annex_iii_high_risk:
        wanted.append(Obligation.ANNEX_III_HIGH_RISK)
    if annex_i_high_risk:
        wanted.append(Obligation.ANNEX_I_HIGH_RISK)
    if article_50:
        wanted.append(Obligation.ARTICLE_50)
    if article_50 and synthetic_content:
        wanted.append(Obligation.ARTICLE_50_2_EXISTING_SYSTEMS)
    return sorted((AI_ACT_DATES[o] for o in wanted), key=lambda r: (r.applies_from, r.obligation.value))


__all__ = [
    "AI_ACT",
    "AI_ACT_DATES",
    "AMENDING_ACT",
    "AMENDING_ACT_URL",
    "DATES_AS_OF",
    "AiActDate",
    "Obligation",
    "applicable_dates",
]
