"""Server-side PDF of a report snapshot.

Rendered only from the frozen snapshot content (never live data), with the same sections as
the report page. The PDF's dates come from the snapshot, so the same snapshot always yields
the same bytes. Fonts: DejaVu (Bitstream Vera licence, fonts/LICENSE-DejaVu.txt), bundled so
any name or title prints correctly without system fonts (serverless hosting has none).
"""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Any

from fpdf import FPDF
from fpdf.enums import XPos, YPos
from fpdf.fonts import FontFace

FONTS = Path(__file__).parent / "fonts"
SEVERITY_ORDER = ("critical", "high", "medium", "low", "info")
CRIMSON = (176, 24, 40)
MUTED = (100, 100, 110)


def _dt(value: Any) -> str:
    if not value:
        return "—"
    try:
        return datetime.fromisoformat(str(value)).strftime("%Y-%m-%d %H:%M UTC")
    except ValueError:
        return str(value)


def _label(value: Any) -> str:
    return str(value or "—").replace("_", " ")


class ReportPDF(FPDF):
    def __init__(self, footer_text: str) -> None:
        super().__init__(format="A4")
        self.footer_text = footer_text
        self.add_font("Sans", "", str(FONTS / "DejaVuSans.ttf"))
        self.add_font("Sans", "B", str(FONTS / "DejaVuSans-Bold.ttf"))
        self.add_font("Mono", "", str(FONTS / "DejaVuSansMono.ttf"))
        self.set_auto_page_break(auto=True, margin=18)
        self.set_margins(18, 18, 18)
        self.section = 0

    def footer(self) -> None:
        self.set_y(-12)
        self.set_font("Mono", size=6.5)
        self.set_text_color(*MUTED)
        self.cell(0, 4, f"{self.footer_text} · page {self.page_no()}/{{nb}}", align="C")
        self.set_text_color(0, 0, 0)

    # Building blocks -----------------------------------------------------------------

    def h2(self, title: str) -> None:
        self.section += 1
        if self.get_y() > self.h - 50:
            self.add_page()
        self.ln(5)
        self.set_font("Sans", "B", 13)
        self.cell(0, 8, f"{self.section}. {title}", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        self.set_draw_color(200, 200, 205)
        self.line(self.l_margin, self.get_y(), self.w - self.r_margin, self.get_y())
        self.ln(2)

    def h3(self, title: str) -> None:
        if self.get_y() > self.h - 40:
            self.add_page()
        self.ln(2)
        self.set_font("Sans", "B", 10.5)
        self.multi_cell(0, 5.5, title, new_x=XPos.LMARGIN, new_y=YPos.NEXT)

    def para(self, text: str, size: float = 9.5, muted: bool = False, mono: bool = False) -> None:
        self.set_font("Mono" if mono else "Sans", size=size)
        if muted:
            self.set_text_color(*MUTED)
        self.multi_cell(0, size * 0.52, text, align="L", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        self.set_text_color(0, 0, 0)
        self.ln(1)

    def field(self, name: str, value: str) -> None:
        if not value:
            return
        self.set_font("Sans", "B", 9)
        self.cell(0, 5, name, new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        self.para(value, size=9)

    def grid(self, head: list[str], rows: list[list[str]], widths: list[float]) -> None:
        self.set_font("Sans", size=8)
        with self.table(
            col_widths=tuple(widths),
            text_align="LEFT",
            line_height=4.2,
            headings_style=FontFace(emphasis="BOLD", color=MUTED),
            borders_layout="HORIZONTAL_LINES",
        ) as t:
            r = t.row()
            for h in head:
                r.cell(h)
            for row in rows:
                r = t.row()
                for v in row:
                    r.cell(v)
        self.ln(2)


def render(content: dict[str, Any], *, report_id: str, sha256: str, taken_by: str) -> bytes:
    c = content
    org = (c.get("organization") or {}).get("name") or "—"
    project = c.get("project") or {}
    generated = c.get("generated_at")
    pdf = ReportPDF(f"JANUS assessment report · snapshot {report_id[:8]} · SHA-256 {sha256[:16]}…")
    if generated:
        pdf.set_creation_date(datetime.fromisoformat(str(generated)))
    pdf.set_title(f"{org} — {project.get('name', '')}")
    pdf.set_subject(f"Assessment report snapshot {report_id}, SHA-256 {sha256}")
    pdf.set_creator("JANUS")
    pdf.add_page()

    # Header
    pdf.set_font("Sans", "B", 8)
    pdf.set_text_color(*CRIMSON)
    pdf.cell(0, 5, "DRE · JANUS · ASSESSMENT REPORT", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.set_text_color(0, 0, 0)
    pdf.set_font("Sans", "B", 18)
    pdf.multi_cell(0, 9, f"{org} — {project.get('name', '')}", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.para(
        f"{_label(project.get('assessment_type')).capitalize()} · generated {_dt(generated)} "
        f"by {taken_by}",
        muted=True,
    )
    rulesets = ", ".join(str(v) for v in (c.get("rulesets") or {}).values())
    pdf.para(f"Snapshot {report_id}\nSHA-256 {sha256}\nRulesets {rulesets}", size=7, mono=True)

    pdf.h2("Executive summary")
    for line in c.get("executive_summary") or []:
        pdf.para(str(line))

    pdf.h2("Assessment scope")
    scope = c.get("scope")
    if scope:
        pdf.para(
            f"Scope v{scope.get('version')}{' (lab)' if scope.get('is_lab') else ''} · "
            f"authorization {scope.get('reference') or '—'} · authorized by "
            f"{scope.get('authorized_by') or '—'} on {_dt(scope.get('authorized_at'))}"
        )
        pdf.para(
            f"Valid {_dt(scope.get('valid_from'))} to {_dt(scope.get('valid_until'))}", muted=True
        )
        targets = scope.get("targets") or []
        if targets:
            pdf.grid(
                ["In scope", "Kind"],
                [[str(t.get("value")), _label(t.get("kind"))] for t in targets],
                [130, 44],
            )
        exclusions = scope.get("exclusions") or []
        if exclusions:
            pdf.grid(
                ["Excluded", "Kind", "Reason"],
                [
                    [str(e.get("value")), _label(e.get("kind")), str(e.get("reason") or "")]
                    for e in exclusions
                ],
                [70, 30, 74],
            )
    else:
        pdf.para("No scope was authorized, so no collection could run.")

    pdf.h2("Methodology")
    collectors = (c.get("methodology") or {}).get("collectors") or []
    if collectors:
        pdf.grid(
            ["Collector", "Risk", "Runs", "Succeeded", "Denied or rejected"],
            [
                [
                    str(m.get("label")),
                    _label(m.get("risk_class")),
                    str(m.get("runs", 0)),
                    str(m.get("succeeded", 0)),
                    str(m.get("denied_or_rejected", 0)),
                ]
                for m in collectors
            ],
            [64, 26, 20, 28, 36],
        )
    else:
        pdf.para("No collection ran.")

    pdf.h2("Severity breakdown (open findings)")
    open_counts = (c.get("severity_breakdown") or {}).get("open") or {}
    pdf.grid(
        [s.capitalize() for s in SEVERITY_ORDER],
        [[str(open_counts.get(s, 0)) for s in SEVERITY_ORDER]],
        [34.8] * 5,
    )

    pdf.h2("Findings")
    findings = c.get("findings") or []
    if not findings:
        pdf.para("No findings were recorded.")
    for f in findings:
        pdf.h3(f"{f.get('ref', '')}  {f.get('title', '')}")
        pdf.para(
            f"Severity {_label(f.get('severity'))} · status {_label(f.get('status'))} · confidence "
            f"{_label(f.get('confidence'))} · origin {_label(f.get('origin'))} · asset "
            f"{f.get('asset') or '—'}",
            size=8.5,
            muted=True,
        )
        if f.get("status") == "hypothesis":
            pdf.para("Hypothesis: plausible, but not shown by evidence.", size=8.5)
        pdf.field("Description", str(f.get("description") or ""))
        pdf.field("Impact", str(f.get("impact") or ""))
        pdf.field("Remediation", str(f.get("remediation") or ""))
        decided = f.get("decided_by")
        if decided:
            note = f": {f.get('decision_note')}" if f.get("decision_note") else ""
            pdf.para(f"Status set by {decided}{note}", size=8.5, muted=True)
        pdf.para(
            f"First observed {_dt(f.get('first_observed_at'))} · last observed "
            f"{_dt(f.get('last_observed_at'))}"
            + (f" · rule {f.get('rule_id')}" if f.get("rule_id") else ""),
            size=8,
            muted=True,
        )
        evidence = f.get("evidence") or []
        if evidence:
            pdf.grid(
                ["Evidence", "Tool", "Collected", "SHA-256"],
                [
                    [
                        str(e.get("id", ""))[:8],
                        str(e.get("tool") or ""),
                        _dt(e.get("collected_at")),
                        str(e.get("sha256") or "")[:16] + "…",
                    ]
                    for e in evidence
                ],
                [22, 42, 50, 60],
            )

    paths = c.get("attack_paths") or []
    pdf.h2("Attack paths")
    if not paths:
        pdf.para("No attack paths were recorded.")
    for p in paths:
        pdf.h3(str(p.get("title", "")))
        pdf.para(
            f"Status {_label(p.get('status'))} · confidence {_label(p.get('confidence'))}",
            size=8.5,
            muted=True,
        )
        if p.get("narrative"):
            pdf.para(str(p["narrative"]))
        for s in p.get("steps") or []:
            finding = (
                f" ({s.get('finding_ref')}: {s.get('finding_title')})"
                if s.get("finding_ref")
                else ""
            )
            pdf.para(f"{s.get('ordinal')}. {s.get('description', '')}{finding}", size=9)

    assets = c.get("assets") or []
    pdf.h2(f"Assets ({len(assets)})")
    if assets:
        pdf.grid(
            ["Asset", "Kind", "Ownership", "Source", "Last seen"],
            [
                [
                    str(a.get("value")),
                    _label(a.get("kind")),
                    _label(a.get("ownership")),
                    str(a.get("source") or ""),
                    _dt(a.get("last_seen_at")),
                ]
                for a in assets
            ],
            [54, 22, 26, 30, 42],
        )
    else:
        pdf.para("No assets were recorded.")

    pdf.h2("Limitations")
    for line in c.get("limitations") or []:
        pdf.para(f"• {line}")

    return bytes(pdf.output())
