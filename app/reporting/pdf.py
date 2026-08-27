"""PDF report rendering with the Deloitte visual identity."""

from __future__ import annotations

import io
from datetime import datetime, timezone
from typing import Any

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (
    BaseDocTemplate,
    Frame,
    KeepTogether,
    NextPageTemplate,
    PageBreak,
    PageTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
)

from .theme import (
    BLACK,
    CHARCOAL,
    DELOITTE_GREEN,
    GREY,
    INK,
    LIGHT_GREY,
    MIST,
    SEVERITY_COLOURS,
    SEVERITY_ORDER,
    SLATE,
    WHITE,
)

PAGE_WIDTH, PAGE_HEIGHT = A4
MARGIN = 18 * mm


def _c(value: str) -> colors.Color:
    return colors.HexColor(value)


def _escape(text: Any) -> str:
    value = "" if text is None else str(text)
    return (
        value.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace("\x00", "")
    )


def _styles() -> dict[str, ParagraphStyle]:
    base = getSampleStyleSheet()
    return {
        "cover_title": ParagraphStyle(
            "cover_title", parent=base["Title"], fontName="Helvetica-Bold", fontSize=30,
            leading=35, textColor=_c(WHITE), alignment=TA_LEFT, spaceAfter=6,
        ),
        "cover_sub": ParagraphStyle(
            "cover_sub", parent=base["Normal"], fontName="Helvetica", fontSize=13,
            leading=18, textColor=_c(DELOITTE_GREEN), alignment=TA_LEFT,
        ),
        "cover_meta": ParagraphStyle(
            "cover_meta", parent=base["Normal"], fontName="Helvetica", fontSize=10,
            leading=15, textColor=_c(WHITE),
        ),
        "h1": ParagraphStyle(
            "h1", parent=base["Heading1"], fontName="Helvetica-Bold", fontSize=17,
            leading=21, textColor=_c(INK), spaceBefore=10, spaceAfter=8,
        ),
        "h2": ParagraphStyle(
            "h2", parent=base["Heading2"], fontName="Helvetica-Bold", fontSize=12.5,
            leading=16, textColor=_c(INK), spaceBefore=10, spaceAfter=5,
        ),
        "h3": ParagraphStyle(
            "h3", parent=base["Heading3"], fontName="Helvetica-Bold", fontSize=10,
            leading=13, textColor=_c(SLATE), spaceBefore=6, spaceAfter=3,
        ),
        "body": ParagraphStyle(
            "body", parent=base["Normal"], fontName="Helvetica", fontSize=9.5,
            leading=14, textColor=_c(CHARCOAL), spaceAfter=5,
        ),
        "small": ParagraphStyle(
            "small", parent=base["Normal"], fontName="Helvetica", fontSize=8,
            leading=11, textColor=_c(GREY),
        ),
        "mono": ParagraphStyle(
            "mono", parent=base["Normal"], fontName="Courier", fontSize=7.4,
            leading=10, textColor=_c(INK),
        ),
        "cell": ParagraphStyle(
            "cell", parent=base["Normal"], fontName="Helvetica", fontSize=8.5, leading=12,
            textColor=_c(CHARCOAL),
        ),
        "cell_bold": ParagraphStyle(
            "cell_bold", parent=base["Normal"], fontName="Helvetica-Bold", fontSize=8.5,
            leading=12, textColor=_c(INK),
        ),
        "header_cell": ParagraphStyle(
            "header_cell", parent=base["Normal"], fontName="Helvetica-Bold", fontSize=8.5,
            leading=12, textColor=_c(WHITE),
        ),
        "centered": ParagraphStyle(
            "centered", parent=base["Normal"], fontName="Helvetica", fontSize=9,
            leading=13, textColor=_c(CHARCOAL), alignment=TA_CENTER,
        ),
    }


class ReportDocument(BaseDocTemplate):
    def __init__(self, buffer, title: str, subtitle: str):
        super().__init__(
            buffer, pagesize=A4, title=title, author="Threat Hunting Factory",
            leftMargin=MARGIN, rightMargin=MARGIN, topMargin=MARGIN, bottomMargin=MARGIN,
        )
        self.report_title = title
        self.report_subtitle = subtitle
        frame_cover = Frame(0, 0, PAGE_WIDTH, PAGE_HEIGHT, id="cover",
                            leftPadding=MARGIN, rightPadding=MARGIN,
                            topPadding=MARGIN, bottomPadding=MARGIN)
        frame_body = Frame(MARGIN, MARGIN + 10 * mm, PAGE_WIDTH - 2 * MARGIN,
                           PAGE_HEIGHT - 2 * MARGIN - 16 * mm, id="body")
        self.addPageTemplates([
            PageTemplate(id="cover", frames=[frame_cover], onPage=self._cover_background),
            PageTemplate(id="body", frames=[frame_body], onPage=self._body_chrome),
        ])

    def _cover_background(self, canvas, doc):
        canvas.saveState()
        canvas.setFillColor(_c(BLACK))
        canvas.rect(0, 0, PAGE_WIDTH, PAGE_HEIGHT, fill=1, stroke=0)
        canvas.setFillColor(_c(DELOITTE_GREEN))
        canvas.rect(0, PAGE_HEIGHT - 14 * mm, PAGE_WIDTH, 6 * mm, fill=1, stroke=0)
        canvas.rect(MARGIN, 40 * mm, 26 * mm, 1.6 * mm, fill=1, stroke=0)
        canvas.restoreState()

    def _body_chrome(self, canvas, doc):
        canvas.saveState()
        canvas.setFillColor(_c(BLACK))
        canvas.rect(0, PAGE_HEIGHT - 12 * mm, PAGE_WIDTH, 12 * mm, fill=1, stroke=0)
        canvas.setFillColor(_c(DELOITTE_GREEN))
        canvas.rect(0, PAGE_HEIGHT - 13.2 * mm, PAGE_WIDTH, 1.2 * mm, fill=1, stroke=0)
        canvas.setFillColor(_c(WHITE))
        canvas.setFont("Helvetica-Bold", 8.5)
        canvas.drawString(MARGIN, PAGE_HEIGHT - 8.4 * mm, "Threat Hunting Factory")
        canvas.setFont("Helvetica", 8)
        canvas.setFillColor(_c(LIGHT_GREY))
        canvas.drawRightString(PAGE_WIDTH - MARGIN, PAGE_HEIGHT - 8.4 * mm, doc.report_subtitle[:90])
        canvas.setStrokeColor(_c(LIGHT_GREY))
        canvas.setLineWidth(0.5)
        canvas.line(MARGIN, 14 * mm, PAGE_WIDTH - MARGIN, 14 * mm)
        canvas.setFont("Helvetica", 7.5)
        canvas.setFillColor(_c(GREY))
        canvas.drawString(MARGIN, 10 * mm, "Confidential, prepared for the client named on the cover")
        canvas.drawRightString(PAGE_WIDTH - MARGIN, 10 * mm, f"Page {doc.page - 1}")
        canvas.restoreState()


def _severity_chip(severity: str, styles) -> Table:
    colour = SEVERITY_COLOURS.get(severity, GREY)
    chip = Table(
        [[Paragraph(f'<font color="{WHITE}"><b>{severity.upper()}</b></font>', styles["small"])]],
        colWidths=[24 * mm], rowHeights=[6.5 * mm],
    )
    chip.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), _c(colour)),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING", (0, 0), (-1, -1), 4),
        ("RIGHTPADDING", (0, 0), (-1, -1), 4),
    ]))
    return chip


def _kv_table(rows: list[tuple[str, str]], styles, width: float, label_width: float = 45 * mm) -> Table:
    data = [
        [Paragraph(_escape(label), styles["cell_bold"]), Paragraph(_escape(value), styles["cell"])]
        for label, value in rows
    ]
    table = Table(data, colWidths=[label_width, width - label_width])
    table.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LINEBELOW", (0, 0), (-1, -2), 0.4, _c(LIGHT_GREY)),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("LEFTPADDING", (0, 0), (-1, -1), 0),
        ("BACKGROUND", (0, 0), (0, -1), _c(WHITE)),
    ]))
    return table


def _severity_bar(counts: dict[str, int], styles, width: float) -> Table:
    total = sum(counts.get(level, 0) for level in SEVERITY_ORDER) or 1
    cells = []
    widths = []
    for level in SEVERITY_ORDER:
        count = counts.get(level, 0)
        if not count:
            continue
        share = count / total
        widths.append(max(width * share, 14 * mm))
        cells.append(Paragraph(
            f'<font color="{WHITE}" size="8"><b>{count} {level}</b></font>', styles["small"]
        ))
    if not cells:
        return Table([[Paragraph("No observations recorded", styles["cell"])]], colWidths=[width])
    scale = width / sum(widths)
    widths = [value * scale for value in widths]
    table = Table([cells], colWidths=widths, rowHeights=[8 * mm])
    style = [
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING", (0, 0), (-1, -1), 2),
        ("RIGHTPADDING", (0, 0), (-1, -1), 2),
    ]
    index = 0
    for level in SEVERITY_ORDER:
        if not counts.get(level):
            continue
        style.append(("BACKGROUND", (index, 0), (index, 0), _c(SEVERITY_COLOURS[level])))
        index += 1
    table.setStyle(TableStyle(style))
    return table


def build_report(context: dict) -> bytes:
    """Render a full hunt report and return the PDF bytes."""
    styles = _styles()
    buffer = io.BytesIO()
    hunt = context["hunt"]
    tenant = context["tenant"]
    observations = context["observations"]
    hypothesis = context.get("hypothesis") or {}
    summary = hunt.get("summary") or {}
    coverage = hunt.get("coverage") or {}
    content_width = PAGE_WIDTH - 2 * MARGIN

    document = ReportDocument(
        buffer,
        title=f"Threat hunting report, {hunt.get('title') or hunt.get('hypothesis_name')}",
        subtitle=f"{tenant.get('name', '')} | {hunt.get('hypothesis_name', '')}",
    )

    story: list = []

    # ---------------------------------------------------------------- cover
    story.append(Spacer(1, 55 * mm))
    story.append(Paragraph("Threat Hunting Report", styles["cover_title"]))
    story.append(Paragraph(_escape(hunt.get("hypothesis_name", "")), styles["cover_sub"]))
    hunt_title = hunt.get("title") or ""
    if hunt_title and hunt_title != hunt.get("hypothesis_name"):
        story.append(Spacer(1, 3 * mm))
        story.append(Paragraph(f'<font color="{WHITE}" size="11">{_escape(hunt_title)}</font>', styles["cover_meta"]))
    story.append(Spacer(1, 12 * mm))
    generated = datetime.now(timezone.utc).strftime("%d %B %Y, %H:%M UTC")
    meta_rows = [
        ("Workspace", tenant.get("name", "")),
        ("Hunt reference", hunt.get("id", "")),
        ("Hypothesis family", hypothesis.get("family", hunt.get("hypothesis_category", ""))),
        ("Analyst", context.get("analyst", "")),
        ("Evidence archive", hunt.get("archive_name", "")),
        ("Generated", generated),
    ]
    meta = Table(
        [[Paragraph(f'<font color="{DELOITTE_GREEN}"><b>{_escape(label)}</b></font>', styles["cover_meta"]),
          Paragraph(f'<font color="{WHITE}">{_escape(value)}</font>', styles["cover_meta"])]
         for label, value in meta_rows],
        colWidths=[45 * mm, content_width - 45 * mm],
    )
    meta.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("TOPPADDING", (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ("LEFTPADDING", (0, 0), (-1, -1), 0),
    ]))
    story.append(meta)
    story.append(Spacer(1, 14 * mm))
    verdict = hunt.get("verdict") or "No significant findings"
    risk = hunt.get("risk_score", 0.0)
    badge_colour = _risk_colour(risk)
    badge_text = WHITE if risk >= 25 else BLACK
    verdict_table = Table(
        [[Paragraph(f'<font color="{badge_text}" size="20"><b>{risk:.0f}</b></font>'
                    f'<font color="{badge_text}" size="9">/100</font>',
                    styles["centered"]),
          Paragraph(f'<font color="{WHITE}" size="11"><b>{_escape(verdict)}</b></font>', styles["cover_meta"])]],
        colWidths=[32 * mm, content_width - 32 * mm], rowHeights=[16 * mm],
    )
    verdict_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, 0), _c(badge_colour)),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("ALIGN", (0, 0), (0, 0), "CENTER"),
        ("LEFTPADDING", (1, 0), (1, 0), 8),
    ]))
    story.append(verdict_table)
    story.append(NextPageTemplate("body"))
    story.append(PageBreak())

    # ---------------------------------------------------- executive summary
    story.append(Paragraph("Executive summary", styles["h1"]))
    severities = summary.get("severities") or {}
    total_obs = len(observations)
    critical_high = severities.get("critical", 0) + severities.get("high", 0)
    narrative = (
        f"This report presents the result of the hypothesis driven hunt "
        f"<b>{_escape(hunt.get('hypothesis_name', ''))}</b> executed against the evidence archive "
        f"<b>{_escape(hunt.get('archive_name', ''))}</b>. The engine parsed "
        f"{hunt.get('events_parsed', 0):,} records from {hunt.get('files_analysed', 0)} log files and applied "
        f"{hunt.get('rules_evaluated', 0)} detections, producing {total_obs} observations of which "
        f"{critical_high} are rated high or critical. The aggregated risk score is "
        f"{risk:.0f} out of 100, which the platform classifies as: {_escape(verdict)}."
    )
    story.append(Paragraph(narrative, styles["body"]))
    story.append(Spacer(1, 4 * mm))
    story.append(Paragraph("Observation severity distribution", styles["h3"]))
    story.append(_severity_bar(severities, styles, content_width))
    story.append(Spacer(1, 6 * mm))

    metric_rows = [
        ["Records parsed", f"{hunt.get('events_parsed', 0):,}"],
        ["Log files analysed", str(hunt.get("files_analysed", 0))],
        ["Detections applied", str(hunt.get("rules_evaluated", 0))],
        ["Observations", str(total_obs)],
        ["Analysis duration", f"{hunt.get('duration_ms', 0) / 1000:.1f} s"],
        ["Risk score", f"{risk:.1f} / 100"],
    ]
    metrics_table = Table(
        [[Paragraph(f'<font color="{GREY}" size="7.5">{_escape(label.upper())}</font><br/>'
                    f'<font color="{INK}" size="13"><b>{_escape(value)}</b></font>', styles["cell"])
          for label, value in metric_rows[:3]],
         [Paragraph(f'<font color="{GREY}" size="7.5">{_escape(label.upper())}</font><br/>'
                    f'<font color="{INK}" size="13"><b>{_escape(value)}</b></font>', styles["cell"])
          for label, value in metric_rows[3:]]],
        colWidths=[content_width / 3] * 3,
    )
    metrics_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), _c(MIST)),
        ("BOX", (0, 0), (-1, -1), 0.5, _c(LIGHT_GREY)),
        ("INNERGRID", (0, 0), (-1, -1), 0.5, _c(WHITE)),
        ("TOPPADDING", (0, 0), (-1, -1), 7),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
        ("LEFTPADDING", (0, 0), (-1, -1), 8),
    ]))
    story.append(metrics_table)
    story.append(Spacer(1, 6 * mm))

    techniques = summary.get("top_techniques") or []
    if techniques:
        story.append(Paragraph("Techniques observed", styles["h2"]))
        rows = [[Paragraph("Technique", styles["header_cell"]), Paragraph("Observations", styles["header_cell"])]]
        for entry in techniques[:10]:
            name, count = (entry[0], entry[1]) if isinstance(entry, (list, tuple)) else (str(entry), "")
            rows.append([Paragraph(_escape(name), styles["cell"]), Paragraph(str(count), styles["cell"])])
        table = Table(rows, colWidths=[content_width - 30 * mm, 30 * mm])
        table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), _c(BLACK)),
            ("TEXTCOLOR", (0, 0), (-1, 0), _c(WHITE)),
            ("LINEBELOW", (0, 1), (-1, -1), 0.4, _c(LIGHT_GREY)),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("TOPPADDING", (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ]))
        story.append(table)
        story.append(Spacer(1, 5 * mm))

    # --------------------------------------------------- hypothesis section
    story.append(Paragraph("Hypothesis and scope", styles["h1"]))
    if hypothesis:
        story.append(Paragraph(_escape(hypothesis.get("narrative", "")), styles["body"]))
        story.append(Paragraph("<b>Rationale</b>", styles["h3"]))
        story.append(Paragraph(_escape(hypothesis.get("rationale", "")), styles["body"]))
        story.append(Paragraph("<b>Analytical method</b>", styles["h3"]))
        story.append(Paragraph(_escape(hypothesis.get("method", "")), styles["body"]))

    files = summary.get("files") or []
    if files:
        story.append(Paragraph("Evidence analysed", styles["h2"]))
        rows = [[Paragraph("File", styles["header_cell"]),
                 Paragraph("Format", styles["header_cell"]),
                 Paragraph("Telemetry", styles["header_cell"]),
                 Paragraph("Records", styles["header_cell"])]]
        for item in files[:30]:
            rows.append([
                Paragraph(_escape(item.get("path", "")), styles["cell"]),
                Paragraph(_escape(item.get("log_format", "")), styles["cell"]),
                Paragraph(_escape(item.get("data_source", "")), styles["cell"]),
                Paragraph(f"{item.get('events', 0):,}", styles["cell"]),
            ])
        table = Table(rows, colWidths=[content_width - 75 * mm, 27 * mm, 28 * mm, 20 * mm], repeatRows=1)
        table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), _c(BLACK)),
            ("TEXTCOLOR", (0, 0), (-1, 0), _c(WHITE)),
            ("LINEBELOW", (0, 1), (-1, -1), 0.4, _c(LIGHT_GREY)),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ]))
        story.append(table)
        story.append(Spacer(1, 4 * mm))

    required = coverage.get("required") or []
    if required:
        story.append(Paragraph("Data source coverage", styles["h2"]))
        rows = [[Paragraph("Required data source", styles["header_cell"]),
                 Paragraph("Present", styles["header_cell"]),
                 Paragraph("Records", styles["header_cell"])]]
        for entry in required:
            rows.append([
                Paragraph(_escape(entry.get("name", entry.get("id", ""))), styles["cell"]),
                Paragraph("Yes" if entry.get("present") else "No", styles["cell"]),
                Paragraph(f"{entry.get('events', 0):,}", styles["cell"]),
            ])
        table = Table(rows, colWidths=[content_width - 60 * mm, 30 * mm, 30 * mm])
        table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), _c(BLACK)),
            ("TEXTCOLOR", (0, 0), (-1, 0), _c(WHITE)),
            ("LINEBELOW", (0, 1), (-1, -1), 0.4, _c(LIGHT_GREY)),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ]))
        story.append(table)

    story.append(PageBreak())

    # --------------------------------------------------------- observations
    story.append(Paragraph("Observations", styles["h1"]))
    if not observations:
        story.append(Paragraph(
            "The engine did not raise any observation for this hypothesis against the evidence provided. "
            "This is a meaningful result: it either supports rejecting the hypothesis for the period covered, "
            "or indicates that the required telemetry was not present in the archive. Review the data source "
            "coverage table above before concluding.",
            styles["body"],
        ))
    for index, observation in enumerate(observations, start=1):
        block: list = []
        header = Table(
            [[Paragraph(f'<font color="{WHITE}" size="10"><b>OBS-{index:03d}</b></font>', styles["small"]),
              Paragraph(f'<font color="{WHITE}" size="10"><b>{_escape(observation.get("title", ""))}</b></font>',
                        styles["small"]),
              _severity_chip(observation.get("severity", "medium"), styles)]],
            colWidths=[20 * mm, content_width - 46 * mm, 26 * mm],
        )
        header.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (1, 0), _c(BLACK)),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("LEFTPADDING", (0, 0), (-1, -1), 6),
            ("RIGHTPADDING", (2, 0), (2, 0), 0),
            ("TOPPADDING", (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ]))
        block.append(header)
        block.append(Spacer(1, 2.5 * mm))

        facts = [
            ("Detection", f"{observation.get('rule_id', '')} ({observation.get('detection_type', '')})"),
            ("Confidence", observation.get("confidence", "")),
            ("Affected entity", observation.get("entity", "")),
            ("Telemetry", observation.get("data_source", "")),
            ("MITRE ATT&CK", " ".join(filter(None, [
                observation.get("mitre_technique_id", ""),
                observation.get("mitre_technique", ""),
                f"({observation.get('mitre_tactic', '')})" if observation.get("mitre_tactic") else "",
            ]))),
            ("Occurrences", str(observation.get("event_count", 1))),
            ("First seen", observation.get("first_seen") or "not available"),
            ("Last seen", observation.get("last_seen") or "not available"),
        ]
        block.append(_kv_table([(label, value) for label, value in facts if value], styles, content_width, 38 * mm))
        block.append(Spacer(1, 2.5 * mm))

        block.append(Paragraph("What was detected", styles["h3"]))
        block.append(Paragraph(_escape(observation.get("description", "")), styles["body"]))
        story.append(KeepTogether(block))

        evidence = observation.get("evidence") or []
        if evidence:
            story.append(Paragraph("Original log evidence", styles["h3"]))
            for item in evidence[:4]:
                location = f"{item.get('source_file', '')} line {item.get('line_no', 0)}"
                stamp = item.get("timestamp") or "no timestamp"
                excerpt = _escape(item.get("excerpt", ""))[:1200]
                evidence_table = Table(
                    [[Paragraph(f'<font color="{GREY}" size="7">{_escape(location)} | {_escape(stamp)}</font>',
                                styles["small"])],
                     [Paragraph(excerpt, styles["mono"])]],
                    colWidths=[content_width],
                )
                evidence_table.setStyle(TableStyle([
                    ("BACKGROUND", (0, 0), (-1, -1), _c(MIST)),
                    ("LINEBEFORE", (0, 0), (0, -1), 2, _c(DELOITTE_GREEN)),
                    ("TOPPADDING", (0, 0), (-1, -1), 4),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                    ("LEFTPADDING", (0, 0), (-1, -1), 7),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 7),
                ]))
                story.append(evidence_table)
                story.append(Spacer(1, 1.5 * mm))

        metrics = observation.get("metrics") or {}
        if metrics:
            story.append(Paragraph("Analytical detail", styles["h3"]))
            metric_pairs = [(str(key).replace("_", " "), _format_metric(value)) for key, value in list(metrics.items())[:12]]
            story.append(_kv_table(metric_pairs, styles, content_width, 55 * mm))
            story.append(Spacer(1, 2 * mm))

        for label, key in (("Cyber risk", "risk"), ("Cyber impact", "impact"), ("Recommendation", "recommendation")):
            text = observation.get(key)
            if text:
                story.append(Paragraph(label, styles["h3"]))
                story.append(Paragraph(_escape(text), styles["body"]))

        references = observation.get("references") or []
        if references:
            story.append(Paragraph(
                f'<font size="7.5" color="{GREY}">References: {_escape(", ".join(references))}</font>',
                styles["small"],
            ))
        story.append(Spacer(1, 6 * mm))

    # ------------------------------------------------------------- appendix
    story.append(PageBreak())
    story.append(Paragraph("Appendix, method and limitations", styles["h1"]))
    story.append(Paragraph(
        "The detection engine normalises every parsed record into a common schema before applying the rule "
        "library, so a single detection works across Windows, Linux, network, web and cloud telemetry. Four "
        "detection styles are used: single event pattern matching, sliding window threshold analysis, ordered "
        "sequence correlation across an entity, and statistical models covering entropy, spectral analysis, "
        "frequency stacking and robust outlier detection.",
        styles["body"],
    ))
    story.append(Paragraph(
        "Findings are derived only from the evidence supplied. Absence of an observation is not proof that the "
        "activity did not occur, since the relevant telemetry may not have been collected, may have been "
        "rotated before collection, or may fall outside the period covered by the archive. Every observation "
        "should be validated against the source system before an operational decision is taken.",
        styles["body"],
    ))
    parse_warnings = summary.get("warnings") or []
    skipped = summary.get("skipped") or []
    if parse_warnings or skipped:
        story.append(Paragraph("Processing notes", styles["h2"]))
        for note in list(parse_warnings)[:10] + list(skipped)[:15]:
            story.append(Paragraph(f"- {_escape(note)}", styles["small"]))

    document.build(story)
    return buffer.getvalue()


def _risk_colour(risk: float) -> str:
    if risk >= 75:
        return SEVERITY_COLOURS["critical"]
    if risk >= 50:
        return SEVERITY_COLOURS["high"]
    if risk >= 25:
        return SEVERITY_COLOURS["medium"]
    return DELOITTE_GREEN


def _format_metric(value: Any) -> str:
    if isinstance(value, float):
        return f"{value:,.4g}"
    if isinstance(value, int):
        return f"{value:,}"
    if isinstance(value, (list, tuple)):
        return ", ".join(str(item) for item in value[:12])
    return str(value)
