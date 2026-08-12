import json
import re
from datetime import datetime

from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    PageBreak,
    Table,
    TableStyle
)


INPUT_JSON = "research_database.json"
OUTPUT_PDF = "research_database.pdf"


def safe_text(s):
    """Remove bad unicode and normalize."""
    if s is None:
        return ""
    s = str(s)
    s = s.replace("\u00a0", " ")
    return s.strip()


def parse_markdown_like_sections(text):
    """
    Splits text into blocks: headings, bullets, normal paragraphs.
    Keeps it simple and stable for PDF.
    """
    text = safe_text(text)
    lines = text.splitlines()

    blocks = []
    buffer = []

    def flush_buffer():
        nonlocal buffer
        if buffer:
            blocks.append(("para", "\n".join(buffer).strip()))
            buffer = []

    for line in lines:
        raw = line.strip()

        if raw == "":
            flush_buffer()
            continue

        # Heading pattern: ### Title
        if raw.startswith("### "):
            flush_buffer()
            blocks.append(("h3", raw.replace("### ", "").strip()))
            continue

        # Subheading pattern: #### Title
        if raw.startswith("#### "):
            flush_buffer()
            blocks.append(("h4", raw.replace("#### ", "").strip()))
            continue

        # Horizontal rule
        if raw == "---":
            flush_buffer()
            blocks.append(("rule", ""))
            continue

        # Bullet
        if raw.startswith("- "):
            flush_buffer()
            blocks.append(("bullet", raw[2:].strip()))
            continue

        # Numbered item like "1. ..."
        if re.match(r"^\d+\.\s+", raw):
            flush_buffer()
            blocks.append(("num", raw))
            continue

        buffer.append(raw)

    flush_buffer()
    return blocks


def extract_markdown_table(text):
    """
    Extracts markdown tables from compliance_analysis and converts into
    ReportLab table objects.

    Returns:
        cleaned_text_without_tables, list_of_tables_as_list_of_rows
    """
    text = safe_text(text)
    lines = text.splitlines()

    tables = []
    cleaned_lines = []

    current_table = []
    in_table = False

    for line in lines:
        raw = line.strip()

        # Detect markdown table rows: | col | col |
        if raw.startswith("|") and raw.endswith("|"):
            in_table = True
            current_table.append(raw)
            continue

        # If we were inside table and table ends
        if in_table and not (raw.startswith("|") and raw.endswith("|")):
            # Convert collected markdown table
            table_rows = []
            for tline in current_table:
                # split and remove empty edges
                cols = [c.strip() for c in tline.split("|")[1:-1]]
                table_rows.append(cols)

            # Remove the separator row if present
            # Example: |---|---|
            if len(table_rows) >= 2:
                sep = table_rows[1]
                if all(re.match(r"^-+$", c.replace(" ", "").replace(":", "")) for c in sep):
                    table_rows.pop(1)

            tables.append(table_rows)

            # reset
            current_table = []
            in_table = False

        # Normal line
        if not in_table:
            cleaned_lines.append(line)

    # Handle case if table ends at EOF
    if in_table and current_table:
        table_rows = []
        for tline in current_table:
            cols = [c.strip() for c in tline.split("|")[1:-1]]
            table_rows.append(cols)

        if len(table_rows) >= 2:
            sep = table_rows[1]
            if all(re.match(r"^-+$", c.replace(" ", "").replace(":", "")) for c in sep):
                table_rows.pop(1)

        tables.append(table_rows)

    cleaned_text = "\n".join(cleaned_lines).strip()
    return cleaned_text, tables


def make_pdf_table(table_rows, page_width):
    """
    Build a ReportLab table with clean formatting.
    """
    if not table_rows or len(table_rows) < 2:
        return None

    # Wrap long text inside cells using Paragraphs
    styles = getSampleStyleSheet()
    cell_style = ParagraphStyle(
        "CellStyle",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=9,
        leading=11,
        spaceAfter=0,
        spaceBefore=0
    )

    wrapped = []
    for r, row in enumerate(table_rows):
        wrapped_row = []
        for cell in row:
            wrapped_row.append(Paragraph(safe_text(cell), cell_style))
        wrapped.append(wrapped_row)

    # Column widths: distribute evenly
    num_cols = len(table_rows[0])
    usable_width = page_width - (1.2 * inch)  # left+right margins
    col_width = usable_width / max(num_cols, 1)
    col_widths = [col_width] * num_cols

    t = Table(wrapped, colWidths=col_widths, repeatRows=1)

    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.lightgrey),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.black),

        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, 0), 9),

        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
    ]))

    return t


def build_report(json_path, pdf_path):
    with open(json_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    # Basic fields
    target_ip = safe_text(data.get("target_ip"))
    generated_at = safe_text(data.get("generated_at"))
    provider = safe_text(data.get("provider"))
    models_used = data.get("models_used", {})
    results = data.get("results", {})

    security_text = safe_text(results.get("security_analysis"))
    compliance_text = safe_text(results.get("compliance_analysis"))
    risk_text = safe_text(results.get("risk_assessment"))

    # PDF setup
    doc = SimpleDocTemplate(
        pdf_path,
        pagesize=A4,
        leftMargin=0.6 * inch,
        rightMargin=0.6 * inch,
        topMargin=0.6 * inch,
        bottomMargin=0.6 * inch
    )

    styles = getSampleStyleSheet()

    title_style = ParagraphStyle(
        "TitleStyle",
        parent=styles["Title"],
        fontName="Helvetica-Bold",
        fontSize=16,
        leading=20,
        spaceAfter=12
    )

    h1_style = ParagraphStyle(
        "H1",
        parent=styles["Heading1"],
        fontName="Helvetica-Bold",
        fontSize=13,
        leading=16,
        spaceAfter=8
    )

    h2_style = ParagraphStyle(
        "H2",
        parent=styles["Heading2"],
        fontName="Helvetica-Bold",
        fontSize=11,
        leading=14,
        spaceAfter=6
    )

    h3_style = ParagraphStyle(
        "H3",
        parent=styles["Heading3"],
        fontName="Helvetica-Bold",
        fontSize=10.5,
        leading=13,
        spaceAfter=4
    )

    normal_style = ParagraphStyle(
        "NormalText",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=10,
        leading=13
    )

    bullet_style = ParagraphStyle(
        "BulletText",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=10,
        leading=13,
        leftIndent=14,
        bulletIndent=6
    )

    small_style = ParagraphStyle(
        "SmallText",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=9,
        leading=12
    )

    story = []

    # Title
    story.append(Paragraph("LLM Security Posture Orchestrator Report", title_style))
    story.append(Spacer(1, 6))

    # Metadata section
    story.append(Paragraph("Report Metadata", h1_style))
    story.append(Paragraph(f"<b>Target IP:</b> {target_ip}", normal_style))
    story.append(Paragraph(f"<b>Generated At:</b> {generated_at}", normal_style))
    story.append(Paragraph(f"<b>Provider:</b> {provider}", normal_style))
    story.append(Spacer(1, 6))

    # Models used
    story.append(Paragraph("Models Used", h2_style))
    if isinstance(models_used, dict) and models_used:
        for k, v in models_used.items():
            story.append(Paragraph(f"- <b>{safe_text(k)}:</b> {safe_text(v)}", bullet_style))
    else:
        story.append(Paragraph("No model details found in JSON.", normal_style))

    story.append(PageBreak())

    # Section: Security Analysis
    story.append(Paragraph("1. Security Analysis", h1_style))
    security_blocks = parse_markdown_like_sections(security_text)

    for btype, content in security_blocks:
        if btype == "h3":
            story.append(Spacer(1, 6))
            story.append(Paragraph(content, h2_style))
        elif btype == "h4":
            story.append(Spacer(1, 4))
            story.append(Paragraph(content, h3_style))
        elif btype == "bullet":
            story.append(Paragraph(content, bullet_style, bulletText="•"))
        elif btype == "num":
            story.append(Paragraph(content, normal_style))
        elif btype == "rule":
            story.append(Spacer(1, 8))
        else:
            story.append(Paragraph(content.replace("\n", "<br/>"), normal_style))
            story.append(Spacer(1, 6))

    story.append(PageBreak())

    # Section: Compliance Analysis
    story.append(Paragraph("2. Compliance Analysis", h1_style))

    cleaned_compliance, tables = extract_markdown_table(compliance_text)

    # Add compliance text first (without tables)
    compliance_blocks = parse_markdown_like_sections(cleaned_compliance)
    for btype, content in compliance_blocks:
        if btype == "h3":
            story.append(Spacer(1, 6))
            story.append(Paragraph(content, h2_style))
        elif btype == "h4":
            story.append(Spacer(1, 4))
            story.append(Paragraph(content, h3_style))
        elif btype == "bullet":
            story.append(Paragraph(content, bullet_style, bulletText="•"))
        elif btype == "num":
            story.append(Paragraph(content, normal_style))
        elif btype == "rule":
            story.append(Spacer(1, 8))
        else:
            story.append(Paragraph(content.replace("\n", "<br/>"), normal_style))
            story.append(Spacer(1, 6))

    # Add tables
    if tables:
        story.append(Spacer(1, 12))
        story.append(Paragraph("Compliance Mapping Tables", h2_style))
        story.append(Spacer(1, 6))

        for i, trows in enumerate(tables, start=1):
            story.append(Paragraph(f"Table {i}", h3_style))
            tbl = make_pdf_table(trows, A4[0])
            if tbl:
                story.append(tbl)
                story.append(Spacer(1, 12))

    story.append(PageBreak())

    # Section: Risk Assessment
    story.append(Paragraph("3. Risk Assessment", h1_style))
    risk_blocks = parse_markdown_like_sections(risk_text)

    for btype, content in risk_blocks:
        if btype == "h3":
            story.append(Spacer(1, 6))
            story.append(Paragraph(content, h2_style))
        elif btype == "h4":
            story.append(Spacer(1, 4))
            story.append(Paragraph(content, h3_style))
        elif btype == "bullet":
            story.append(Paragraph(content, bullet_style, bulletText="•"))
        elif btype == "num":
            story.append(Paragraph(content, normal_style))
        elif btype == "rule":
            story.append(Spacer(1, 8))
        else:
            story.append(Paragraph(content.replace("\n", "<br/>"), normal_style))
            story.append(Spacer(1, 6))

    # Footer note
    story.append(Spacer(1, 18))
    story.append(Paragraph(
        "Note: This report is generated from scan evidence and LLM analysis. "
        "It should be validated using internal configuration checks and vulnerability scans.",
        small_style
    ))

    # Build PDF
    doc.build(story)
    print(f"[OK] PDF generated: {pdf_path}")


if __name__ == "__main__":
    build_report(INPUT_JSON, OUTPUT_PDF)
