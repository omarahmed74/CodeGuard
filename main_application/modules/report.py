"""
Final Report Generation
========================
Builds a standalone, professional HTML report from the merged scan +
AI-enrichment results. No external CSS/JS dependency — this file is
meant to be opened, printed, or emailed on its own.
"""

import io
from datetime import datetime

from xhtml2pdf import pisa
from openpyxl import Workbook
from openpyxl.styles import Font, PatternFill, Alignment, Border, Side
from openpyxl.utils import get_column_letter

SEV_COLOR = {
    "critical": "#c0293a",
    "high": "#c96a20",
    "medium": "#a6821f",
    "low": "#1f7a52",
    "unknown": "#5b6883",
}


def _sev_badge(sev: str) -> str:
    key = (sev or "unknown").lower()
    color = SEV_COLOR.get(key, SEV_COLOR["unknown"])
    return f'<span style="display:inline-block;padding:2px 9px;border-radius:999px;font-size:11px;font-weight:700;letter-spacing:.03em;text-transform:uppercase;color:#fff;background:{color};">{sev}</span>'


def generate_report_html(project_name: str, sbom_summary: dict, severity_counts: dict, merged_findings: list) -> str:
    generated_at = datetime.now().strftime("%d %B %Y, %H:%M")
    total_deps = sbom_summary.get("total_dependencies", 0)
    total_vulns = severity_counts.get("total", 0)

    critical_findings = [f for f in merged_findings if (f.get("severity") or "").lower() == "critical"]
    high_findings = [f for f in merged_findings if (f.get("severity") or "").lower() == "high"]

    # Sort all findings by CVSS desc for the appendix table
    sorted_findings = sorted(merged_findings, key=lambda f: (f.get("cvss") or 0), reverse=True)

    def finding_row(f):
        ai = f.get("ai") or {}
        fixes = ", ".join(f.get("fix_version") or []) or "No fix published"
        cvss = f.get("cvss")
        cvss_display = f"{cvss:.1f}" if isinstance(cvss, (int, float)) else "—"
        priority = ai.get("priority_tier") or "—"
        advisory = f.get("advisory_id")
        advisory_line = f'<br/><span style="color:#8d99b5;font-size:10px;">{advisory}</span>' if advisory else ""
        return f"""
        <tr>
          <td>
            <code>{f.get('cve','—')}</code>{advisory_line}<br/>
            <span style="color:#5b6883;">{f.get('package','—')} {f.get('version','')}</span>
          </td>
          <td>{_sev_badge(f.get('severity'))}<div style="margin-top:5px;font-size:10.5px;color:#5b6883;">CVSS {cvss_display} · {priority} priority</div></td>
          <td>{f.get('description','')}</td>
          <td>{fixes}</td>
        </tr>"""

    def critical_block(f):
        ai = f.get("ai") or {}
        advisory = f.get("advisory_id")
        advisory_note = f' <span style="color:#8d99b5;font-weight:400;font-size:11px;">({advisory})</span>' if advisory else ""
        sev = f.get("severity") or "Unknown"
        sev_color = SEV_COLOR.get(sev.lower(), SEV_COLOR["unknown"])
        sev_label = f'<span style="color:{sev_color};font-weight:700;font-size:13px;text-transform:uppercase;">{sev}</span>'
        return f"""
        <div class="finding-block" style="border-left:4px solid {sev_color};">
          <table class="finding-header"><tr>
            <td style="text-align:left;"><strong style="font-size:14.5px;">{f.get('cve','—')} — {f.get('package','—')} {f.get('version','')}</strong>{advisory_note}</td>
            <td style="text-align:right;width:90px;">{sev_label}</td>
          </tr></table>
          <p>{ai.get('explanation', f.get('description',''))}</p>
          <p><strong>Banking impact:</strong> {ai.get('banking_context_risk','Not yet analyzed.')}</p>
          <p><strong>Remediation:</strong> {ai.get('remediation', 'Update to a patched version: ' + ', '.join(f.get('fix_version') or ['no fix published']))}</p>
        </div>"""

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Security Assessment Report — {project_name}</title>
<style>
  body {{ font-family: Georgia, 'Times New Roman', serif; color:#1c2230; max-width:880px; margin:0 auto; padding:48px 32px; line-height:1.6; font-size:15.5px; }}
  p {{ font-size:15.5px; line-height:1.6; }}
  h1 {{ font-family: Arial, sans-serif; font-size:26px; margin-bottom:4px; }}
  h2 {{ font-family: Arial, sans-serif; font-size:18px; border-bottom:2px solid #1c2230; padding-bottom:6px; margin-top:40px; }}
  .meta {{ font-family: Arial, sans-serif; color:#5b6883; font-size:13px; margin-bottom:28px; }}
  table {{ width:100%; border-collapse:collapse; font-family: Arial, sans-serif; font-size:12.5px; }}
  th {{ text-align:left; background:#f2f4f8; padding:8px 10px; font-size:11px; text-transform:uppercase; letter-spacing:.03em; color:#5b6883; }}
  td {{ padding:8px 10px; border-top:1px solid #e3e7ee; vertical-align:top; word-wrap:break-word; }}
  .findings-table {{ table-layout:fixed; font-size:11px; }}
  .findings-table td {{ line-height:1.4; }}
  .kpi-row {{ width:100%; font-family: Arial, sans-serif; border-collapse:separate; border-spacing:7px 0; }}
  .kpi {{ display:table-cell; border:1px solid #e3e7ee; border-radius:10px; padding:14px; text-align:center; }}
  .kpi .num {{ font-size:26px; font-weight:700; }}
  .kpi .label {{ font-size:11px; text-transform:uppercase; color:#5b6883; letter-spacing:.03em; }}
  code {{ background:#f2f4f8; padding:1px 5px; border-radius:4px; font-size:12px; }}

  /* Critical-finding blocks: internal spacing (header -> paragraphs) is
     deliberately tighter than the gap *between* two findings, so a reader
     can tell at a glance where one finding ends and the next begins
     instead of every gap looking the same size. page-break-inside:avoid
     keeps a single finding's box from being torn across a page break,
     which is what made boxes look randomly fragmented/inconsistent. */
  .finding-block {{border:1px solid #e3e7ee; border-radius:8px; padding:18px 20px; margin:0 0 40px 0; page-break-inside:avoid;}}
  .finding-header {{ width:100%; border:none; margin-bottom:6px; }}
  .finding-header td {{ border:none; padding:0; }}
  .finding-block p {{ margin:7px 0; color:#3a3f4b; }}
  .finding-block p:first-of-type {{ margin-top:0; }}
  .finding-block p:last-of-type {{ margin-bottom:0; }}

  @media print {{ body {{ padding:0; }} }}
</style>
</head>
<body>

  <h1>AI-Assisted Software Dependency Risk Review</h1>
  <div class="meta">Target: <strong>{project_name}</strong> · Generated {generated_at} · Confidential — Internal use</div>

  <h2>1. Executive Summary</h2>
  <p>This report summarizes an automated software supply-chain risk review of <strong>{project_name}</strong>.
  The scan identified <strong>{total_deps} third-party dependencies</strong>, of which
  <strong>{total_vulns} carry known, publicly disclosed vulnerabilities</strong>. Findings were enriched with
  AI-generated, banking-context risk analysis to help prioritize remediation beyond raw CVSS scores alone.</p>

  <h2>2. Scan Overview</h2>
  <table class="kpi-row"><tr>
    <td class="kpi"><div class="num">{total_deps}</div><div class="label">Dependencies</div></td>
    <td class="kpi"><div class="num">{total_vulns}</div><div class="label">Total findings</div></td>
    <td class="kpi"><div class="num" style="color:{SEV_COLOR['critical']}">{severity_counts.get('critical',0)}</div><div class="label">Critical</div></td>
    <td class="kpi"><div class="num" style="color:{SEV_COLOR['high']}">{severity_counts.get('high',0)}</div><div class="label">High</div></td>
    <td class="kpi"><div class="num" style="color:{SEV_COLOR['medium']}">{severity_counts.get('medium',0)}</div><div class="label">Medium</div></td>
    <td class="kpi"><div class="num" style="color:{SEV_COLOR['low']}">{severity_counts.get('low',0)}</div><div class="label">Low</div></td>
  </tr></table>

  <h2>3. Dependency Summary</h2>
  <p>The SBOM was generated with Syft in CycloneDX format, covering {total_deps} resolved packages across the
  application's dependency tree (direct and transitive).</p>

  <h2>4. Vulnerability Summary</h2>
  <p>{total_vulns} known vulnerabilities were matched against the dependency set via Snyk's proprietary
  vulnerability database, cross-referenced against CVE identifiers where a CVE Numbering Authority has
  assigned one.</p>

  <h2>5. Critical Findings</h2>
  {"".join(critical_block(f) for f in critical_findings) if critical_findings else "<p>No critical-severity findings in this scan.</p>"}

  <h2>6. AI Risk Analysis &amp; 7. Banking / Business Impact</h2>
  <p>Each finding below was analyzed for plain-language explanation, banking-specific impact, and a priority
  tier that considers business context rather than CVSS score alone.</p>
  <table class="findings-table">
    <colgroup>
      <col style="width:19%"><col style="width:16%"><col style="width:47%"><col style="width:18%">
    </colgroup>
    <thead><tr><th>Finding</th><th>Severity</th><th>Description</th><th>Fix version(s)</th></tr></thead>
    <tbody>{"".join(finding_row(f) for f in sorted_findings)}</tbody>
  </table>

  <h2>8. Remediation Recommendations</h2>
  <p>Prioritize Tier 1 (Critical) and Tier 2 (High) findings above, starting with direct dependencies that sit
  on request-handling or authentication paths. Where a fix version is published, upgrading the dependency is
  the primary remediation; where no fix exists, apply compensating controls (WAF rules, input validation,
  network segmentation) and track the package for a future patch.</p>

  <h2>9. Final Risk Overview</h2>
  <p>Overall posture: <strong>{"Elevated" if severity_counts.get('critical',0) or severity_counts.get('high',0) else "Moderate"}</strong> risk,
  driven primarily by {severity_counts.get('critical',0)} critical and {severity_counts.get('high',0)} high-severity
  findings. Re-run this scan after each remediation cycle to confirm risk reduction.</p>

</body>
</html>"""


def generate_report_pdf(html: str) -> bytes:
    """
    Render the same report HTML to PDF bytes using xhtml2pdf (pure Python,
    no system libraries like Cairo/Pango required — safe for offline/Windows
    deployment).
    """
    buffer = io.BytesIO()
    result = pisa.CreatePDF(src=html, dest=buffer)
    if result.err:
        raise RuntimeError(f"PDF generation failed with {result.err} error(s).")
    return buffer.getvalue()

# ------------------------------------------------------------------
# Excel (.xlsx) report
# ------------------------------------------------------------------

_HEADER_FILL = PatternFill(start_color="1C2230", end_color="1C2230", fill_type="solid")
_HEADER_FONT = Font(name="Arial", size=10.5, bold=True, color="FFFFFF")
_BASE_FONT = Font(name="Arial", size=10.5)
_WRAP = Alignment(wrap_text=True, vertical="top")
_CENTER = Alignment(horizontal="center", vertical="center", wrap_text=True)
_THIN = Side(style="thin", color="E3E7EE")
_BORDER = Border(left=_THIN, right=_THIN, top=_THIN, bottom=_THIN)

_SEV_FILL = {
    "critical": PatternFill(start_color="C0293A", end_color="C0293A", fill_type="solid"),
    "high": PatternFill(start_color="C96A20", end_color="C96A20", fill_type="solid"),
    "medium": PatternFill(start_color="A6821F", end_color="A6821F", fill_type="solid"),
    "low": PatternFill(start_color="1F7A52", end_color="1F7A52", fill_type="solid"),
    "unknown": PatternFill(start_color="5B6883", end_color="5B6883", fill_type="solid"),
}
_SEV_FONT = Font(name="Arial", size=10.5, bold=True, color="FFFFFF")


def _autosize(ws, widths: dict):
    for col, width in widths.items():
        ws.column_dimensions[get_column_letter(col)].width = width


def generate_report_xlsx(project_name: str, sbom_summary: dict, severity_counts: dict, merged_findings: list) -> bytes:
    """
    Build the same underlying data as the PDF/HTML report as an .xlsx
    workbook: a Summary sheet with KPIs, and a Findings sheet with one
    row per vulnerability (including the AI banking-impact / remediation
    text), sortable and filterable in Excel.
    """
    generated_at = datetime.now().strftime("%d %B %Y, %H:%M")
    total_deps = sbom_summary.get("total_dependencies", 0)
    total_vulns = severity_counts.get("total", 0)
    sorted_findings = sorted(merged_findings, key=lambda f: (f.get("cvss") or 0), reverse=True)

    wb = Workbook()

    # ---------------- Summary sheet ----------------
    ws = wb.active
    ws.title = "Summary"

    ws["A1"] = "AI-Assisted Software Dependency Risk Review"
    ws["A1"].font = Font(name="Arial", size=16, bold=True)
    ws["A2"] = f"Target: {project_name}"
    ws["A2"].font = Font(name="Arial", size=11, italic=True, color="5B6883")
    ws["A3"] = f"Generated {generated_at} · Confidential — Internal use"
    ws["A3"].font = Font(name="Arial", size=9.5, color="5B6883")

    _SEV_TEXT_COLOR = {
        "critical": "C0293A", "high": "C96A20", "medium": "A6821F", "low": "1F7A52",
    }
    kpi_rows = [
        ("Dependencies", total_deps, None),
        ("Total findings", total_vulns, None),
        ("Critical", severity_counts.get("critical", 0), "critical"),
        ("High", severity_counts.get("high", 0), "high"),
        ("Medium", severity_counts.get("medium", 0), "medium"),
        ("Low", severity_counts.get("low", 0), "low"),
    ]
    start_row = 5
    ws.cell(row=start_row, column=1, value="Metric").font = _HEADER_FONT
    ws.cell(row=start_row, column=1).fill = _HEADER_FILL
    ws.cell(row=start_row, column=2, value="Count").font = _HEADER_FONT
    ws.cell(row=start_row, column=2).fill = _HEADER_FILL
    for i, (label, value, sev_key) in enumerate(kpi_rows, start=1):
        r = start_row + i
        c1 = ws.cell(row=r, column=1, value=label)
        c2 = ws.cell(row=r, column=2, value=value)
        c1.font = _BASE_FONT
        c1.border = _BORDER
        c2.border = _BORDER
        if sev_key:
            c2.font = Font(name="Arial", size=10.5, bold=True, color=_SEV_TEXT_COLOR[sev_key])
        else:
            c2.font = Font(name="Arial", size=10.5, bold=True)

    posture_row = start_row + len(kpi_rows) + 2
    posture = "Elevated" if severity_counts.get("critical", 0) or severity_counts.get("high", 0) else "Moderate"
    ws.cell(row=posture_row, column=1, value="Overall posture").font = Font(name="Arial", size=10.5, bold=True)
    ws.cell(row=posture_row, column=2, value=posture).font = Font(name="Arial", size=10.5, bold=True)

    _autosize(ws, {1: 22, 2: 14})

    # ---------------- Findings sheet ----------------
    fs = wb.create_sheet("Findings")
    headers = [
        "CVE", "Advisory ID", "Package", "Version", "Severity", "CVSS",
        "Priority Tier", "Description", "Fix Version(s)",
        "Banking Impact", "Remediation",
    ]
    for col, h in enumerate(headers, start=1):
        cell = fs.cell(row=1, column=col, value=h)
        cell.font = _HEADER_FONT
        cell.fill = _HEADER_FILL
        cell.alignment = _CENTER
        cell.border = _BORDER
    fs.freeze_panes = "A2"

    for r, f in enumerate(sorted_findings, start=2):
        ai = f.get("ai") or {}
        sev = (f.get("severity") or "unknown").lower()
        cvss = f.get("cvss")
        fixes = ", ".join(f.get("fix_version") or []) or "No fix published"
        row_values = [
            f.get("cve", "—"),
            f.get("advisory_id", ""),
            f.get("package", "—"),
            f.get("version", ""),
            (f.get("severity") or "Unknown").title(),
            round(cvss, 1) if isinstance(cvss, (int, float)) else None,
            ai.get("priority_tier", "—"),
            f.get("description", ""),
            fixes,
            ai.get("banking_context_risk", "Not yet analyzed."),
            ai.get("remediation", f"Update to a patched version: {fixes}"),
        ]
        for col, val in enumerate(row_values, start=1):
            cell = fs.cell(row=r, column=col, value=val)
            cell.font = _BASE_FONT
            cell.alignment = _WRAP
            cell.border = _BORDER
            if col == 5:  # Severity column
                cell.fill = _SEV_FILL.get(sev, _SEV_FILL["unknown"])
                cell.font = _SEV_FONT
                cell.alignment = _CENTER

    fs.auto_filter.ref = f"A1:{get_column_letter(len(headers))}{len(sorted_findings) + 1}"
    _autosize(fs, {
        1: 16, 2: 14, 3: 22, 4: 12, 5: 11, 6: 8,
        7: 13, 8: 42, 9: 20, 10: 38, 11: 38,
    })
    for r in range(2, len(sorted_findings) + 2):
        fs.row_dimensions[r].height = 60

    buffer = io.BytesIO()
    wb.save(buffer)
    return buffer.getvalue()