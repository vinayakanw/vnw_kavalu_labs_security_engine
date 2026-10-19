"""
Report Generator Module
-------------------------
Generates the security report from scan results in three formats:

  PDF   The engine's deliverable format. Written to the reports directory and
        nowhere else — it is the only artifact this engine persists to disk.
  HTML  A print-ready web rendering of the same content. Built entirely in
        memory and streamed back to the browser as a download. It is never
        written to the reports directory (or to disk at all).
  JSON  A machine-readable export of the same scan data. Built entirely in
        memory and streamed back to the browser as a download. It is never
        written to the reports directory (or to disk at all).

All three mirror the dashboard's dark/red "Kavalu Labs" visual identity, group
every finding under its OWASP Top 10:2021 category, show the Detection
Engine's risk score with a full explainable breakdown, and close with a
prioritized remediation roadmap.
"""

__author__ = "Vinayaka N Walshettar"

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, PageBreak
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from datetime import datetime
import json
import os
from typing import Dict, Any, List

from .owasp_mapping import OWASP_TOP_10, build_coverage_matrix
from .detection_engine import score_findings
from .paths import ensure_dirs, report_path, scan_state_path

ENGINE_NAME = "Kavalu Labs Security Engine"
ENGINE_VERSION = "2.0"
AUTHOR_NAME = "Vinayaka N Walshettar"
AUTHOR_URL = "https://www.nayaka100.in/"

#: Every format the report endpoint can serve.
SUPPORTED_FORMATS = ('pdf', 'html', 'json')

#: Formats that are rendered in memory and streamed as a download without ever
#: touching the reports directory (or the filesystem at all).
DOWNLOAD_ONLY_FORMATS = ('html', 'json')

MIMETYPES = {
    'pdf': 'application/pdf',
    'html': 'text/html',
    'json': 'application/json',
}

#: Standalone HTML report shell (self-contained styling, no external assets).
_HTML_HEADER = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Kavalu Labs Security Engine - Web Application Security Assessment</title>
<style>
:root {
    --rd: #FF0000; --bg: #0A0A0A; --sf: #141414; --sf2: #1c1c1b;
    --ln: #2a2a27; --tx: #F2EFE8; --mu: #8A8A82; --ok: #7CFF9B;
    --warn: #FFB347; --low: #8AB4FF;
}
* { box-sizing: border-box; margin: 0; padding: 0; }
body {
    background: var(--bg); color: var(--tx); max-width: 1100px; margin: 0 auto;
    padding: 48px 32px 64px; font-size: 15px; line-height: 1.6;
    font-family: Inter, system-ui, -apple-system, "Segoe UI", sans-serif;
}
h1.title {
    font-family: Anton, Impact, "Arial Narrow", sans-serif; font-size: 40px;
    letter-spacing: .04em; text-transform: uppercase; color: var(--rd); text-align: center;
}
p.subtitle {
    font-family: "Space Mono", ui-monospace, Menlo, Consolas, monospace; font-size: 12px;
    letter-spacing: .18em; text-transform: uppercase; color: var(--mu);
    text-align: center; margin: 8px 0 16px;
}
p.notice {
    text-align: center; color: #B00000; font-size: 12px; line-height: 1.6;
    border: 1px solid rgba(255,0,0,.35); padding: 12px 16px; margin: 0 auto 34px; max-width: 760px;
}
h2.heading {
    font-family: Anton, Impact, "Arial Narrow", sans-serif; font-size: 22px; letter-spacing: .04em;
    text-transform: uppercase; color: var(--tx); border-bottom: 1px solid var(--ln);
    padding-bottom: 8px; margin: 40px 0 18px;
}
h3.cat {
    font-family: "Space Mono", ui-monospace, Menlo, Consolas, monospace; font-size: 15px;
    letter-spacing: .06em; text-transform: uppercase; color: var(--rd); margin: 26px 0 12px;
}
p.body { margin: 0 0 12px; color: var(--tx); }
p.meta {
    font-family: "Space Mono", ui-monospace, Menlo, Consolas, monospace; font-size: 11px;
    color: var(--mu); letter-spacing: .04em; margin: 0 0 8px;
}
table { width: 100%; border-collapse: collapse; margin: 0 0 10px; font-size: 13.5px; }
th, td { text-align: left; padding: 9px 12px; border: 1px solid var(--ln); vertical-align: top; }
thead th {
    background: var(--sf2); font-family: "Space Mono", ui-monospace, Menlo, Consolas, monospace;
    font-size: 11px; letter-spacing: .1em; text-transform: uppercase; color: var(--tx);
}
table.kv th { width: 32%; background: var(--sf); font-weight: 700; }
table.kv tr.hi th, table.kv tr.hi td { background: var(--rd); color: #0A0A0A; font-weight: 700; }
table.kv.alt th { background: #1c1428; color: #cbb6f0; }
table.matrix td.c { text-align: center; }
table.details { margin: 6px 0 10px; font-size: 12.5px; }
table.details th { width: 26%; background: var(--sf); color: var(--mu); font-weight: 600; }
.finding {
    background: var(--sf); border: 1px solid var(--ln); border-left: 3px solid var(--ln);
    padding: 16px 18px; margin: 0 0 12px;
}
.finding.critical { border-left-color: #FF0000; }
.finding.high { border-left-color: #FF4D4D; }
.finding.medium { border-left-color: var(--warn); }
.finding.low { border-left-color: var(--low); }
.finding.info { border-left-color: var(--ok); }
.f-head { display: flex; align-items: center; gap: 10px; flex-wrap: wrap; margin-bottom: 10px; }
.chip {
    font-family: "Space Mono", ui-monospace, Menlo, Consolas, monospace; font-size: 10px;
    letter-spacing: .1em; padding: 3px 8px; border: 1px solid currentColor; color: var(--mu);
}
.finding.critical .chip { color: #FF0000; }
.finding.high .chip { color: #FF4D4D; }
.finding.medium .chip { color: var(--warn); }
.finding.low .chip { color: var(--low); }
.finding.info .chip { color: var(--ok); }
.f-title { font-weight: 700; font-size: 15px; }
p.remed {
    font-size: 13px; color: #7ddc8a; background: rgba(27,94,32,.12);
    border-left: 2px solid #1b5e20; padding: 10px 12px; margin: 10px 0 0;
}
ul.roadmap, ul.modules { margin: 0 0 14px 20px; }
ul.roadmap li, ul.modules li { margin-bottom: 8px; }
.mstat {
    font-family: "Space Mono", ui-monospace, Menlo, Consolas, monospace; font-size: 10px;
    letter-spacing: .1em; padding: 2px 7px; border: 1px solid currentColor; margin-right: 8px;
}
.mstat.ran { color: var(--ok); }
.mstat.skipped { color: var(--mu); }
p.disclaimer { color: #777; font-size: 12px; border-top: 1px solid var(--ln); padding-top: 14px; margin-top: 34px; }
p.author { margin-top: 10px; font-size: 12.5px; color: var(--mu); }
p.author a { color: var(--rd); }
@media print {
    body { background: #fff; color: #111; padding: 0; }
    h2.heading, h3.cat { color: #C40000; }
    .finding, table.details th, table.kv th { background: #fafafa; }
}
</style>
</head>
<body>
"""

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
SEVERITY_COLOR_HEX = {
    "critical": "#FF0000",
    "high": "#FF4D4D",
    "medium": "#FFB347",
    "low": "#8AB4FF",
    "info": "#8A8A82",
}
STATUS_COLOR_HEX = {
    "critical": "#FF0000",
    "high": "#FF4D4D",
    "attention": "#FFB347",
    "clear": "#7CFF9B",
    "not_tested": "#4a4a44",
}
STATUS_LABEL = {
    "critical": "CRITICAL ISSUES",
    "high": "HIGH-RISK ISSUES",
    "attention": "NEEDS ATTENTION",
    "clear": "TESTED · CLEAR",
    "not_tested": "NOT APPLICABLE",
}


class ReportGenerator:
    """Generate the security report for a scan in PDF, HTML or JSON."""

    @staticmethod
    def generate_report(scan_id: str, format_type: str = 'pdf') -> str:
        """Generate the PDF report for a scan.

        PDF is the only format that is persisted to disk. The file lands in
        the reports directory and is returned as an absolute path.

        Returns:
            str — absolute path to the saved .pdf file on disk
        """
        if format_type and format_type.lower() != 'pdf':
            raise ValueError("Only PDF reports are written to disk by this engine.")

        scan_data = ReportGenerator._prepare_scan_data(scan_id)
        return ReportGenerator._generate_pdf(scan_data)

    @staticmethod
    def build_download(scan_id: str, format_type: str = 'html') -> tuple:
        """Build a report payload in memory for immediate download.

        Used for the HTML and JSON formats. Nothing is written to disk — not
        to the reports directory and not anywhere else — the payload is built
        in memory and returned so the caller can stream it straight to the
        browser as an attachment.

        Returns:
            tuple — (filename, mimetype, payload_bytes)
        """
        fmt = (format_type or '').strip().lower()
        if fmt not in DOWNLOAD_ONLY_FORMATS:
            raise ValueError(
                f"Unsupported download format '{format_type}'. "
                f"Supported: {', '.join(SUPPORTED_FORMATS)}"
            )

        scan_data = ReportGenerator._prepare_scan_data(scan_id)
        stamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        base = f"scan_{scan_data['scan_id'][:8]}_{stamp}"

        if fmt == 'html':
            content = ReportGenerator._generate_html(scan_data)
        else:
            content = ReportGenerator._generate_json(scan_data)

        return f"{base}.{fmt}", MIMETYPES[fmt], content.encode('utf-8')

    @staticmethod
    def _prepare_scan_data(scan_id: str) -> Dict[str, Any]:
        """Load a scan's data and backfill the derived report fields."""
        scan_data = ReportGenerator._load_scan_data(scan_id)
        if not scan_data:
            raise ValueError(f"Scan {scan_id} not found")

        # Ensure OWASP coverage + risk score are present even for scans run
        # before this module's fields existed (backward compatibility).
        findings = scan_data.get('findings', [])
        if not scan_data.get('owasp_coverage'):
            scan_data['owasp_coverage'] = build_coverage_matrix(findings)
        if not scan_data.get('risk') or scan_data['risk'].get('grade') == '—':
            scan_data['risk'] = score_findings(findings)

        return scan_data

    @staticmethod
    def _load_scan_data(scan_id: str) -> Dict[str, Any]:
        # 1. Check in-memory active scans
        try:
            import app as app_mod
            if hasattr(app_mod, 'scanner'):
                status = app_mod.scanner.get_scan_status(scan_id)
                if status and status.get('scan_id') == scan_id and status.get('findings'):
                    return status
        except Exception:
            pass

        # 2. Check the persisted per-scan state file
        state_file = scan_state_path(scan_id)
        if os.path.exists(state_file):
            try:
                with open(state_file, 'r', encoding='utf-8') as rf:
                    return json.load(rf)
            except Exception:
                pass

        return None

    # ------------------------------------------------------------------
    # Shared helpers
    # ------------------------------------------------------------------
    @staticmethod
    def _sorted_findings(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        return sorted(findings, key=lambda f: SEVERITY_ORDER.get(f.get('severity', 'info'), 5))

    @staticmethod
    def _findings_by_owasp(findings: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
        grouped: Dict[str, List[Dict[str, Any]]] = {k: [] for k in OWASP_TOP_10}
        grouped['_other'] = []
        for f in findings:
            key = f.get('owasp')
            if key in grouped:
                grouped[key].append(f)
            else:
                grouped['_other'].append(f)
        for key in grouped:
            grouped[key] = ReportGenerator._sorted_findings(grouped[key])
        return grouped

    @staticmethod
    def _executive_narrative(scan_data: Dict[str, Any]) -> str:
        stats = scan_data.get('stats', {})
        risk = scan_data.get('risk', {})
        target = scan_data.get('target_url', 'the target')
        crit = stats.get('critical', 0)
        high = stats.get('high', 0)
        med = stats.get('medium', 0)
        low = stats.get('low', 0)
        total_actionable = crit + high + med + low

        if total_actionable == 0:
            return (
                f"This assessment of {target} did not identify any actionable vulnerabilities "
                f"across the OWASP Top 10:2021 categories covered by this scan. This reflects the "
                f"automated surface tested at the time of the scan and does not replace manual "
                f"penetration testing, authenticated testing, or business-logic review."
            )

        urgency = "requires immediate remediation" if crit > 0 else (
            "should be prioritized for near-term remediation" if high > 0 else
            "should be addressed as part of routine hardening"
        )
        parts = []
        if crit:
            parts.append(f"{crit} critical")
        if high:
            parts.append(f"{high} high-severity")
        if med:
            parts.append(f"{med} medium-severity")
        if low:
            parts.append(f"{low} low-severity")
        finding_phrase = ", ".join(parts[:-1]) + (" and " + parts[-1] if len(parts) > 1 else parts[0]) if parts else "no"

        return (
            f"This assessment of {target} identified {finding_phrase} finding(s), producing an "
            f"overall risk score of {risk.get('score', 0)}/100 (Grade {risk.get('grade', '—')} — "
            f"{risk.get('label', '')}). The combined result set {urgency}. Findings are organized "
            f"below under their OWASP Top 10:2021 category with evidence, potential impact, and "
            f"concrete remediation guidance for each."
        )

    @staticmethod
    def _remediation_roadmap(findings: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, str]]]:
        roadmap = {"immediate": [], "near_term": [], "best_practice": []}
        seen_titles = set()
        for f in ReportGenerator._sorted_findings(findings):
            if not f.get('remediation'):
                continue
            key = (f.get('title'), f.get('remediation'))
            if key in seen_titles:
                continue
            seen_titles.add(key)
            entry = {
                "title": f.get('title', 'Finding'),
                "remediation": f.get('remediation'),
                "owasp_code": f.get('owasp_code') or '—',
            }
            sev = f.get('severity')
            if sev == 'critical' or sev == 'high':
                roadmap["immediate"].append(entry)
            elif sev == 'medium':
                roadmap["near_term"].append(entry)
            else:
                roadmap["best_practice"].append(entry)
        return roadmap

    # ------------------------------------------------------------------
    # PDF report
    # ------------------------------------------------------------------
    @staticmethod
    def _generate_pdf(scan_data: Dict[str, Any]) -> str:
        ensure_dirs()
        report_file = report_path(
            f"scan_{scan_data['scan_id'][:8]}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
        )

        doc = SimpleDocTemplate(report_file, pagesize=A4, topMargin=0.6 * inch, bottomMargin=0.6 * inch)
        elements = []
        styles = getSampleStyleSheet()

        title_style = ParagraphStyle('CustomTitle', parent=styles['Heading1'], fontSize=22,
                                      textColor=colors.HexColor('#C40000'), spaceAfter=6, alignment=TA_CENTER)
        subtitle_style = ParagraphStyle('CustomSubtitle', parent=styles['Normal'], fontSize=10,
                                         textColor=colors.HexColor('#555555'), spaceAfter=20, alignment=TA_CENTER)
        heading_style = ParagraphStyle('CustomHeading', parent=styles['Heading2'], fontSize=15,
                                        textColor=colors.HexColor('#1a1a1a'), spaceBefore=16, spaceAfter=10,
                                        borderWidth=0, borderPadding=0)
        body_style = ParagraphStyle('CustomBody', parent=styles['Normal'], fontSize=9.5, leading=14,
                                     spaceAfter=8)
        finding_title_style = ParagraphStyle('FindingTitle', parent=styles['Normal'], fontSize=11,
                                              textColor=colors.HexColor('#1a1a1a'), spaceAfter=2,
                                              fontName='Helvetica-Bold')
        small_style = ParagraphStyle('Small', parent=styles['Normal'], fontSize=8.5, leading=12,
                                      textColor=colors.HexColor('#444444'))

        deployment = scan_data.get('deployment_info') or {}
        developer = scan_data.get('developer_info') or {}
        stats = scan_data.get('stats', {}) or {}
        risk = scan_data.get('risk', {}) or {}
        findings = scan_data.get('findings', [])
        owasp_coverage = scan_data.get('owasp_coverage') or build_coverage_matrix(findings)

        # ---- Cover / Title ----
        elements.append(Paragraph(f"{ENGINE_NAME}", title_style))
        elements.append(Paragraph("WEB APPLICATION SECURITY ASSESSMENT REPORT", subtitle_style))
        elements.append(Paragraph(
            "CONFIDENTIAL — for the recipient's authorized use only. This assessment covers only "
            "the automated checks listed in the Engine &amp; Methodology section and does not "
            "constitute a complete penetration test.",
            ParagraphStyle('Notice', parent=small_style, alignment=TA_CENTER, textColor=colors.HexColor('#B00000'))
        ))
        elements.append(Spacer(1, 0.25 * inch))

        # ---- Executive Summary ----
        elements.append(Paragraph("Executive Summary", heading_style))
        elements.append(Paragraph(_esc(ReportGenerator._executive_narrative(scan_data)), body_style))

        risk_table_data = [
            ['Overall Risk Score', f"{risk.get('score', 0)} / 100"],
            ['Risk Grade', f"{risk.get('grade', '—')} — {risk.get('label', 'N/A')}"],
            ['Critical / High / Medium / Low / Info',
             f"{stats.get('critical', 0)} / {stats.get('high', 0)} / {stats.get('medium', 0)} / "
             f"{stats.get('low', 0)} / {stats.get('info', 0)}"],
            ['Target URL', scan_data.get('target_url', 'N/A')],
            ['Scan ID', scan_data['scan_id']],
            ['Assessment Engine', f"{ENGINE_NAME} v{ENGINE_VERSION}"],
            ['Start Time', scan_data.get('start_time', 'N/A')],
            ['End Time', scan_data.get('end_time', 'N/A')],
        ]
        risk_table = Table(risk_table_data, colWidths=[2.1 * inch, 4.1 * inch])
        risk_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#1a1a1a')),
            ('TEXTCOLOR', (0, 0), (0, -1), colors.white),
            ('TEXTCOLOR', (1, 0), (1, -1), colors.black),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 9),
            ('GRID', (0, 0), (-1, -1), 0.75, colors.grey),
            ('ROWBACKGROUNDS', (1, 2), (1, -1), [colors.white, colors.HexColor('#f5f5f5')]),
            ('BACKGROUND', (0, 0), (-1, 1), colors.HexColor('#C40000')),
            ('TEXTCOLOR', (1, 0), (1, 1), colors.white),
            ('FONTNAME', (1, 0), (1, 1), 'Helvetica-Bold'),
            ('FONTSIZE', (1, 0), (1, 1), 11),
        ]))
        elements.append(risk_table)
        elements.append(Spacer(1, 0.25 * inch))

        # ---- OWASP Top 10 Coverage Matrix ----
        elements.append(Paragraph("OWASP Top 10:2021 Coverage Matrix", heading_style))
        owasp_table_data = [['Category', 'Name', 'Status', 'C', 'H', 'M', 'L']]
        for cat in owasp_coverage:
            owasp_table_data.append([
                cat['code'], cat['name'], STATUS_LABEL.get(cat['status'], cat['status']),
                str(cat['counts']['critical']), str(cat['counts']['high']),
                str(cat['counts']['medium']), str(cat['counts']['low']),
            ])
        owasp_table = Table(owasp_table_data, colWidths=[0.75 * inch, 2.35 * inch, 1.5 * inch,
                                                           0.35 * inch, 0.35 * inch, 0.35 * inch, 0.35 * inch])
        owasp_style_cmds = [
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1a1a1a')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 8),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
            ('ALIGN', (3, 0), (-1, -1), 'CENTER'),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f7f7f7')]),
        ]
        for i, cat in enumerate(owasp_coverage, start=1):
            color = colors.HexColor(STATUS_COLOR_HEX.get(cat['status'], '#4a4a44'))
            owasp_style_cmds.append(('TEXTCOLOR', (2, i), (2, i), color))
        owasp_table.setStyle(TableStyle(owasp_style_cmds))
        elements.append(owasp_table)
        elements.append(Spacer(1, 0.25 * inch))

        # ---- Target Infrastructure & Developer Attribution ----
        elements.append(Paragraph("Target Infrastructure &amp; Developer Attribution", heading_style))
        attr_table_data = [
            ['Deployed Platform', str(deployment.get('platform', 'Custom Web Server'))],
            ['Server Geolocation', str(deployment.get('location', deployment.get('server_location', 'Unknown')))],
            ['Server IP Address', str(deployment.get('ip_address', deployment.get('server_ip', 'Unknown')))],
            ['Reverse DNS / Host', str(deployment.get('reverse_dns', 'N/A'))],
            ['Web Server Header', str(deployment.get('server_header', 'N/A'))],
            ['Hosting Provider / ASN', f"{deployment.get('hosting_org', 'N/A')} ({deployment.get('asn', deployment.get('network_asn', 'N/A'))})"],
            ['Discovered Developer', str(developer.get('developer_name', 'Not Disclosed in Public Metadata'))],
            ['Attribution Confidence', f"{developer.get('confidence', 'N/A')} (Source: {developer.get('discovery_source', 'N/A')})"],
        ]
        attr_table = Table(attr_table_data, colWidths=[2.2 * inch, 4.0 * inch])
        attr_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#ede7f6')),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 8.5),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#b39ddb')),
            ('ROWBACKGROUNDS', (0, 0), (-1, -1), [colors.white, colors.HexColor('#fafafa')]),
        ]))
        elements.append(attr_table)
        elements.append(PageBreak())

        # ---- Detailed Findings grouped by OWASP category ----
        elements.append(Paragraph(f"Detailed Findings ({len(findings)} total)", heading_style))
        grouped = ReportGenerator._findings_by_owasp(findings)
        for key, cat in OWASP_TOP_10.items():
            items = [f for f in grouped.get(key, []) if f.get('severity') != 'info' or True]
            if not items:
                continue
            elements.append(Paragraph(f"{cat['code']} — {cat['name']}", ParagraphStyle(
                'CatHeading', parent=styles['Heading3'], fontSize=12.5,
                textColor=colors.HexColor('#C40000'), spaceBefore=14, spaceAfter=6)))
            for f in items:
                sev = f.get('severity', 'info')
                sev_hex = SEVERITY_COLOR_HEX.get(sev, '#8A8A82')
                elements.append(Paragraph(
                    f'<font color="{sev_hex}">[{sev.upper()}]</font> {_esc(f.get("title", "Finding"))}',
                    finding_title_style))
                elements.append(Paragraph(_esc(f.get('description', '')), body_style))
                cwe = ", ".join(f.get('cwe', []) or [])
                meta_bits = [f"Type: {_esc(f.get('type', 'n/a'))}"]
                if cwe:
                    meta_bits.append(f"CWE: {_esc(cwe)}")
                elements.append(Paragraph(" &nbsp;|&nbsp; ".join(meta_bits), small_style))
                details = f.get('details', {}) or {}
                if details:
                    detail_bits = []
                    for k, v in list(details.items())[:5]:
                        val = json.dumps(v)[:120] if isinstance(v, (list, dict)) else str(v)[:120]
                        detail_bits.append(f"<b>{_esc(k)}:</b> {_esc(val)}")
                    elements.append(Paragraph(" &nbsp;·&nbsp; ".join(detail_bits), small_style))
                if f.get('remediation'):
                    elements.append(Paragraph(f"<b>Remediation:</b> {_esc(f['remediation'])}",
                                               ParagraphStyle('Remed', parent=small_style,
                                                               textColor=colors.HexColor('#1b5e20'),
                                                               spaceBefore=3, spaceAfter=10)))
                else:
                    elements.append(Spacer(1, 0.08 * inch))

        # ---- Remediation Roadmap ----
        elements.append(PageBreak())
        elements.append(Paragraph("Remediation Roadmap", heading_style))
        roadmap = ReportGenerator._remediation_roadmap(findings)
        roadmap_sections = [
            ("Immediate (Critical / High)", roadmap["immediate"], '#C40000'),
            ("Near-Term (Medium)", roadmap["near_term"], '#B8860B'),
            ("Best Practice (Low / Info)", roadmap["best_practice"], '#555555'),
        ]
        for label, items, hexcolor in roadmap_sections:
            if not items:
                continue
            elements.append(Paragraph(label, ParagraphStyle(
                'RoadmapHeading', parent=styles['Heading3'], fontSize=11.5,
                textColor=colors.HexColor(hexcolor), spaceBefore=10, spaceAfter=6)))
            for item in items[:15]:
                elements.append(Paragraph(
                    f"<b>[{_esc(item['owasp_code'])}] {_esc(item['title'])}:</b> {_esc(item['remediation'])}",
                    body_style))

        # ---- Methodology / disclaimer footer ----
        elements.append(Spacer(1, 0.2 * inch))
        elements.append(Paragraph("Engine &amp; Methodology", heading_style))
        for mod in scan_data.get('engine_modules', []):
            status = "RAN" if mod.get('ran') else "SKIPPED"
            elements.append(Paragraph(
                f"<b>[{status}] {_esc(mod['name'])}:</b> {_esc(mod['description'])}", small_style))
        elements.append(Spacer(1, 0.15 * inch))
        elements.append(Paragraph(
            "This report was produced by automated, non-destructive detection probes. It reflects "
            "the state of the target's publicly reachable surface at the time of the scan and is not "
            "a substitute for manual penetration testing, source-code review, or ongoing monitoring. "
            "Only scan systems you own or are explicitly authorized to test.",
            ParagraphStyle('Disclaimer', parent=small_style, textColor=colors.HexColor('#777777'))
        ))
        elements.append(Spacer(1, 0.12 * inch))
        elements.append(Paragraph(
            f'<b>Authored by:</b> <font color="#C40000"><u><a href="{AUTHOR_URL}">{AUTHOR_NAME}</a></u></font>',
            small_style
        ))

        doc.build(elements)
        return report_file

    # ------------------------------------------------------------------
    # HTML report (built in memory — never written to disk)
    # ------------------------------------------------------------------
    @staticmethod
    def _generate_html(scan_data: Dict[str, Any]) -> str:
        """Render the full assessment as a self-contained HTML document.

        The document carries its own styling so it opens correctly as a
        standalone download with no external assets.
        """
        risk = scan_data.get('risk', {}) or {}
        stats = scan_data.get('stats', {}) or {}
        findings = scan_data.get('findings', [])
        owasp_coverage = scan_data.get('owasp_coverage') or build_coverage_matrix(findings)
        deployment = scan_data.get('deployment_info') or {}
        developer = scan_data.get('developer_info') or {}
        grouped = ReportGenerator._findings_by_owasp(findings)
        roadmap = ReportGenerator._remediation_roadmap(findings)

        out: List[str] = []
        out.append(_HTML_HEADER)
        out.append(f'<h1 class="title">{_esc(ENGINE_NAME)}</h1>')
        out.append('<p class="subtitle">WEB APPLICATION SECURITY ASSESSMENT REPORT</p>')
        out.append('<p class="notice">CONFIDENTIAL &mdash; for the recipient&rsquo;s authorized use only. '
                   'This assessment covers only the automated checks listed in the Engine &amp; Methodology '
                   'section and does not constitute a complete penetration test.</p>')

        # ---- Executive summary ----
        out.append('<h2 class="heading">Executive Summary</h2>')
        out.append(f'<p class="body">{_esc(ReportGenerator._executive_narrative(scan_data))}</p>')

        out.append('<table class="kv"><tbody>')
        out.append(f'<tr class="hi"><th>Overall Risk Score</th><td>{_esc(risk.get("score", 0))} / 100</td></tr>')
        out.append(f'<tr class="hi"><th>Risk Grade</th><td>{_esc(risk.get("grade", "—"))} &mdash; '
                   f'{_esc(risk.get("label", "N/A"))}</td></tr>')
        out.append('<tr><th>Critical / High / Medium / Low / Info</th><td>'
                   f'{stats.get("critical", 0)} / {stats.get("high", 0)} / {stats.get("medium", 0)} / '
                   f'{stats.get("low", 0)} / {stats.get("info", 0)}</td></tr>')
        out.append(f'<tr><th>Target URL</th><td>{_esc(scan_data.get("target_url", "N/A"))}</td></tr>')
        out.append(f'<tr><th>Scan ID</th><td>{_esc(scan_data.get("scan_id", "N/A"))}</td></tr>')
        out.append(f'<tr><th>Assessment Engine</th><td>{_esc(ENGINE_NAME)} v{_esc(ENGINE_VERSION)}</td></tr>')
        out.append(f'<tr><th>Start Time</th><td>{_esc(scan_data.get("start_time", "N/A"))}</td></tr>')
        out.append(f'<tr><th>End Time</th><td>{_esc(scan_data.get("end_time", "N/A"))}</td></tr>')
        out.append('</tbody></table>')

        # ---- OWASP coverage matrix ----
        out.append('<h2 class="heading">OWASP Top 10:2021 Coverage Matrix</h2>')
        out.append('<table class="matrix"><thead><tr><th>Category</th><th>Name</th><th>Status</th>'
                   '<th>C</th><th>H</th><th>M</th><th>L</th></tr></thead><tbody>')
        for cat in owasp_coverage:
            counts = cat['counts']
            color = STATUS_COLOR_HEX.get(cat['status'], '#4a4a44')
            out.append(
                '<tr>'
                f'<td>{_esc(cat["code"])}</td>'
                f'<td>{_esc(cat["name"])}</td>'
                f'<td style="color:{color}">{_esc(STATUS_LABEL.get(cat["status"], cat["status"]))}</td>'
                f'<td class="c">{counts["critical"]}</td>'
                f'<td class="c">{counts["high"]}</td>'
                f'<td class="c">{counts["medium"]}</td>'
                f'<td class="c">{counts["low"]}</td>'
                '</tr>'
            )
        out.append('</tbody></table>')

        # ---- Attribution ----
        out.append('<h2 class="heading">Target Infrastructure &amp; Developer Attribution</h2>')
        out.append('<table class="kv alt"><tbody>')
        for label, value in [
            ('Deployed Platform', deployment.get('platform', 'Custom Web Server')),
            ('Server Geolocation', deployment.get('location', deployment.get('server_location', 'Unknown'))),
            ('Server IP Address', deployment.get('ip_address', deployment.get('server_ip', 'Unknown'))),
            ('Reverse DNS / Host', deployment.get('reverse_dns', 'N/A')),
            ('Web Server Header', deployment.get('server_header', 'N/A')),
            ('Hosting Provider / ASN',
             f"{deployment.get('hosting_org', 'N/A')} ({deployment.get('asn', deployment.get('network_asn', 'N/A'))})"),
            ('Discovered Developer', developer.get('developer_name', 'Not Disclosed in Public Metadata')),
            ('Attribution Confidence',
             f"{developer.get('confidence', 'N/A')} (Source: {developer.get('discovery_source', 'N/A')})"),
        ]:
            out.append(f'<tr><th>{_esc(label)}</th><td>{_esc(value)}</td></tr>')
        out.append('</tbody></table>')

        # ---- Detailed findings ----
        out.append(f'<h2 class="heading">Detailed Findings ({len(findings)} total)</h2>')
        for key, cat in OWASP_TOP_10.items():
            items = grouped.get(key, [])
            if not items:
                continue
            out.append(f'<h3 class="cat">{_esc(cat["code"])} &mdash; {_esc(cat["name"])}</h3>')
            for f in items:
                sev = f.get('severity', 'info')
                out.append(f'<div class="finding {sev}">')
                out.append(f'<div class="f-head"><span class="chip">{_esc(sev.upper())}</span>'
                           f'<span class="f-title">{_esc(f.get("title", "Finding"))}</span></div>')
                out.append(f'<p class="body">{_esc(f.get("description", ""))}</p>')
                meta_bits = [f"Type: {_esc(f.get('type', 'n/a'))}"]
                cwe = ", ".join(f.get('cwe', []) or [])
                if cwe:
                    meta_bits.append(f"CWE: {_esc(cwe)}")
                out.append(f'<p class="meta">{" &nbsp;|&nbsp; ".join(meta_bits)}</p>')
                details = f.get('details', {}) or {}
                if details:
                    out.append('<table class="details"><tbody>')
                    for k, v in list(details.items())[:8]:
                        val = json.dumps(v) if isinstance(v, (list, dict)) else str(v)
                        out.append(f'<tr><th>{_esc(k)}</th><td>{_esc(val)}</td></tr>')
                    out.append('</tbody></table>')
                if f.get('remediation'):
                    out.append(f'<p class="remed"><b>Remediation:</b> {_esc(f["remediation"])}</p>')
                out.append('</div>')

        # ---- Remediation roadmap ----
        out.append('<h2 class="heading">Remediation Roadmap</h2>')
        for label, key, color in [
            ("Immediate (Critical / High)", "immediate", '#FF0000'),
            ("Near-Term (Medium)", "near_term", '#FFB347'),
            ("Best Practice (Low / Info)", "best_practice", '#8A8A82'),
        ]:
            items = roadmap.get(key, [])
            if not items:
                continue
            out.append(f'<h3 class="cat" style="color:{color}">{_esc(label)}</h3><ul class="roadmap">')
            for item in items[:15]:
                out.append('<li>'
                           f'<b>[{_esc(item["owasp_code"])}] {_esc(item["title"])}:</b> '
                           f'{_esc(item["remediation"])}</li>')
            out.append('</ul>')

        # ---- Methodology / disclaimer ----
        out.append('<h2 class="heading">Engine &amp; Methodology</h2><ul class="modules">')
        for mod in scan_data.get('engine_modules', []):
            status = "RAN" if mod.get('ran') else "SKIPPED"
            status_class = 'ran' if mod.get('ran') else 'skipped'
            out.append(f'<li><span class="mstat {status_class}">{status}</span> '
                       f'<b>{_esc(mod["name"])}:</b> {_esc(mod["description"])}</li>')
        out.append('</ul>')

        out.append('<p class="disclaimer">This report was produced by automated, non-destructive detection '
                   'probes. It reflects the state of the target&rsquo;s publicly reachable surface at the time '
                   'of the scan and is not a substitute for manual penetration testing, source-code review, or '
                   'ongoing monitoring. Only scan systems you own or are explicitly authorized to test.</p>')
        out.append(f'<p class="author">Authored by: <a href="{AUTHOR_URL}">{_esc(AUTHOR_NAME)}</a></p>')
        out.append('</body></html>')
        return "\n".join(out)

    # ------------------------------------------------------------------
    # JSON report (built in memory — never written to disk)
    # ------------------------------------------------------------------
    @staticmethod
    def _generate_json(scan_data: Dict[str, Any]) -> str:
        """Render the full assessment as a machine-readable JSON document."""
        findings = scan_data.get('findings', [])
        owasp_coverage = scan_data.get('owasp_coverage') or build_coverage_matrix(findings)
        risk = scan_data.get('risk', {}) or {}
        grouped = ReportGenerator._findings_by_owasp(findings)

        findings_by_owasp = {}
        for key in list(OWASP_TOP_10.keys()) + ['_other']:
            if grouped.get(key):
                findings_by_owasp[key] = grouped[key]

        payload = {
            "report_metadata": {
                "engine": ENGINE_NAME,
                "engine_version": ENGINE_VERSION,
                "author": AUTHOR_NAME,
                "author_url": AUTHOR_URL,
                "format": "json",
                "generated_at": datetime.now().isoformat(timespec='seconds'),
                "confidentiality": "CONFIDENTIAL - for the recipient's authorized use only.",
                "note": (
                    "Generated in memory and streamed as a download. This report is not "
                    "persisted to the engine's reports directory."
                ),
            },
            "scan": {
                "scan_id": scan_data.get('scan_id'),
                "target_url": scan_data.get('target_url'),
                "status": scan_data.get('status'),
                "start_time": scan_data.get('start_time'),
                "end_time": scan_data.get('end_time'),
                "scan_types": scan_data.get('scan_types', []),
                "total_requests": scan_data.get('stats', {}).get('total_requests', 0),
            },
            "executive_summary": ReportGenerator._executive_narrative(scan_data),
            "risk": risk,
            "stats": scan_data.get('stats', {}),
            "owasp_coverage": owasp_coverage,
            "attribution": {
                "deployment": scan_data.get('deployment_info', {}) or {},
                "developer": scan_data.get('developer_info', {}) or {},
            },
            "findings": ReportGenerator._sorted_findings(findings),
            "findings_by_owasp": findings_by_owasp,
            "remediation_roadmap": ReportGenerator._remediation_roadmap(findings),
            "engine_modules": scan_data.get('engine_modules', []),
        }
        return json.dumps(payload, indent=2, ensure_ascii=False, default=str)


def _esc(value: Any) -> str:
    """Escape text so it is safe to embed in the PDF report markup."""
    s = str(value)
    return (s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;"))
