"""
HTML Report Generator
======================
Generates enterprise-grade HTML compliance reports with executive summary,
risk heatmap, failed/manual-review controls tables, and remediation
recommendations.

All dynamic values (rule text, and especially anything derived from the
uploaded configuration file such as hostnames, banner text, or interface
names) are HTML-escaped before being embedded in the page. A FortiGate
config file is untrusted input from the tool's perspective -- without
escaping, a hostname or banner string containing `<script>` would be
reflected straight into the report and executed in the viewer's browser.
"""

import html
import logging
from datetime import datetime
from pathlib import Path

logger = logging.getLogger(__name__)

BENCHMARK_NAME = "CIS FortiGate 7.4.x Benchmark v1.0.1"
TOOL_VERSION = "3.0.0"


def _e(value) -> str:
    """Escape a value for safe embedding in HTML."""
    return html.escape(str(value), quote=True)


class HTMLReportGenerator:
    """Generate enterprise-grade HTML compliance reports."""

    def generate(self, report, config_file: str = "", output_path: str = "") -> str:
        """Generate HTML report from ComplianceReport."""
        html_doc = self._build_report(report, config_file)

        if output_path:
            Path(output_path).write_text(html_doc, encoding="utf-8")
            logger.info(f"HTML report saved: {output_path}")

        return html_doc

    def _status_badge(self, status_value: str) -> str:
        cls = {"PASS": "pass", "FAIL": "fail", "MANUAL_REVIEW": "manual", "ERROR": "error"}.get(status_value, "manual")
        label = {"MANUAL_REVIEW": "MANUAL REVIEW"}.get(status_value, status_value)
        return f'<span class="status-badge status-{cls}">{_e(label)}</span>'

    def _build_report(self, report, config_file: str) -> str:
        """Build the complete HTML report."""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        heatmap_rows = ""
        for name, cs in report.category_scores.items():
            pct = cs.percentage
            color = self._pct_color(pct)
            heatmap_rows += f"""
                <tr>
                    <td>{_e(name)}</td>
                    <td>{cs.total}</td>
                    <td>{cs.passed}</td>
                    <td>{cs.failed}</td>
                    <td>{cs.manual_review}</td>
                    <td>
                        <div class="progress-bar">
                            <div class="progress-fill" style="width:{pct}%;background:{color}"></div>
                        </div>
                        <span class="pct-label">{pct}%</span>
                    </td>
                </tr>"""

        failed_rows = ""
        for r in report.failed_results:
            sev_class = r.severity.value.lower()
            level_badge = f"L{r.level.value}"
            failed_rows += f"""
                <tr class="severity-{sev_class}">
                    <td><span class="rule-id">{_e(r.rule_id)}</span></td>
                    <td>{_e(r.title)}</td>
                    <td><span class="badge badge-level">{level_badge}</span></td>
                    <td><span class="badge badge-{sev_class}">{_e(r.severity.value)}</span></td>
                    <td class="actual-value">{_e(r.actual_value)}</td>
                    <td class="expected-value">{_e(r.expected_value)}</td>
                    <td class="remediation">{_e(r.remediation)}</td>
                    <td class="notes">{_e(r.notes) if r.notes else ""}</td>
                </tr>"""

        manual_rows = ""
        for r in report.manual_review_results:
            level_badge = f"L{r.level.value}"
            manual_rows += f"""
                <tr>
                    <td><span class="rule-id">{_e(r.rule_id)}</span></td>
                    <td>{_e(r.title)}</td>
                    <td><span class="badge badge-level">{level_badge}</span></td>
                    <td class="actual-value">{_e(r.actual_value)}</td>
                    <td class="remediation">{_e(r.remediation)}</td>
                    <td class="notes">{_e(r.notes) if r.notes else ""}</td>
                </tr>"""

        all_rows = ""
        for r in report.results:
            status_class = r.status.value.lower().replace("_", "-")
            sev_class = r.severity.value.lower()
            all_rows += f"""
                <tr class="row-{status_class}" data-severity="{_e(r.severity.value)}" data-level="{r.level.value}" data-category="{_e(r.category)}" data-status="{_e(r.status.value)}">
                    <td><span class="rule-id">{_e(r.rule_id)}</span></td>
                    <td>{_e(r.title)}</td>
                    <td><span class="badge badge-level">L{r.level.value}</span></td>
                    <td><span class="badge badge-{sev_class}">{_e(r.severity.value)}</span></td>
                    <td>{self._status_badge(r.status.value)}</td>
                    <td class="actual-value">{_e(r.actual_value)}</td>
                    <td class="notes">{_e(r.notes) if r.notes else ""}</td>
                </tr>"""

        gauge_color = self._pct_color(report.overall_percentage)
        l1_color = self._pct_color(report.level1_percentage)
        l2_color = self._pct_color(report.level2_percentage)
        safe_config_file = _e(config_file) if config_file else "N/A"

        html_doc = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>FortiGate CIS Benchmark Audit Report</title>
<style>
:root {{
    --bg-primary: #0a0e17;
    --bg-secondary: #111827;
    --bg-card: #1a2332;
    --bg-card-hover: #1f2b3d;
    --text-primary: #e5e7eb;
    --text-secondary: #9ca3af;
    --text-muted: #6b7280;
    --accent-blue: #3b82f6;
    --accent-cyan: #06b6d4;
    --accent-green: #10b981;
    --accent-red: #ef4444;
    --accent-orange: #f59e0b;
    --accent-purple: #8b5cf6;
    --accent-gray: #9ca3af;
    --border: #1f2937;
    --radius: 12px;
    --shadow: 0 4px 24px rgba(0,0,0,0.3);
}}

* {{ margin: 0; padding: 0; box-sizing: border-box; }}

body {{
    font-family: 'Segoe UI', 'Inter', system-ui, -apple-system, sans-serif;
    background: var(--bg-primary);
    color: var(--text-primary);
    line-height: 1.6;
    min-height: 100vh;
}}

.container {{ max-width: 1400px; margin: 0 auto; padding: 30px; }}

.report-header {{
    background: linear-gradient(135deg, #1e3a5f 0%, #0f172a 50%, #1a1a2e 100%);
    border-radius: var(--radius);
    padding: 40px;
    margin-bottom: 30px;
    border: 1px solid rgba(59,130,246,0.2);
    position: relative;
    overflow: hidden;
}}
.report-header h1 {{
    font-size: 28px;
    font-weight: 700;
    background: linear-gradient(135deg, #60a5fa, #a78bfa);
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
    margin-bottom: 8px;
}}
.report-header .subtitle {{ color: var(--text-secondary); font-size: 14px; }}
.report-header .meta {{ color: var(--text-muted); font-size: 13px; margin-top: 12px; }}
.report-header .disclaimer {{ color: var(--text-muted); font-size: 12px; margin-top: 10px; max-width: 900px; }}

.score-grid {{
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
    gap: 20px;
    margin-bottom: 30px;
}}
.score-card {{
    background: var(--bg-card);
    border-radius: var(--radius);
    padding: 24px;
    border: 1px solid var(--border);
    text-align: center;
    transition: transform 0.2s, box-shadow 0.2s;
}}
.score-card:hover {{ transform: translateY(-2px); box-shadow: var(--shadow); }}
.score-card .score-value {{ font-size: 42px; font-weight: 700; margin: 8px 0; }}
.score-card .score-label {{ font-size: 13px; color: var(--text-secondary); text-transform: uppercase; letter-spacing: 1px; }}
.score-card .score-detail {{ font-size: 12px; color: var(--text-muted); margin-top: 8px; }}

.section {{
    background: var(--bg-card);
    border-radius: var(--radius);
    padding: 28px;
    margin-bottom: 24px;
    border: 1px solid var(--border);
}}
.section-title {{ font-size: 18px; font-weight: 600; margin-bottom: 20px; display: flex; align-items: center; gap: 10px; }}

table {{ width: 100%; border-collapse: collapse; font-size: 13px; }}
th {{
    text-align: left; padding: 12px 16px; background: var(--bg-secondary); color: var(--text-secondary);
    font-weight: 600; font-size: 11px; text-transform: uppercase; letter-spacing: 0.5px; border-bottom: 1px solid var(--border);
}}
td {{ padding: 12px 16px; border-bottom: 1px solid rgba(255,255,255,0.04); vertical-align: top; word-break: break-word; }}
tr:hover {{ background: var(--bg-card-hover); }}

.badge {{
    padding: 3px 10px; border-radius: 20px; font-size: 11px; font-weight: 600; display: inline-block;
    text-transform: uppercase; letter-spacing: 0.5px;
}}
.badge-critical {{ background: rgba(239,68,68,0.15); color: #f87171; }}
.badge-high {{ background: rgba(245,158,11,0.15); color: #fbbf24; }}
.badge-medium {{ background: rgba(59,130,246,0.15); color: #60a5fa; }}
.badge-low {{ background: rgba(16,185,129,0.15); color: #34d399; }}
.badge-level {{ background: rgba(139,92,246,0.15); color: #a78bfa; }}

.status-badge {{ padding: 4px 12px; border-radius: 20px; font-size: 11px; font-weight: 700; white-space: nowrap; }}
.status-pass {{ background: rgba(16,185,129,0.15); color: #34d399; }}
.status-fail {{ background: rgba(239,68,68,0.15); color: #f87171; }}
.status-manual {{ background: rgba(156,163,175,0.18); color: #d1d5db; }}
.status-error {{ background: rgba(245,158,11,0.18); color: #fbbf24; }}

.rule-id {{ font-family: 'Consolas', 'Monaco', monospace; font-weight: 600; color: var(--accent-cyan); }}

.progress-bar {{
    width: 120px; height: 8px; background: rgba(255,255,255,0.06); border-radius: 4px;
    overflow: hidden; display: inline-block; vertical-align: middle;
}}
.progress-fill {{ height: 100%; border-radius: 4px; transition: width 0.5s ease; }}
.pct-label {{ font-size: 12px; font-weight: 600; color: var(--text-secondary); margin-left: 8px; }}

.risk-indicator {{
    display: inline-flex; align-items: center; gap: 8px; padding: 6px 16px; border-radius: 20px;
    font-weight: 700; font-size: 13px; margin-top: 8px;
}}

.severity-grid {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 16px; margin-bottom: 20px; }}
.severity-item {{ background: var(--bg-secondary); border-radius: 8px; padding: 16px; text-align: center; border-left: 3px solid; }}

.controls-bar {{ display: flex; gap: 12px; margin-bottom: 16px; flex-wrap: wrap; align-items: center; }}
.search-input {{
    background: var(--bg-secondary); border: 1px solid var(--border); border-radius: 8px; padding: 8px 16px;
    color: var(--text-primary); font-size: 13px; flex: 1; min-width: 200px;
}}
.search-input:focus {{ outline: none; border-color: var(--accent-blue); }}
.filter-btn {{
    background: var(--bg-secondary); border: 1px solid var(--border); border-radius: 8px; padding: 8px 16px;
    color: var(--text-secondary); font-size: 12px; cursor: pointer; transition: all 0.2s;
}}
.filter-btn:hover, .filter-btn.active {{ background: var(--accent-blue); color: white; border-color: var(--accent-blue); }}

.actual-value {{ color: var(--accent-orange); font-family: monospace; font-size: 12px; }}
.expected-value {{ color: var(--accent-green); font-family: monospace; font-size: 12px; }}
.remediation {{ font-size: 12px; color: var(--text-secondary); }}
.notes {{ font-size: 12px; color: var(--accent-purple); font-style: italic; white-space: pre-wrap; }}

.report-footer {{ text-align: center; color: var(--text-muted); font-size: 12px; padding: 20px; margin-top: 20px; }}

@media print {{
    body {{ background: white; color: #333; }}
    .report-header {{ background: #f3f4f6; }}
    .section {{ border: 1px solid #e5e7eb; }}
    .score-card {{ border: 1px solid #e5e7eb; }}
    .controls-bar {{ display: none; }}
}}
</style>
</head>
<body>
<div class="container">
    <div class="report-header">
        <h1>&#128737; FortiGate CIS Benchmark Audit Report</h1>
        <div class="subtitle">{_e(BENCHMARK_NAME)} Compliance Assessment</div>
        <div class="meta">
            Generated: {_e(timestamp)} &nbsp;|&nbsp; Config: {safe_config_file} &nbsp;|&nbsp;
            Total Controls: {report.total_rules}
        </div>
        <div class="disclaimer">
            Scores reflect only the {report.evaluated_rules} control(s) this tool could definitively verify from the
            uploaded configuration file. {report.manual_review_rules} control(s) require manual review on the live
            device and are excluded from the percentage/weighted score below -- see the "Requires Manual Review"
            section. This report was generated entirely offline; no configuration data was sent to any external service.
        </div>
    </div>

    <div class="score-grid">
        <div class="score-card">
            <div class="score-label">Overall Compliance</div>
            <div class="score-value" style="color:{gauge_color}">{report.overall_percentage}%</div>
            <div class="score-detail">{report.passed_rules}/{report.evaluated_rules} evaluated controls passed</div>
            <div class="risk-indicator" style="background:rgba(0,0,0,0.3);color:{report.risk_color}">
                &#9888; Risk: {_e(report.risk_rating)}
            </div>
        </div>
        <div class="score-card">
            <div class="score-label">Level 1 (Basic)</div>
            <div class="score-value" style="color:{l1_color}">{report.level1_percentage}%</div>
            <div class="score-detail">{report.level1.passed}/{report.level1.evaluated} evaluated ({report.level1_total} total)</div>
        </div>
        <div class="score-card">
            <div class="score-label">Level 2 (Advanced)</div>
            <div class="score-value" style="color:{l2_color}">{report.level2_percentage}%</div>
            <div class="score-detail">{report.level2.passed}/{report.level2.evaluated} evaluated ({report.level2_total} total)</div>
        </div>
        <div class="score-card">
            <div class="score-label">Weighted Score</div>
            <div class="score-value" style="color:{gauge_color}">{report.weighted_score}%</div>
            <div class="score-detail">Severity-weighted, evaluated controls only</div>
        </div>
        <div class="score-card">
            <div class="score-label">Manual Review</div>
            <div class="score-value" style="color:var(--accent-gray)">{report.manual_review_rules}</div>
            <div class="score-detail">Controls needing a human on the live device</div>
        </div>
    </div>

    <div class="section">
        <div class="section-title">&#9888;&#65039; Severity Breakdown (evaluated controls)</div>
        <div class="severity-grid">
            <div class="severity-item" style="border-color:#ef4444">
                <div style="font-size:24px;font-weight:700;color:#f87171">{report.severity.get('Critical').failed if report.severity.get('Critical') else 0}</div>
                <div style="font-size:12px;color:var(--text-secondary)">Critical Failures</div>
                <div style="font-size:11px;color:var(--text-muted)">{report.severity.get('Critical').passed if report.severity.get('Critical') else 0}/{report.severity.get('Critical').evaluated if report.severity.get('Critical') else 0} passed</div>
            </div>
            <div class="severity-item" style="border-color:#f59e0b">
                <div style="font-size:24px;font-weight:700;color:#fbbf24">{report.severity.get('High').failed if report.severity.get('High') else 0}</div>
                <div style="font-size:12px;color:var(--text-secondary)">High Failures</div>
                <div style="font-size:11px;color:var(--text-muted)">{report.severity.get('High').passed if report.severity.get('High') else 0}/{report.severity.get('High').evaluated if report.severity.get('High') else 0} passed</div>
            </div>
            <div class="severity-item" style="border-color:#3b82f6">
                <div style="font-size:24px;font-weight:700;color:#60a5fa">{report.severity.get('Medium').failed if report.severity.get('Medium') else 0}</div>
                <div style="font-size:12px;color:var(--text-secondary)">Medium Failures</div>
                <div style="font-size:11px;color:var(--text-muted)">{report.severity.get('Medium').passed if report.severity.get('Medium') else 0}/{report.severity.get('Medium').evaluated if report.severity.get('Medium') else 0} passed</div>
            </div>
            <div class="severity-item" style="border-color:#10b981">
                <div style="font-size:24px;font-weight:700;color:#34d399">{report.severity.get('Low').failed if report.severity.get('Low') else 0}</div>
                <div style="font-size:12px;color:var(--text-secondary)">Low Failures</div>
                <div style="font-size:11px;color:var(--text-muted)">{report.severity.get('Low').passed if report.severity.get('Low') else 0}/{report.severity.get('Low').evaluated if report.severity.get('Low') else 0} passed</div>
            </div>
        </div>
    </div>

    <div class="section">
        <div class="section-title">&#128200; Compliance by Category</div>
        <table>
            <thead><tr><th>Category</th><th>Total</th><th>Passed</th><th>Failed</th><th>Manual</th><th>Score</th></tr></thead>
            <tbody>{heatmap_rows}</tbody>
        </table>
    </div>

    <div class="section">
        <div class="section-title">&#10060; Failed Controls ({report.failed_rules})</div>
        {"<p style='color:var(--accent-green);font-size:14px;'>No failed controls. &#10004;</p>" if report.failed_rules == 0 else f'''
        <table>
            <thead><tr><th>Rule ID</th><th>Control</th><th>Level</th><th>Severity</th><th>Actual Value</th><th>Expected Value</th><th>Remediation</th><th>Notes</th></tr></thead>
            <tbody>{failed_rows}</tbody>
        </table>'''}
    </div>

    <div class="section">
        <div class="section-title">&#128269; Requires Manual Review ({report.manual_review_rules})</div>
        <p style="font-size:12px;color:var(--text-muted);margin-bottom:12px;">
            These controls cannot be conclusively verified from a static configuration backup alone (they need a live
            device check, external comparison, or a human judgement call). They are not counted toward the compliance
            percentage above.
        </p>
        {"<p style='color:var(--text-muted);font-size:13px;'>None.</p>" if report.manual_review_rules == 0 else f'''
        <table>
            <thead><tr><th>Rule ID</th><th>Control</th><th>Level</th><th>Evidence Gathered</th><th>Guidance</th><th>Notes</th></tr></thead>
            <tbody>{manual_rows}</tbody>
        </table>'''}
    </div>

    <div class="section">
        <div class="section-title">&#128203; All Controls ({report.total_rules})</div>
        <div class="controls-bar">
            <input type="text" class="search-input" placeholder="Search rules..." oninput="filterTable(this.value)" id="searchInput">
            <button class="filter-btn active" onclick="filterStatus('all', this)">All</button>
            <button class="filter-btn" onclick="filterStatus('PASS', this)">Pass</button>
            <button class="filter-btn" onclick="filterStatus('FAIL', this)">Fail</button>
            <button class="filter-btn" onclick="filterStatus('MANUAL_REVIEW', this)">Manual Review</button>
            <button class="filter-btn" onclick="filterSeverity('Critical', this)">Critical</button>
            <button class="filter-btn" onclick="filterSeverity('High', this)">High</button>
            <button class="filter-btn" onclick="filterSeverity('Medium', this)">Medium</button>
            <button class="filter-btn" onclick="filterSeverity('Low', this)">Low</button>
        </div>
        <table id="allControlsTable">
            <thead><tr><th>Rule ID</th><th>Control</th><th>Level</th><th>Severity</th><th>Status</th><th>Value</th><th>Notes</th></tr></thead>
            <tbody>{all_rows}</tbody>
        </table>
    </div>

    <div class="report-footer">
        FortiGate CIS Benchmark Checker v{TOOL_VERSION} &bull; {_e(BENCHMARK_NAME)} &bull; Generated {_e(timestamp)}
    </div>
</div>

<script>
let currentStatusFilter = 'all';
let currentSeverityFilter = 'all';

function filterTable(query) {{
    const rows = document.querySelectorAll('#allControlsTable tbody tr');
    const q = query.toLowerCase();
    rows.forEach(row => {{
        const text = row.textContent.toLowerCase();
        const matchText = !q || text.includes(q);
        const status = row.dataset.status;
        const severity = row.dataset.severity;
        const matchStatus = currentStatusFilter === 'all' || status === currentStatusFilter;
        const matchSev = currentSeverityFilter === 'all' || severity === currentSeverityFilter;
        row.style.display = matchText && matchStatus && matchSev ? '' : 'none';
    }});
}}

function filterStatus(status, btn) {{
    currentStatusFilter = status;
    document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
    btn.classList.add('active');
    filterTable(document.getElementById('searchInput').value);
}}

function filterSeverity(severity, btn) {{
    currentSeverityFilter = severity === currentSeverityFilter ? 'all' : severity;
    filterTable(document.getElementById('searchInput').value);
}}
</script>
</body>
</html>"""
        return html_doc

    def _pct_color(self, pct: float) -> str:
        if pct >= 80:
            return "#10b981"
        elif pct >= 60:
            return "#f59e0b"
        elif pct >= 40:
            return "#f97316"
        else:
            return "#ef4444"
