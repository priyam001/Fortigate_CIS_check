"""
FortiGate CIS Benchmark Web Dashboard
=======================================
Flask-based web UI for running CIS compliance audits entirely locally.

No configuration data is ever sent to an external service: parsing,
rule evaluation, and report generation all happen in-process against the
uploaded file, which is deleted immediately after the audit completes.

Audit results are kept server-side in memory, keyed by a per-browser
session id (a random value stored in a signed cookie) so concurrent users
of the same running dashboard never see each other's results.
"""

import os
import sys
import uuid
import logging
import tempfile
from pathlib import Path
from datetime import datetime

from flask import Flask, render_template, request, jsonify, send_file, redirect, url_for, session
from werkzeug.utils import secure_filename

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from cis_benchmark.config_parser import FortiGateConfigParser, ConfigParseError
from cis_benchmark.rules import get_all_rules, get_level1_rules, get_level2_rules
from cis_benchmark.scoring import ComplianceScorer
from cis_benchmark.remediation import RemediationEngine
from cis_benchmark.reporting import HTMLReportGenerator, JSONReportGenerator, PDFReportGenerator

logger = logging.getLogger(__name__)

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024  # 50MB max upload, matches parser's own limit
app.config['SECRET_KEY'] = os.environ.get('CIS_AUDIT_SECRET_KEY') or os.urandom(32).hex()

ALLOWED_EXTENSIONS = {'.conf', '.txt', '.cfg'}
MAX_NOTE_LENGTH = 2000

# Per-session audit results: {session_id: {"report": ..., "config_file": ..., "timestamp": ...}}
_AUDITS = {}

UPLOAD_FOLDER = tempfile.mkdtemp(prefix="fortigate_audit_")


def _session_id() -> str:
    if 'sid' not in session:
        session['sid'] = uuid.uuid4().hex
    return session['sid']


def _get_audit() -> dict:
    return _AUDITS.get(_session_id(), {"report": None, "config_file": "", "timestamp": None})


def run_audit(config_path: str, level_filter: str = "all"):
    """Run CIS audit on a config file."""
    parser = FortiGateConfigParser()
    config = parser.parse_file(config_path)

    if level_filter == "1":
        rules = get_level1_rules()
    elif level_filter == "2":
        rules = get_level2_rules()
    else:
        rules = get_all_rules()

    results = [rule.evaluate(config) for rule in rules]

    scorer = ComplianceScorer()
    return scorer.calculate(results)


def _save_upload(file) -> str:
    """Validate and save an uploaded config file, returning its temp path."""
    filename = secure_filename(file.filename or "")
    if not filename:
        raise ValueError("Invalid filename")
    ext = os.path.splitext(filename)[1].lower()
    if ext not in ALLOWED_EXTENSIONS:
        raise ValueError(f"Unsupported file type '{ext}'. Allowed: {', '.join(sorted(ALLOWED_EXTENSIONS))}")

    unique_name = f"{uuid.uuid4().hex}_{filename}"
    filepath = os.path.join(UPLOAD_FOLDER, unique_name)
    file.save(filepath)
    return filepath


@app.route('/')
def index():
    """Dashboard home page."""
    return render_template('dashboard.html', audit=_get_audit())


@app.route('/upload', methods=['POST'])
def upload_config():
    """Upload and audit a FortiGate config file."""
    if 'config_file' not in request.files or request.files['config_file'].filename == '':
        return jsonify({"error": "No file uploaded"}), 400

    file = request.files['config_file']
    try:
        filepath = _save_upload(file)
    except ValueError as e:
        return jsonify({"error": str(e)}), 400

    try:
        level_filter = request.form.get('level', 'all')
        if level_filter not in ('1', '2', 'all'):
            level_filter = 'all'
        report = run_audit(filepath, level_filter)

        _AUDITS[_session_id()] = {
            "report": report,
            "config_file": secure_filename(file.filename),
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        }
        return redirect(url_for('index'))
    except (FileNotFoundError, PermissionError, ValueError, ConfigParseError) as e:
        logger.warning(f"Audit rejected: {e}")
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        logger.error(f"Audit failed: {e}")
        return jsonify({"error": "Internal error while auditing the configuration file."}), 500
    finally:
        try:
            os.remove(filepath)
        except OSError:
            pass


@app.route('/note/<rule_id>', methods=['POST'])
def save_note(rule_id):
    """
    Save a free-text note against one finding in the current session's audit
    results. Notes live on the same RuleResult objects the report/download
    endpoints already read from, so they show up in every report generated
    afterwards (HTML, JSON, PDF) without any extra plumbing, and persist
    across format downloads until a new audit is run in this session.
    """
    audit = _get_audit()
    report = audit.get("report")
    if not report:
        return jsonify({"error": "No audit results available. Run an audit first."}), 400

    payload = request.get_json(silent=True) or {}
    note_text = payload.get("note", request.form.get("note", ""))
    note_text = (note_text or "").strip()
    if len(note_text) > MAX_NOTE_LENGTH:
        return jsonify({"error": f"Note is too long (max {MAX_NOTE_LENGTH} characters)."}), 400

    result = next((r for r in report.results if r.rule_id == rule_id), None)
    if result is None:
        return jsonify({"error": f"Unknown rule_id '{rule_id}'"}), 404

    result.notes = note_text
    return jsonify({"ok": True, "rule_id": rule_id, "notes": result.notes})


@app.route('/download/<format_type>')
def download_report(format_type):
    """Download report in specified format."""
    audit = _get_audit()
    if not audit["report"]:
        return jsonify({"error": "No audit results available. Run an audit first."}), 400

    report = audit["report"]
    config_file = audit["config_file"]
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_name = f"CIS_Report_{timestamp}"

    if format_type == "html":
        gen = HTMLReportGenerator()
        output_path = os.path.join(UPLOAD_FOLDER, f"{out_name}.html")
        gen.generate(report, config_file=config_file, output_path=output_path)
        return send_file(output_path, as_attachment=True, download_name=f"{out_name}.html")

    elif format_type == "json":
        gen = JSONReportGenerator()
        output_path = os.path.join(UPLOAD_FOLDER, f"{out_name}.json")
        gen.generate(report, config_file=config_file, output_path=output_path)
        return send_file(output_path, as_attachment=True, download_name=f"{out_name}.json")

    elif format_type == "pdf":
        html_gen = HTMLReportGenerator()
        html_content = html_gen.generate(report, config_file=config_file)
        pdf_gen = PDFReportGenerator()
        output_path = os.path.join(UPLOAD_FOLDER, f"{out_name}.pdf")
        pdf_gen.generate(html_content, output_path)
        actual_file = output_path if os.path.exists(output_path) else output_path.replace('.pdf', '_report.html')
        return send_file(actual_file, as_attachment=True)

    elif format_type == "remediation":
        engine = RemediationEngine()
        script = engine.generate_script(report.failed_results, report.manual_review_results, dry_run=True)
        output_path = os.path.join(UPLOAD_FOLDER, f"Remediation_{timestamp}.txt")
        engine.save_script(script, output_path)
        return send_file(output_path, as_attachment=True, download_name=f"Remediation_{timestamp}.txt")

    return jsonify({"error": "Invalid format"}), 400


def create_app():
    """Application factory."""
    return app


if __name__ == '__main__':
    app.run(host='127.0.0.1', port=5000, debug=False)
