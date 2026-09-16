"""
Unit Tests -- Web Dashboard
=============================
Tests the Flask app's upload validation, per-session isolation, and
report download endpoints using Flask's test client (no live server).
"""

import io
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from web.app import app


@pytest.fixture
def client():
    app.config["TESTING"] = True
    return app.test_client()


@pytest.fixture
def sample_bytes():
    return (Path(__file__).parent / "test_sample_config.conf").read_bytes()


class TestUpload:
    def test_index_without_upload(self, client):
        r = client.get("/")
        assert r.status_code == 200

    def test_rejects_missing_file(self, client):
        r = client.post("/upload", data={}, content_type="multipart/form-data")
        assert r.status_code == 400

    def test_rejects_disallowed_extension(self, client, sample_bytes):
        r = client.post(
            "/upload",
            data={"config_file": (io.BytesIO(sample_bytes), "config.exe")},
            content_type="multipart/form-data",
        )
        assert r.status_code == 400
        assert "Unsupported file type" in r.get_json()["error"]

    def test_rejects_non_fortigate_content(self, client):
        r = client.post(
            "/upload",
            data={"config_file": (io.BytesIO(b"just some random text file"), "notreal.conf")},
            content_type="multipart/form-data",
        )
        assert r.status_code == 400

    def test_accepts_valid_config_and_runs_audit(self, client, sample_bytes):
        r = client.post(
            "/upload",
            data={"config_file": (io.BytesIO(sample_bytes), "sample.conf"), "level": "all"},
            content_type="multipart/form-data",
        )
        assert r.status_code == 302
        r2 = client.get("/")
        assert b"Overall Compliance" in r2.data

    def test_reports_download_after_audit(self, client, sample_bytes):
        client.post(
            "/upload",
            data={"config_file": (io.BytesIO(sample_bytes), "sample.conf"), "level": "all"},
            content_type="multipart/form-data",
        )
        for fmt in ("html", "json", "remediation"):
            r = client.get(f"/download/{fmt}")
            assert r.status_code == 200, fmt
            assert len(r.data) > 0

    def test_download_without_audit_errors(self, client):
        r = client.get("/download/json")
        assert r.status_code == 400


class TestSessionIsolation:
    def test_two_clients_do_not_share_results(self, sample_bytes):
        app.config["TESTING"] = True
        client_a = app.test_client()
        client_b = app.test_client()

        client_a.post(
            "/upload",
            data={"config_file": (io.BytesIO(sample_bytes), "sample.conf"), "level": "all"},
            content_type="multipart/form-data",
        )

        assert b"Overall Compliance" in client_a.get("/").data
        assert b"Overall Compliance" not in client_b.get("/").data


class TestNotes:
    def test_note_requires_active_audit(self, client):
        r = client.post("/note/1.1", json={"note": "hello"})
        assert r.status_code == 400

    def test_save_and_read_back_note(self, client, sample_bytes):
        client.post(
            "/upload",
            data={"config_file": (io.BytesIO(sample_bytes), "sample.conf"), "level": "all"},
            content_type="multipart/form-data",
        )
        r = client.get("/")
        # grab a real rule_id straight off the rendered page's note textareas
        import re
        match = re.search(rb'data-rule-id="([^"]+)"', r.data)
        assert match, "expected at least one finding with a note textarea"
        rid = match.group(1).decode()

        save = client.post(f"/note/{rid}", json={"note": "  Remediated on 2026-09-16  "})
        assert save.status_code == 200
        assert save.get_json()["notes"] == "Remediated on 2026-09-16"

        r2 = client.get("/")
        assert b"Remediated on 2026-09-16" in r2.data

    def test_note_persists_into_downloaded_reports(self, client, sample_bytes):
        client.post(
            "/upload",
            data={"config_file": (io.BytesIO(sample_bytes), "sample.conf"), "level": "all"},
            content_type="multipart/form-data",
        )
        import re
        match = re.search(rb'data-rule-id="([^"]+)"', client.get("/").data)
        rid = match.group(1).decode()
        client.post(f"/note/{rid}", json={"note": "Risk accepted by CISO"})

        html_report = client.get("/download/html")
        assert b"Risk accepted by CISO" in html_report.data

        json_report = client.get("/download/json")
        assert b"Risk accepted by CISO" in json_report.data

    def test_note_unknown_rule_id_404s(self, client, sample_bytes):
        client.post(
            "/upload",
            data={"config_file": (io.BytesIO(sample_bytes), "sample.conf"), "level": "all"},
            content_type="multipart/form-data",
        )
        r = client.post("/note/not-a-real-rule", json={"note": "x"})
        assert r.status_code == 404

    def test_note_too_long_rejected(self, client, sample_bytes):
        client.post(
            "/upload",
            data={"config_file": (io.BytesIO(sample_bytes), "sample.conf"), "level": "all"},
            content_type="multipart/form-data",
        )
        import re
        match = re.search(rb'data-rule-id="([^"]+)"', client.get("/").data)
        rid = match.group(1).decode()
        r = client.post(f"/note/{rid}", json={"note": "x" * 2001})
        assert r.status_code == 400

    def test_note_is_escaped_in_html_download(self, client, sample_bytes):
        client.post(
            "/upload",
            data={"config_file": (io.BytesIO(sample_bytes), "sample.conf"), "level": "all"},
            content_type="multipart/form-data",
        )
        import re
        match = re.search(rb'data-rule-id="([^"]+)"', client.get("/").data)
        rid = match.group(1).decode()
        client.post(f"/note/{rid}", json={"note": "<script>alert(1)</script>"})

        r = client.get("/download/html")
        assert b"<script>alert(1)</script>" not in r.data
        assert b"&lt;script&gt;" in r.data


class TestXSSHardening:
    def test_hostile_hostname_is_escaped_in_html_download(self, client):
        content = (
            '#config-version=FGT-7.4.5-FW-build1-1\n'
            'config system global\n'
            '    set hostname "<script>alert(1)</script>"\n'
            'end\n'
            'config system admin\n'
            '    edit "admin"\n'
            '    next\n'
            'end\n'
            'config firewall policy\nend\n'
        ).encode()
        client.post(
            "/upload",
            data={"config_file": (io.BytesIO(content), "evil.conf"), "level": "all"},
            content_type="multipart/form-data",
        )
        r = client.get("/download/html")
        assert r.status_code == 200
        assert b"<script>alert(1)</script>" not in r.data
        assert b"&lt;script&gt;" in r.data
