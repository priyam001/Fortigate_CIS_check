"""
Remediation Engine
===================
Generates a human-readable FortiGate CLI remediation script from failed
CIS controls. This module NEVER connects to a FortiGate device -- it only
writes commands to a local text file for an administrator to review and
apply manually. Controls resolved to MANUAL_REVIEW are listed separately
with guidance text (no CLI commands are invented for them), since they
require a human judgement call this tool cannot make from a config file
alone.
"""

import logging
from typing import List, Optional
from datetime import datetime
from cis_benchmark.rules.base import RuleResult

logger = logging.getLogger(__name__)


class RemediationEngine:
    """
    Generates remediation scripts from failed CIS rules.

    Usage:
        engine = RemediationEngine()
        script = engine.generate_script(failed_results, manual_review_results)
        engine.save_script(script, "remediation.txt")
    """

    HEADER = """# ============================================================
# FortiGate CIS Benchmark Remediation Script (REVIEW ONLY)
# Generated: {timestamp}
# Failed controls with CLI commands: {count}
# ============================================================
#
# This file is a REVIEW ARTIFACT ONLY. This tool has no network
# connection to any FortiGate device and cannot and does not apply any
# of these commands automatically. Every command below must be reviewed
# and applied manually by an authorized administrator.
#
# Before applying anything:
#   1. Take a full configuration backup of the target device.
#   2. Test changes in a lab/maintenance window first.
#   3. Apply one section at a time via SSH/console and verify with
#      'get system status' / the relevant 'show' command.
#
# Lines prefixed with '# [REVIEW]' are commented out on purpose -- this
# script never executes anything on its own even if pasted into a CLI
# session verbatim.
# ============================================================
"""

    @staticmethod
    def _note_comment(note: str) -> str:
        """Render a (possibly multi-line) note as '# Note: ...' comment lines."""
        lines = note.splitlines() or [note]
        rendered = f"# Note: {lines[0]}\n"
        for line in lines[1:]:
            rendered += f"#       {line}\n"
        return rendered

    def generate_script(
        self,
        failed_results: List[RuleResult],
        manual_review_results: Optional[List[RuleResult]] = None,
        dry_run: bool = True,
    ) -> str:
        """Generate a remediation review script from failed rule results."""
        commands = [r for r in failed_results if r.remediation_cli]
        manual_only_failed = [r for r in failed_results if not r.remediation_cli]

        script = self.HEADER.format(
            timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            count=len(commands),
        )

        script += self._render_section("FAILED CONTROLS -- SUGGESTED CLI COMMANDS", commands, dry_run)

        if manual_only_failed:
            script += "\n\n# " + "=" * 60
            script += "\n# FAILED CONTROLS -- NO SINGLE CLI FIX (see remediation guidance)\n"
            script += "# " + "=" * 60 + "\n"
            for r in manual_only_failed:
                script += f"\n# Rule {r.rule_id}: {r.title}\n# Guidance: {r.remediation}\n"
                if r.notes:
                    script += self._note_comment(r.notes)

        if manual_review_results:
            script += "\n\n# " + "=" * 60
            script += "\n# CONTROLS REQUIRING MANUAL REVIEW (not counted as pass/fail)\n"
            script += "# " + "=" * 60 + "\n"
            for r in manual_review_results:
                script += f"\n# Rule {r.rule_id}: {r.title}\n# Evidence: {r.actual_value}\n# Guidance: {r.remediation}\n"
                if r.notes:
                    script += self._note_comment(r.notes)

        script += "\n\n# === END OF REMEDIATION SCRIPT ===\n"
        return script

    def _render_section(self, heading: str, results: List[RuleResult], dry_run: bool) -> str:
        if not results:
            return f"\n# {heading}: none\n"

        script = ""
        categories = {}
        for result in results:
            categories.setdefault(result.category or "General", []).append(result)

        for category, cat_results in sorted(categories.items()):
            script += f"\n# {'=' * 60}\n# Category: {category}\n# {'=' * 60}\n\n"
            for result in cat_results:
                script += f"# Rule {result.rule_id}: {result.title}\n"
                script += f"# Severity: {result.severity.value}\n"
                script += f"# Current: {result.actual_value}\n"
                script += f"# Expected: {result.expected_value}\n"
                if result.notes:
                    script += self._note_comment(result.notes)
                for line in result.remediation_cli.split('\n'):
                    script += f"# [REVIEW] {line}\n"
                script += "\n"
        return script

    def save_script(self, script: str, filepath: str):
        """Save remediation script to file."""
        try:
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(script)
            logger.info(f"Remediation script saved: {filepath}")
        except Exception as e:
            logger.error(f"Failed to save remediation script: {e}")
            raise

    def get_remediation_summary(self, failed_results: List[RuleResult]) -> dict:
        """Get a summary of remediations grouped by severity."""
        summary = {
            "total_remediations": 0,
            "with_cli_commands": 0,
            "manual_only": 0,
            "by_severity": {},
            "by_category": {},
        }

        for result in failed_results:
            summary["total_remediations"] += 1
            if result.remediation_cli:
                summary["with_cli_commands"] += 1
            else:
                summary["manual_only"] += 1

            summary["by_severity"][result.severity.value] = summary["by_severity"].get(result.severity.value, 0) + 1
            cat = result.category or "General"
            summary["by_category"][cat] = summary["by_category"].get(cat, 0) + 1

        return summary
