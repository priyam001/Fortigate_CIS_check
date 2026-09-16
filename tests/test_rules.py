"""
Unit Tests -- CIS FortiGate 7.4.x Benchmark v1.0.1 Rules
===========================================================
Tests rule structure/metadata, PASS behavior against the compliant sample
config, FAIL behavior against small targeted negative configs, and correct
MANUAL_REVIEW handling.
"""

import pytest
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from cis_benchmark.config_parser import FortiGateConfigParser
from cis_benchmark.rules import get_all_rules, get_level1_rules, get_level2_rules
from cis_benchmark.rules.base import CISLevel, RuleSeverity, RuleResult, RuleStatus, AssessmentStatus


@pytest.fixture
def parser():
    return FortiGateConfigParser()


@pytest.fixture
def config(parser):
    return parser.parse_file(str(Path(__file__).parent / "test_sample_config.conf"))


def rule_by_id(rule_id):
    for r in get_all_rules():
        if r.rule_id == rule_id:
            return r
    raise KeyError(rule_id)


class TestRuleStructure:
    """Test rule metadata and structure."""

    def test_all_rules_have_ids(self):
        for rule in get_all_rules():
            assert rule.rule_id, f"Rule missing ID: {rule.title}"

    def test_all_rules_have_titles(self):
        for rule in get_all_rules():
            assert rule.title, f"Rule {rule.rule_id} missing title"

    def test_all_rules_have_severity(self):
        for rule in get_all_rules():
            assert isinstance(rule.severity, RuleSeverity)

    def test_all_rules_have_level(self):
        for rule in get_all_rules():
            assert isinstance(rule.level, CISLevel)

    def test_all_rules_have_assessment_status(self):
        for rule in get_all_rules():
            assert isinstance(rule.assessment_status, AssessmentStatus)

    def test_total_rule_count_matches_benchmark(self):
        """CIS FortiGate 7.4.x Benchmark v1.0.1 publishes 64 recommendations (39 L1 + 25 L2)."""
        assert len(get_level1_rules()) == 39
        assert len(get_level2_rules()) == 25
        assert len(get_all_rules()) == 64

    def test_unique_rule_ids(self):
        ids = [r.rule_id for r in get_all_rules()]
        assert len(ids) == len(set(ids)), f"Duplicate IDs found: {[x for x in ids if ids.count(x) > 1]}"

    # 7.3.2/7.3.3 are CIS-labeled Manual but are deliberately given real
    # PASS/FAIL verdicts here (see level1_rules.py docstring) because their
    # audit procedure is fully derivable from a static config, identical to
    # their Automated twin 7.3.1.
    DELIBERATE_MANUAL_EXCEPTIONS = {"7.3.2", "7.3.3"}

    def test_manual_cis_controls_resolve_manual_review(self, config):
        """Every control CIS classifies 'Manual' (with documented exceptions) avoids guessing PASS/FAIL."""
        for rule in get_all_rules():
            if rule.assessment_status == AssessmentStatus.MANUAL and rule.rule_id not in self.DELIBERATE_MANUAL_EXCEPTIONS:
                result = rule.evaluate(config)
                assert result.status == RuleStatus.MANUAL_REVIEW, (
                    f"Rule {rule.rule_id} is CIS-classified Manual but returned {result.status}"
                )

    def test_all_rules_evaluatable_without_error(self, config):
        for rule in get_all_rules():
            result = rule.evaluate(config)
            assert isinstance(result, RuleResult)
            assert result.status != RuleStatus.ERROR, f"Rule {rule.rule_id} errored: {result.actual_value}"


class TestCompliantBaseline:
    """The bundled test_sample_config.conf is built to satisfy nearly every automated control."""

    @pytest.mark.parametrize("rule_id", [
        "1.1", "2.1.1", "2.1.2", "2.1.3", "2.1.5", "2.1.7", "2.1.8", "2.1.9",
        "2.1.10", "2.1.11", "2.1.12", "2.1.13", "2.2.1", "2.2.2", "2.3.1",
        "2.3.3", "2.3.4", "2.4.1", "2.4.4", "2.4.5", "2.4.6", "2.4.7", "2.4.8",
        "2.5.1", "2.5.2", "2.5.3", "2.5.4", "3.3", "3.4", "4.1.1", "4.2.1",
        "4.2.3", "4.2.4", "4.2.5", "4.2.6", "4.3.1", "4.3.2", "4.4.1", "4.5.2",
        "5.1.1", "6.1.1", "6.1.2", "7.1.1", "7.2.1", "7.3.1", "7.3.2", "7.3.3",
    ])
    def test_passes_on_compliant_config(self, config, rule_id):
        rule = rule_by_id(rule_id)
        result = rule.evaluate(config)
        assert result.status == RuleStatus.PASS, f"{rule_id} ({rule.title}) expected PASS, got {result.status}: {result.actual_value}"

    def test_no_all_service_fails_on_deny_isdb_policy(self, config):
        """The sample config's Tor-blocking deny policy intentionally uses service ALL."""
        result = rule_by_id("3.2").evaluate(config)
        assert result.status == RuleStatus.FAIL

    def test_dns_filter_not_applied_to_isdb_policy(self, config):
        result = rule_by_id("4.3.3").evaluate(config)
        assert result.status == RuleStatus.FAIL


class TestNegativePaths:
    """Small targeted configs that should trip each control's FAIL branch."""

    def _cfg(self, parser, body):
        header = "#config-version=FGT-7.4.5-FW-build1-1\n"
        return parser.parse_content(header + body)

    def test_pre_login_banner_fails_when_absent(self, parser):
        config = self._cfg(parser, "config system global\nend\n")
        result = rule_by_id("2.1.1").evaluate(config)
        assert result.status == RuleStatus.FAIL

    def test_password_policy_fails_short_length(self, parser):
        config = self._cfg(parser, "config system password-policy\n set status enable\n set minimum-length 8\nend\n")
        result = rule_by_id("2.2.1").evaluate(config)
        assert result.status == RuleStatus.FAIL

    def test_default_admin_account_fails(self, parser):
        config = self._cfg(parser, 'config system admin\n edit "admin"\n set accprofile "super_admin"\n next\nend\n')
        result = rule_by_id("2.4.1").evaluate(config)
        assert result.status == RuleStatus.FAIL

    def test_encrypted_access_fails_with_http_allowed(self, parser):
        config = self._cfg(parser, 'config system interface\n edit "port1"\n set allowaccess ping https http\n next\nend\n')
        result = rule_by_id("2.4.5").evaluate(config)
        assert result.status == RuleStatus.FAIL
        assert "http" in result.actual_value.lower()

    def test_snmpv3_fails_with_v1_community(self, parser):
        config = self._cfg(parser, (
            'config system snmp sysinfo\n set status enable\n end\n'
            'config system snmp community\n edit 1\n set name "public"\n next\n end\n'
        ))
        result = rule_by_id("2.3.1").evaluate(config)
        assert result.status == RuleStatus.FAIL

    def test_snmpv3_passes_when_disabled_entirely(self, parser):
        config = self._cfg(parser, "config system global\nend\n")
        result = rule_by_id("2.3.1").evaluate(config)
        assert result.status == RuleStatus.PASS

    def test_ha_not_configured_is_manual_review_not_fail(self, parser):
        """Controls that only apply when an optional feature (HA) is used should not be false FAILs."""
        config = self._cfg(parser, "config system global\nend\n")
        for rule_id in ("2.5.1", "2.5.2", "2.5.3", "2.5.4"):
            result = rule_by_id(rule_id).evaluate(config)
            assert result.status == RuleStatus.MANUAL_REVIEW, f"{rule_id} should be MANUAL_REVIEW when HA is unused"

    def test_ssl_vpn_not_configured_is_manual_review(self, parser):
        config = self._cfg(parser, "config system global\nend\n")
        for rule_id in ("6.1.1", "6.1.2"):
            result = rule_by_id(rule_id).evaluate(config)
            assert result.status == RuleStatus.MANUAL_REVIEW

    def test_default_ports_fail_when_unset(self, parser):
        config = self._cfg(parser, "config system global\nend\n")
        result = rule_by_id("2.4.7").evaluate(config)
        assert result.status == RuleStatus.FAIL

    def test_strong_crypto_passes_by_default(self, parser):
        """strong-crypto defaults to enabled; absence should not be penalized."""
        config = self._cfg(parser, "config system global\nend\n")
        result = rule_by_id("2.1.9").evaluate(config)
        assert result.status == RuleStatus.PASS

    def test_static_tls_keys_fails_by_default(self, parser):
        """ssl-static-key-ciphers defaults to enabled (insecure); absence should FAIL."""
        config = self._cfg(parser, "config system global\nend\n")
        result = rule_by_id("2.1.8").evaluate(config)
        assert result.status == RuleStatus.FAIL

    def test_botnet_detection_fails_when_sensor_not_applied(self, parser):
        config = self._cfg(parser, (
            'config ips sensor\n edit "default"\n set scan-botnet-connections block\n next\n end\n'
            'config firewall policy\n edit 1\n set name "p1"\n next\n end\n'
        ))
        result = rule_by_id("4.1.1").evaluate(config)
        assert result.status == RuleStatus.FAIL
        assert "not applied" in result.actual_value.lower()


class TestRuleResults:
    """Test RuleResult serialization."""

    def test_result_to_dict(self, config):
        rule = get_level1_rules()[0]
        result = rule.evaluate(config)
        d = result.to_dict()
        assert "rule_id" in d
        assert "status" in d
        assert "severity" in d
        assert "manual_review" in d
        assert d["status"] in ["PASS", "FAIL", "MANUAL_REVIEW", "ERROR"]

    def test_result_status_values(self, config):
        for rule in get_all_rules():
            result = rule.evaluate(config)
            assert result.status in (RuleStatus.PASS, RuleStatus.FAIL, RuleStatus.MANUAL_REVIEW, RuleStatus.ERROR)

    def test_result_notes_default_empty(self, config):
        rule = get_level1_rules()[0]
        result = rule.evaluate(config)
        assert result.notes == ""
        assert result.to_dict()["notes"] == ""

    def test_result_notes_round_trip_in_dict(self, config):
        rule = get_level1_rules()[0]
        result = rule.evaluate(config)
        result.notes = "Remediated 2026-09-16, verified via console"
        assert result.to_dict()["notes"] == "Remediated 2026-09-16, verified via console"
