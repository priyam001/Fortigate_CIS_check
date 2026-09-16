"""
Unit Tests -- Config Parser
============================
Tests for the FortiGate configuration parser module, including the
recursive nested-block parsing and secret redaction.
"""

import pytest
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from cis_benchmark.config_parser import (
    FortiGateConfigParser,
    FortiGateConfig,
    ConfigParseError,
    redact_value,
    clean_console_paste,
)


@pytest.fixture
def parser():
    return FortiGateConfigParser()


@pytest.fixture
def sample_config_path():
    return str(Path(__file__).parent / "test_sample_config.conf")


@pytest.fixture
def sample_config(parser, sample_config_path):
    return parser.parse_file(sample_config_path)


class TestConfigParser:
    """Test config file parsing."""

    def test_parse_file_exists(self, parser, sample_config_path):
        config = parser.parse_file(sample_config_path)
        assert isinstance(config, FortiGateConfig)

    def test_parse_file_not_found(self, parser):
        with pytest.raises(FileNotFoundError):
            parser.parse_file("nonexistent.conf")

    def test_version_detection(self, sample_config):
        assert sample_config.model == "FGT60F"
        assert sample_config.version == "7.4.5"
        assert sample_config.build == "2670"

    def test_hostname_extraction(self, sample_config):
        assert sample_config.hostname == "EDGE-FW-01"

    def test_global_settings(self, sample_config):
        assert sample_config.get_global_setting("strong-crypto") == "enable"
        assert sample_config.get_global_setting("admintimeout") == "10"

    def test_global_setting_default(self, sample_config):
        assert sample_config.get_global_setting("nonexistent", "default") == "default"

    def test_has_global_setting(self, sample_config):
        assert sample_config.has_global_setting("hostname")
        assert not sample_config.has_global_setting("nonexistent")

    def test_interface_blocks(self, sample_config):
        interfaces = sample_config.get_interface_blocks()
        assert len(interfaces) == 3
        wan = [i for i in interfaces if i.get("role") == "wan"]
        assert len(wan) == 1

    def test_policy_blocks(self, sample_config):
        policies = sample_config.get_policy_blocks()
        assert len(policies) == 2

    def test_admin_blocks(self, sample_config):
        admins = sample_config.get_admin_blocks()
        assert len(admins) == 2
        assert {a.name for a in admins} == {"netadmin", "readonly"}

    def test_zone_blocks(self, sample_config):
        zones = sample_config.get_zone_blocks()
        assert len(zones) == 1
        assert zones[0].name == "DMZ"
        assert zones[0].get("intrazone") == "deny"

    def test_search_pattern(self, sample_config):
        assert sample_config.search(r'config system global')
        assert not sample_config.search(r'nonexistent_pattern_xyz')

    def test_search_value(self, sample_config):
        val = sample_config.search_value(r'set hostname\s+"?([^"\n]+)"?')
        assert val is not None
        assert "EDGE-FW-01" in val

    def test_get_blocks(self, sample_config):
        dns = sample_config.get_blocks("system dns")
        assert len(dns) > 0

    def test_get_block_single(self, sample_config):
        block = sample_config.get_block("system dns")
        assert block is not None

    def test_validate_config_valid(self, parser, sample_config_path):
        content = Path(sample_config_path).read_text()
        assert parser.validate_config(content)

    def test_validate_config_invalid(self, parser):
        assert not parser.validate_config("this is not a fortigate config")

    def test_parse_file_rejects_non_fortigate_content(self, parser, tmp_path):
        bogus = tmp_path / "bogus.conf"
        bogus.write_text("this is not a fortigate config at all, just some text\n")
        with pytest.raises(ConfigParseError):
            parser.parse_file(str(bogus))

    def test_parse_content_direct(self, parser):
        content = """
config system global
    set hostname "TEST"
    set timezone 5
end
"""
        config = parser.parse_content(content)
        assert config.hostname == "TEST"
        assert config.get_global_setting("timezone") == "5"

    def test_nested_blocks(self, sample_config):
        ha = sample_config.get_block("system ha")
        assert ha is not None
        assert ha.get("mode") == "a-p"

    def test_deeply_nested_blocks(self, sample_config):
        """config system ha -> config ha-mgmt-interfaces -> edit 1 -> set interface/gateway."""
        ha = sample_config.get_block("system ha")
        mgmt = ha.get_child_block("ha-mgmt-interfaces")
        assert mgmt is not None
        assert len(mgmt.sub_blocks) == 1
        entry = mgmt.sub_blocks[0]
        assert entry.get("interface") == "port5"
        assert entry.get("gateway") == "10.0.0.1"

    def test_nested_blocks_inside_edit(self, sample_config):
        """config antivirus profile -> edit "default" -> config http -> set outbreak-prevention block."""
        profiles = sample_config.get_all_edit_entries("antivirus profile")
        assert len(profiles) == 1
        http_block = profiles[0].get_child_block("http")
        assert http_block is not None
        assert http_block.get("outbreak-prevention") == "block"

    def test_multi_token_quoted_list_value(self, sample_config):
        """`set service "HTTPS" "DNS"` should parse as a clean space-joined token list, not `HTTPS" "DNS`."""
        policies = sample_config.get_policy_blocks()
        policy1 = next(p for p in policies if p.name == "1")
        assert policy1.get("service") == "HTTPS DNS"
        assert '"' not in policy1.get("service")

    def test_empty_content(self, parser):
        config = parser.parse_content("")
        assert config.hostname == ""


class TestConsolePasteCleanup:
    """
    Regression tests for parsing raw interactive-CLI/console captures, e.g. a
    session pasted from a browser terminal where a truncated/retried
    `show full-configuration` precedes the real, complete dump. Without
    cleanup, the truncated block never hits its own `end`, so the parser
    keeps swallowing everything after it (including the entire real dump) as
    nested children of one broken top-level block, and every other top-level
    block type (interfaces, policies, admins, ...) silently disappears.
    """

    CONSOLE_PASTE = """MedGulf $ SHOW FUL
command parse error before 'SHOW'

MedGulf $ show full-configuration
#config-version=FGT80F-7.2.13-FW-build1762-260128:opmode=1:vdom=0
#buildno=1762
config system global
    set admintimeout 5

MedGulf $ show full-configuration
#config-version=FGT80F-7.2.13-FW-build1762-260128:opmode=1:vdom=0
#buildno=1762
config system global
    set hostname "MedGulf"
    set admintimeout 15
end
config system interface
    edit "port1"
        set ip 10.0.0.1 255.255.255.0
    next
end
"""

    def test_prompt_and_error_lines_stripped(self):
        cleaned = clean_console_paste("MedGulf $ show full-configuration\ncommand parse error before 'SHOW'\nset hostname \"x\"\n")
        assert "MedGulf $" not in cleaned
        assert "command parse error" not in cleaned
        assert 'set hostname "x"' in cleaned

    def test_duplicate_dump_keeps_last_complete_capture(self):
        cleaned = clean_console_paste(self.CONSOLE_PASTE)
        assert cleaned.count("#config-version=") == 1
        assert "set admintimeout 15" in cleaned
        assert "set admintimeout 5\n" not in cleaned

    def test_retried_full_config_still_parses_all_top_level_blocks(self, parser):
        config = parser.parse_content(self.CONSOLE_PASTE)
        # Before the cleanup, the truncated first attempt swallowed everything
        # after it as nested children, so "system interface" never showed up
        # as a top-level block and get_interface_blocks() returned [].
        assert config.get_global_setting("hostname") == "MedGulf"
        assert config.get_global_setting("admintimeout") == "15"
        interfaces = config.get_interface_blocks()
        assert len(interfaces) == 1
        assert interfaces[0].get("ip") == "10.0.0.1 255.255.255.0"


class TestConfigSecurity:
    """Test security features of the parser."""

    def test_null_byte_removal(self, parser):
        content = "config system global\x00\n    set hostname \"test\"\nend\n"
        config = parser.parse_content(content)
        assert '\x00' not in config.raw_content

    def test_empty_file_error(self, parser, tmp_path):
        empty_file = tmp_path / "empty.conf"
        empty_file.write_text("")
        with pytest.raises(ValueError, match="empty"):
            parser.parse_file(str(empty_file))

    def test_oversized_file_rejected(self, parser, tmp_path, monkeypatch):
        import cis_benchmark.config_parser as cp
        monkeypatch.setattr(cp, "MAX_CONFIG_SIZE_BYTES", 10)
        big_file = tmp_path / "big.conf"
        big_file.write_text("config system global\nend\n" * 5)
        with pytest.raises(ValueError, match="too large"):
            parser.parse_file(str(big_file))

    def test_redact_value_masks_passwords(self):
        assert redact_value("password", "ENC_SECRETVALUE") == "***REDACTED***"
        assert redact_value("passwd", "hunter2") == "***REDACTED***"
        assert redact_value("auth-pwd", "hunter2") == "***REDACTED***"
        assert redact_value("psksecret", "hunter2") == "***REDACTED***"

    def test_redact_value_leaves_non_sensitive_alone(self):
        assert redact_value("hostname", "FGT1") == "FGT1"
        assert redact_value("admin-port", "8443") == "8443"
