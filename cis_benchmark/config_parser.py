"""
FortiGate Configuration Parser
===============================
Parses FortiGate configuration backup (.conf) files into a structured,
recursively-nested tree of config/edit blocks.

FortiGate's CLI config grammar is a simple recursive structure:

    config <type>
        set <key> <value>
        edit <name-or-id>
            set <key> <value>
            config <subtype>
                edit <n>
                    set <key> <value>
                next
            end
        next
    end

Blocks can nest to arbitrary depth (e.g. `config antivirus profile` ->
`edit <name>` -> `config content-disarm` -> `set option ...`, or
`config system ha` -> `config ha-mgmt-interfaces` -> `edit 1` -> `set ...`).
This parser walks that grammar recursively so nested settings are captured
accurately instead of only the first level, which matters for CIS controls
that inspect nested blocks (IPS sensor entries, HA mgmt interfaces, SNMPv3
users, webfilter FortiGuard categories, DNS filter domain filters, etc).
"""

import re
import os
import logging
from typing import Dict, List, Optional, Tuple
from pathlib import Path
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)

MAX_CONFIG_SIZE_MB = 50
MAX_CONFIG_SIZE_BYTES = MAX_CONFIG_SIZE_MB * 1024 * 1024

# Setting names whose values must never be surfaced verbatim in evidence,
# actual_value strings, or reports, even though FortiGate stores most of
# these pre-encrypted (ENC ...). Defensive redaction regardless.
_SENSITIVE_KEY_PATTERN = re.compile(
    r'(password|passwd|secret|private-key|privatekey|psksecret|psk-secret|'
    r'auth-pwd|auth-password|ppk-secret|community|passphrase|'
    r'radius-secret|ldap-password|shared-secret)',
    re.I,
)

REDACTED = "***REDACTED***"

# --- Interactive console-paste cleanup -------------------------------------
# Config files aren't always a clean `show full-configuration` export -- they
# are sometimes copy-pasted straight out of an interactive CLI/SSH session
# (e.g. a browser terminal or jump-host), which mixes in shell prompts,
# echoed commands, pager artifacts, and ANSI escapes that the block parser
# below (which only understands config/edit/set/unset/next/end tokens)
# doesn't otherwise choke on -- it just ignores unrecognized lines. The real
# hazard is a *retried* `show full-configuration`: if the first attempt got
# cut off (e.g. a mistyped command, or the pager/terminal losing output) and
# the operator re-ran it, the file contains two `#config-version=` dumps back
# to back. The first, truncated `config system global` block never sees its
# own `end`, so the block parser keeps consuming everything after it --
# including the entire second, complete dump -- as *nested children* of that
# one broken top-level block. Every other top-level block type (interfaces,
# policies, admins, ...) then silently vanishes from `config.blocks`, and
# every rule that reads them reports the same stale/failed result no matter
# what was actually remediated.
_ANSI_ESCAPE_RE = re.compile(r'\x1b\[[0-9;]*[A-Za-z]')
_PAGER_ARTIFACT_RE = re.compile(r'--More--\s*(\x08\s*)*', re.I)
_CLI_PROMPT_LINE_RE = re.compile(r'^\S+\s*[$#](\s+\S.*)?\s*$')
_CLI_ERROR_LINE_RE = re.compile(
    r'^(command parse error|unknown action|unrecognized command|invalid command|command fail)\b.*$',
    re.I,
)
_CONFIG_VERSION_HEADER_RE = re.compile(r'^#config-version=', re.M)


def clean_console_paste(content: str) -> str:
    """
    Strip interactive-session artifacts from raw config text and, if the
    text contains more than one `#config-version=` header (a re-run/retried
    `show full-configuration` pasted into the same capture), keep only the
    last -- most recent and most likely complete -- dump.
    """
    content = _ANSI_ESCAPE_RE.sub('', content)
    content = _PAGER_ARTIFACT_RE.sub('', content)

    lines = content.split('\n')
    cleaned_lines = [
        line for line in lines
        if not _CLI_PROMPT_LINE_RE.match(line.strip()) and not _CLI_ERROR_LINE_RE.match(line.strip())
    ]
    content = '\n'.join(cleaned_lines)

    headers = list(_CONFIG_VERSION_HEADER_RE.finditer(content))
    if len(headers) > 1:
        logger.warning(
            f"Input contains {len(headers)} '#config-version=' headers (looks like a "
            "retried/duplicated 'show full-configuration' pasted from a console session); "
            "using only the last, most complete capture and discarding the earlier one(s)."
        )
        content = content[headers[-1].start():]

    return content


def redact_value(key: str, value: str) -> str:
    """Mask sensitive setting values so they never leak into evidence/reports."""
    if value and _SENSITIVE_KEY_PATTERN.search(key or ""):
        return REDACTED
    return value


@dataclass
class ConfigBlock:
    """
    A single parsed `config <type>` block or `edit <name>` entry.

    `name` is empty for a bare `config` block and holds the edit
    name/index for an `edit` entry.
    `children` holds nested `config` blocks found directly inside this
    block (not inside one of its edit entries), keyed by lowercase type.
    `sub_blocks` holds `edit` entries found directly inside this block.
    """
    block_type: str
    name: str = ""
    settings: Dict[str, str] = field(default_factory=dict)
    children: Dict[str, List["ConfigBlock"]] = field(default_factory=dict)
    sub_blocks: List["ConfigBlock"] = field(default_factory=list)
    raw_text: str = ""

    def get(self, key: str, default: str = "") -> str:
        return self.settings.get(key.lower(), default)

    def get_safe(self, key: str, default: str = "") -> str:
        """Like get(), but redacts sensitive values."""
        return redact_value(key, self.get(key, default))

    def has(self, key: str) -> bool:
        return key.lower() in self.settings

    def get_child_blocks(self, block_type: str) -> List["ConfigBlock"]:
        """Nested `config <block_type>` blocks directly inside this block."""
        return self.children.get(block_type.lower(), [])

    def get_child_block(self, block_type: str) -> Optional["ConfigBlock"]:
        blocks = self.get_child_blocks(block_type)
        return blocks[0] if blocks else None

    def get_sub_block(self, name: str) -> Optional["ConfigBlock"]:
        """Find an edit entry directly inside this block by its edit name/id."""
        for sb in self.sub_blocks:
            if sb.name.lower() == name.lower():
                return sb
        return None

    def all_settings_text(self) -> str:
        """Flattened 'key value' text of this block's own settings, for regex fallback checks."""
        return "\n".join(f"{k} {v}" for k, v in self.settings.items())


@dataclass
class FortiGateConfig:
    """Structured representation of a full FortiGate configuration."""
    raw_content: str
    version: str = ""
    build: str = ""
    model: str = ""
    hostname: str = ""
    vdom_enabled: bool = False
    blocks: Dict[str, List[ConfigBlock]] = field(default_factory=dict)

    def get_blocks(self, block_type: str) -> List[ConfigBlock]:
        return self.blocks.get(block_type.lower(), [])

    def get_block(self, block_type: str) -> Optional[ConfigBlock]:
        blocks = self.get_blocks(block_type)
        return blocks[0] if blocks else None

    def get_global_setting(self, key: str, default: str = "") -> str:
        block = self.get_block("system global")
        if block:
            return block.get(key, default)
        return default

    def has_global_setting(self, key: str) -> bool:
        block = self.get_block("system global")
        return block.has(key) if block else False

    def get_policy_blocks(self) -> List[ConfigBlock]:
        """All firewall policy entries (across all `config firewall policy` blocks)."""
        entries = []
        for block in self.get_blocks("firewall policy"):
            entries.extend(block.sub_blocks)
        return entries

    def get_interface_blocks(self) -> List[ConfigBlock]:
        """All `config system interface` edit entries."""
        entries = []
        for block in self.get_blocks("system interface"):
            entries.extend(block.sub_blocks)
        return entries

    def get_admin_blocks(self) -> List[ConfigBlock]:
        """All `config system admin` edit entries (administrator accounts)."""
        entries = []
        for block in self.get_blocks("system admin"):
            entries.extend(block.sub_blocks)
        return entries

    def get_zone_blocks(self) -> List[ConfigBlock]:
        entries = []
        for block in self.get_blocks("system zone"):
            entries.extend(block.sub_blocks)
        return entries

    def get_all_edit_entries(self, block_type: str) -> List[ConfigBlock]:
        """Every edit entry across all top-level blocks of the given type."""
        entries = []
        for block in self.get_blocks(block_type):
            entries.extend(block.sub_blocks)
        return entries

    def search(self, pattern: str, flags: int = re.I | re.M) -> bool:
        try:
            return bool(re.search(pattern, self.raw_content, flags))
        except re.error:
            return False

    def search_value(self, pattern: str, group: int = 1, flags: int = re.I | re.M) -> Optional[str]:
        try:
            m = re.search(pattern, self.raw_content, flags)
            return m.group(group) if m else None
        except (re.error, IndexError):
            return None

    def search_all(self, pattern: str, flags: int = re.I | re.M) -> List[str]:
        try:
            return re.findall(pattern, self.raw_content, flags)
        except re.error:
            return []


class ConfigParseError(ValueError):
    """Raised when a config file cannot be parsed or fails validation."""


class FortiGateConfigParser:
    """
    Parses FortiGate configuration backup files into structured data.

    Usage:
        parser = FortiGateConfigParser()
        config = parser.parse_file("fortigate.conf")

        hostname = config.get_global_setting("hostname")
        policies = config.get_policy_blocks()
        interfaces = config.get_interface_blocks()
        has_ssl = config.search(r'set strong-crypto enable')
    """

    # FortiGate config markers for validation
    FORTIGATE_MARKERS = [
        r'^config system global',
        r'^config system interface',
        r'^config firewall policy',
        r'^config system admin',
        r'^set hostname',
        r'#config-version=',
    ]

    def parse_file(self, filepath: str) -> FortiGateConfig:
        """Parse a FortiGate configuration file."""
        path = Path(filepath)

        # Security: validate path
        if not path.exists():
            raise FileNotFoundError(f"Configuration file not found: {filepath}")
        if not path.is_file():
            raise ValueError(f"Path is not a file: {filepath}")
        if not os.access(filepath, os.R_OK):
            raise PermissionError(f"No read permission for: {filepath}")

        # Security: check file size before reading into memory
        file_size = path.stat().st_size
        if file_size > MAX_CONFIG_SIZE_BYTES:
            raise ValueError(
                f"Config file too large ({file_size / 1024 / 1024:.1f}MB). "
                f"Maximum allowed: {MAX_CONFIG_SIZE_MB}MB"
            )
        if file_size == 0:
            raise ValueError("Config file is empty")

        content = path.read_text(encoding="utf-8", errors="ignore")

        if not self.validate_config(content):
            raise ConfigParseError(
                "This does not look like a FortiGate configuration backup "
                "(no recognizable 'config system ...' blocks or FortiGate "
                "config-version header found)."
            )

        logger.info(f"Loaded config file ({file_size / 1024:.1f}KB)")
        return self.parse_content(content)

    def parse_content(self, content: str) -> FortiGateConfig:
        """Parse FortiGate configuration content string."""
        # Sanitize: remove null bytes and other dangerous control chars
        content = content.replace('\x00', '')
        content = content.replace('\r\n', '\n').replace('\r', '\n')
        content = clean_console_paste(content)

        config = FortiGateConfig(raw_content=content)

        self._parse_header(content, config)
        config.blocks = self._parse_all_blocks(content)

        if config.has_global_setting("hostname"):
            config.hostname = config.get_global_setting("hostname").strip('"').strip("'")

        config.vdom_enabled = ':vdom=1' in content.splitlines()[0] if content else False

        logger.info(
            f"Parsed config: model={config.model or 'unknown'}, version={config.version or 'unknown'}, "
            f"blocks={sum(len(v) for v in config.blocks.values())}"
        )
        return config

    def validate_config(self, content: str) -> bool:
        """Validate if content is a FortiGate configuration."""
        matches = sum(1 for marker in self.FORTIGATE_MARKERS if re.search(marker, content, re.I | re.M))
        return matches >= 2

    def _parse_header(self, content: str, config: FortiGateConfig):
        """Extract version, model, and build from the config header comments."""
        # Format: #config-version=FG100D-5.04-FW-build1064-160608:opmode=1:vdom=0
        header_match = re.search(
            r'#config-version=([A-Za-z0-9_]+)-([\d.]+)-FW-build(\d+)',
            content,
        )
        if header_match:
            config.model = header_match.group(1)
            config.version = header_match.group(2)
            config.build = header_match.group(3)

        if not config.build:
            build_match = re.search(r'#buildno=(\d+)', content)
            if build_match:
                config.build = build_match.group(1)

        version_match = re.search(r'^\s*set\s+version\s+"?([^"\n]+)"?', content, re.I | re.M)
        if version_match and not config.version:
            config.version = version_match.group(1)

    def _parse_all_blocks(self, content: str) -> Dict[str, List[ConfigBlock]]:
        """Parse all top-level `config ...` blocks from the content."""
        blocks: Dict[str, List[ConfigBlock]] = {}
        lines = content.split('\n')
        i = 0
        n = len(lines)

        while i < n:
            line = lines[i].strip()
            config_match = re.match(r'^config\s+(.+)$', line, re.I)
            if config_match:
                block_type = config_match.group(1).strip()
                settings, children, sub_blocks, end_idx = self._parse_body(lines, i + 1, is_edit=False)
                block = ConfigBlock(
                    block_type=block_type,
                    settings=settings,
                    children=children,
                    sub_blocks=sub_blocks,
                    raw_text='\n'.join(lines[i:min(end_idx + 1, n)]),
                )
                key = block_type.lower()
                blocks.setdefault(key, []).append(block)
                i = end_idx + 1
            else:
                i += 1

        return blocks

    def _parse_body(
        self, lines: List[str], i: int, is_edit: bool
    ) -> Tuple[Dict[str, str], Dict[str, List[ConfigBlock]], List[ConfigBlock], int]:
        """
        Recursively parse the body of a config/edit block starting at line
        index `i` (the line *after* the opening `config .../edit ...`).
        Returns (settings, children, sub_blocks, index_of_terminator_line).

        `is_edit` selects the terminator: 'next' for edit bodies, 'end' for
        config bodies. A bare 'end' also terminates an edit body defensively,
        in case of malformed/truncated config files (missing 'next').
        """
        settings: Dict[str, str] = {}
        children: Dict[str, List[ConfigBlock]] = {}
        sub_blocks: List[ConfigBlock] = []
        n = len(lines)

        while i < n:
            line = lines[i].strip()
            low = line.lower()

            if low == 'end':
                return settings, children, sub_blocks, i
            if is_edit and low == 'next':
                return settings, children, sub_blocks, i

            config_match = re.match(r'^config\s+(.+)$', line, re.I)
            if config_match:
                child_type = config_match.group(1).strip()
                c_settings, c_children, c_subs, end_idx = self._parse_body(lines, i + 1, is_edit=False)
                child = ConfigBlock(
                    block_type=child_type,
                    settings=c_settings,
                    children=c_children,
                    sub_blocks=c_subs,
                    raw_text='\n'.join(lines[i:min(end_idx + 1, n)]),
                )
                children.setdefault(child_type.lower(), []).append(child)
                i = end_idx + 1
                continue

            edit_match = re.match(r'^edit\s+"?([^"\n]*?)"?\s*$', line, re.I)
            if edit_match:
                edit_name = edit_match.group(1)
                e_settings, e_children, e_subs, next_idx = self._parse_body(lines, i + 1, is_edit=True)
                edit_block = ConfigBlock(
                    block_type="edit",
                    name=edit_name,
                    settings=e_settings,
                    children=e_children,
                    sub_blocks=e_subs,
                    raw_text='\n'.join(lines[i:min(next_idx + 1, n)]),
                )
                sub_blocks.append(edit_block)
                i = next_idx + 1
                continue

            set_match = re.match(r'^set\s+(\S+)\s+(.*)$', line, re.I)
            if set_match:
                key = set_match.group(1).lower()
                value = self._clean_value(set_match.group(2))
                settings[key] = value
                i += 1
                continue

            unset_match = re.match(r'^unset\s+(\S+)', line, re.I)
            if unset_match:
                settings[unset_match.group(1).lower()] = ""
                i += 1
                continue

            i += 1

        # Reached EOF without a matching terminator (truncated/malformed file).
        return settings, children, sub_blocks, n - 1

    @staticmethod
    def _clean_value(raw: str) -> str:
        value = raw.strip()
        if '"' not in value:
            return value

        # FortiGate quotes both single string values (`set hostname "FGT1"`)
        # and space-separated lists of quoted tokens
        # (`set service "HTTPS" "DNS"`, `set monitor "port1" "port2"`).
        # Naively stripping only the first/last character mangles the list
        # form (leaving stray quotes stuck to the inner tokens), so detect
        # whether the whole value is exactly a sequence of quoted tokens and
        # reconstruct it as a clean space-separated, unquoted string.
        quoted_tokens = re.findall(r'"([^"]*)"', value)
        if quoted_tokens:
            reconstructed = ' '.join(f'"{t}"' for t in quoted_tokens)
            if re.sub(r'\s+', '', reconstructed) == re.sub(r'\s+', '', value):
                return quoted_tokens[0] if len(quoted_tokens) == 1 else ' '.join(quoted_tokens)
        return value

    def extract_section_text(self, content: str, section_name: str) -> str:
        """Extract raw text of a named top-level config section (first match)."""
        pattern = rf'(config\s+{re.escape(section_name)}\b.*?)(?=\nconfig\s|\Z)'
        match = re.search(pattern, content, re.I | re.S)
        return match.group(1) if match else ""
