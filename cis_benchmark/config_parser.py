"""
FortiGate Configuration Parser
===============================
Parses FortiGate configuration backup (.conf) files into structured data.
Supports nested config blocks, key-value extraction, and FortiOS version detection.
"""

import re
import os
import logging
from typing import Dict, List, Optional, Any
from pathlib import Path
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)

MAX_CONFIG_SIZE_MB = 50
MAX_CONFIG_SIZE_BYTES = MAX_CONFIG_SIZE_MB * 1024 * 1024


@dataclass
class ConfigBlock:
    """Represents a parsed configuration block."""
    block_type: str
    name: str = ""
    settings: Dict[str, str] = field(default_factory=dict)
    sub_blocks: List["ConfigBlock"] = field(default_factory=list)
    raw_text: str = ""

    def get(self, key: str, default: str = "") -> str:
        return self.settings.get(key, default)

    def has(self, key: str) -> bool:
        return key in self.settings

    def get_sub_block(self, block_type: str) -> Optional["ConfigBlock"]:
        for sb in self.sub_blocks:
            if sb.block_type.lower() == block_type.lower():
                return sb
        return None


@dataclass
class FortiGateConfig:
    """Structured representation of a full FortiGate configuration."""
    raw_content: str
    version: str = ""
    build: str = ""
    model: str = ""
    hostname: str = ""
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
        return self.get_blocks("firewall policy")

    def get_av_profile_blocks(self) -> List[ConfigBlock]:
        return self.get_blocks("antivirus profile")

    def get_interface_blocks(self) -> List[ConfigBlock]:
        return self.get_blocks("system interface")

    def get_admin_blocks(self) -> List[ConfigBlock]:
        return self.get_blocks("system admin")

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


class FortiGateConfigParser:
    """
    Parses FortiGate configuration backup files into structured data.
    
    Usage:
        parser = FortiGateConfigParser()
        config = parser.parse_file("fortigate.conf")
        
        # Access system global settings
        hostname = config.get_global_setting("hostname")
        
        # Access specific config blocks
        policies = config.get_policy_blocks()
        interfaces = config.get_interface_blocks()
        
        # Raw regex search
        has_ssl = config.search(r'set strong-crypto enable')
    """

    # FortiGate config markers for validation
    FORTIGATE_MARKERS = [
        r'config system global',
        r'config system interface',
        r'config firewall policy',
        r'config system admin',
        r'set hostname',
        r'#config-version=',
        r'config antivirus profile',
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

        # Security: check file size
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
            logger.warning("File may not be a valid FortiGate configuration")

        logger.info(f"Loaded config: {filepath} ({file_size / 1024:.1f}KB)")
        return self.parse_content(content)

    def parse_content(self, content: str) -> FortiGateConfig:
        """Parse FortiGate configuration content string."""
        # Sanitize: remove null bytes and other dangerous chars
        content = content.replace('\x00', '')

        config = FortiGateConfig(raw_content=content)

        # Extract metadata from header
        self._parse_header(content, config)

        # Parse all config blocks
        config.blocks = self._parse_all_blocks(content)

        # Extract hostname
        if config.has_global_setting("hostname"):
            config.hostname = config.get_global_setting("hostname").strip('"').strip("'")

        logger.info(
            f"Parsed config: model={config.model}, version={config.version}, "
            f"hostname={config.hostname}, blocks={sum(len(v) for v in config.blocks.values())}"
        )
        return config

    def validate_config(self, content: str) -> bool:
        """Validate if content is a FortiGate configuration."""
        matches = sum(1 for marker in self.FORTIGATE_MARKERS if re.search(marker, content, re.I))
        return matches >= 2

    def _parse_header(self, content: str, config: FortiGateConfig):
        """Extract version, model, and build from config header."""
        # Format: #config-version=FG100D-5.04-FW-build1064-160608:opmode=1:vdom=0
        header_match = re.search(
            r'#config-version=(\w+)-([\d.]+)-FW-build(\d+)',
            content
        )
        if header_match:
            config.model = header_match.group(1)
            config.version = header_match.group(2)
            config.build = header_match.group(3)

        # Also check for newer format
        version_match = re.search(r'set\s+version\s+"?([^"\n]+)"?', content, re.I)
        if version_match and not config.version:
            config.version = version_match.group(1)

    def _parse_all_blocks(self, content: str) -> Dict[str, List[ConfigBlock]]:
        """Parse all top-level config blocks from the content."""
        blocks: Dict[str, List[ConfigBlock]] = {}
        lines = content.split('\n')
        i = 0

        while i < len(lines):
            line = lines[i].strip()

            # Match top-level config block start
            config_match = re.match(r'^config\s+(.+)$', line, re.I)
            if config_match:
                block_type = config_match.group(1).strip()
                block, end_idx = self._parse_block(lines, i, block_type)
                if block:
                    key = block_type.lower()
                    if key not in blocks:
                        blocks[key] = []
                    blocks[key].append(block)
                i = end_idx + 1
            else:
                i += 1

        return blocks

    def _parse_block(self, lines: List[str], start_idx: int, block_type: str) -> tuple:
        """Parse a config block starting at the given index. Returns (block, end_index)."""
        block = ConfigBlock(block_type=block_type)
        raw_lines = [lines[start_idx]]
        i = start_idx + 1
        depth = 1
        current_edit_name = ""
        current_edit_settings: Dict[str, str] = {}
        current_edit_start = -1
        in_edit = False
        current_subconfig_name = ""
        current_subconfig_settings: Dict[str, str] = {}
        current_subconfig_start = -1
        current_subconfig_blocks = []
        in_subconfig = False

        while i < len(lines) and depth > 0:
            line = lines[i].strip()
            raw_lines.append(lines[i])

            if line.lower() == 'end':
                depth -= 1
                if depth == 0:
                    # If we were in a subconfig block, save it
                    if in_subconfig:
                        sub = ConfigBlock(
                            block_type=block_type,
                            name=f"{current_edit_name}.{current_subconfig_name}",
                            settings=dict(current_subconfig_settings),
                        )
                        current_subconfig_blocks.append(sub)
                    # If we were in an edit block, save it
                    if in_edit:
                        sub = ConfigBlock(
                            block_type=block_type,
                            name=current_edit_name,
                            settings=dict(current_edit_settings),
                            sub_blocks=current_subconfig_blocks,
                        )
                        block.sub_blocks.append(sub)
                        current_subconfig_blocks = []
                    break
                i += 1
                continue

#            if re.match(r'^config\s+', line, re.I):
#                depth += 1
#                i += 1
#                continue

            # Handle 'config' entries (like in antivirus profile)
            config_match = re.match(r'^config\s+"?([^"]*)"?\s*$', line, re.I)
            if config_match:
                # Save previous subconfig block
                if in_edit and in_subconfig:
                    sub = ConfigBlock(
                        block_type=block_type,
                        name=f"{current_edit_name}.{current_subconfig_name}",
                        settings=dict(current_subconfig_settings),
                    )
                    current_subconfig_blocks.append(sub)
                current_subconfig_name = config_match.group(1)
                current_subconfig_settings = {}
                in_subconfig = True
                depth += 1
                i += 1
                continue

            # Handle 'edit' entries (like in firewall policy, system interface)
            edit_match = re.match(r'^edit\s+"?([^"]*)"?\s*$', line, re.I)
            if edit_match:
                # Save previous edit block
                if in_edit and current_edit_name:
                    sub = ConfigBlock(
                        block_type=block_type,
                        name=current_edit_name,
                        settings=dict(current_edit_settings),
                        sub_blocks=current_subconfig_blocks,
                    )
                    block.sub_blocks.append(sub)
                    current_subconfig_blocks = []
                current_edit_name = edit_match.group(1)
                current_edit_settings = {}
                in_edit = True
                i += 1
                continue

            if line.lower() == 'next':
                if in_edit and current_edit_name:
                    sub = ConfigBlock(
                        block_type=block_type,
                        name=current_edit_name,
                        settings=dict(current_edit_settings),
                        sub_blocks=current_subconfig_blocks,
                    )
                    block.sub_blocks.append(sub)
                    current_subconfig_blocks = []
                    current_edit_name = ""
                    current_edit_settings = {}
                    in_edit = False
                i += 1
                continue

            # Parse 'set' directives
            set_match = re.match(r'^set\s+(\S+)\s+(.*)', line, re.I)
            if set_match:
                key = set_match.group(1).lower()
                value = set_match.group(2).strip().strip('"').strip("'")
                if in_subconfig:
                    current_subconfig_settings[key] = value
                elif in_edit:
                    current_edit_settings[key] = value
                else:
                    block.settings[key] = value

            # Parse 'unset' directives
            unset_match = re.match(r'^unset\s+(\S+)', line, re.I)
            if unset_match:
                key = unset_match.group(1).lower()
                if in_subconfig:
                    current_subconfig_settings[key] = value
                elif in_edit:
                    current_edit_settings[key] = ""
                else:
                    block.settings[key] = ""

            i += 1

        block.raw_text = '\n'.join(raw_lines[:i - start_idx + 1])
        return block, i

    def extract_section_text(self, content: str, section_name: str) -> str:
        """Extract raw text of a named config section."""
        pattern = rf'(config\s+{re.escape(section_name)}.*?)(?=\nconfig\s|\Z)'
        match = re.search(pattern, content, re.I | re.S)
        return match.group(1) if match else ""

    def get_all_edit_entries(self, config: FortiGateConfig, block_type: str) -> List[ConfigBlock]:
        """Get all 'edit' entries from a specific block type."""
        entries = []
        for block in config.get_blocks(block_type):
            entries.extend(block.sub_blocks)
        return entries
