"""Permanent local safety boundaries for the reverse-engineering control plane."""

from __future__ import annotations

import ipaddress
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from pathlib import Path, PureWindowsPath
from urllib.parse import urlsplit

from editor010.error_codes import ErrorCode
from .paths import PRIVATE_ROOT


_NETWORK_CONFIGURATION_PROGRAMS = frozenset({"netsh", "route", "netcfg"})
_NETWORK_CONFIGURATION_MARKERS = (
    "set-netipinterface",
    "new-netipaddress",
    "remove-netipaddress",
    "set-dnsclientserveraddress",
    "set-netfirewall",
    "new-netfirewall",
    "remove-netfirewall",
    "enable-netadapter",
    "disable-netadapter",
)
_SYSTEM_CONFIGURATION_PROGRAMS = frozenset({"bcdedit", "pnputil", "devcon", "diskpart", "manage-bde"})
_SYSTEM_CONFIGURATION_MARKERS = (
    "set-mppreference",
    "add-mppreference",
    "remove-mppreference",
    "set-windowsdefender",
)
_SYSTEM_PROTECTED_ROOTS = (
    r"C:\Windows\System32\drivers",
    r"C:\Windows\System32\DriverStore",
    r"C:\Windows\System32\config",
    r"C:\Windows\System32\GroupPolicy",
    r"C:\Windows\Boot",
    r"C:\EFI",
    r"C:\ProgramData\Microsoft\Windows Defender",
)


class PolicyViolation(PermissionError):
    """A redacted permanent-denial result suitable for a protocol error envelope."""

    def __init__(self, rule_id: str, category: str) -> None:
        super().__init__(f"REA Forge policy denied operation ({rule_id})")
        self.rule_id = rule_id
        self.category = category
        self.code = ErrorCode.POLICY_HARD_DENY.value

    def to_event(self) -> dict[str, str]:
        """Return non-secret evidence fields; never include paths, commands, or token material."""
        return {"kind": "policy_denied", "error_code": self.code, "rule_id": self.rule_id, "category": self.category}


@dataclass(frozen=True)
class HardDenyPolicy:
    """Fail closed before a tool, bridge, or worker can cross a permanent boundary."""

    codex_roots: tuple[str, ...]

    def __init__(self, *, codex_roots: Iterable[str | Path] | None = None) -> None:
        roots = codex_roots if codex_roots is not None else (Path.home() / ".codex", PRIVATE_ROOT / "config")
        normalized = tuple(self._normalized_path(root) for root in roots)
        if not normalized:
            raise ValueError("at least one Codex configuration root is required")
        object.__setattr__(self, "codex_roots", normalized)

    def require_loopback_endpoint(self, endpoint: str) -> None:
        host = urlsplit(endpoint).hostname
        if not host or not self._is_numeric_loopback(host):
            raise PolicyViolation("NET.REMOTE_ENDPOINT", "network")

    def require_loopback_listener(self, address: str) -> None:
        if not self._is_numeric_loopback(address):
            raise PolicyViolation("NET.NON_LOOPBACK_LISTENER", "network")

    def require_local_path(self, path: str | Path) -> PureWindowsPath:
        raw = str(path)
        if raw.startswith(("\\", "//")):
            raise PolicyViolation("PATH.UNC_OR_REMOTE", "path")
        normalized = self._normalized_path(raw)
        if any(self._is_under(normalized, root) for root in self.codex_roots):
            raise PolicyViolation("PATH.CODEX_CONFIG", "path")
        if any(self._is_under(normalized, self._normalized_path(root)) for root in _SYSTEM_PROTECTED_ROOTS):
            raise PolicyViolation("PATH.SYSTEM_DRIVER_FIRMWARE_SECURITY", "path")
        return PureWindowsPath(raw)

    def require_safe_command(self, argv: Sequence[str]) -> tuple[str, ...]:
        if not argv or any(not isinstance(item, str) or not item for item in argv):
            raise ValueError("command argv must be a non-empty sequence of non-empty strings")
        program = PureWindowsPath(argv[0]).name.casefold()
        if program.endswith(".exe"):
            program = program[:-4]
        command_text = "\n".join(argv).casefold()
        if program in _NETWORK_CONFIGURATION_PROGRAMS or any(marker in command_text for marker in _NETWORK_CONFIGURATION_MARKERS):
            raise PolicyViolation("CMD.NETWORK_CONFIG", "command")
        if program in _SYSTEM_CONFIGURATION_PROGRAMS or any(marker in command_text for marker in _SYSTEM_CONFIGURATION_MARKERS):
            raise PolicyViolation("CMD.SYSTEM_CONFIGURATION", "command")
        return tuple(argv)

    @staticmethod
    def _is_numeric_loopback(address: str) -> bool:
        try:
            return ipaddress.ip_address(address).is_loopback
        except ValueError:
            return False

    @staticmethod
    def _normalized_path(path: str | Path) -> str:
        return str(PureWindowsPath(str(path).replace("/", "\\"))).casefold().rstrip("\\")

    @staticmethod
    def _is_under(candidate: str, root: str) -> bool:
        return candidate == root or candidate.startswith(root + "\\")
