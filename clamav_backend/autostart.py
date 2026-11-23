"""Manage this app's launch-at-login entry for the current desktop user."""

from __future__ import annotations

import configparser
import os
import plistlib
import subprocess
import sys
import tempfile
from pathlib import Path

MINIMIZED_FLAG = "--start-minimized"
_LINUX_ENTRY = "clamav-security-center-login.desktop"
_MAC_LABEL = "io.github.jxs1985.clamav-security-center.login"
_WINDOWS_KEY = r"Software\Microsoft\Windows\CurrentVersion\Run"
_WINDOWS_VALUE = "ClamAV Security Center"


def _launch_command(script_path: str) -> list[str]:
    executable = sys.executable
    if getattr(sys, "frozen", False):
        if sys.platform == "darwin":
            binary = Path(executable)
            contents = binary.parent.parent
            if binary.parent.name == "MacOS" and contents.name == "Contents" and contents.parent.suffix.lower() == ".app":
                return ["/usr/bin/open", "-g", "-a", str(contents.parent), "--args", MINIMIZED_FLAG]
        return [executable, MINIMIZED_FLAG]

    if sys.platform == "win32":
        windowed_python = Path(executable).with_name("pythonw.exe")
        if windowed_python.is_file():
            executable = str(windowed_python)
    return [executable, script_path, MINIMIZED_FLAG]


def _entry_path() -> Path:
    if sys.platform == "darwin":
        return Path.home() / "Library" / "LaunchAgents" / f"{_MAC_LABEL}.plist"
    config_home = Path(os.environ.get("XDG_CONFIG_HOME", ""))
    if not config_home.is_absolute():
        config_home = Path.home() / ".config"
    return config_home / "autostart" / _LINUX_ENTRY


def _desktop_entry(command: list[str]) -> bytes:
    # The desktop-entry string escape layer is decoded before Exec quoting.
    quoted_args = []
    for arg in command:
        quoted = "".join("\\" + ch if ch in '\\"`$' else ch for ch in arg)
        escaped = quoted.replace("\\", "\\\\").replace("%", "%%")
        escaped = escaped.replace("\n", "\\n").replace("\r", "\\r").replace("\t", "\\t")
        quoted_args.append(f'"{escaped}"')
    return (
        "[Desktop Entry]\n"
        "Type=Application\n"
        "Name=ClamAV Security Center\n"
        "Icon=clamav-security-center\n"
        f"Exec={' '.join(quoted_args)}\n"
        "Terminal=false\n"
    ).encode("utf-8")


def _write_entry(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = tempfile.NamedTemporaryFile(dir=path.parent, delete=False)
    temp_path = Path(temp.name)
    try:
        with temp:
            temp.write(data)
        temp_path.replace(path)
    finally:
        temp_path.unlink(missing_ok=True)


def is_enabled() -> bool:
    """Check whether the app's login entry is registered for the current user."""
    if sys.platform == "win32":
        import winreg

        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, _WINDOWS_KEY) as key:
                winreg.QueryValueEx(key, _WINDOWS_VALUE)
        except FileNotFoundError:
            return False
        return True

    path = _entry_path()
    try:
        if sys.platform == "darwin":
            path.stat()
            return True
        entry = configparser.ConfigParser(interpolation=None)
        with path.open(encoding="utf-8") as file:
            entry.read_file(file)
        return not entry.getboolean("Desktop Entry", "Hidden", fallback=False)
    except FileNotFoundError:
        return False
    except (configparser.Error, ValueError) as exc:
        raise OSError("Could not read the login desktop entry") from exc


def set_enabled(enabled: bool, script_path: str) -> None:
    """Register or remove the app's login entry without launching the app now."""
    if sys.platform == "win32":
        import winreg

        if enabled:
            command = subprocess.list2cmdline(_launch_command(script_path))
            if len(command.encode("utf-16-le")) // 2 > 260:
                raise OSError("The Windows login command exceeds 260 characters. Move the app to a shorter path.")
            with winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER, _WINDOWS_KEY, 0, winreg.KEY_SET_VALUE) as key:
                winreg.SetValueEx(key, _WINDOWS_VALUE, 0, winreg.REG_SZ, command)
        else:
            try:
                with winreg.OpenKey(winreg.HKEY_CURRENT_USER, _WINDOWS_KEY, 0, winreg.KEY_SET_VALUE) as key:
                    winreg.DeleteValue(key, _WINDOWS_VALUE)
            except FileNotFoundError:
                pass
        return

    path = _entry_path()
    if not enabled:
        path.unlink(missing_ok=True)
        return

    command = _launch_command(script_path)
    if sys.platform == "darwin":
        data = plistlib.dumps({
            "Label": _MAC_LABEL,
            "LimitLoadToSessionType": "Aqua",
            "ProgramArguments": command,
            "RunAtLoad": True,
        })
    else:
        data = _desktop_entry(command)
    _write_entry(path, data)
