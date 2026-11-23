"""Test per-user login registrations without changing the host's startup settings."""

from __future__ import annotations

import configparser
import os
import plistlib
import sys
import tempfile
import unittest
import uuid
from pathlib import Path
from unittest import mock

from clamav_backend import autostart


class TestLoginAutostart(unittest.TestCase):
    def setUp(self) -> None:
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.home = Path(temp.name)
        home_patch = mock.patch.object(Path, "home", return_value=self.home)
        home_patch.start()
        self.addCleanup(home_patch.stop)
        self.script = str(self.home / "ClamAV GUI" / "clamav_gui.py")

    def test_linux_login_entry_enable_disable_and_escaping(self) -> None:
        config_home = self.home / "custom config"
        with mock.patch.object(sys, "platform", "linux"), mock.patch.object(
            sys, "executable", "/opt/ClamAV 100%/bin/python3"
        ), mock.patch.dict(os.environ, {"XDG_CONFIG_HOME": str(config_home)}):
            entry = config_home / "autostart" / "clamav-security-center-login.desktop"
            self.assertFalse(autostart.is_enabled())
            self.assertFalse(entry.parent.exists())

            script = '/home/ClamAV $USER `test` "safe" \\copy/clamav_gui.py'
            autostart.set_enabled(True, script)
            self.assertTrue(autostart.is_enabled())
            parser = configparser.ConfigParser(interpolation=None)
            parser.read(entry, encoding="utf-8")
            self.assertEqual(parser["Desktop Entry"]["Type"], "Application")
            self.assertEqual(
                parser["Desktop Entry"]["Exec"],
                r'"/opt/ClamAV 100%%/bin/python3" "/home/ClamAV \\$USER \\`test\\` \\"safe\\" \\\\copy/clamav_gui.py" "--start-minimized"',
            )

            entry.write_text(entry.read_text(encoding="utf-8") + "Hidden=true\n", encoding="utf-8")
            self.assertFalse(autostart.is_enabled())
            autostart.set_enabled(True, script)
            self.assertTrue(autostart.is_enabled())
            autostart.set_enabled(False, script)
            autostart.set_enabled(False, script)
            self.assertFalse(entry.exists())

    def test_linux_default_config_directory_and_failed_replacement(self) -> None:
        with mock.patch.object(sys, "platform", "linux"), mock.patch.dict(
            os.environ, {"XDG_CONFIG_HOME": "relative"}
        ):
            autostart.set_enabled(True, self.script)
            directory = self.home / ".config" / "autostart"
            entry = directory / "clamav-security-center-login.desktop"
            original = entry.read_bytes()
            with mock.patch.object(Path, "replace", side_effect=PermissionError("read-only")):
                with self.assertRaises(PermissionError):
                    autostart.set_enabled(True, self.script + "-moved")
            self.assertEqual(entry.read_bytes(), original)
            self.assertEqual(list(directory.iterdir()), [entry])

    def test_macos_login_agent_for_bundled_and_source_launches(self) -> None:
        bundle = self.home / "Applications" / "ClamAV Security Center.app"
        binary = bundle / "Contents" / "MacOS" / "clamav-security-center"
        entry = self.home / "Library" / "LaunchAgents" / "io.github.jxs1985.clamav-security-center.login.plist"
        with mock.patch.object(sys, "platform", "darwin"), mock.patch.object(
            sys, "executable", str(binary)
        ), mock.patch.object(sys, "frozen", True, create=True):
            self.assertFalse(autostart.is_enabled())
            autostart.set_enabled(True, self.script)
            self.assertTrue(autostart.is_enabled())
            with entry.open("rb") as file:
                self.assertEqual(plistlib.load(file), {
                    "Label": entry.stem,
                    "LimitLoadToSessionType": "Aqua",
                    "ProgramArguments": ["/usr/bin/open", "-g", "-a", str(bundle), "--args", "--start-minimized"],
                    "RunAtLoad": True,
                })
            with mock.patch.object(sys, "frozen", False), mock.patch.object(sys, "executable", "/opt/venv/bin/python"):
                autostart.set_enabled(True, self.script)
                with entry.open("rb") as file:
                    self.assertEqual(plistlib.load(file)["ProgramArguments"], [
                        "/opt/venv/bin/python", self.script, "--start-minimized",
                    ])
            autostart.set_enabled(False, self.script)
            self.assertFalse(autostart.is_enabled())
            self.assertFalse(entry.exists())

    def test_windows_packaged_login_command_and_removal(self) -> None:
        registry = mock.MagicMock()
        registry.QueryValueEx.side_effect = FileNotFoundError
        exe = r"C:\Portable Apps\ClamAV Security Center.exe"
        with mock.patch.object(sys, "platform", "win32"), mock.patch.dict(sys.modules, {"winreg": registry}), \
                mock.patch.object(sys, "executable", exe), mock.patch.object(sys, "frozen", True, create=True):
            self.assertFalse(autostart.is_enabled())
            autostart.set_enabled(True, self.script)
            registry.CreateKeyEx.assert_called_once_with(
                registry.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run", 0, registry.KEY_SET_VALUE,
            )
            registry.SetValueEx.assert_called_once_with(
                registry.CreateKeyEx.return_value.__enter__.return_value,
                "ClamAV Security Center", 0, registry.REG_SZ, f'"{exe}" --start-minimized',
            )
            registry.QueryValueEx.side_effect = None
            self.assertTrue(autostart.is_enabled())
            autostart.set_enabled(False, self.script)
            registry.DeleteValue.assert_called_once_with(
                registry.OpenKey.return_value.__enter__.return_value, "ClamAV Security Center",
            )
            registry.DeleteValue.side_effect = FileNotFoundError
            autostart.set_enabled(False, self.script)

    def test_windows_source_launch_and_command_limit(self) -> None:
        exe = self.home / "python.exe"
        windowed_exe = exe.with_name("pythonw.exe")
        windowed_exe.touch()
        registry = mock.MagicMock()
        with mock.patch.object(sys, "platform", "win32"), mock.patch.dict(sys.modules, {"winreg": registry}), \
                mock.patch.object(sys, "executable", str(exe)):
            self.assertEqual(autostart._launch_command(self.script), [str(windowed_exe), self.script, "--start-minimized"])
            with self.assertRaisesRegex(OSError, "260 characters"):
                autostart.set_enabled(True, self.script + "x" * 260)
            registry.CreateKeyEx.assert_not_called()

    @unittest.skipUnless(sys.platform == "win32", "native Windows registry test")
    def test_windows_native_registry_round_trip(self) -> None:
        import winreg

        test_key = rf"Software\ClamAVSecurityCenterTest-{uuid.uuid4()}"
        with winreg.CreateKey(winreg.HKEY_CURRENT_USER, test_key):
            pass
        self.addCleanup(winreg.DeleteKey, winreg.HKEY_CURRENT_USER, test_key)
        with mock.patch.object(autostart, "_WINDOWS_KEY", test_key):
            self.assertFalse(autostart.is_enabled())
            autostart.set_enabled(True, self.script)
            self.assertTrue(autostart.is_enabled())
            autostart.set_enabled(False, self.script)
            self.assertFalse(autostart.is_enabled())
