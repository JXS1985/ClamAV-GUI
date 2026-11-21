#!/usr/bin/env python3
"""Verify installed .deb/.rpm package, Start Menu (.desktop), and Notification/Tray integration."""

from __future__ import annotations

import argparse
import configparser
import importlib.util
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path
from unittest import mock

INSTALLED_BIN = Path("/usr/bin/clamav-security-center")
INSTALLED_ALIAS = Path("/usr/bin/clamav-kde-gui")
INSTALLED_APP_DIR = Path("/usr/share/clamav-security-center")
INSTALLED_PY = INSTALLED_APP_DIR / "clamav_gui.py"
INSTALLED_RUN = INSTALLED_APP_DIR / "run.sh"
INSTALLED_DESKTOP = Path("/usr/share/applications/clamav-kde-gui.desktop")


def verify_package_files(pkg_type: str) -> None:
    print("[os-verify] Checking installed package files...")
    for p in (INSTALLED_BIN, INSTALLED_ALIAS, INSTALLED_PY, INSTALLED_RUN, INSTALLED_DESKTOP):
        assert p.exists(), f"Missing installed path: {p}"
    for p in (INSTALLED_BIN, INSTALLED_PY, INSTALLED_RUN):
        assert os.access(p, os.X_OK), f"Expected executable permissions on {p}"
    assert INSTALLED_ALIAS.is_symlink(), f"Expected symlink at {INSTALLED_ALIAS}"

    if pkg_type == "rpm":
        res = subprocess.run(["rpm", "-qf", str(INSTALLED_DESKTOP)], capture_output=True, text=True, check=False)
        assert res.returncode == 0, f"rpm -qf failed: {res.stderr}"
        print(f"[os-verify] RPM owns desktop entry: {res.stdout.strip()}")
    elif pkg_type == "deb":
        res = subprocess.run(["dpkg", "-S", str(INSTALLED_DESKTOP)], capture_output=True, text=True, check=False)
        assert res.returncode == 0, f"dpkg -S failed: {res.stderr}"
        print(f"[os-verify] DEB owns desktop entry: {res.stdout.strip()}")

    st_res = subprocess.run([str(INSTALLED_BIN), "--self-test"], capture_output=True, text=True, check=False)
    assert st_res.returncode == 0, f"Installed --self-test failed:\n{st_res.stdout}\n{st_res.stderr}"
    print("[os-verify] Installed CLI /usr/bin/clamav-security-center --self-test passed.")


def verify_start_menu_entry(desktop: str) -> None:
    print(f"[os-verify] Verifying Start Menu / Application Launcher entry for {desktop}...")
    if shutil.which("desktop-file-validate"):
        val = subprocess.run(
            ["desktop-file-validate", str(INSTALLED_DESKTOP)], capture_output=True, text=True, check=False
        )
        assert val.returncode == 0, f"desktop-file-validate failed:\n{val.stdout}\n{val.stderr}"
        print("[os-verify] desktop-file-validate passed.")

    if shutil.which("update-desktop-database"):
        subprocess.run(["update-desktop-database", "/usr/share/applications"], check=False)

    cp = configparser.ConfigParser(interpolation=None)
    cp.optionxform = str  # preserve case
    cp.read(INSTALLED_DESKTOP, encoding="utf-8")
    assert cp.has_section("Desktop Entry"), "Missing [Desktop Entry] section"
    entry = cp["Desktop Entry"]
    assert entry.get("Type") == "Application"
    assert entry.get("Name"), "Missing Name in .desktop"
    assert entry.get("Name[de]"), "Missing Name[de] in .desktop"
    assert entry.get("NoDisplay", "false").lower() != "true", "Desktop entry must be visible in Start Menu"
    assert entry.get("OnlyShowIn") is None and entry.get("NotShowIn") is None, "Must show in both KDE and GNOME"
    exec_bin = entry.get("Exec", "").split()[0]
    assert exec_bin == str(INSTALLED_BIN) and os.access(exec_bin, os.X_OK), f"Invalid Exec target: {exec_bin}"
    cats = set(filter(None, entry.get("Categories", "").split(";")))
    assert {"System", "Security", "KDE", "GNOME"}.issubset(cats), f"Missing expected categories: {cats}"
    assert entry.get("Icon") == "security-high"

    # Optional Gio.DesktopAppInfo lookup (matches GNOME / XDG launcher visibility)
    try:
        from gi.repository import Gio  # type: ignore[import-not-found]

        app_info = Gio.DesktopAppInfo.new_from_filename(str(INSTALLED_DESKTOP))
        assert app_info is not None, f"Gio.DesktopAppInfo could not load {INSTALLED_DESKTOP}"
        assert app_info.should_show(), "Gio.DesktopAppInfo.should_show() returned False"
        if desktop == "gnome":
            assert app_info.get_show_in("GNOME"), "Desktop entry not shown in GNOME"
        elif desktop == "kde":
            assert app_info.get_show_in("KDE"), "Desktop entry not shown in KDE"
        assert app_info.get_executable() == str(INSTALLED_BIN)
        print(f"[os-verify] Gio.DesktopAppInfo resolved '{app_info.get_display_name()}' for {desktop} cleanly.")
    except ImportError:
        print("[os-verify] PyGObject (gi) not present; XDG configparser check completed.")

    # Optional KDE Sycoca rebuild check
    if desktop == "kde" and shutil.which("kbuildsycoca6"):
        syc = subprocess.run(["kbuildsycoca6", "--noincremental"], capture_output=True, text=True, check=False)
        assert syc.returncode == 0, f"kbuildsycoca6 failed: {syc.stderr}"
        print("[os-verify] kbuildsycoca6 rebuilt KDE menu cache cleanly.")


def verify_notification_and_tray_entry(desktop: str) -> None:
    print(f"[os-verify] Verifying Notification Panel & System Tray integration for {desktop}...")
    spec = importlib.util.spec_from_file_location("installed_clamav_gui", str(INSTALLED_PY))
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)

    # Launch installed window headlessly if no display, or against live Xvfb/Wayland/X11 if available
    has_live_display = bool(os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY"))
    if not has_live_display:
        os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

    win = mod.create_main_window(auto_poll=False, lang="en")
    try:
        assert win._qt_app.desktopFileName() == "clamav-kde-gui", (
            f"Expected desktopFileName='clamav-kde-gui', got {win._qt_app.desktopFileName()!r}"
        )

        # Verify tray setup constructs icon, tooltip, and full context menu
        try:
            from PySide6.QtWidgets import QSystemTrayIcon
        except ImportError:
            from PyQt6.QtWidgets import QSystemTrayIcon  # type: ignore[no-redef]

        live_tray = bool(has_live_display and QSystemTrayIcon.isSystemTrayAvailable())
        print(f"[os-verify] has_live_display={has_live_display}, QSystemTrayIcon.isSystemTrayAvailable()={live_tray}")

        if live_tray:
            win._setup_tray()
            win._qt_app.processEvents()
            assert win._tray_icon is not None and win._tray_icon.isVisible(), "Tray icon failed to become visible"
            assert win.tray_open_act is not None and win.tray_quick_act is not None and win.tray_quit_act is not None
            # Emit real tray notification on live panel
            win._notify("ClamAV OS Test", "Notification panel check from installed package")
            win._qt_app.processEvents()
        else:
            # Verify tray construction deterministically with mocked availability
            with mock.patch.object(QSystemTrayIcon, "isSystemTrayAvailable", return_value=True), mock.patch.object(
                QSystemTrayIcon, "show"
            ):
                win._setup_tray()
                assert win._tray_icon is not None
                assert win.tray_open_act is not None and win.tray_quick_act is not None and win.tray_quit_act is not None
                # Also verify fallback notify-send command parameters include desktop-entry link
                with mock.patch.object(win._tray_icon, "isVisible", return_value=False), mock.patch(
                    "shutil.which", return_value="/usr/bin/notify-send"
                ), mock.patch("subprocess.Popen") as mock_popen:
                    win._notify("ClamAV OS Test", "Notification test")
                cmd = mock_popen.call_args[0][0]
                assert "string:desktop-entry:clamav-kde-gui" in cmd, cmd
                assert "security-high" in cmd, cmd
    finally:
        win._force_quit = True
        if win._tray_icon is not None:
            win._tray_icon.hide()
        win.close()
        win._qt_app.processEvents()

    # If live D-Bus session notification daemon or StatusNotifierWatcher is running, verify live registration too
    if os.environ.get("DBUS_SESSION_BUS_ADDRESS") and shutil.which("gdbus"):
        notif_info = subprocess.run(
            [
                "gdbus",
                "call",
                "--session",
                "--dest",
                "org.freedesktop.Notifications",
                "--object-path",
                "/org/freedesktop/Notifications",
                "--method",
                "org.freedesktop.Notifications.GetServerInformation",
            ],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
        if notif_info.returncode == 0:
            print(f"[os-verify] Live org.freedesktop.Notifications daemon: {notif_info.stdout.strip()}")
            if shutil.which("notify-send"):
                ns = subprocess.run(
                    [
                        "notify-send",
                        "-i",
                        "security-high",
                        "-h",
                        "string:desktop-entry:clamav-kde-gui",
                        "-a",
                        "ClamAV Security Center",
                        "ClamAV CI Notification Test",
                        f"Verified installed package notification on {desktop}",
                    ],
                    capture_output=True,
                    text=True,
                    timeout=5,
                    check=False,
                )
                assert ns.returncode == 0, f"notify-send failed against live daemon: {ns.stderr}"
                print("[os-verify] Live desktop notification delivered via org.freedesktop.Notifications.")

        if has_live_display:
            # Launch installed GUI binary briefly on live session & check StatusNotifierWatcher if active
            proc = subprocess.Popen([str(INSTALLED_BIN), "--lang", "en"])
            try:
                time.sleep(2.5)
                assert proc.poll() is None, f"Installed GUI exited prematurely with {proc.returncode}"
                sni = subprocess.run(
                    [
                        "gdbus",
                        "call",
                        "--session",
                        "--dest",
                        "org.kde.StatusNotifierWatcher",
                        "--object-path",
                        "/StatusNotifierWatcher",
                        "--method",
                        "org.freedesktop.DBus.Properties.Get",
                        "org.kde.StatusNotifierWatcher",
                        "RegisteredStatusNotifierItems",
                    ],
                    capture_output=True,
                    text=True,
                    timeout=5,
                    check=False,
                )
                if sni.returncode == 0:
                    print(f"[os-verify] Live StatusNotifierWatcher items: {sni.stdout.strip()}")
            finally:
                proc.terminate()
                try:
                    proc.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait(timeout=2)

    print("[os-verify] Notification panel & tray entry checks passed.")


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify installed ClamAV Security Center OS package")
    parser.add_argument("--pkg-type", choices=("rpm", "deb"), required=True)
    parser.add_argument("--desktop", choices=("kde", "gnome"), required=True)
    args = parser.parse_args()

    verify_package_files(args.pkg_type)
    verify_start_menu_entry(args.desktop)
    verify_notification_and_tray_entry(args.desktop)
    print("[os-verify] ALL INSTALLED PACKAGE & DE CHECKS PASSED.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
