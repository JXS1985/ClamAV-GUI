#!/usr/bin/env python3
"""Extensive headless Qt6 UI test suite covering all ClamAV Security Center GUI functionality."""

from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

# Run all Qt GUI tests completely headlessly without touching the user desktop session
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import clamav_gui as app_mod  # noqa: E402

try:
    from PySide6.QtCore import QItemSelectionModel, QMimeData, QPoint, QPointF, Qt, QTime, QUrl
    from PySide6.QtGui import QCloseEvent, QDragEnterEvent, QDropEvent
    from PySide6.QtTest import QTest
    from PySide6.QtWidgets import (
        QApplication,
        QDialog,
        QFileDialog,
        QInputDialog,
        QLabel,
        QMessageBox,
        QPushButton,
        QSystemTrayIcon,
    )
except ImportError:
    from PyQt6.QtCore import QItemSelectionModel, QMimeData, QPoint, QPointF, Qt, QTime, QUrl  # type: ignore[no-redef]
    from PyQt6.QtGui import QCloseEvent, QDragEnterEvent, QDropEvent  # type: ignore[no-redef]
    from PyQt6.QtTest import QTest  # type: ignore[no-redef]
    from PyQt6.QtWidgets import (  # type: ignore[no-redef]
        QApplication,
        QDialog,
        QFileDialog,
        QInputDialog,
        QLabel,
        QMessageBox,
        QPushButton,
        QSystemTrayIcon,
    )


class _UIEnvMixin:
    """Shared isolated temporary filesystem environment and window helpers for UI tests."""

    _tmp_dir: tempfile.TemporaryDirectory[str]
    win: app_mod.Any  # type: ignore[name-defined]

    @classmethod
    def _setup_isolated_env(cls, lang: str = "en") -> None:
        cls._tmp_dir = tempfile.TemporaryDirectory()
        cls._orig_history = app_mod.HISTORY_FILE_PATH
        cls._orig_log = app_mod.DEFAULT_LOG_PATH
        cls._orig_settings = app_mod.SETTINGS_FILE_PATH
        cls._orig_quar = app_mod.DEFAULT_QUARANTINE_DIR

        tmp = Path(cls._tmp_dir.name)
        app_mod.HISTORY_FILE_PATH = tmp / "history.json"
        app_mod.DEFAULT_LOG_PATH = str(tmp / "nonexistent.log")
        app_mod.SETTINGS_FILE_PATH = tmp / "settings.json"
        app_mod.DEFAULT_QUARANTINE_DIR = str(tmp / "quarantine")

        with mock.patch.object(
            app_mod,
            "get_clamav_metadata",
            return_value={"version": "ClamAV 1.4.6-test", "freshclam_service": "active"},
        ):
            cls.win = app_mod.create_main_window(auto_poll=False, lang=lang)
        cls.win.show()
        cls.win._qt_app.processEvents()

    @classmethod
    def _teardown_isolated_env(cls) -> None:
        cls.win._force_quit = True
        cls.win.close()
        cls.win._qt_app.processEvents()
        app_mod.HISTORY_FILE_PATH = cls._orig_history
        app_mod.DEFAULT_LOG_PATH = cls._orig_log
        app_mod.SETTINGS_FILE_PATH = cls._orig_settings
        app_mod.DEFAULT_QUARANTINE_DIR = cls._orig_quar
        cls._tmp_dir.cleanup()

    def _reset_window_state(self) -> None:
        app_mod.cancel_background_precount()
        self.win._current_proc = None
        self.win._known_procs = []
        self.win._last_active_scan = None
        self.win._pending_scan_labels.clear()
        self.win.telemetry.selected_pid = None
        self.win.telemetry.last_proc_data = {}
        self.win.telemetry.last_precount = {}
        self.win.telemetry.last_eta_speed_bps = None
        self.win._reset_log_state(reset_offset=True)
        self.win.log_filter_edit.clear()
        self.win.bg_mode_chk.setChecked(False)
        if self.win.toggle_tabs_btn.isChecked():
            QTest.mouseClick(self.win.toggle_tabs_btn, Qt.MouseButton.LeftButton)
            self.win._qt_app.processEvents()
        self.win._update_auth_banner()
        self.win._update_controls_enabled()
        self.win._update_hero_banner(None)
        self.win._qt_app.processEvents()


class TestUIInitialLayoutAndCompactMode(unittest.TestCase, _UIEnvMixin):
    """UI tests for streamlined compact layout, metadata, tab disclosure, and widget structure."""

    @classmethod
    def setUpClass(cls) -> None:
        cls._setup_isolated_env(lang="en")

    @classmethod
    def tearDownClass(cls) -> None:
        cls._teardown_isolated_env()

    def setUp(self) -> None:
        self._reset_window_state()

    def test_compact_layout_and_on_demand_tab_toggle(self) -> None:
        self.assertTrue(self.win.tabs.isHidden())
        self.assertFalse(hasattr(self.win, "tech_details_chk"))
        self.assertFalse(hasattr(self.win, "proc_combo"))
        self.assertFalse(hasattr(self.win, "cmdline_edit"))

        self.assertEqual(self.win.tabs.count(), 4)
        self.assertEqual(self.win.tabs.tabText(0), "Live Log && History")
        self.assertEqual(self.win.tabs.tabText(1), "Threats (0) && Quarantine (0)")
        self.assertEqual(self.win.tabs.tabText(2), "Schedule && Custom Scan")
        self.assertEqual(self.win.tabs.tabText(3), "Virus Database")

        self.assertIn("ClamAV 1.4.6-test", self.win.meta_lbl.text())
        self.assertIn("Active", self.win.meta_lbl.text())
        self.assertTrue(hasattr(self.win, "stats_strip"))
        self.assertTrue(hasattr(self.win, "header_shield_lbl"))
        self.assertTrue(hasattr(self.win, "hero_icon_lbl"))
        self.assertFalse(hasattr(self.win, "lang_de_btn"))
        self.assertFalse(hasattr(self.win, "lang_en_btn"))
        self.assertFalse(hasattr(self.win, "lang_combo"))

        initial_w = self.win.width()
        initial_h = self.win.height()
        self.assertGreaterEqual(initial_w, 980)
        self.assertLessEqual(initial_w, 1440)
        self.assertLess(initial_h, 700)
        self.assertIn("Show", self.win.toggle_tabs_btn.text())

        # Expand via genuine mouse click
        QTest.mouseClick(self.win.toggle_tabs_btn, Qt.MouseButton.LeftButton)
        self.win._qt_app.processEvents()
        self.assertFalse(self.win.tabs.isHidden())
        self.assertIn("Hide", self.win.toggle_tabs_btn.text())
        self.assertEqual(self.win.width(), initial_w)
        self.assertGreater(self.win.height(), initial_h + 200)

        # Switching tabs works cleanly once visible
        for idx in range(4):
            self.win._open_tab(idx)
            self.assertEqual(self.win.tabs.currentIndex(), idx)

        # Collapse via genuine mouse click
        QTest.mouseClick(self.win.toggle_tabs_btn, Qt.MouseButton.LeftButton)
        self.win._qt_app.processEvents()
        self.assertTrue(self.win.tabs.isHidden())
        self.assertIn("Show", self.win.toggle_tabs_btn.text())
        self.assertEqual(self.win.width(), initial_w)
        self.assertEqual(self.win.height(), initial_h)

        # Clicking header About button opens About dialog with creator, version, GPL-3.0 license, and GitHub link
        with mock.patch.object(QDialog, "exec", return_value=0) as mock_about_exec:
            QTest.mouseClick(self.win.about_btn, Qt.MouseButton.LeftButton)
        mock_about_exec.assert_called_once()
        about_dlg = self.win._last_about_dialog
        self.assertIsNotNone(about_dlg)
        assert about_dlg is not None
        labels = about_dlg.findChildren(QLabel)
        joined = "\n".join(lbl.text() for lbl in labels)
        self.assertIn(app_mod.APP_AUTHOR, joined)
        self.assertIn(app_mod.APP_GITHUB_URL, joined)
        self.assertIn(app_mod.APP_LICENSE, joined)
        self.assertIn(app_mod.APP_VERSION, joined)
        self.assertTrue(any(lbl.openExternalLinks() and app_mod.APP_GITHUB_URL in lbl.text() for lbl in labels))


class TestUILocalizationAndPersistence(unittest.TestCase):
    """UI tests verifying complete German/English coverage and live switching without restart."""

    def test_german_ui_full_translation_and_settings_persistence(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            orig_settings = app_mod.SETTINGS_FILE_PATH
            orig_history = app_mod.HISTORY_FILE_PATH
            orig_log = app_mod.DEFAULT_LOG_PATH
            try:
                app_mod.SETTINGS_FILE_PATH = tmp / "settings.json"
                app_mod.HISTORY_FILE_PATH = tmp / "history.json"
                app_mod.DEFAULT_LOG_PATH = str(tmp / "none.log")

                with mock.patch.object(
                    app_mod,
                    "get_clamav_metadata",
                    return_value={"version": "ClamAV 1.4.6", "freshclam_service": "active"},
                ):
                    win = app_mod.create_main_window(auto_poll=False, lang="de")
                    win.show()
                    win._qt_app.processEvents()
                    try:
                        # Top header, cards, quick buttons, controls
                        self.assertEqual(win.lang, "de")
                        self.assertIn("Sicherheitszentrum", win.windowTitle())
                        self.assertEqual(win.app_title_lbl.text(), "ClamAV Sicherheitszentrum")
                        self.assertEqual(win.hero_title_lbl.text(), "Ihr Computer ist geschützt")
                        self.assertIn("Schnellscan", win.btn_quick_scan.text())
                        self.assertIn("Vollständiger", win.btn_full_scan.text())
                        self.assertIn("scannen", win.btn_pick_scan.text())
                        self.assertTrue(win.ctrl_box.isHidden())
                        self.assertEqual(win.card_status.title_lbl.text(), "Status")
                        self.assertEqual(win.card_cpu.title_lbl.text(), "Letzter Scan")
                        self.assertEqual(win.card_io.title_lbl.text(), "Virensignaturen")
                        self.assertEqual(win.card_threats.title_lbl.text(), "Geplanter Scan")
                        self.assertEqual(win.progress_bar.text(), "Inaktiv")
                        self.assertEqual(win.tabs.count(), 4)
                        self.assertEqual(win.tabs.tabText(0), "Live-Protokoll && Verlauf")
                        self.assertEqual(win.tabs.tabText(1), "Bedrohungen (0) && Quarantäne (0)")
                        self.assertEqual(win.tabs.tabText(2), "Zeitplan && Erweiterter Scan")
                        self.assertEqual(win.tabs.tabText(3), "Virendatenbank")
                        self.assertEqual(win.threats_table.horizontalHeaderItem(0).text(), "Dateipfad")
                        self.assertEqual(win.threats_table.horizontalHeaderItem(1).text(), "Bedrohungssignatur")
                        self.assertEqual(win.quarantine_table.horizontalHeaderItem(0).text(), "Dateiname")
                        self.assertEqual(win.history_table.horizontalHeaderItem(0).text(), "Abgeschlossen am")
                        self.assertEqual(win.sched_freq_combo.itemText(0), "Täglich")
                        self.assertEqual(win.sched_freq_combo.itemText(1), "Wöchentlich")
                        self.assertEqual(win.freshclam_btn.text(), "Virensignaturen jetzt aktualisieren (freshclam)")

                    finally:
                        win._force_quit = True
                        win.close()
                        win._qt_app.processEvents()

                    # New window without explicit lang uses OS locale (ignoring stale settings.json)
                    app_mod.SETTINGS_FILE_PATH.write_text('{"language": "en"}', encoding="utf-8")
                    with mock.patch.dict(
                        os.environ, {"LANG": "de_DE.UTF-8", "LC_ALL": "", "LC_MESSAGES": "", "LANGUAGE": ""}
                    ):
                        win2 = app_mod.create_main_window(auto_poll=False, lang=None)
                        try:
                            self.assertEqual(win2.lang, "de")
                            self.assertEqual(win2.app_title_lbl.text(), "ClamAV Sicherheitszentrum")
                        finally:
                            win2._force_quit = True
                            win2.close()
            finally:
                app_mod.SETTINGS_FILE_PATH = orig_settings
                app_mod.HISTORY_FILE_PATH = orig_history
                app_mod.DEFAULT_LOG_PATH = orig_log


class TestUIAuthAndUnlockFlows(unittest.TestCase, _UIEnvMixin):
    """UI tests for sudo/pkexec unlock banners, dialogs, error handling, and disconnect reset."""

    @classmethod
    def setUpClass(cls) -> None:
        cls._setup_isolated_env(lang="en")

    @classmethod
    def tearDownClass(cls) -> None:
        cls._teardown_isolated_env()

    def setUp(self) -> None:
        self._reset_window_state()

    def test_sudo_unlock_cancel_failure_and_success_and_disconnect(self) -> None:
        self.assertFalse(self.win.auth_banner.isHidden())
        self.assertTrue(self.win.root_badge_lbl.isHidden())

        # Cancelled password dialog
        with mock.patch.object(QInputDialog, "getText", return_value=("", False)):
            QTest.mouseClick(self.win.sudo_btn, Qt.MouseButton.LeftButton)
        self.assertFalse(self.win.auth_banner.isHidden())

        # Wrong password shows warning
        with (
            mock.patch.object(QInputDialog, "getText", return_value=("badpw", True)),
            mock.patch.object(self.win.helper, "start_with_sudo", return_value=(False, "Sorry, try again.")),
            mock.patch.object(QMessageBox, "warning") as mock_warn,
        ):
            QTest.mouseClick(self.win.sudo_btn, Qt.MouseButton.LeftButton)
        mock_warn.assert_called_once()
        self.assertFalse(self.win.auth_banner.isHidden())

        # Successful password unlock connects the helper for this session.
        def fake_call(action: str, _params: dict | None = None, **_kw: object) -> dict:
            if action == "list_quarantine":
                return {"items": []}
            if action == "get_schedule":
                return {"enabled": False, "scan_type": "quick", "frequency": "weekly", "day_of_week": "Sun", "time_of_day": "03:00", "next_run": "-"}
            if action == "inspect_proc":
                return {"proc": {"alive": False}, "log": {"exists": False}}
            return {}

        with (
            mock.patch.object(QInputDialog, "getText", return_value=("goodpw", True)),
            mock.patch.object(self.win.helper, "start_with_sudo", return_value=(True, "Root helper active")),
            mock.patch.object(type(self.win.helper), "is_connected", new_callable=mock.PropertyMock, return_value=True),
            mock.patch.object(self.win.helper, "call", side_effect=fake_call) as mock_call,
            mock.patch.object(app_mod, "discover_clamscan_processes", return_value=[]),
        ):
            QTest.mouseClick(self.win.sudo_btn, Qt.MouseButton.LeftButton)
            self.win._qt_app.processEvents()
            self.assertTrue(self.win.auth_banner.isHidden())
            self.assertFalse(self.win.root_badge_lbl.isHidden())

        called_actions = [c[0][0] for c in mock_call.call_args_list]
        self.assertNotIn("install_polkit_rule", called_actions)
        self.assertIn("list_quarantine", called_actions)
        self.assertIn("get_schedule", called_actions)

        # Helper disconnect brings back auth banner and clears proc telemetry
        self.win.telemetry.last_proc_data = {"alive": True}
        self.win._on_helper_disconnected()
        self.assertFalse(self.win.auth_banner.isHidden())
        self.assertTrue(self.win.root_badge_lbl.isHidden())
        self.assertEqual(self.win.telemetry.last_proc_data, {})

    def test_linux_startup_does_not_request_elevation(self) -> None:
        app_mod.save_json_file(app_mod.SETTINGS_FILE_PATH, {"polkit_rule_installed": True})
        try:
            with (
                mock.patch.object(app_mod, "IS_WINDOWS", False),
                mock.patch.object(app_mod, "IS_MACOS", False),
                mock.patch.object(app_mod, "_euid", return_value=1000),
                mock.patch("threading.Thread") as launch,
            ):
                self.win._try_auto_connect()
            launch.assert_not_called()
        finally:
            app_mod.SETTINGS_FILE_PATH.unlink(missing_ok=True)

    @unittest.skipIf(sys.platform != "linux", "POSIX polkit/sudo unlock prompt test")
    def test_pkexec_unlock_and_require_root_helper_prompt(self) -> None:
        # Clicking pkexec button enters waiting state, failure warns & restores button
        with mock.patch("threading.Thread") as mock_thread:
            QTest.mouseClick(self.win.pkexec_btn, Qt.MouseButton.LeftButton)
            mock_thread.assert_called_once()
        self.assertFalse(self.win.pkexec_btn.isEnabled())
        self.assertEqual(self.win.pkexec_btn.text(), "Waiting for Polkit...")

        with mock.patch.object(QMessageBox, "warning") as mock_warn:
            self.win._on_pkexec_done(False, "Cancelled", False)
        mock_warn.assert_called_once()
        self.assertTrue(self.win.pkexec_btn.isEnabled())
        self.assertEqual(self.win.pkexec_btn.text(), "Unlock via Polkit")

        # _require_root_helper Cancel -> returns False
        with mock.patch.object(QMessageBox, "exec", return_value=0), mock.patch.object(
            QMessageBox, "clickedButton", return_value=None
        ):
            self.assertFalse(self.win._require_root_helper())

    @unittest.skipIf(sys.platform != "linux", "Linux User Mode fallback flow test")
    def test_user_mode_activation_scans_quarantine_and_user_schedule(self) -> None:
        with tempfile.TemporaryDirectory() as um_tmp:
            root = Path(um_tmp)
            orig_app_dir = app_mod.APP_DATA_DIR
            orig_log = app_mod.DEFAULT_LOG_PATH
            orig_quar = app_mod.DEFAULT_QUARANTINE_DIR
            orig_usvc = app_mod.USER_SYSTEMD_SERVICE_PATH
            orig_utmr = app_mod.USER_SYSTEMD_TIMER_PATH
            orig_log_edit = self.win.log_path_edit.text()
            orig_new_log_edit = self.win.new_log_edit.text()
            orig_tel_log = self.win.telemetry.log_path

            try:
                app_mod.APP_DATA_DIR = root / "appdata"
                app_mod.DEFAULT_LOG_PATH = "/var/log/clamav-scan.log"
                app_mod.DEFAULT_QUARANTINE_DIR = "/root/quarantine"
                app_mod.USER_SYSTEMD_SERVICE_PATH = str(root / "systemd-user" / "clamav-gui-scan.service")
                app_mod.USER_SYSTEMD_TIMER_PATH = str(root / "systemd-user" / "clamav-gui-scan.timer")
                self.win.log_path_edit.setText("/var/log/clamav-scan.log")
                self.win.new_log_edit.setText("/var/log/clamav-scan.log")
                self.win.telemetry.log_path = "/var/log/clamav-scan.log"

                user_db = app_mod.APP_DATA_DIR / "database"
                user_db.mkdir(parents=True)
                (user_db / "main.cvd").write_bytes(b"CVD")

                fake_proc = mock.Mock()
                fake_proc.poll.return_value = None
                fake_proc.stdin = mock.Mock()

                def fake_start_local() -> tuple[bool, str]:
                    self.win.helper._proc = fake_proc
                    self.win.helper.uid = 1000
                    return True, "Local helper active."

                calls: list[tuple[str, dict]] = []

                def fake_call(action: str, params: dict | None = None, **_kw: object) -> dict:
                    calls.append((action, dict(params or {})))
                    if action == "start_scan":
                        return {"pid": 7171, "log_path": (params or {}).get("log_path", "")}
                    if action == "list_quarantine":
                        return {"items": []}
                    if action == "get_schedule":
                        return {"enabled": False, "scan_type": "quick", "frequency": "weekly", "day_of_week": "Sun", "time_of_day": "03:00", "next_run": "-"}
                    if action == "set_schedule":
                        return {"enabled": True, "next_run": "tomorrow"}
                    if action == "quarantine_file":
                        return {"dest": str(app_mod.APP_DATA_DIR / "quarantine" / "bad.bin")}
                    if action == "run_freshclam":
                        return {"success": True, "returncode": 0, "output": "ok"}
                    return {"proc": {"alive": False}, "log": {"exists": False}}

                self.win._update_auth_banner()
                self.assertFalse(self.win.auth_banner.isHidden())
                self.assertFalse(self.win.user_mode_btn.isHidden())

                with (
                    mock.patch.object(app_mod, "IS_WINDOWS", False),
                    mock.patch.object(self.win.helper, "start_local", side_effect=fake_start_local),
                    mock.patch.object(self.win.helper, "call", side_effect=fake_call),
                    mock.patch.object(app_mod, "discover_clamscan_processes", return_value=[]),
                    mock.patch.object(app_mod, "_default_db_dir", return_value=str(user_db)),
                    mock.patch.object(QMessageBox, "question", return_value=QMessageBox.StandardButton.Yes),
                    mock.patch.object(QMessageBox, "information"),
                ):
                    QTest.mouseClick(self.win.user_mode_btn, Qt.MouseButton.LeftButton)
                    self.win._qt_app.processEvents()

                    self.assertTrue(self.win.helper.is_connected)
                    self.assertTrue(self.win.helper.is_user_mode)
                    self.assertFalse(self.win.helper.is_root)
                    self.assertTrue(self.win.auth_banner.isHidden())
                    self.assertFalse(self.win.root_badge_lbl.isHidden())
                    self.assertIn("User Mode", self.win.root_badge_lbl.text())

                    expected_log = str(app_mod.APP_DATA_DIR / "clamav-scan.log")
                    expected_qdir = str(app_mod.APP_DATA_DIR / "quarantine")
                    self.assertEqual(self.win.log_path_edit.text(), expected_log)
                    self.assertEqual(self.win.new_log_edit.text(), expected_log)

                    # Quick scan uses user log & --database=user_db
                    QTest.mouseClick(self.win.btn_quick_scan, Qt.MouseButton.LeftButton)
                    start_call = next(c for c in calls if c[0] == "start_scan")
                    self.assertEqual(start_call[1]["log_path"], expected_log)
                    self.assertIn(f"--database={user_db}", start_call[1]["cmd_args"])

                    # Quarantine uses APP_DATA_DIR/quarantine
                    with mock.patch.object(self.win, "_notify"):
                        self.win._apply_log_result(
                            {"exists": True, "reset": False, "new_offset": 40, "new_text": "/tmp/user_bad.bin: Test.Trojan FOUND\n"}
                        )
                    self.win.threats_table.selectRow(0)
                    self.win._quarantine_selected_threat()
                    q_call = next(c for c in calls if c[0] == "quarantine_file")
                    self.assertEqual(q_call[1]["quarantine_dir"], expected_qdir)

                    # Save schedule & run freshclam pass user_mode=True
                    self.win._open_tab(2)
                    QTest.mouseClick(self.win.sched_save_btn, Qt.MouseButton.LeftButton)
                    s_call = next(c for c in calls if c[0] == "set_schedule")
                    self.assertTrue(s_call[1].get("user_mode"))

                    self.win._run_freshclam()
                    deadline = time.monotonic() + 2.0
                    while not any(c[0] == "run_freshclam" for c in calls) and time.monotonic() < deadline:
                        time.sleep(0.02)
                        self.win._qt_app.processEvents()
                    f_call = next(c for c in calls if c[0] == "run_freshclam")
                    self.assertEqual(f_call[1], {"user_mode": True})

                # Also verify _require_root_helper dialog's "Continue in User Mode" button path
                self.win.helper._proc = None
                self.win.helper.uid = None
                with (
                    mock.patch.object(app_mod, "IS_WINDOWS", False),
                    mock.patch.object(self.win, "_activate_user_mode", return_value=True) as mock_act,
                    mock.patch.object(QMessageBox, "exec", return_value=0),
                    mock.patch.object(
                        QMessageBox,
                        "addButton",
                        side_effect=["btn_sudo", "btn_polkit", "btn_user", "btn_cancel"],
                    ),
                    mock.patch.object(QMessageBox, "clickedButton", return_value="btn_user"),
                ):
                    self.assertTrue(self.win._require_root_helper())
                    mock_act.assert_called_once()
            finally:
                self.win.helper._proc = None
                self.win.helper.uid = None
                app_mod.APP_DATA_DIR = orig_app_dir
                app_mod.DEFAULT_LOG_PATH = orig_log
                app_mod.DEFAULT_QUARANTINE_DIR = orig_quar
                app_mod.USER_SYSTEMD_SERVICE_PATH = orig_usvc
                app_mod.USER_SYSTEMD_TIMER_PATH = orig_utmr
                self.win.log_path_edit.setText(orig_log_edit)
                self.win.new_log_edit.setText(orig_new_log_edit)
                self.win.telemetry.log_path = orig_tel_log
                self.win._update_auth_banner()


class TestUITelemetryProgressAndLiveLog(unittest.TestCase, _UIEnvMixin):
    """UI tests for telemetry rendering, hybrid progress/ETA, partial log streaming, and threat banner."""

    @classmethod
    def setUpClass(cls) -> None:
        cls._setup_isolated_env(lang="en")

    @classmethod
    def tearDownClass(cls) -> None:
        cls._teardown_isolated_env()

    def setUp(self) -> None:
        self._reset_window_state()

    def test_unprivileged_running_and_paused_states(self) -> None:
        fake_running = {
            "pid": 4444,
            "cmdline": ["clamscan", "-r", "-i", "/"],
            "state": "R",
            "elapsed_sec": 30.0,
            "quiet_infected_only": True,
            "nice": 19,
            "rss_kb": 16384,
            "cpu_ticks": 500,
            "user": "root",
            "uid": 0,
        }
        with mock.patch.object(app_mod, "start_background_precount", return_value={"done": False, "running": True, "all_files": 1200}):
            self.win._current_proc = fake_running
            self.win._render_unprivileged_telemetry(fake_running)
            self.win._update_controls_enabled()
            self.win._update_hero_banner(fake_running)

        self.assertEqual(self.win.card_status.value_lbl.text(), "RUNNING")
        self.assertTrue(self.win.bg_mode_chk.isChecked())
        self.assertEqual(self.win.progress_bar.maximum(), 0)  # indeterminate until unlocked
        self.assertIn("counting files", self.win.progress_sub_lbl.text().lower())
        self.assertFalse(self.win.restart_verbose_btn.isHidden())
        self.assertIn("running in background", self.win.hero_title_lbl.text().lower())

        # Paused unprivileged scan
        fake_paused = {**fake_running, "state": "T"}
        self.win._current_proc = fake_paused
        self.win._render_unprivileged_telemetry(fake_paused)
        self.win._update_controls_enabled()
        self.win._update_hero_banner(fake_paused)
        self.assertEqual(self.win.card_status.value_lbl.text(), "PAUSED")
        self.assertEqual(self.win.pause_btn.text(), "Resume Scan")
        self.assertIn("Paused", self.win.progress_bar.format())
        self.assertIn("paused", self.win.hero_title_lbl.text().lower())

    def test_privileged_inspect_done_live_fd_streaming_and_progress(self) -> None:
        mb = 1024 * 1024
        fake_proc = {
            "pid": 8888,
            "cmdline": ["clamscan", "-r", "-i", "/"],
            "state": "R",
            "elapsed_sec": 50.0,
            "quiet_infected_only": True,
            "nice": 0,
            "rss_kb": 8192,
            "cpu_ticks": 100,
            "user": "root",
            "uid": 0,
        }
        self.win._current_proc = fake_proc
        self.win.telemetry.last_io_bytes = 490 * mb
        self.win.telemetry.last_io_time = app_mod.time.monotonic() - 1.0

        inspect_payload = {
            "precount": {
                "done": True,
                "running": False,
                "eligible_bytes": 1000 * mb,
                "eligible_files": 500,
                "all_files": 510,
                "all_bytes": 2000 * mb,
            },
            "proc": {
                "alive": True,
                "current_file": "/home/user/large-archive.tar.gz",
                "tmp_count": 2,
                "io": {"rchar": 810 * mb, "read_bytes": 800 * mb},
            },
            "log": {"exists": True, "reset": False, "new_offset": 20, "new_text": "/tmp/a.txt: OK\n"},
        }

        with mock.patch.object(type(self.win.helper), "is_connected", new_callable=mock.PropertyMock, return_value=True):
            self.win._on_inspect_done(inspect_payload, "")

        self.assertIn("/home/user/large-archive.tar.gz", self.win.current_file_edit.text())
        self.assertIn("+2 archive temp file", self.win.current_file_edit.text())
        self.assertEqual(self.win.progress_bar.value(), 500)
        self.assertIn("50.0%", self.win.progress_bar.text())
        self.assertTrue(self.win.eta_lbl.text().startswith("ETA: 00:"))
        self.assertIn("Accurate pre-count", self.win.progress_sub_lbl.text())
        self.assertIn("[LIVE] /home/user/large-archive.tar.gz", self.win.log_view.toPlainText())
        self.assertIn("/tmp/a.txt: OK", self.win.log_view.toPlainText())

    def test_log_chunk_truncation_key_filter_and_threat_review_navigation(self) -> None:
        with mock.patch.object(self.win, "_notify") as mock_notify:
            self.win._apply_log_result(
                {"exists": True, "reset": False, "new_offset": 19, "new_text": "/tmp/clean.txt: OK\n/tmp/bad"}
            )
            self.assertEqual(self.win.telemetry.partial_line, "/tmp/bad")
            self.win._apply_log_result(
                {"exists": True, "reset": False, "new_offset": 49, "new_text": ".exe: Win.Test.EICAR-1 FOUND\n"}
            )
            mock_notify.assert_called_once()

        self.assertEqual(self.win.threats_table.rowCount(), 1)
        self.assertFalse(self.win.hero_review_btn.isHidden())
        self.assertIn("Action Required", self.win.hero_title_lbl.text())

        # Type into filter box with QTest.keyClicks
        self.win._open_tab(0)
        QTest.keyClicks(self.win.log_filter_edit, "FOUND")
        self.win._qt_app.processEvents()
        self.assertNotIn("clean.txt", self.win.log_view.toPlainText())
        self.assertIn("Win.Test.EICAR-1 FOUND", self.win.log_view.toPlainText())

        # Log reset/truncation clears log and starts fresh
        self.win.log_filter_edit.clear()
        self.win._apply_log_result(
            {"exists": True, "reset": True, "new_offset": 12, "new_text": "/tmp/fresh\n"}
        )
        self.assertEqual(self.win.threats_table.rowCount(), 0)
        self.assertEqual(self.win.log_view.toPlainText().strip(), "/tmp/fresh")

        # Re-add a threat and click hero_review_btn while tabs are collapsed -> opens Threats tab (1)
        with mock.patch.object(self.win, "_notify"):
            self.win._apply_log_result(
                {"exists": True, "reset": False, "new_offset": 45, "new_text": "/tmp/v.exe: Trojan.X FOUND\n"}
            )
        if self.win.toggle_tabs_btn.isChecked():
            QTest.mouseClick(self.win.toggle_tabs_btn, Qt.MouseButton.LeftButton)
        QTest.mouseClick(self.win.hero_review_btn, Qt.MouseButton.LeftButton)
        self.win._qt_app.processEvents()
        self.assertFalse(self.win.tabs.isHidden())
        self.assertEqual(self.win.tabs.currentIndex(), 1)


class TestUIScanActionsAndProcessControl(unittest.TestCase, _UIEnvMixin):
    """UI tests for launching scans, pause/resume, stop, priority, restart-without-i, and completion."""

    @classmethod
    def setUpClass(cls) -> None:
        cls._setup_isolated_env(lang="en")

    @classmethod
    def tearDownClass(cls) -> None:
        cls._teardown_isolated_env()

    def setUp(self) -> None:
        self._reset_window_state()

    def test_quick_full_and_picker_scan_buttons(self) -> None:
        calls: list[tuple[str, dict]] = []

        def fake_call(action: str, params: dict | None = None, **_kw: object) -> dict:
            calls.append((action, dict(params or {})))
            if action == "start_scan":
                return {"pid": 7777}
            return {}

        with (
            mock.patch.object(type(self.win.helper), "is_connected", new_callable=mock.PropertyMock, return_value=True),
            mock.patch.object(self.win.helper, "call", side_effect=fake_call),
            mock.patch.object(app_mod, "discover_clamscan_processes", return_value=[]),
        ):
            # Quick Scan with background priority checked
            self.win.bg_mode_chk.setChecked(True)
            QTest.mouseClick(self.win.btn_quick_scan, Qt.MouseButton.LeftButton)
            self.assertEqual(calls[0][0], "start_scan")
            self.assertNotIn("--exclude-dir=^/proc", calls[0][1]["cmd_args"])
            self.assertEqual(calls[1], ("set_priority", {"pid": 7777, "mode": "idle"}))

            # Full Scan adds virtual exclusions on Linux and targets system root
            calls.clear()
            QTest.mouseClick(self.win.btn_full_scan, Qt.MouseButton.LeftButton)
            full_args = calls[0][1]["cmd_args"]
            if app_mod.IS_WINDOWS:
                self.assertNotIn("--exclude-dir=^/proc", full_args)
            else:
                self.assertIn("--exclude-dir=^/proc", full_args)
            self.assertEqual(full_args[-1], app_mod._system_root_target())

            # Direct file/folder browser picker (no intermediate QMessageBox menu)
            with tempfile.TemporaryDirectory() as pick_tmp:
                tmp_root = Path(pick_tmp)
                sub_dir = tmp_root / "pick_folder"
                sub_dir.mkdir()
                sample_file = tmp_root / "pick_file.txt"
                sample_file.write_text("clean", encoding="utf-8")

                def _wait_and_select(dlg: object, entry_name: str) -> None:
                    dlg.setDirectory(str(tmp_root))  # type: ignore[attr-defined]
                    dlg.show()  # type: ignore[attr-defined]
                    lv = dlg._lv  # type: ignore[attr-defined]
                    model = lv.model()
                    target_idx = None
                    for _ in range(50):
                        self.win._qt_app.processEvents()
                        root_idx = lv.rootIndex()
                        for row in range(model.rowCount(root_idx)):
                            idx = model.index(row, 0, root_idx)
                            if model.data(idx) == entry_name:
                                target_idx = idx
                                break
                        if target_idx is not None:
                            break
                        time.sleep(0.02)
                    self.assertIsNotNone(target_idx, f"Entry {entry_name!r} did not load in picker")
                    lv.selectionModel().select(
                        target_idx,
                        QItemSelectionModel.SelectionFlag.ClearAndSelect | QItemSelectionModel.SelectionFlag.Rows,
                    )
                    self.win._qt_app.processEvents()

                # 1. Highlight a folder and click Open -> scans that folder immediately; QMessageBox not shown
                calls.clear()

                def pick_folder_exec(dlg: object) -> int:
                    _wait_and_select(dlg, "pick_folder")
                    self.assertTrue(dlg._open_btn.isEnabled())  # type: ignore[attr-defined]
                    dlg._open_btn.click()  # type: ignore[attr-defined]
                    return int(dlg.result())  # type: ignore[attr-defined]

                with (
                    mock.patch.object(QMessageBox, "exec") as mock_msg_exec,
                    mock.patch.object(QFileDialog, "exec", pick_folder_exec),
                ):
                    QTest.mouseClick(self.win.btn_pick_scan, Qt.MouseButton.LeftButton)
                mock_msg_exec.assert_not_called()
                self.assertEqual(Path(calls[0][1]["cmd_args"][-1]), sub_dir)

                # 2. Highlight a file and click Open -> scans that file immediately; accept() on folder navigates into it
                calls.clear()

                def pick_file_and_nav_exec(dlg: object) -> int:
                    _wait_and_select(dlg, "pick_folder")
                    dlg.accept()  # type: ignore[attr-defined]
                    self.win._qt_app.processEvents()
                    self.assertEqual(Path(dlg.directory().absolutePath()), sub_dir)  # type: ignore[attr-defined]

                    _wait_and_select(dlg, "pick_file.txt")
                    dlg._open_btn.click()  # type: ignore[attr-defined]
                    return int(dlg.result())  # type: ignore[attr-defined]

                with (
                    mock.patch.object(QMessageBox, "exec") as mock_msg_exec,
                    mock.patch.object(QFileDialog, "exec", pick_file_and_nav_exec),
                ):
                    QTest.mouseClick(self.win.btn_pick_scan, Qt.MouseButton.LeftButton)
                mock_msg_exec.assert_not_called()
                self.assertEqual(Path(calls[0][1]["cmd_args"][-1]), sample_file)

    @unittest.skipIf(sys.platform != "linux", "POSIX signal test")
    @mock.patch.object(app_mod, "start_background_precount", return_value={})
    def test_pause_stop_priority_and_restart_without_i(self, _precount: mock.Mock) -> None:
        own_proc = {
            "pid": 6161,
            "cmdline": ["clamscan", "-ri", "--log=/tmp/custom.log", "/home"],
            "state": "R",
            "elapsed_sec": 12.0,
            "quiet_infected_only": True,
            "nice": 0,
            "rss_kb": 1024,
            "cpu_ticks": 20,
            "user": "user",
            "uid": app_mod._uid(),
            "log_path": "/tmp/custom.log",
        }
        self.win._current_proc = own_proc
        self.win._update_controls_enabled()

        # Pause unprivileged own-UID process via os.kill(SIGSTOP)
        with (
            mock.patch("os.kill") as mock_kill,
            mock.patch.object(app_mod, "discover_clamscan_processes", return_value=[{**own_proc, "state": "T"}]),
        ):
            QTest.mouseClick(self.win.pause_btn, Qt.MouseButton.LeftButton)
            mock_kill.assert_called_once_with(6161, signal.SIGSTOP)
        self.assertEqual(self.win.pause_btn.text(), "Resume Scan")

        # Stop paused scan confirmation Yes -> SIGTERM + SIGCONT
        with (
            mock.patch.object(QMessageBox, "question", return_value=QMessageBox.StandardButton.Yes),
            mock.patch("os.kill") as mock_kill_paused,
            mock.patch.object(app_mod, "discover_clamscan_processes", return_value=[]),
            mock.patch.object(self.win, "_notify"),
        ):
            QTest.mouseClick(self.win.stop_btn, Qt.MouseButton.LeftButton)
            self.assertEqual(
                [c[0] for c in mock_kill_paused.call_args_list],
                [(6161, signal.SIGTERM), (6161, signal.SIGCONT)],
            )

        # Stop running (unpaused) scan confirmation Yes -> SIGTERM only
        self.win._current_proc = dict(own_proc)
        self.win._update_controls_enabled()
        with (
            mock.patch.object(QMessageBox, "question", return_value=QMessageBox.StandardButton.Yes),
            mock.patch("os.kill") as mock_kill,
            mock.patch.object(app_mod, "discover_clamscan_processes", return_value=[]),
            mock.patch.object(self.win, "_notify"),
        ):
            QTest.mouseClick(self.win.stop_btn, Qt.MouseButton.LeftButton)
            mock_kill.assert_called_once_with(6161, signal.SIGTERM)

        # Priority toggle via bg_mode_chk + _restart_scan_without_i
        self.win._current_proc = own_proc
        self.win._update_controls_enabled()
        with (
            mock.patch.object(type(self.win.helper), "is_connected", new_callable=mock.PropertyMock, return_value=True),
            mock.patch.object(self.win.helper, "call", return_value={"pid": 6262}) as mock_call,
            mock.patch.object(QMessageBox, "question", return_value=QMessageBox.StandardButton.Yes),
            mock.patch("os.path.exists", return_value=False),
            mock.patch.object(app_mod, "discover_clamscan_processes", return_value=[]),
            mock.patch("threading.Thread"),
        ):
            QTest.mouseClick(self.win.bg_mode_chk, Qt.MouseButton.LeftButton)
            prio_calls = [c for c in mock_call.call_args_list if c[0][0] == "set_priority"]
            self.assertEqual(len(prio_calls), 1)
            self.assertEqual(prio_calls[0][0][1], {"pid": 6161, "mode": "idle"})

            mock_call.reset_mock()
            self.win._current_proc = own_proc
            self.win._restart_scan_without_i()
            actions = [c[0][0] for c in mock_call.call_args_list]
            self.assertEqual(actions[0], "signal_proc")
            self.assertEqual(actions[1], "start_scan")
            restarted_args = mock_call.call_args_list[1][0][1]["cmd_args"]
            self.assertIn("-r", restarted_args)
            self.assertNotIn("-i", restarted_args)
            self.assertNotIn("-ri", restarted_args)

    def test_windows_pause_confirmation_survives_process_polling(self) -> None:
        process = {
            "pid": 6789,
            "cmdline": ["clamscan.exe"],
            "state": "R",
            "elapsed_sec": 2.0,
            "nice": 0,
            "rss_kb": 1024,
            "cpu_ticks": 20,
            "user": "user",
            "uid": app_mod._uid(),
            "log_path": "",
            "quiet_infected_only": False,
        }
        with (
            mock.patch.object(app_mod, "IS_WINDOWS", True),
            mock.patch.object(app_mod, "discover_clamscan_processes", side_effect=lambda: [dict(process)]),
            mock.patch.object(type(self.win.helper), "is_connected", new_callable=mock.PropertyMock, return_value=True),
            mock.patch.object(self.win.helper, "call", side_effect=[{"paused": True}, {"paused": False}]) as call,
            mock.patch("threading.Thread"),
        ):
            self.win._poll_tick()
            self.win._toggle_pause_scan()
            self.win._poll_tick()
            self.assertEqual(self.win.pause_btn.text(), "Resume Scan")
            self.win._toggle_pause_scan()
            self.win._poll_tick()
            self.assertEqual(self.win._current_proc["state"], "R")
            self.assertEqual(call.call_args_list, [
                mock.call("signal_proc", {"pid": 6789, "sig": "SIGSTOP"}),
                mock.call("signal_proc", {"pid": 6789, "sig": "SIGCONT"}),
            ])

    def test_handle_scan_finished_records_history_and_notifies(self) -> None:
        self.win.telemetry.total_lines_logged = 123
        with mock.patch.object(self.win, "_notify") as mock_notify:
            self.win._handle_scan_finished({"label": "Quick Scan", "elapsed_sec": 15.0, "log_path": app_mod.DEFAULT_LOG_PATH})
        mock_notify.assert_called_once()
        self.assertGreaterEqual(self.win.history_table.rowCount(), 1)
        self.assertEqual(self.win.history_table.item(0, 1).text(), "Quick Scan")
        self.assertEqual(self.win.history_table.item(0, 5).text(), "Clean")

    def test_start_and_cancel_running_and_paused_job_returns_to_start(self) -> None:
        self.win._qt_app.processEvents()
        idle_h = self.win.height()
        # 1. Start a job -> active scanning state with elapsed time advancing
        active_proc = {
            "pid": 8282,
            "cmdline": ["clamscan", "-r", "/home/user/Downloads"],
            "cmdline_str": "clamscan -r /home/user/Downloads",
            "state": "R",
            "nice": 0,
            "rss_kb": 4096,
            "cpu_ticks": 100,
            "elapsed_sec": 3.0,
            "user": "root",
            "uid": 0,
            "log_path": app_mod.DEFAULT_LOG_PATH,
            "quiet_infected_only": False,
        }
        with (
            mock.patch.object(type(self.win.helper), "is_connected", new_callable=mock.PropertyMock, return_value=True),
            mock.patch.object(self.win.helper, "call", return_value={"pid": 8282}) as mock_call,
            mock.patch.object(app_mod, "discover_clamscan_processes", return_value=[dict(active_proc)]),
            mock.patch.object(self.win, "_poll_tick", wraps=self.win._poll_tick),
            mock.patch("threading.Thread"),
        ):
            self.win._known_procs = []
            QTest.mouseClick(self.win.btn_quick_scan, Qt.MouseButton.LeftButton)

        self.assertTrue(any(c[0][0] == "start_scan" for c in mock_call.call_args_list))
        self.assertIsNotNone(self.win._current_proc)
        self.win._qt_app.processEvents()
        self.assertFalse(self.win.ctrl_box.isHidden())
        self.assertGreater(self.win.height(), idle_h + 100)
        self.assertEqual(self.win.card_status.value_lbl.text(), "RUNNING")
        self.assertEqual(self.win.card_cpu.value_lbl.text(), "00:00:03")

        # Tick while running: elapsed clock advances to 00:00:08
        tick2_proc = {**active_proc, "elapsed_sec": 8.0, "cpu_ticks": 180}
        with (
            mock.patch.object(type(self.win.helper), "is_connected", new_callable=mock.PropertyMock, return_value=True),
            mock.patch.object(app_mod, "discover_clamscan_processes", return_value=[tick2_proc]),
            mock.patch("threading.Thread"),
        ):
            self.win._poll_tick()
        self.assertEqual(self.win.card_cpu.value_lbl.text(), "00:00:08")

        # 2. Cancel running job via Stop button -> sends SIGTERM, stops precount, resets UI to idle start
        hist_before = self.win.history_table.rowCount()
        with (
            mock.patch.object(type(self.win.helper), "is_connected", new_callable=mock.PropertyMock, return_value=True),
            mock.patch.object(QMessageBox, "question", return_value=QMessageBox.StandardButton.Yes),
            mock.patch.object(self.win.helper, "call", return_value={"pid": 8282, "sig": "SIGTERM"}) as mock_stop_call,
            mock.patch.object(app_mod, "cancel_background_precount") as mock_cancel_pre,
            mock.patch.object(app_mod, "discover_clamscan_processes", return_value=[]),
            mock.patch("threading.Thread"),
        ):
            QTest.mouseClick(self.win.stop_btn, Qt.MouseButton.LeftButton)
            mock_stop_call.assert_called_with("signal_proc", {"pid": 8282, "sig": "SIGTERM"})
            mock_cancel_pre.assert_called()

        self.win._qt_app.processEvents()
        self.assertIsNone(self.win._current_proc)
        self.assertIsNone(self.win._last_active_scan)
        self.assertIsNone(self.win.telemetry.selected_pid)
        self.assertTrue(self.win.ctrl_box.isHidden())
        self.assertEqual(self.win.height(), idle_h)
        self.assertEqual(self.win.hero_title_lbl.text(), "Your computer is protected")
        self.assertEqual(self.win.card_status.value_lbl.text(), "Protected")
        self.assertEqual(self.win.card_cpu.title_lbl.text(), self.win._tr("idle_col_last_scan"))
        self.assertNotIn("00:00:", self.win.card_cpu.value_lbl.text())
        self.assertEqual(self.win.progress_bar.value(), 0)
        self.assertEqual(self.win.progress_bar.format(), "Idle")
        self.assertFalse(self.win.pause_btn.isEnabled())
        self.assertFalse(self.win.stop_btn.isEnabled())
        # Canceled job must not log a false Clean history entry
        self.assertEqual(self.win.history_table.rowCount(), hist_before)

        # Subsequent idle poll ticks must keep elapsed clock stopped / stay on Start UI
        with (
            mock.patch.object(type(self.win.helper), "is_connected", new_callable=mock.PropertyMock, return_value=True),
            mock.patch.object(app_mod, "discover_clamscan_processes", return_value=[]),
            mock.patch("threading.Thread"),
        ):
            self.win._poll_tick()
        self.assertTrue(self.win.ctrl_box.isHidden())
        self.assertEqual(self.win.card_cpu.title_lbl.text(), self.win._tr("idle_col_last_scan"))
        self.assertNotIn("00:00:", self.win.card_cpu.value_lbl.text())

        # 3. Stale in-flight inspect_proc callback arriving after cancel must not revive scan UI
        self.win._inspect_inflight = True
        self.win._on_inspect_done(
            {"proc": {"alive": True, "current_file": "/stale", "io": {"rchar": 999}}, "log": {}, "precount": {"done": True}},
            "",
        )
        self.assertEqual(self.win.telemetry.last_proc_data, {})
        self.assertEqual(self.win.telemetry.last_precount, {})
        self.assertEqual(self.win.hero_title_lbl.text(), "Your computer is protected")

        # 4. Natural scan completion via _poll_tick also shrinks the expanded window back down
        with (
            mock.patch.object(app_mod, "discover_clamscan_processes", return_value=[dict(active_proc)]),
            mock.patch("threading.Thread"),
        ):
            self.win._poll_tick()
            self.win._qt_app.processEvents()
        running_h = self.win.height()
        self.assertGreater(running_h, idle_h + 100)

        with (
            mock.patch.object(app_mod, "discover_clamscan_processes", return_value=[]),
            mock.patch.object(self.win, "_notify"),
            mock.patch("threading.Thread"),
        ):
            self.win._poll_tick()
            self.win._qt_app.processEvents()
        self.assertTrue(self.win.ctrl_box.isHidden())
        self.assertLess(self.win.height(), running_h - 100)

    @unittest.skipIf(sys.platform != "linux", "POSIX signal test")
    def test_start_pause_then_cancel_real_helper_subprocess(self) -> None:
        # Real end-to-end HelperClient + `--helper` subprocess spawning and canceling a live process
        import shutil

        has_clamscan = bool(shutil.which("clamscan"))
        has_db = bool(app_mod.check_system_dependencies().get("has_virus_db"))

        client = app_mod.HelperClient()
        proc = subprocess.Popen(
            [sys.executable, app_mod.SCRIPT_PATH, "--helper"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
        )
        try:
            ready = json.loads(proc.stdout.readline())
            self.assertEqual(ready.get("type"), "ready")
            client._attach(proc, ready["uid"])

            with (
                mock.patch.object(self.win, "helper", client),
                mock.patch.object(self.win, "_notify"),
                mock.patch.object(QMessageBox, "warning"),
            ):
                if not has_clamscan or not has_db:
                    ping_res = client.call("ping", {}, timeout=5.0)
                    self.assertEqual(ping_res["pid"], proc.pid)
                    insp_res = client.call("inspect_proc", {"pid": None, "log_path": "", "log_offset": 0}, timeout=5.0)
                    self.assertFalse(insp_res["proc"]["alive"])

                    paused = subprocess.Popen(
                        [sys.executable, "-c", "import time; time.sleep(30)"],
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                    )
                    try:
                        time.sleep(0.1)
                        os.kill(paused.pid, signal.SIGSTOP)
                        deadline = time.monotonic() + 1.0
                        while time.monotonic() < deadline:
                            st = app_mod.parse_proc_stat(paused.pid)
                            if st and st["state"] == "T":
                                break
                            time.sleep(0.02)
                        app_mod._terminate_pid_gracefully(paused.pid, force_cont=True)
                        self.assertIsNotNone(paused.wait(timeout=1.0))
                    finally:
                        if paused.poll() is None:
                            paused.kill()
                            paused.wait(timeout=1.0)
                    return

                # Launch real clamscan against /usr/share via Quick/Custom helper flow
                res = client.call("start_scan", {"cmd_args": ["clamscan", "-r", "/usr/share"], "log_path": ""}, timeout=5.0)
                real_pid = int(res["pid"])
                self.win.telemetry.selected_pid = real_pid
                found = False
                for _ in range(20):
                    self.win._poll_tick()
                    if self.win._current_proc and self.win._current_proc["pid"] == real_pid:
                        found = True
                        break
                    time.sleep(0.05)
                self.assertTrue(found, "Helper-started clamscan process was not discovered")
                self.assertFalse(self.win.ctrl_box.isHidden())

                # Pause via Pause button -> enters 'T' state
                QTest.mouseClick(self.win.pause_btn, Qt.MouseButton.LeftButton)
                self.assertEqual(self.win._current_proc["state"], "T")
                self.assertEqual(self.win.pause_btn.text(), "Resume Scan")

                # Cancel paused scan via Stop button -> kills & reaps cleanly, returns UI to Start
                with mock.patch.object(QMessageBox, "question", return_value=QMessageBox.StandardButton.Yes):
                    QTest.mouseClick(self.win.stop_btn, Qt.MouseButton.LeftButton)

                self.assertIsNone(self.win._current_proc)
                self.assertTrue(self.win.ctrl_box.isHidden())
                self.assertEqual(self.win.hero_title_lbl.text(), "Your computer is protected")
                self.assertFalse(any(p["pid"] == real_pid for p in app_mod.discover_clamscan_processes()))
        finally:
            client.close()
            if proc.poll() is None:
                proc.terminate()
                proc.wait(timeout=2.0)

    def test_restart_without_i_preserves_bg_priority_and_disconnected_reload_log_errors(self) -> None:
        proc = {
            "pid": 6161,
            "cmdline": ["clamscan", "-ri", "--log=/var/log/clamav-scan.log", "/home"],
            "state": "R",
            "elapsed_sec": 10.0,
            "quiet_infected_only": True,
            "nice": 19,
            "rss_kb": 1024,
            "cpu_ticks": 10,
            "user": "root",
            "uid": 0,
            "log_path": "/var/log/clamav-scan.log",
        }
        self.win._current_proc = dict(proc)
        self.win._pending_scan_labels[6161] = "Custom Scan (/home)"
        self.win.bg_mode_chk.setChecked(True)

        with (
            mock.patch.object(type(self.win.helper), "is_connected", new_callable=mock.PropertyMock, return_value=True),
            mock.patch.object(QMessageBox, "question", return_value=QMessageBox.StandardButton.Yes),
            mock.patch.object(self.win.helper, "call", side_effect=[{}, {"pid": 6262}, {}]) as mock_call,
            mock.patch.object(app_mod, "cancel_background_precount") as mock_cancel_pre,
            mock.patch("os.path.exists", return_value=False),
            mock.patch.object(app_mod, "discover_clamscan_processes", return_value=[]),
        ):
            self.win._restart_scan_without_i()
            mock_cancel_pre.assert_called_once()
        actions = [(c[0][0], c[0][1]) for c in mock_call.call_args_list]
        self.assertEqual(actions[0][0], "signal_proc")
        self.assertEqual(actions[1][0], "start_scan")
        self.assertEqual(actions[2], ("set_priority", {"pid": 6262, "mode": "idle"}))
        self.assertEqual(self.win._pending_scan_labels.get(6262), "Custom Scan (/home)")
        self.assertNotIn(6161, self.win._pending_scan_labels)

        # Disconnected _reload_log surfaces missing-file feedback in log_hint_lbl
        with tempfile.TemporaryDirectory() as tmpdir:
            missing_log = str(Path(tmpdir) / "does_not_exist.log")
            self.win.log_path_edit.setText(missing_log)
            with mock.patch.object(app_mod, "discover_clamscan_processes", return_value=[]):
                self.win._reload_log()
            self.assertIn("does_not_exist.log", self.win.log_hint_lbl.text())

        # Full closeEvent calls cancel_background_precount()
        self.win._force_quit = True
        with mock.patch.object(app_mod, "cancel_background_precount") as mock_close_pre:
            self.win.closeEvent(QCloseEvent())
            mock_close_pre.assert_called_once()


class TestUIThreatsQuarantineAndHistoryTabs(unittest.TestCase, _UIEnvMixin):
    """UI tests for Threats tab, Quarantine tab, and History tab actions."""

    @classmethod
    def setUpClass(cls) -> None:
        cls._setup_isolated_env(lang="en")

    @classmethod
    def tearDownClass(cls) -> None:
        cls._teardown_isolated_env()

    def setUp(self) -> None:
        self._reset_window_state()

    def test_threats_tab_actions(self) -> None:
        self.win._open_tab(1)
        # No row selected shows info prompt
        with mock.patch.object(QMessageBox, "information") as mock_info:
            self.win._copy_threat_path()
        mock_info.assert_called_once()

        with mock.patch.object(self.win, "_notify"):
            self.win._apply_log_result(
                {"exists": True, "reset": False, "new_offset": 40, "new_text": "/tmp/evil.bin: Sig.Test FOUND\n"}
            )
        self.win.threats_table.selectRow(0)

        # Copy Path
        self.win._copy_threat_path()
        self.assertEqual(QApplication.clipboard().text(), "/tmp/evil.bin")

        # Reveal in the native file manager.
        with mock.patch.dict(os.environ, {"XDG_CURRENT_DESKTOP": "KDE", "DESKTOP_SESSION": "plasma"}), mock.patch(
            "shutil.which", return_value="/usr/bin/dolphin"
        ), mock.patch("subprocess.Popen") as mock_p:
            self.win._reveal_threat_in_dolphin()
            if app_mod.IS_WINDOWS:
                mock_p.assert_called_once_with(
                    ["explorer.exe", f"/select,{os.path.normpath('/tmp/evil.bin')}"],
                    creationflags=subprocess.CREATE_NO_WINDOW,
                )
            elif app_mod.IS_MACOS:
                mock_p.assert_called_once_with(["open", "-R", "/tmp/evil.bin"], start_new_session=True)
            else:
                mock_p.assert_called_once_with(["dolphin", "--select", "/tmp/evil.bin"], start_new_session=True)

        # Quarantine Selected Threat & Delete Selected Threat
        with (
            mock.patch.object(type(self.win.helper), "is_connected", new_callable=mock.PropertyMock, return_value=True),
            mock.patch.object(QMessageBox, "question", return_value=QMessageBox.StandardButton.Yes),
            mock.patch.object(QMessageBox, "warning", return_value=QMessageBox.StandardButton.Yes),
            mock.patch.object(
                self.win.helper,
                "call",
                side_effect=lambda act, *_a, **_kw: {"dest": "/var/lib/q/evil.bin"}
                if act == "quarantine_file"
                else ({"items": []} if act == "list_quarantine" else {"deleted": "/tmp/evil.bin"}),
            ),
        ):
            self.win._quarantine_selected_threat()
            self.assertIn("Quarantined", self.win.threats_table.item(0, 2).text())

            self.win._delete_selected_threat()
            self.assertEqual(self.win.threats_table.item(0, 2).text(), "Deleted")

    def test_quarantine_tab_refresh_restore_and_delete(self) -> None:
        self.win._open_tab(1)
        items = [
            {
                "name": "bad.sh",
                "original_path": "/home/user/Downloads/bad.sh",
                "threat_name": "Unix.Trojan-1",
                "date": "2026-11-21 20:00:00",
                "size": 2048,
            }
        ]
        rpc_calls: list[tuple[str, dict]] = []

        def fake_call(action: str, params: dict | None = None, **_kw: object) -> dict:
            rpc_calls.append((action, dict(params or {})))
            if action == "list_quarantine":
                return {"items": items}
            if action == "restore_quarantine":
                items.clear()
                return {"restored_to": (params or {}).get("dest_path", "/tmp/bad.sh")}
            if action == "delete_quarantine":
                items.clear()
                return {"deleted": "bad.sh"}
            return {}

        with (
            mock.patch.object(type(self.win.helper), "is_connected", new_callable=mock.PropertyMock, return_value=True),
            mock.patch.object(self.win.helper, "call", side_effect=fake_call),
        ):
            self.win._refresh_quarantine()
            self.assertEqual(self.win.quarantine_table.rowCount(), 1)
            self.assertEqual(self.win.quarantine_group.title(), "Quarantine (1)")
            self.assertEqual(self.win.tabs.tabText(1), "Threats (0) && Quarantine (1)")
            self.win.quarantine_table.selectRow(0)

            restore_dir = Path(self._tmp_dir.name) / "restored"
            with (
                mock.patch.object(QFileDialog, "getExistingDirectory", return_value=str(restore_dir)),
                mock.patch.object(QMessageBox, "question", return_value=QMessageBox.StandardButton.Yes),
                mock.patch.object(QMessageBox, "information") as mock_info,
            ):
                self.win._restore_quarantine(pick_dir=True)
            mock_info.assert_called_once()
            self.assertEqual(self.win.quarantine_table.rowCount(), 0)
            self.assertEqual(self.win.quarantine_group.title(), "Quarantine (0)")
            self.assertEqual(self.win.tabs.tabText(1), "Threats (0) && Quarantine (0)")
            restore_call = next(c for c in rpc_calls if c[0] == "restore_quarantine")
            self.assertEqual(Path(restore_call[1]["dest_path"]), restore_dir / "bad.sh")

    def test_history_tab_merge_log_summaries_and_clear(self) -> None:
        self.win._open_tab(0)
        # Write a log summary to DEFAULT_LOG_PATH and an entry to HISTORY_FILE_PATH
        Path(app_mod.DEFAULT_LOG_PATH).write_text(
            "----------- SCAN SUMMARY -----------\n"
            "Scanned files: 50\n"
            "Infected files: 1\n"
            "Data scanned: 10.00 MB\n"
            "Time: 2.000 sec (0 m 2 s)\n"
            "Start Date: 2026:11:21 15:00:00\n"
            "End Date:   2026:11:21 15:00:02\n",
            encoding="utf-8",
        )
        self.win._refresh_history()
        self.assertGreaterEqual(self.win.history_table.rowCount(), 1)
        self.assertEqual(self.win.history_table.item(0, 5).text(), "Threats Found")

        # Clear JSON history
        app_mod.save_json_file(app_mod.HISTORY_FILE_PATH, [{"date": "2026-11-21 18:00:00", "target": "X", "duration": "1s", "scanned": "See log summary", "threats": 0}])
        with mock.patch.object(QMessageBox, "question", return_value=QMessageBox.StandardButton.Yes):
            self.win._clear_history()
        self.assertEqual(app_mod.load_json_file(app_mod.HISTORY_FILE_PATH, ["x"]), [])
        Path(app_mod.DEFAULT_LOG_PATH).unlink(missing_ok=True)


class TestUIScheduleCustomScanAndUpdatesTabs(unittest.TestCase, _UIEnvMixin):
    """UI tests for Scheduled Scans, Custom Scan builder, and Engine & Updates tabs."""

    @classmethod
    def setUpClass(cls) -> None:
        cls._setup_isolated_env(lang="en")

    @classmethod
    def tearDownClass(cls) -> None:
        cls._teardown_isolated_env()

    def setUp(self) -> None:
        self._reset_window_state()

    def test_schedule_tab_refresh_daily_toggle_and_save(self) -> None:
        self.win._open_tab(2)
        mock_sched = {
            "enabled": True,
            "scan_type": "full",
            "frequency": "weekly",
            "day_of_week": "Fri",
            "time_of_day": "02:30",
            "next_run": "Fri 2026-11-27 02:30:00",
        }
        with (
            mock.patch.object(type(self.win.helper), "is_connected", new_callable=mock.PropertyMock, return_value=True),
            mock.patch.object(self.win.helper, "call", return_value=mock_sched),
        ):
            self.win._refresh_schedule()

        self.assertTrue(self.win.sched_enabled_chk.isChecked())
        self.assertEqual(self.win.sched_type_combo.currentData(), "full")
        self.assertTrue(self.win.sched_day_combo.isEnabled())

        # Switching frequency to daily disables day-of-week combo
        self.win.sched_freq_combo.setCurrentIndex(self.win.sched_freq_combo.findData("daily"))
        self.assertFalse(self.win.sched_day_combo.isEnabled())
        self.win.sched_time_edit.setTime(QTime(4, 45))

        with (
            mock.patch.object(type(self.win.helper), "is_connected", new_callable=mock.PropertyMock, return_value=True),
            mock.patch.object(self.win.helper, "call", return_value={"enabled": True, "next_run": "tomorrow"}) as mock_call,
            mock.patch.object(QMessageBox, "information"),
        ):
            self.win._save_schedule()
        self.assertEqual(mock_call.call_args[0][0], "set_schedule")
        self.assertEqual(mock_call.call_args[0][1]["frequency"], "daily")
        self.assertEqual(mock_call.call_args[0][1]["time_of_day"], "04:45")

    @unittest.skipIf(sys.platform != "linux", "POSIX systemd schedule test")
    def test_schedule_save_updates_idle_home_card_and_disable_clears_it(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            svc = Path(tmpdir) / "clamav-gui-scan.service"
            tmr = Path(tmpdir) / "clamav-gui-scan.timer"
            orig_svc, orig_tmr = app_mod.SYSTEMD_SERVICE_PATH, app_mod.SYSTEMD_TIMER_PATH
            try:
                app_mod.SYSTEMD_SERVICE_PATH = str(svc)
                app_mod.SYSTEMD_TIMER_PATH = str(tmr)
                timer_enabled = {"val": False}

                def _fake_run(cmd: list[str], **_kwargs: object) -> mock.Mock:
                    if cmd[:2] == ["systemctl", "enable"]:
                        timer_enabled["val"] = True
                        return mock.Mock(returncode=0, stdout="", stderr="")
                    if cmd[:2] == ["systemctl", "disable"]:
                        timer_enabled["val"] = False
                        return mock.Mock(returncode=0, stdout="", stderr="")
                    if cmd[:2] == ["systemctl", "is-enabled"]:
                        return mock.Mock(
                            returncode=0 if timer_enabled["val"] else 1,
                            stdout="enabled\n" if timer_enabled["val"] else "disabled\n",
                            stderr="",
                        )
                    if cmd[:2] == ["systemctl", "list-timers"]:
                        return mock.Mock(returncode=0, stdout="Wed 2026-11-25 06:15:00\n", stderr="")
                    return mock.Mock(returncode=0, stdout="", stderr="")

                def _helper_dispatch(action: str, params: dict[str, object] | None = None, **_kw: object) -> dict[str, object]:
                    with mock.patch("subprocess.run", side_effect=_fake_run):
                        return app_mod.HELPER_HANDLERS[action](params or {})

                # Unconnected save attempts to elevate via _require_root_helper
                self.win.show()
                self.win._open_tab(2)
                self.win._qt_app.processEvents()
                self.assertGreaterEqual(self.win.sched_status_lbl.width(), 450)
                req_h1 = (
                    self.win.sched_status_lbl.heightForWidth(self.win.sched_status_lbl.width())
                    if self.win.sched_status_lbl.hasHeightForWidth()
                    else self.win.sched_status_lbl.sizeHint().height()
                )
                self.assertGreaterEqual(self.win.sched_status_lbl.height(), req_h1)
                with mock.patch.object(self.win, "_require_root_helper", return_value=False) as mock_req:
                    QTest.mouseClick(self.win.sched_save_btn, Qt.MouseButton.LeftButton)
                    mock_req.assert_called_once()

                # Connected enable Weekly Wed 06:15 -> saves units & updates Home Schedule card
                with (
                    mock.patch.object(type(self.win.helper), "is_connected", new_callable=mock.PropertyMock, return_value=True),
                    mock.patch.object(self.win.helper, "call", side_effect=_helper_dispatch),
                    mock.patch.object(QMessageBox, "information"),
                ):
                    self.win.sched_enabled_chk.setChecked(True)
                    self.win.sched_type_combo.setCurrentIndex(self.win.sched_type_combo.findData("full"))
                    self.win.sched_freq_combo.setCurrentIndex(self.win.sched_freq_combo.findData("weekly"))
                    self.win.sched_day_combo.setCurrentIndex(self.win.sched_day_combo.findData("Wed"))
                    self.win.sched_time_edit.setTime(QTime(6, 15))
                    QTest.mouseClick(self.win.sched_save_btn, Qt.MouseButton.LeftButton)
                    self.win._qt_app.processEvents()

                    self.assertTrue(tmr.exists())
                    self.assertEqual(self.win.card_threats.value_lbl.text(), "Wed 06:15")
                    self.assertIn("Enabled", self.win.sched_status_lbl.text())
                    self.assertGreaterEqual(self.win.sched_status_lbl.width(), 450)
                    req_h2 = (
                        self.win.sched_status_lbl.heightForWidth(self.win.sched_status_lbl.width())
                        if self.win.sched_status_lbl.hasHeightForWidth()
                        else self.win.sched_status_lbl.sizeHint().height()
                    )
                    self.assertGreaterEqual(self.win.sched_status_lbl.height(), req_h2)

                    # Disabling schedule resets Home Schedule card back to "Not scheduled" even while unit file exists
                    self.win.sched_enabled_chk.setChecked(False)
                    QTest.mouseClick(self.win.sched_save_btn, Qt.MouseButton.LeftButton)
                    self.assertEqual(self.win.card_threats.value_lbl.text(), self.win._tr("idle_val_not_sched"))

                    # Re-enable daily 02:05 and verify refresh reads persisted state back
                    self.win.sched_enabled_chk.setChecked(True)
                    self.win.sched_freq_combo.setCurrentIndex(self.win.sched_freq_combo.findData("daily"))
                    self.win.sched_time_edit.setTime(QTime(2, 5))
                    QTest.mouseClick(self.win.sched_save_btn, Qt.MouseButton.LeftButton)
                    self.assertEqual(self.win.card_threats.value_lbl.text(), "Daily 02:05")

                    self.win.sched_time_edit.setTime(QTime(12, 0))
                    QTest.mouseClick(self.win.sched_refresh_btn, Qt.MouseButton.LeftButton)
                    self.assertEqual(self.win.sched_time_edit.time(), QTime(2, 5))
                    self.assertEqual(self.win.sched_freq_combo.currentData(), "daily")
            finally:
                app_mod.SYSTEMD_SERVICE_PATH = orig_svc
                app_mod.SYSTEMD_TIMER_PATH = orig_tmr

    def test_custom_scan_tab_preview_and_launch(self) -> None:
        self.win._open_tab(2)
        self.win.scan_target_combo.setCurrentText("/var/www")
        self.win.opt_recursive.setChecked(True)
        self.win.opt_infected_only.setChecked(True)
        self.win.opt_exclude_virtual.setChecked(True)
        self.win.opt_cross_fs.setChecked(True)
        self.win.max_size_spin.setValue(250)
        self.win.infected_action_combo.setCurrentIndex(self.win.infected_action_combo.findData("move"))
        self.win.new_log_edit.setText("/tmp/myscan.log")

        preview = self.win.cmd_preview_edit.text()
        self.assertIn("--max-filesize=250M", preview)
        self.assertIn("--cross-fs=no", preview)
        self.assertIn("--move=", preview)
        self.assertTrue(preview.endswith("/var/www"))

        with (
            mock.patch.object(type(self.win.helper), "is_connected", new_callable=mock.PropertyMock, return_value=True),
            mock.patch.object(self.win.helper, "call", return_value={"pid": 9090}) as mock_call,
            mock.patch.object(app_mod, "discover_clamscan_processes", return_value=[]),
        ):
            QTest.mouseClick(self.win.start_scan_btn, Qt.MouseButton.LeftButton)
        self.assertEqual(mock_call.call_args_list[0][0][0], "start_scan")
        self.assertEqual(mock_call.call_args_list[0][0][1]["log_path"], "/tmp/myscan.log")

    def test_delegated_linux_custom_scan_uses_report_only(self) -> None:
        action = self.win.infected_action_combo
        action.setCurrentIndex(action.findData("move"))
        with (
            mock.patch.object(app_mod, "IS_WINDOWS", False),
            mock.patch.object(app_mod, "IS_MACOS", False),
            mock.patch.object(app_mod, "_euid", return_value=1000),
            mock.patch.object(type(self.win.helper), "is_root", new_callable=mock.PropertyMock, return_value=True),
        ):
            self.win._update_controls_enabled()
            self.assertEqual(action.currentData(), "report")
            self.assertFalse(action.isEnabled())
            self.assertNotIn("--move=", self.win.cmd_preview_edit.text())
        self.win._update_controls_enabled()
        self.assertTrue(action.isEnabled())

    def test_freshclam_tab_execution_and_completion_states(self) -> None:
        self.win._open_tab(3)
        with (
            mock.patch.object(type(self.win.helper), "is_connected", new_callable=mock.PropertyMock, return_value=True),
            mock.patch("threading.Thread") as mock_thread,
        ):
            QTest.mouseClick(self.win.freshclam_btn, Qt.MouseButton.LeftButton)
            mock_thread.assert_called_once()
        self.assertFalse(self.win.freshclam_btn.isEnabled())
        self.assertEqual(self.win.freshclam_btn.text(), "Updating Signatures...")

        with mock.patch.object(
            app_mod,
            "get_clamav_metadata",
            return_value={"version": "ClamAV 1.4.6", "freshclam_service": "active"},
        ):
            self.win._on_freshclam_done(True, "daily.cvd updated")
            self.assertTrue(self.win.freshclam_btn.isEnabled())
            self.assertIn("[SUCCESS]", self.win.freshclam_output.toPlainText())
            self.assertIn("daily.cvd updated", self.win.freshclam_output.toPlainText())

            self.win._on_freshclam_done(False, "Mirror unreachable")
            self.assertIn("[FINISHED WITH ERRORS]", self.win.freshclam_output.toPlainText())


class TestUIDragDropAndTrayBehavior(unittest.TestCase, _UIEnvMixin):
    """UI tests for drag-and-drop file scanning and system tray close/restore/quit behavior."""

    @classmethod
    def setUpClass(cls) -> None:
        cls._setup_isolated_env(lang="en")

    @classmethod
    def tearDownClass(cls) -> None:
        cls._teardown_isolated_env()

    def setUp(self) -> None:
        self._reset_window_state()

    def test_drag_and_drop_accepts_existing_files_and_launches_scan(self) -> None:
        with tempfile.TemporaryDirectory() as drop_dir:
            f1 = Path(drop_dir) / "suspect1.exe"
            f1.write_bytes(b"test")

            mime_bad = QMimeData()
            mime_bad.setText("just text")
            ev_bad = QDragEnterEvent(QPoint(10, 10), Qt.DropAction.CopyAction, mime_bad, Qt.MouseButton.LeftButton, Qt.KeyboardModifier.NoModifier)
            self.win.dragEnterEvent(ev_bad)
            self.assertFalse(ev_bad.isAccepted())

            mime_ok = QMimeData()
            mime_ok.setUrls([QUrl.fromLocalFile(str(f1))])
            ev_enter = QDragEnterEvent(QPoint(10, 10), Qt.DropAction.CopyAction, mime_ok, Qt.MouseButton.LeftButton, Qt.KeyboardModifier.NoModifier)
            self.win.dragEnterEvent(ev_enter)
            self.assertTrue(ev_enter.isAccepted())

            ev_drop = QDropEvent(QPointF(10, 10), Qt.DropAction.CopyAction, mime_ok, Qt.MouseButton.LeftButton, Qt.KeyboardModifier.NoModifier)
            with (
                mock.patch.object(QMessageBox, "question", return_value=QMessageBox.StandardButton.Yes),
                mock.patch.object(self.win, "_launch_scan_args") as mock_launch,
            ):
                self.win.dropEvent(ev_drop)
            mock_launch.assert_called_once()
            self.assertEqual([Path(target) for target in mock_launch.call_args[0][0]], [f1])
            self.assertIn("suspect1.exe", mock_launch.call_args[1]["label"])

            # Dropping >5 files truncates preview with dlg_drop_more
            many = []
            for idx in range(7):
                fp = Path(drop_dir) / f"f{idx}.bin"
                fp.write_bytes(b"x")
                many.append(QUrl.fromLocalFile(str(fp)))
            mime_many = QMimeData()
            mime_many.setUrls(many)
            ev_many = QDropEvent(QPointF(10, 10), Qt.DropAction.CopyAction, mime_many, Qt.MouseButton.LeftButton, Qt.KeyboardModifier.NoModifier)
            with (
                mock.patch.object(QMessageBox, "question", return_value=QMessageBox.StandardButton.No) as mock_q,
                mock.patch.object(self.win, "_launch_scan_args"),
            ):
                self.win.dropEvent(ev_many)
            self.assertIn("and 2 more", mock_q.call_args[0][2])

    def test_tray_setup_close_to_tray_and_quit(self) -> None:
        fake_tray = mock.Mock()
        fake_tray.isVisible.return_value = True
        with mock.patch.object(QSystemTrayIcon, "isSystemTrayAvailable", return_value=True):
            # Attach mocked tray actions cleanly by letting _setup_tray run with QSystemTrayIcon mocked
            orig_tray_cls = app_mod.QSystemTrayIcon if hasattr(app_mod, "QSystemTrayIcon") else None
            _ = orig_tray_cls
            self.win._tray_icon = fake_tray

            # Close when _force_quit is False hides window instead of quitting
            self.win._force_quit = False
            self.win._tray_hint_shown = False
            ev = QCloseEvent()
            with mock.patch.object(self.win, "_notify") as mock_notify:
                self.win.closeEvent(ev)
            self.assertFalse(ev.isAccepted())
            self.assertTrue(self.win._tray_hint_shown)
            mock_notify.assert_called_once()

            # _restore_from_tray shows window again
            self.win._restore_from_tray()
            self.assertTrue(self.win.isVisible())

            # _quit_app accepts close and cleans up
            self.win._force_quit = True
            self.win._tray_icon = None

            # _notify fallback via notify-send sets desktop-entry hint & custom shield icon
            self.assertFalse(self.win.windowIcon().isNull())
            self.assertGreater(len(self.win.windowIcon().availableSizes()), 1)
            with mock.patch("shutil.which", return_value="/usr/bin/notify-send"), mock.patch(
                "subprocess.Popen"
            ) as mock_notify_proc:
                self.win._notify("Scan Complete", "0 threats", critical=False)
            mock_notify_proc.assert_called_once()
            notify_cmd = mock_notify_proc.call_args[0][0]
            self.assertEqual(notify_cmd[0], "notify-send")
            self.assertIn("string:desktop-entry:clamav-security-center", notify_cmd)
            self.assertIn("clamav-security-center", notify_cmd)


class TestUIGNOMECompatibility(unittest.TestCase, _UIEnvMixin):
    """UI tests verifying clean behavior on stock GNOME (no tray extension, Nautilus/FileManager1, Adwaita)."""

    @classmethod
    def setUpClass(cls) -> None:
        with mock.patch.dict(os.environ, {"XDG_CURRENT_DESKTOP": "GNOME", "DESKTOP_SESSION": "gnome"}):
            cls._setup_isolated_env(lang="en")

    @classmethod
    def tearDownClass(cls) -> None:
        cls._teardown_isolated_env()

    def setUp(self) -> None:
        self._reset_window_state()

    def test_gnome_trayless_close_exits_and_notify_uses_notify_send(self) -> None:
        with mock.patch.dict(os.environ, {"XDG_CURRENT_DESKTOP": "GNOME", "DESKTOP_SESSION": "gnome"}), mock.patch.object(
            QSystemTrayIcon, "isSystemTrayAvailable", return_value=False
        ):
            self.win._tray_icon = None
            self.win._setup_tray()
            self.assertIsNone(self.win._tray_icon)

            # Without a tray icon on stock GNOME, closeEvent must accept close instead of hiding invisibly
            self.win._force_quit = False
            ev = QCloseEvent()
            self.win.closeEvent(ev)
            self.assertTrue(ev.isAccepted())

            # Notifications route cleanly via notify-send with desktop-entry link to GNOME panel
            with mock.patch("shutil.which", return_value="/usr/bin/notify-send"), mock.patch(
                "subprocess.Popen"
            ) as mock_popen:
                self.win._notify("Threat Detected!", "EICAR", critical=True)
            cmd = mock_popen.call_args[0][0]
            self.assertEqual(cmd[0], "notify-send")
            self.assertIn("critical", cmd)
            self.assertIn("string:desktop-entry:clamav-security-center", cmd)

    @unittest.skipIf(sys.platform != "linux", "POSIX GNOME Nautilus reveal test")
    def test_gnome_threat_reveal_uses_nautilus_and_neutral_labels(self) -> None:
        self.win._open_tab(1)
        with mock.patch.object(self.win, "_notify"):
            self.win._apply_log_result(
                {"exists": True, "reset": False, "new_offset": 40, "new_text": "/tmp/gnome_test: EICAR FOUND\n"}
            )
        self.win.threats_table.selectRow(0)

        with mock.patch.dict(os.environ, {"XDG_CURRENT_DESKTOP": "GNOME", "DESKTOP_SESSION": "gnome"}), mock.patch(
            "shutil.which", side_effect=lambda b: "/usr/bin/nautilus" if b == "nautilus" else None
        ), mock.patch("subprocess.Popen") as mock_popen:
            self.win._reveal_threat_in_dolphin()
        mock_popen.assert_called_once_with(["nautilus", "--select", "/tmp/gnome_test"], start_new_session=True)
        self.assertEqual(self.win.windowTitle(), "ClamAV Security Center")
        self.assertEqual(self.win.pkexec_btn.text(), "Unlock via Polkit")


class TestUIDependencyAndDatabaseStatus(unittest.TestCase, _UIEnvMixin):
    """UI tests for missing ClamAV engine, missing freshclam/tools, and missing virus database warnings."""

    @classmethod
    def setUpClass(cls) -> None:
        cls._setup_isolated_env(lang="en")

    @classmethod
    def tearDownClass(cls) -> None:
        cls._teardown_isolated_env()

    def setUp(self) -> None:
        self._reset_window_state()

    def test_missing_clamscan_disables_scans_and_warns_in_hero_banner(self) -> None:
        missing_meta = {
            "version": "Unavailable",
            "freshclam_service": "inactive",
            "has_clamscan": False,
            "has_freshclam": False,
            "has_virus_db": False,
            "db_files_count": 0,
            "db_dir": "/var/lib/clamav",
            "missing_required": ["clamscan", "freshclam"],
            "missing_optional": ["pkexec", "notify-send"],
        }
        with mock.patch.object(app_mod, "get_clamav_metadata", return_value=missing_meta):
            self.win._refresh_metadata()

        self.assertEqual(self.win.hero_title_lbl.text(), "ClamAV Scanner Not Installed")
        self.assertIn("clamscan", self.win.hero_sub_lbl.text())
        self.assertFalse(self.win.btn_quick_scan.isEnabled())
        self.assertFalse(self.win.btn_full_scan.isEnabled())
        self.assertFalse(self.win.btn_pick_scan.isEnabled())
        self.assertFalse(self.win.start_scan_btn.isEnabled())
        self.assertFalse(self.win.freshclam_btn.isEnabled())
        self.assertIn("pkexec", self.win.db_status_lbl.text())

    def test_missing_virus_db_shows_update_button_and_navigates_to_db_tab(self) -> None:
        no_db_meta = {
            "version": "ClamAV 1.4.6",
            "freshclam_service": "inactive",
            "has_clamscan": True,
            "has_freshclam": True,
            "has_virus_db": False,
            "db_files_count": 0,
            "db_dir": "/var/lib/clamav",
            "missing_required": [],
            "missing_optional": [],
        }
        with mock.patch.object(app_mod, "get_clamav_metadata", return_value=no_db_meta):
            self.win._refresh_metadata()

        self.assertEqual(self.win.hero_title_lbl.text(), "Virus Database Missing — Update Needed")
        self.assertTrue(self.win.btn_quick_scan.isEnabled())
        self.assertFalse(self.win.hero_db_btn.isHidden())
        self.assertIn("Missing", self.win.meta_lbl.text())

        QTest.mouseClick(self.win.hero_db_btn, Qt.MouseButton.LeftButton)
        self.win._qt_app.processEvents()
        self.assertFalse(self.win.tabs.isHidden())
        self.assertEqual(self.win.tabs.currentIndex(), 3)

        # Restoring healthy metadata clears warning and returns green Protected banner
        ok_meta = {
            "version": "ClamAV 1.4.6",
            "freshclam_service": "active",
            "has_clamscan": True,
            "has_freshclam": True,
            "has_virus_db": True,
            "db_files_count": 3,
            "db_dir": "/var/lib/clamav",
            "missing_required": [],
            "missing_optional": [],
        }
        with mock.patch.object(app_mod, "get_clamav_metadata", return_value=ok_meta):
            self.win._refresh_metadata()
        self.assertEqual(self.win.hero_title_lbl.text(), "Your computer is protected")
        self.assertTrue(self.win.hero_db_btn.isHidden())

    def test_os_locales_tiles_inspect_error_and_overflow_audit(self) -> None:
        # Verify German auto-detection via OS locale (no UI picker) + localized error messages
        with (
            mock.patch.dict(
                os.environ, {"LC_ALL": "de_DE.UTF-8", "LC_MESSAGES": "", "LANG": "", "LANGUAGE": ""}
            ),
            mock.patch.object(
                app_mod,
                "get_clamav_metadata",
                return_value={
                    "version": "Unavailable",
                    "freshclam_service": "inactive",
                    "has_clamscan": False,
                    "has_freshclam": False,
                    "has_virus_db": False,
                    "db_files_count": 0,
                    "db_dir": "/var/lib/clamav",
                    "missing_required": ["clamscan", "freshclam"],
                    "missing_optional": [],
                },
            ),
        ):
            win_de = app_mod.create_main_window(auto_poll=False, lang=None)
            win_de.show()
            win_de._qt_app.processEvents()
            try:
                self.assertEqual(win_de.lang, "de")
                self.assertIn("Downloads & Home", win_de.btn_quick_scan.sub_lbl.text())
                self.assertIn("außerdem fehlt", win_de.hero_sub_lbl.text())
                self.assertIn("Inaktiv", win_de.meta_lbl.text())

                Path(app_mod.DEFAULT_LOG_PATH).write_text(
                    "----------- SCAN SUMMARY -----------\n"
                    "Scanned files: 10\n"
                    "Infected files: 0\n"
                    "Start Date: 2026:11:21 15:00:00\n",
                    encoding="utf-8",
                )
                try:
                    win_de._refresh_history()
                    self.assertEqual(win_de.history_table.item(0, 1).text(), "System- / Protokollscan")
                finally:
                    Path(app_mod.DEFAULT_LOG_PATH).unlink(missing_ok=True)

                win_de._on_inspect_done(None, "Root helper restricts scan logs to /var/log/")
                self.assertIn("Protokoll-Hinweis", win_de.log_hint_lbl.text())
            finally:
                win_de._force_quit = True
                win_de.close()
                win_de._qt_app.processEvents()

        # Text overflow & layout geometry audit across all 8 supported OS locales
        locale_map = (
            ("en_US.UTF-8", "en"),
            ("de_DE.UTF-8", "de"),
            ("es_ES.UTF-8", "es"),
            ("fr_FR.UTF-8", "fr"),
            ("pt_BR.UTF-8", "pt"),
            ("zh_CN.UTF-8", "zh"),
            ("ja_JP.UTF-8", "ja"),
            ("ru_RU.UTF-8", "ru"),
        )
        ok_meta = {"version": "ClamAV 1.4.6", "freshclam_service": "active"}
        for loc_env, expected_code in locale_map:
            with (
                mock.patch.dict(
                    os.environ, {"LC_ALL": loc_env, "LC_MESSAGES": "", "LANG": "", "LANGUAGE": ""}
                ),
                mock.patch.object(app_mod, "get_clamav_metadata", return_value=ok_meta),
            ):
                w = app_mod.create_main_window(auto_poll=False, lang=None)
                w.show()
                w._qt_app.processEvents()
                try:
                    self.assertEqual(w.lang, expected_code)
                    self.assertLessEqual(w.width(), 1200, msg=f"Window widened for {expected_code}: {w.width()}")

                    # Check action tiles fit their label bounds cleanly
                    for tile in (w.btn_quick_scan, w.btn_full_scan, w.btn_pick_scan):
                        self.assertGreaterEqual(tile.width(), 240, msg=f"Narrow tile in {expected_code}")
                        for lbl in (tile.title_lbl, tile.sub_lbl):
                            self.assertTrue(lbl.wordWrap())
                            self.assertGreaterEqual(
                                lbl.width(), 120, msg=f"Tile label clipped in {expected_code}"
                            )
                            self.assertGreaterEqual(
                                lbl.height(),
                                lbl.fontMetrics().height(),
                                msg=f"Zero height tile label in {expected_code}",
                            )

                    # Check 4-column status strip fits without horizontal or vertical clipping
                    for card in (w.card_status, w.card_cpu, w.card_io, w.card_threats):
                        self.assertTrue(card.title_lbl.wordWrap())
                        self.assertTrue(card.value_lbl.wordWrap())
                        self.assertGreaterEqual(
                            card.width(), 180, msg=f"Narrow stat card in {expected_code}"
                        )
                        if card.value_lbl.hasHeightForWidth():
                            needed_h = card.value_lbl.heightForWidth(card.value_lbl.width())
                            self.assertGreaterEqual(
                                card.value_lbl.height(),
                                needed_h,
                                msg=f"StatCard vertical clip in {expected_code}: {card.value_lbl.text()!r}",
                            )

                    # Non-wrapped action buttons must fit text width inside widget rect
                    for btn in (w.about_btn, w.sudo_btn, w.pkexec_btn, w.user_mode_btn, w.toggle_tabs_btn):
                        txt = btn.text().replace("&&", "&")
                        txt_w = btn.fontMetrics().horizontalAdvance(txt)
                        self.assertLessEqual(
                            txt_w,
                            btn.width(),
                            msg=f"Button overflow in {expected_code}: {txt!r} ({txt_w} > {btn.width()})",
                        )

                    # Active control bar also renders cleanly without horizontal overflow
                    w._current_proc = {
                        "pid": 7777,
                        "cmdline": ["clamscan", "-r", "/home"],
                        "state": "R",
                        "elapsed_sec": 8.0,
                        "quiet_infected_only": False,
                        "nice": 0,
                        "rss_kb": 1024,
                        "cpu_ticks": 10,
                        "user": "user",
                        "uid": app_mod._uid(),
                        "log_path": "",
                    }
                    w._update_controls_enabled()
                    w._qt_app.processEvents()
                    self.assertFalse(w.ctrl_box.isHidden())
                    for act_btn in (w.pause_btn, w.stop_btn):
                        t = act_btn.text().replace("&&", "&")
                        tw = act_btn.fontMetrics().horizontalAdvance(t)
                        self.assertLessEqual(
                            tw,
                            act_btn.width(),
                            msg=f"Active button overflow in {expected_code}: {t!r}",
                        )

                    # Each tab remains visible when selected, including with a scrolling tab bar.
                    w._open_tab(0)
                    tab_bar = w.tabs.tabBar()
                    self.assertEqual(tab_bar.elideMode(), Qt.TextElideMode.ElideNone)
                    for index in range(w.tabs.count()):
                        w.tabs.setCurrentIndex(index)
                        w._qt_app.processEvents()
                        self.assertTrue(
                            tab_bar.rect().contains(tab_bar.tabRect(index)),
                            msg=f"Selected tab {index} is clipped in {expected_code}",
                        )
                finally:
                    w._force_quit = True
                    w.close()
                    w._qt_app.processEvents()


@unittest.skipUnless(os.environ.get("CLAMAV_GUI_LIVE_TEST") == "1", "Requires a local ClamAV installation")
class TestUILiveClamAV(unittest.TestCase, _UIEnvMixin):
    """Exercise the native scanner, helper, and Qt threat workflow with an inert signature."""

    @classmethod
    def setUpClass(cls) -> None:
        app_mod._ensure_standard_path()
        cls._setup_isolated_env()

    @classmethod
    def tearDownClass(cls) -> None:
        cls._teardown_isolated_env()

    def test_quick_scan_and_quarantine_round_trip(self) -> None:
        self.assertFalse(app_mod._is_posix_root(), "Run this test as an unprivileged user")
        root = Path(self._tmp_dir.name).resolve()
        database = root / "database"
        targets = root / "targets"
        database.mkdir()
        targets.mkdir()
        payload = b"CLAMAV_GUI_CI_TEST_PAYLOAD"
        signature = "ClamAV.GUI.CI.SmokeTest"
        (database / "smoke.ndb").write_text(f"{signature}:0:*:{payload.hex()}\n", encoding="ascii")
        clean = targets / "clean.txt"
        clean.write_text("clean file", encoding="utf-8")
        sample = targets / "sample.bin"
        sample.write_bytes(payload)
        log_path = root / "scan.log"

        with (
            mock.patch.object(app_mod, "_default_db_dir", return_value=str(database)),
            mock.patch.object(app_mod, "get_quick_scan_targets", return_value=[str(targets)]),
            mock.patch.object(app_mod, "DEFAULT_LOG_PATH", str(log_path)),
            mock.patch.object(app_mod, "DEFAULT_QUARANTINE_DIR", str(root / "quarantine")),
            mock.patch.object(self.win, "_notify"),
            mock.patch.object(QMessageBox, "question", return_value=QMessageBox.StandardButton.Yes),
            mock.patch.object(QMessageBox, "information"),
            mock.patch.object(QMessageBox, "warning") as warning,
        ):
            metadata = app_mod.get_clamav_metadata()
            self.assertTrue(metadata["has_clamscan"] and metadata["has_freshclam"], metadata)
            self.assertIn("ClamAV", metadata["version"])
            ok, message = self.win.helper.start_local()
            self.assertTrue(ok, message)
            self.win._last_meta = metadata
            self.win._update_controls_enabled()
            QTest.mouseClick(self.win.btn_quick_scan, Qt.MouseButton.LeftButton)
            warning.assert_not_called()
            deadline = time.monotonic() + 30
            log_text = ""
            while time.monotonic() < deadline:
                self.win._poll_tick()
                QTest.qWait(50)
                if log_path.exists():
                    log_text = log_path.read_text(encoding="utf-8", errors="replace")
                if "SCAN SUMMARY" in log_text and self.win.threats_table.rowCount() and not self.win._inspect_inflight:
                    break

            summaries = app_mod.parse_scan_summaries_from_log(log_text)
            self.assertEqual([entry["threats"] for entry in summaries], [1], log_text)
            self.assertEqual(self.win.threats_table.rowCount(), 1, log_text)
            self.assertEqual(Path(self.win.threats_table.item(0, 0).text()), sample)
            self.assertIn(signature, self.win.threats_table.item(0, 1).text())
            self.win.threats_table.selectRow(0)
            self.win._quarantine_selected_threat()
            warning.assert_not_called()
            self.assertFalse(sample.exists())
            self.assertEqual(self.win.quarantine_table.rowCount(), 1)
            self.win.quarantine_table.selectRow(0)
            self.win._restore_quarantine()
            warning.assert_not_called()
            self.assertEqual(sample.read_bytes(), payload)
            self.assertTrue(clean.exists())
            self.assertEqual(self.win.quarantine_table.rowCount(), 0)


if __name__ == "__main__":
    unittest.main()
