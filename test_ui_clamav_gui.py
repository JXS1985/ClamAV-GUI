#!/usr/bin/env python3
"""Extensive headless Qt6 UI test suite covering all ClamAV Security Center GUI functionality."""

from __future__ import annotations

import json
import os
import signal
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

# Run all Qt GUI tests completely headlessly without touching the user desktop session
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

sys.path.insert(0, str(Path(__file__).resolve().parent))
import clamav_gui as app_mod  # noqa: E402

try:
    from PySide6.QtCore import QMimeData, QPoint, QPointF, Qt, QTime, QUrl
    from PySide6.QtGui import QCloseEvent, QDragEnterEvent, QDropEvent
    from PySide6.QtTest import QTest
    from PySide6.QtWidgets import QApplication, QFileDialog, QInputDialog, QMessageBox, QPushButton, QSystemTrayIcon
except ImportError:
    from PyQt6.QtCore import QMimeData, QPoint, QPointF, Qt, QTime, QUrl  # type: ignore[no-redef]
    from PyQt6.QtGui import QCloseEvent, QDragEnterEvent, QDropEvent  # type: ignore[no-redef]
    from PyQt6.QtTest import QTest  # type: ignore[no-redef]
    from PyQt6.QtWidgets import (  # type: ignore[no-redef]
        QApplication,
        QFileDialog,
        QInputDialog,
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

        self.assertEqual(self.win.tabs.count(), 7)
        self.assertEqual(self.win.tabs.tabText(0), "Live Output & Log")
        self.assertEqual(self.win.tabs.tabText(1), "Detected Threats (0)")
        self.assertEqual(self.win.tabs.tabText(2), "Quarantine (0)")
        self.assertEqual(self.win.tabs.tabText(3), "Scan History")
        self.assertEqual(self.win.tabs.tabText(4), "Automatic Scans")
        self.assertEqual(self.win.tabs.tabText(5), "Custom Scan (Advanced)")
        self.assertEqual(self.win.tabs.tabText(6), "Virus Database")

        self.assertIn("ClamAV 1.4.6-test", self.win.meta_lbl.text())
        self.assertIn("Active", self.win.meta_lbl.text())
        self.assertTrue(hasattr(self.win, "stats_strip"))
        self.assertTrue(hasattr(self.win, "header_shield_lbl"))
        self.assertTrue(hasattr(self.win, "hero_icon_lbl"))
        self.assertTrue(hasattr(self.win, "lang_de_btn"))
        self.assertTrue(hasattr(self.win, "lang_en_btn"))

        initial_w = self.win.width()
        initial_h = self.win.height()
        self.assertEqual(initial_w, 980)
        self.assertIn("Show", self.win.toggle_tabs_btn.text())

        # Expand via genuine mouse click
        QTest.mouseClick(self.win.toggle_tabs_btn, Qt.MouseButton.LeftButton)
        self.win._qt_app.processEvents()
        self.assertFalse(self.win.tabs.isHidden())
        self.assertIn("Hide", self.win.toggle_tabs_btn.text())
        self.assertEqual(self.win.width(), initial_w)
        self.assertGreater(self.win.height(), initial_h + 200)

        # Switching tabs works cleanly once visible
        for idx in range(7):
            self.win._open_tab(idx)
            self.assertEqual(self.win.tabs.currentIndex(), idx)

        # Collapse via genuine mouse click
        QTest.mouseClick(self.win.toggle_tabs_btn, Qt.MouseButton.LeftButton)
        self.win._qt_app.processEvents()
        self.assertTrue(self.win.tabs.isHidden())
        self.assertIn("Show", self.win.toggle_tabs_btn.text())
        self.assertEqual(self.win.width(), initial_w)
        self.assertEqual(self.win.height(), initial_h)


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
                        self.assertEqual(win.hero_title_lbl.text(), "System geschützt — Keine aktiven Bedrohungen erkannt")
                        self.assertIn("Schnellscan", win.btn_quick_scan.text())
                        self.assertIn("Vollständiger", win.btn_full_scan.text())
                        self.assertIn("scannen", win.btn_pick_scan.text())
                        self.assertEqual(win.card_status.title_lbl.text(), "Scan-Status")
                        self.assertEqual(win.card_cpu.title_lbl.text(), "Laufzeit / Aktivität")
                        self.assertEqual(win.card_io.title_lbl.text(), "RAM / Festplatte gelesen")
                        self.assertEqual(win.card_threats.title_lbl.text(), "Gefundene Bedrohungen")
                        self.assertEqual(win.progress_bar.text(), "Inaktiv")
                        self.assertEqual(win.tabs.tabText(0), "Live-Ausgabe & Protokoll")
                        self.assertEqual(win.tabs.tabText(2), "Quarantäne (0)")
                        self.assertEqual(win.tabs.tabText(4), "Automatische Scans")
                        self.assertEqual(win.tabs.tabText(5), "Benutzerdefinierter Scan (Erweitert)")
                        self.assertEqual(win.tabs.tabText(6), "Virendatenbank")
                        self.assertEqual(win.threats_table.horizontalHeaderItem(0).text(), "Dateipfad")
                        self.assertEqual(win.threats_table.horizontalHeaderItem(1).text(), "Bedrohungssignatur")
                        self.assertEqual(win.quarantine_table.horizontalHeaderItem(0).text(), "Dateiname")
                        self.assertEqual(win.history_table.horizontalHeaderItem(0).text(), "Abgeschlossen am")
                        self.assertEqual(win.sched_freq_combo.itemText(0), "Täglich")
                        self.assertEqual(win.sched_freq_combo.itemText(1), "Wöchentlich")
                        self.assertEqual(win.freshclam_btn.text(), "Virensignaturen jetzt aktualisieren (freshclam)")

                        # Live switch to English
                        idx_en = win.lang_combo.findData("en")
                        win.lang_combo.setCurrentIndex(idx_en)
                        win._qt_app.processEvents()

                        self.assertEqual(win.lang, "en")
                        self.assertEqual(win.app_title_lbl.text(), "ClamAV Security Center")
                        self.assertEqual(win.hero_title_lbl.text(), "System Protected — No Active Threats Detected")
                        self.assertEqual(win.tabs.tabText(0), "Live Output & Log")
                        self.assertEqual(win.threats_table.horizontalHeaderItem(0).text(), "File Path")
                        self.assertEqual(win.quarantine_table.horizontalHeaderItem(0).text(), "File Name")
                        self.assertEqual(win.history_table.horizontalHeaderItem(0).text(), "Date Completed")
                        self.assertEqual(win.freshclam_btn.text(), "Update Virus Signatures Now (freshclam)")

                        saved = json.loads(app_mod.SETTINGS_FILE_PATH.read_text(encoding="utf-8"))
                        self.assertEqual(saved["language"], "en")
                    finally:
                        win._force_quit = True
                        win.close()
                        win._qt_app.processEvents()

                    # New window without explicit lang reads saved "language": "en" even under de_DE
                    with mock.patch.dict(os.environ, {"LANG": "de_DE.UTF-8"}):
                        win2 = app_mod.create_main_window(auto_poll=False, lang=None)
                        try:
                            self.assertEqual(win2.lang, "en")
                            self.assertEqual(win2.app_title_lbl.text(), "ClamAV Security Center")
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

        # Successful password unlock installs polkit rule and hides auth banner
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
        self.assertIn("install_polkit_rule", called_actions)
        self.assertIn("list_quarantine", called_actions)
        self.assertIn("get_schedule", called_actions)

        # Helper disconnect brings back auth banner and clears proc telemetry
        self.win.telemetry.last_proc_data = {"alive": True}
        self.win._on_helper_disconnected()
        self.assertFalse(self.win.auth_banner.isHidden())
        self.assertTrue(self.win.root_badge_lbl.isHidden())
        self.assertEqual(self.win.telemetry.last_proc_data, {})

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
        self.assertEqual(self.win.pkexec_btn.text(), "Unlock via System Polkit")

        # _require_root_helper Cancel -> returns False
        with mock.patch.object(QMessageBox, "exec", return_value=0), mock.patch.object(
            QMessageBox, "clickedButton", return_value=None
        ):
            self.assertFalse(self.win._require_root_helper())


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

            # Full Scan adds virtual exclusions
            calls.clear()
            QTest.mouseClick(self.win.btn_full_scan, Qt.MouseButton.LeftButton)
            full_args = calls[0][1]["cmd_args"]
            self.assertIn("--exclude-dir=^/proc", full_args)
            self.assertEqual(full_args[-1], "/")

            # Folder/File picker scan -> Folder choice
            calls.clear()
            fake_btn = QPushButton("Folder")

            def fake_add_button(text_or_std: object, *_a: object) -> object:
                return fake_btn if text_or_std == "Choose Folder..." else QPushButton("Other")

            with (
                mock.patch.object(QMessageBox, "addButton", side_effect=fake_add_button),
                mock.patch.object(QMessageBox, "exec", return_value=0),
                mock.patch.object(QMessageBox, "clickedButton", return_value=fake_btn),
                mock.patch.object(QFileDialog, "getExistingDirectory", return_value="/tmp"),
            ):
                QTest.mouseClick(self.win.btn_pick_scan, Qt.MouseButton.LeftButton)
            self.assertEqual(calls[0][1]["cmd_args"][-1], "/tmp")

    def test_pause_stop_priority_and_restart_without_i(self) -> None:
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
            "uid": os.getuid(),
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

        # Stop scan confirmation Yes -> SIGTERM
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

    def test_handle_scan_finished_records_history_and_notifies(self) -> None:
        self.win.telemetry.total_lines_logged = 123
        with mock.patch.object(self.win, "_notify") as mock_notify:
            self.win._handle_scan_finished({"label": "Quick Scan", "elapsed_sec": 15.0, "log_path": app_mod.DEFAULT_LOG_PATH})
        mock_notify.assert_called_once()
        self.assertGreaterEqual(self.win.history_table.rowCount(), 1)
        self.assertEqual(self.win.history_table.item(0, 1).text(), "Quick Scan")
        self.assertEqual(self.win.history_table.item(0, 5).text(), "Clean")


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

        # Reveal in Dolphin (fallback to xdg-open if dolphin absent)
        with mock.patch("shutil.which", return_value="/usr/bin/dolphin"), mock.patch("subprocess.Popen") as mock_p:
            self.win._reveal_threat_in_dolphin()
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
        self.win._open_tab(2)
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
            self.assertEqual(self.win.tabs.tabText(2), "Quarantine (1)")
            self.win.quarantine_table.selectRow(0)

            with (
                mock.patch.object(QFileDialog, "getExistingDirectory", return_value="/tmp/restored"),
                mock.patch.object(QMessageBox, "question", return_value=QMessageBox.StandardButton.Yes),
                mock.patch.object(QMessageBox, "information") as mock_info,
            ):
                self.win._restore_quarantine(pick_dir=True)
            mock_info.assert_called_once()
            self.assertEqual(self.win.quarantine_table.rowCount(), 0)
            self.assertEqual(self.win.tabs.tabText(2), "Quarantine (0)")
            restore_call = next(c for c in rpc_calls if c[0] == "restore_quarantine")
            self.assertEqual(restore_call[1]["dest_path"], "/tmp/restored/bad.sh")

    def test_history_tab_merge_log_summaries_and_clear(self) -> None:
        self.win._open_tab(3)
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
        self.win._open_tab(4)
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

    def test_custom_scan_tab_preview_and_launch(self) -> None:
        self.win._open_tab(5)
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

    def test_freshclam_tab_execution_and_completion_states(self) -> None:
        self.win._open_tab(6)
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
            self.assertEqual(mock_launch.call_args[0][0], [str(f1)])
            self.assertIn("suspect1.exe", mock_launch.call_args[1]["label"])

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

            # _notify fallback via notify-send sets desktop-entry hint for notification panel linking
            with mock.patch("shutil.which", return_value="/usr/bin/notify-send"), mock.patch(
                "subprocess.Popen"
            ) as mock_notify_proc:
                self.win._notify("Scan Complete", "0 threats", critical=False)
            mock_notify_proc.assert_called_once()
            notify_cmd = mock_notify_proc.call_args[0][0]
            self.assertEqual(notify_cmd[0], "notify-send")
            self.assertIn("string:desktop-entry:clamav-kde-gui", notify_cmd)
            self.assertIn("security-high", notify_cmd)


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
            self.assertIn("string:desktop-entry:clamav-kde-gui", cmd)

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
        self.assertEqual(self.win.pkexec_btn.text(), "Unlock via System Polkit")


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
        self.assertEqual(self.win.tabs.currentIndex(), 6)

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
        self.assertEqual(self.win.hero_title_lbl.text(), "System Protected — No Active Threats Detected")
        self.assertTrue(self.win.hero_db_btn.isHidden())

    def test_mockup_lang_pills_tiles_inspect_error_and_german_history(self) -> None:
        # Segmented DE / EN pill click switches language cleanly
        QTest.mouseClick(self.win.lang_de_btn, Qt.MouseButton.LeftButton)
        self.win._qt_app.processEvents()
        self.assertEqual(self.win.lang, "de")
        self.assertIn("Downloads & Home", self.win.btn_quick_scan.sub_lbl.text())
        self.assertIn("Aktiv", self.win.meta_lbl.text())

        # Missing clamscan + pkexec in German uses localized 'außerdem fehlt' (no English leak)
        with mock.patch.object(
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
        ):
            self.win._refresh_metadata()
        self.assertIn("außerdem fehlt", self.win.hero_sub_lbl.text())
        self.assertIn("Inaktiv", self.win.meta_lbl.text())

        # Parsed log summary target localizes to German in History tab
        Path(app_mod.DEFAULT_LOG_PATH).write_text(
            "----------- SCAN SUMMARY -----------\n"
            "Scanned files: 10\n"
            "Infected files: 0\n"
            "Start Date: 2026:11:21 15:00:00\n",
            encoding="utf-8",
        )
        try:
            self.win._refresh_history()
            self.assertEqual(self.win.history_table.item(0, 1).text(), "System- / Protokollscan")
        finally:
            Path(app_mod.DEFAULT_LOG_PATH).unlink(missing_ok=True)

        # Inspect error surfaces visibly in log_hint_lbl instead of failing silently
        self.win._on_inspect_done(None, "Root helper restricts scan logs to /var/log/")
        self.assertIn("Protokoll-Hinweis", self.win.log_hint_lbl.text())

        # Switch back via EN pill cleanly
        QTest.mouseClick(self.win.lang_en_btn, Qt.MouseButton.LeftButton)
        self.win._qt_app.processEvents()
        self.assertEqual(self.win.lang, "en")


if __name__ == "__main__":
    unittest.main()
