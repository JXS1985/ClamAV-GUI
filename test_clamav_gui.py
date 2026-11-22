#!/usr/bin/env python3
"""Comprehensive backend, telemetry, RPC, and localization test suite for clamav_gui.py."""

from __future__ import annotations

import json
import os
import signal
import string
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

# Ensure Qt stays headless if anything instantiates QApplication during backend tests
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

sys.path.insert(0, str(Path(__file__).resolve().parent))
import clamav_gui as app_mod  # noqa: E402


def _make_stat_line(pid: int, comm: str = "clamscan", state: str = "R", nice: int = 0) -> str:
    """Build a syntactically valid /proc/<pid>/stat line for testing."""
    # Fields after '(comm)': state(3), ppid(4), pgrp(5), session(6), tty(7), tpgid(8),
    # flags(9), minflt(10), cminflt(11), majflt(12), cmajflt(13), utime(14), stime(15),
    # cutime(16), cstime(17), priority(18), nice(19), num_threads(20), itrealvalue(21), starttime(22)
    tail = [
        state,
        "1",
        "100",
        "100",
        "0",
        "-1",
        "4194304",
        "10",
        "0",
        "0",
        "0",
        "120",
        "30",
        "0",
        "0",
        "20",
        str(nice),
        "1",
        "0",
        "500",
    ]
    return f"{pid} ({comm}) " + " ".join(tail) + "\n"


class TestFormattingAndParsers(unittest.TestCase):
    """Tests for formatting, size/command parsing, threat detection, JSON IO, and schedule generation."""

    def test_format_bytes_and_duration(self) -> None:
        self.assertEqual(app_mod.format_bytes(0), "0 B")
        self.assertEqual(app_mod.format_bytes(-10), "0 B")
        self.assertEqual(app_mod.format_bytes(512), "512 B")
        self.assertEqual(app_mod.format_bytes(1024), "1.00 KB")
        self.assertEqual(app_mod.format_bytes(5 * 1024 * 1024), "5.00 MB")
        self.assertEqual(app_mod.format_bytes(3 * 1024**3), "3.00 GB")
        self.assertEqual(app_mod.format_bytes(2 * 1024**4), "2.00 TB")

        self.assertEqual(app_mod.format_duration(-5), "00:00:00")
        self.assertEqual(app_mod.format_duration(0), "00:00:00")
        self.assertEqual(app_mod.format_duration(3661), "01:01:01")
        self.assertEqual(app_mod.format_duration(90061), "25:01:01")

    def test_parse_size_to_bytes(self) -> None:
        self.assertEqual(app_mod.parse_size_to_bytes("100B"), 100)
        self.assertEqual(app_mod.parse_size_to_bytes("512K"), 512 * 1024)
        self.assertEqual(app_mod.parse_size_to_bytes("512kb"), 512 * 1024)
        self.assertEqual(app_mod.parse_size_to_bytes("25M"), 25 * 1024 * 1024)
        self.assertEqual(app_mod.parse_size_to_bytes("25MB"), 25 * 1024 * 1024)
        self.assertEqual(app_mod.parse_size_to_bytes("2G"), 2 * 1024**3)
        self.assertEqual(app_mod.parse_size_to_bytes("1.5G"), int(1.5 * 1024**3))
        self.assertEqual(app_mod.parse_size_to_bytes("1T"), 1024**4)
        self.assertEqual(app_mod.parse_size_to_bytes("12345"), 12345)
        self.assertEqual(app_mod.parse_size_to_bytes("", default=777), 777)
        self.assertEqual(app_mod.parse_size_to_bytes("bad-value", default=999), 999)
        self.assertEqual(app_mod.parse_size_to_bytes("badM", default=888), 888)

    def test_normalize_exclude_path(self) -> None:
        self.assertEqual(app_mod._normalize_exclude_path("^/sys/"), "/sys")
        self.assertEqual(app_mod._normalize_exclude_path("/mnt/backup/$"), "/mnt/backup")
        self.assertIsNone(app_mod._normalize_exclude_path("relative/path"))
        self.assertIsNone(app_mod._normalize_exclude_path("^/var/*.log"))
        self.assertIsNone(app_mod._normalize_exclude_path("/home/(a|b)"))

    def test_extract_log_path_and_targets(self) -> None:
        cmd = [
            "/usr/bin/clamscan",
            "-r",
            "-i",
            "--exclude-dir=^/sys",
            "--exclude-dir",
            "^/mnt/backup/",
            "--max-filesize=150M",
            "--max-filesize",
            "200M",
            "--cross-fs=no",
            "--log=/tmp/custom-clam.log",
            "/home/user",
            "/tmp",
        ]
        self.assertEqual(app_mod.extract_log_path_from_cmdline(cmd), "/tmp/custom-clam.log")
        self.assertEqual(app_mod.extract_log_path_from_cmdline(["clamscan", "-l", "/var/log/a.log", "/"]), "/var/log/a.log")
        self.assertEqual(app_mod.extract_log_path_from_cmdline(["clamscan", "--log", "/var/log/b.log", "/"]), "/var/log/b.log")
        with mock.patch("os.path.exists", side_effect=lambda p: p == app_mod.DEFAULT_LOG_PATH):
            self.assertEqual(app_mod.extract_log_path_from_cmdline(["clamscan", "/tmp"]), app_mod.DEFAULT_LOG_PATH)
        with mock.patch("os.path.exists", return_value=False):
            self.assertEqual(app_mod.extract_log_path_from_cmdline(["clamscan", "/tmp"]), "")

        parsed = app_mod.parse_scan_targets_and_limits(cmd)
        self.assertEqual(parsed["targets"], ["/home/user", "/tmp"])
        self.assertEqual(parsed["max_filesize"], 200 * 1024 * 1024)
        self.assertFalse(parsed["cross_fs"])
        self.assertIn("/sys", parsed["exclude_dirs"])
        self.assertIn("/mnt/backup", parsed["exclude_dirs"])

        # Default target "/" and `--` end-of-options separator
        self.assertEqual(app_mod.parse_scan_targets_and_limits(["clamscan", "-r"])["targets"], ["/"])
        self.assertEqual(
            app_mod.parse_scan_targets_and_limits(["clamscan", "-r", "--", "/dir-with-dash"])["targets"],
            ["/dir-with-dash"],
        )

    def test_parse_threats_from_text(self) -> None:
        sample = (
            "/tmp/clean.txt: OK\n"
            "/tmp/evil1.exe: Win.Test.EICAR_HDB-1 FOUND\n"
            "/tmp/folder with spaces/a:b.doc: Doc.Malware-42 FOUND\n"
            "LibClamAV Warning: Can't open file /root/x: Permission denied\n"
            "----------- SCAN SUMMARY -----------\n"
        )
        threats = app_mod.parse_threats_from_text(sample)
        self.assertEqual(
            threats,
            [
                ("/tmp/evil1.exe", "Win.Test.EICAR_HDB-1"),
                ("/tmp/folder with spaces/a:b.doc", "Doc.Malware-42"),
            ],
        )

    def test_parse_scan_summaries_from_log(self) -> None:
        sample_log = (
            "Noise before summary\n"
            "----------- SCAN SUMMARY -----------\n"
            "Incomplete block without scanned files\n\n"
            "----------- SCAN SUMMARY -----------\n"
            "Known viruses: 3628232\n"
            "Engine version: 1.4.6\n"
            "Scanned directories: 10\n"
            "Scanned files: 125\n"
            "Infected files: 0\n"
            "Data scanned: 42.10 MB\n"
            "Time: 12.345 sec (0 m 12 s)\n"
            "Start Date: 2026:11:21 10:00:00\n"
            "End Date:   2026:11:21 10:00:12\n\n"
            "----------- SCAN SUMMARY -----------\n"
            "Scanned files: badint\n"
            "Infected files: 2\n"
            "Data scanned: 1.50 MB\n"
            "Time: 4.000 sec (0 m 4 s)\n"
            "Start Date: 2026:11:21 12:00:00\n"
        )
        entries = app_mod.parse_scan_summaries_from_log(sample_log)
        self.assertEqual(len(entries), 2)
        self.assertEqual(entries[0]["date"], "2026-11-21 10:00:12")
        self.assertEqual(entries[0]["threats"], 0)
        self.assertEqual(entries[0]["status"], "Clean")
        self.assertEqual(entries[1]["date"], "2026-11-21 12:00:00")
        self.assertEqual(entries[1]["threats"], 2)
        self.assertEqual(entries[1]["status"], "Threats Found")
        self.assertIn("0 files", entries[1]["scanned"])

    def test_build_systemd_schedule_units(self) -> None:
        svc_w, tmr_w, cfg_w = app_mod.build_systemd_schedule_units(
            "weekly", "Friday", "04:30", "full", ["/tmp"]
        )
        self.assertIn("SuccessExitStatus=0 1", svc_w)
        self.assertIn("--exclude-dir=^/proc", svc_w)
        self.assertIn("OnCalendar=Fri *-*-* 04:30:00", tmr_w)
        self.assertEqual(cfg_w["day_of_week"], "Fri")
        self.assertIn(f"# CLAMAV_GUI_CONFIG={json.dumps(cfg_w)}", tmr_w)

        svc_d, tmr_d, cfg_d = app_mod.build_systemd_schedule_units(
            "daily", "Monday", "22:05", "quick", ["/tmp", "relative/bad", "/nonexistent_xyz_123"]
        )
        self.assertIn('"/tmp"', svc_d)
        self.assertNotIn("relative/bad", svc_d)
        self.assertIn("OnCalendar=*-*-* 22:05:00", tmr_d)
        self.assertEqual(cfg_d["scan_type"], "quick")

        # Out-of-range and invalid times clamp/fallback cleanly
        _, tmr_bad, cfg_bad = app_mod.build_systemd_schedule_units(
            "weekly", "UnknownDay", "bad:time", "quick", ["/nonexistent_xyz_123"]
        )
        self.assertEqual(cfg_bad["day_of_week"], "Sun")
        self.assertEqual(cfg_bad["time_of_day"], "03:00")
        self.assertIn("OnCalendar=Sun *-*-* 03:00:00", tmr_bad)

    def test_get_quick_scan_targets_and_json_helpers(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            home = Path(tmpdir) / "userhome"
            (home / "Downloads").mkdir(parents=True)
            (home / "Schreibtisch").mkdir(parents=True)
            targets = app_mod.get_quick_scan_targets(str(home))
            self.assertIn(str(home / "Downloads"), targets)
            self.assertIn(str(home / "Schreibtisch"), targets)
            self.assertIn("/tmp", targets)

            empty_home = Path(tmpdir) / "emptyhome"
            empty_home.mkdir()
            with mock.patch("os.path.exists", side_effect=lambda p: p == str(empty_home)):
                self.assertEqual(app_mod.get_quick_scan_targets(str(empty_home)), [str(empty_home)])

            # load_json_file / save_json_file
            jpath = Path(tmpdir) / "nested" / "cfg.json"
            self.assertEqual(app_mod.load_json_file(jpath, {"a": 1}), {"a": 1})
            app_mod.save_json_file(jpath, {"language": "de", "n": 42})
            self.assertEqual(app_mod.load_json_file(jpath, {}), {"language": "de", "n": 42})
            jpath.write_text("{corrupt json", encoding="utf-8")
            self.assertEqual(app_mod.load_json_file(jpath, ["fallback"]), ["fallback"])


class TestProcAndFilesystemTelemetry(unittest.TestCase):
    """Tests for /proc inspection, PID validation, statvfs disk estimation, and background pre-counter."""

    def test_proc_readers_on_self_and_missing(self) -> None:
        pid = os.getpid()
        self.assertGreater(app_mod.parse_proc_uptime(), 0.0)
        stat = app_mod.parse_proc_stat(pid)
        self.assertIsNotNone(stat)
        assert stat is not None
        self.assertIn("state", stat)
        self.assertIn("nice", stat)

        status = app_mod.parse_proc_status(pid)
        self.assertEqual(status["uid"], os.getuid())
        self.assertGreater(status["rss_kb"], 0)

        cmdline = app_mod.read_proc_cmdline(pid)
        self.assertTrue(len(cmdline) >= 1)

        self.assertIsNone(app_mod.parse_proc_stat(99999999))
        self.assertEqual(app_mod.read_proc_cmdline(99999999), [])

    def test_discover_clamscan_processes_and_validate_pid(self) -> None:
        # Real PID 1 or self is not clamscan -> PermissionError
        with self.assertRaises(ValueError):
            app_mod._validate_clamscan_pid(1)
        with self.assertRaises(ProcessLookupError):
            app_mod._validate_clamscan_pid(99999999)
        with self.assertRaises(PermissionError):
            app_mod._validate_clamscan_pid(os.getpid())

        # Mocked /proc with a clamscan process and a python process
        with tempfile.TemporaryDirectory() as fake_proc:
            p1 = Path(fake_proc) / "111"
            p2 = Path(fake_proc) / "222"
            p3 = Path(fake_proc) / "333"
            (p1).mkdir()
            (p2).mkdir()
            (p3).mkdir()
            (p1 / "comm").write_text("python3\n", encoding="utf-8")
            (p2 / "comm").write_text("clamscan\n", encoding="utf-8")
            (p2 / "stat").write_text(_make_stat_line(222, "clamscan", "T", nice=19), encoding="utf-8")
            (p2 / "status").write_text(
                f"Uid:\t{os.getuid()} {os.getuid()} {os.getuid()} {os.getuid()}\n"
                "VmRSS:\t   20480 kB\n"
                "voluntary_ctxt_switches:\t10\n"
                "nonvoluntary_ctxt_switches:\t2\n",
                encoding="utf-8",
            )
            (p2 / "cmdline").write_bytes(b"/usr/bin/clamscan\x00-r\x00-i\x00--log=/tmp/t.log\x00/\x00")
            # Zombie clamscan must be filtered out and never reported as an active scan
            (p3 / "comm").write_text("clamscan\n", encoding="utf-8")
            (p3 / "stat").write_text(_make_stat_line(333, "clamscan", "Z", nice=0), encoding="utf-8")

            orig_listdir = os.listdir
            orig_open = open

            def fake_listdir(path: str = ".") -> list[str]:
                if path == "/proc":
                    return ["111", "222", "333", "self"]
                return orig_listdir(path)

            def fake_open(file: object, *args: object, **kwargs: object):  # type: ignore[no-untyped-def]
                if isinstance(file, str) and file.startswith("/proc/222/"):
                    return orig_open(os.path.join(fake_proc, "222", file[len("/proc/222/"):]), *args, **kwargs)
                if isinstance(file, str) and file.startswith("/proc/333/"):
                    return orig_open(os.path.join(fake_proc, "333", file[len("/proc/333/"):]), *args, **kwargs)
                if isinstance(file, str) and file.startswith("/proc/111/"):
                    return orig_open(os.path.join(fake_proc, "111", file[len("/proc/111/"):]), *args, **kwargs)
                return orig_open(file, *args, **kwargs)  # type: ignore[arg-type]

            with (
                mock.patch("os.listdir", side_effect=fake_listdir),
                mock.patch("builtins.open", side_effect=fake_open),
                mock.patch.object(app_mod, "parse_proc_uptime", return_value=100.0),
            ):
                found = app_mod.discover_clamscan_processes()

            self.assertEqual(len(found), 1)
            self.assertEqual(found[0]["pid"], 222)
            self.assertEqual(found[0]["state"], "T")
            self.assertEqual(found[0]["nice"], 19)
            self.assertEqual(found[0]["rss_kb"], 20480)
            self.assertEqual(found[0]["log_path"], "/tmp/t.log")
            self.assertTrue(found[0]["quiet_infected_only"])

    def test_inspect_proc_fds_and_io(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            fd_dir = Path(tmpdir) / "fd"
            fd_dir.mkdir()
            links = {
                "0": "/dev/null",
                "1": "/dev/pts/0",
                "3": "/proc/123/stat",
                "4": "/tmp/clamav-abc123/inner",
                "5": "/home/user/Downloads/archive.zip",
            }
            orig_listdir = os.listdir
            orig_readlink = os.readlink

            with (
                mock.patch("os.listdir", side_effect=lambda p: list(links.keys()) if p == "/proc/333/fd" else orig_listdir(p)),
                mock.patch("os.readlink", side_effect=lambda p: links[os.path.basename(p)] if p.startswith("/proc/333/fd/") else orig_readlink(p)),
            ):
                fd_res = app_mod._inspect_proc_fds(333)

            self.assertEqual(fd_res["current_file"], "/home/user/Downloads/archive.zip")
            self.assertEqual(fd_res["tmp_count"], 1)
            self.assertIsNone(fd_res["fd_error"])
            self.assertIn("/home/user/Downloads/archive.zip", fd_res["open_files"])

        io_self = app_mod._inspect_proc_io(os.getpid())
        self.assertIsInstance(io_self, dict)

    def test_statvfs_and_background_precount(self) -> None:
        root_used = app_mod.estimate_statvfs_used_bytes(["/"], cross_fs=False)
        self.assertGreater(root_used, 0)
        self.assertEqual(app_mod.estimate_statvfs_used_bytes(["/nonexistent_path_xyz_999"]), 0)

        with tempfile.TemporaryDirectory() as tmpdir:
            small_a = Path(tmpdir) / "small_a.bin"
            small_b = Path(tmpdir) / "sub" / "small_b.bin"
            large_c = Path(tmpdir) / "large_c.bin"
            excluded_dir = Path(tmpdir) / "skipme"
            excluded_file = excluded_dir / "ignored.bin"

            small_b.parent.mkdir(parents=True)
            excluded_dir.mkdir(parents=True)
            small_a.write_bytes(b"a" * 100)
            small_b.write_bytes(b"b" * 250)
            large_c.write_bytes(b"c" * 2000)
            excluded_file.write_bytes(b"x" * 50)

            self.assertEqual(app_mod.estimate_statvfs_used_bytes([str(small_a)]), 100)

            snap = app_mod.start_background_precount([tmpdir], [str(excluded_dir)], 500, cross_fs=True)
            deadline = time.monotonic() + 5.0
            while not snap.get("done") and time.monotonic() < deadline:
                time.sleep(0.05)
                snap = app_mod.get_precount_snapshot()

            self.assertTrue(snap.get("done"))
            self.assertEqual(snap["all_files"], 3)
            self.assertEqual(snap["all_bytes"], 2350)
            self.assertEqual(snap["eligible_files"], 2)
            self.assertEqual(snap["eligible_bytes"], 350)

            # Calling again with identical parameters returns cached completed snapshot
            snap_cached = app_mod.start_background_precount([tmpdir], [str(excluded_dir)], 500, cross_fs=True)
            self.assertTrue(snap_cached.get("done"))
            self.assertEqual(snap_cached["gen"], snap["gen"])

            # Empty targets finishes immediately without spawning find
            snap_empty = app_mod.start_background_precount(["/nonexistent_xyz_123"], [], 500, cross_fs=True)
            self.assertTrue(snap_empty.get("done"))
            self.assertFalse(snap_empty.get("running"))


class TestPrivilegedHelperHandlers(unittest.TestCase):
    """Tests for helper file/process/systemd/polkit/quarantine handlers with mocked privileged OS ops."""

    def test_read_log_chunk_and_ensure_log_readable(self) -> None:
        self.assertFalse(app_mod._read_log_chunk("", 0)["exists"])
        self.assertFalse(app_mod._read_log_chunk("/nonexistent_xyz_123.log", 0)["exists"])

        with tempfile.TemporaryDirectory() as tmpdir, mock.patch("os.geteuid", return_value=1000):
            log_file = Path(tmpdir) / "scan.log"
            log_file.write_text("line1\nline2\n", encoding="utf-8")

            chunk1 = app_mod._read_log_chunk(str(log_file), 0)
            self.assertTrue(chunk1["exists"])
            self.assertFalse(chunk1["reset"])
            self.assertEqual(chunk1["new_text"], "line1\nline2\n")

            with log_file.open("a", encoding="utf-8") as fh:
                fh.write("line3\n")
            chunk2 = app_mod._read_log_chunk(str(log_file), chunk1["new_offset"])
            self.assertFalse(chunk2["reset"])
            self.assertEqual(chunk2["new_text"], "line3\n")

            # Truncate file and confirm reset=True triggers
            log_file.write_text("new\n", encoding="utf-8")
            chunk3 = app_mod._read_log_chunk(str(log_file), chunk2["new_offset"])
            self.assertTrue(chunk3["reset"])
            self.assertEqual(chunk3["new_text"], "new\n")

            # _ensure_log_readable refuses non-/var/log paths as root, allows /var/log/clamav*
            os.chmod(log_file, 0o600)
            with mock.patch("os.geteuid", return_value=0):
                app_mod._ensure_log_readable(str(log_file))
                self.assertEqual(os.stat(log_file).st_mode & 0o777, 0o600)
                with mock.patch.object(app_mod, "_validate_helper_log_path", return_value=str(log_file)):
                    app_mod._ensure_log_readable(str(log_file))
            self.assertEqual(os.stat(log_file).st_mode & 0o777, 0o644)

    def test_quarantine_lifecycle_collisions_and_delete_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir, mock.patch("os.geteuid", return_value=1000):
            qdir = str(Path(tmpdir) / "quarantine")
            self.assertEqual(app_mod._helper_list_quarantine({"quarantine_dir": qdir})["items"], [])

            src_dir = Path(tmpdir) / "downloads"
            src_dir.mkdir()
            bad_file = src_dir / "payload.bin"
            bad_file.write_bytes(b"EICAR_TEST_DATA")

            qres = app_mod._helper_quarantine_file(
                {"path": str(bad_file), "quarantine_dir": qdir, "threat_name": "Test.Threat-1"}
            )
            self.assertFalse(bad_file.exists())
            self.assertTrue(Path(qres["dest"]).exists())
            self.assertEqual(os.stat(qdir).st_mode & 0o777, 0o700)

            # Collision handling: second file with same basename gets timestamp suffix
            bad_file.write_bytes(b"SECOND")
            qres2 = app_mod._helper_quarantine_file(
                {"path": str(bad_file), "quarantine_dir": qdir, "threat_name": "Test.Threat-2"}
            )
            self.assertNotEqual(qres2["name"], "payload.bin")

            listed = app_mod._helper_list_quarantine({"quarantine_dir": qdir})["items"]
            self.assertEqual(len(listed), 2)

            # Path safety validations
            with self.assertRaises(ValueError):
                app_mod._helper_quarantine_file({"path": "relative.bin", "quarantine_dir": qdir})
            with self.assertRaises(FileNotFoundError):
                app_mod._helper_quarantine_file({"path": "/nonexistent/file.bin", "quarantine_dir": qdir})
            with self.assertRaises(ValueError):
                app_mod._helper_delete_quarantine({"name": "../evil", "quarantine_dir": qdir})
            with self.assertRaises(ValueError):
                app_mod._helper_delete_quarantine({"name": app_mod.QUARANTINE_MANIFEST, "quarantine_dir": qdir})

            # Restore back to original path and verify FileExistsError on second restore to same target
            rres = app_mod._helper_restore_quarantine({"name": "payload.bin", "quarantine_dir": qdir})
            self.assertEqual(rres["restored_to"], str(bad_file))
            self.assertTrue(bad_file.exists())
            with self.assertRaises(FileExistsError):
                app_mod._helper_restore_quarantine({"name": qres2["name"], "quarantine_dir": qdir})

            # Permanently delete remaining quarantined item
            dres = app_mod._helper_delete_quarantine({"name": qres2["name"], "quarantine_dir": qdir})
            self.assertEqual(dres["deleted"], qres2["name"])
            self.assertEqual(app_mod._helper_list_quarantine({"quarantine_dir": qdir})["items"], [])

            # _helper_delete_file
            with self.assertRaises(ValueError):
                app_mod._helper_delete_file({"path": "relative.txt"})
            with self.assertRaises(FileNotFoundError):
                app_mod._helper_delete_file({"path": "/nonexistent_file_123"})
            del_res = app_mod._helper_delete_file({"path": str(bad_file)})
            self.assertEqual(del_res["deleted"], str(bad_file))
            self.assertFalse(bad_file.exists())

    def test_signal_priority_and_start_scan_handlers(self) -> None:
        with self.assertRaises(ValueError):
            app_mod._helper_signal_proc({"pid": 1234, "sig": "SIGHUP"})
        with self.assertRaises(ValueError):
            app_mod._helper_set_priority({"pid": 1234, "mode": "realtime"})

        with (
            mock.patch.object(app_mod, "_validate_clamscan_pid"),
            mock.patch("os.kill") as mock_kill,
        ):
            res = app_mod._helper_signal_proc({"pid": 4321, "sig": "SIGSTOP"})
            self.assertEqual(res, {"pid": 4321, "sig": "SIGSTOP"})
            mock_kill.assert_called_once_with(4321, signal.SIGSTOP)

        # Stopping a paused (SIGSTOP -> state 'T') scan sends SIGTERM + SIGCONT and escalates to SIGKILL if alive
        with (
            mock.patch.object(app_mod, "_validate_clamscan_pid"),
            mock.patch.object(
                app_mod,
                "parse_proc_stat",
                side_effect=[{"state": "T"}, {"state": "R"}, {"state": "R"}, None],
            ),
            mock.patch("os.path.exists", return_value=True),
            mock.patch("time.monotonic", side_effect=[0.0, 0.1, 0.7, 0.7, 0.8]),
            mock.patch("time.sleep"),
            mock.patch("os.kill") as mock_kill2,
        ):
            res2 = app_mod._helper_signal_proc({"pid": 4321, "sig": "SIGTERM"})
            self.assertEqual(res2, {"pid": 4321, "sig": "SIGTERM"})
            self.assertEqual(
                [c[0] for c in mock_kill2.call_args_list],
                [(4321, signal.SIGTERM), (4321, signal.SIGCONT), (4321, signal.SIGKILL), (4321, signal.SIGCONT)],
            )

        with (
            mock.patch.object(app_mod, "_validate_clamscan_pid"),
            mock.patch("subprocess.run", return_value=mock.Mock(returncode=0, stdout="old 0, new 19", stderr="")) as mock_run,
        ):
            prio = app_mod._helper_set_priority({"pid": 4321, "mode": "idle"})
            self.assertEqual(prio["mode"], "idle")
            self.assertEqual(mock_run.call_count, 2)
            self.assertEqual(mock_run.call_args_list[0][0][0], ["renice", "-n", "19", "-p", "4321"])
            self.assertEqual(mock_run.call_args_list[1][0][0], ["ionice", "-c", "3", "-p", "4321"])

        # _helper_start_scan validation + log truncation
        with self.assertRaises(ValueError):
            app_mod._helper_start_scan({"cmd_args": []})
        with self.assertRaises(PermissionError):
            app_mod._helper_start_scan({"cmd_args": ["/bin/rm", "-rf", "/"]})

        with tempfile.TemporaryDirectory() as tmpdir, mock.patch("os.geteuid", return_value=1000):
            log_file = Path(tmpdir) / "scan.log"
            log_file.write_text("old data\n", encoding="utf-8")
            fake_proc = mock.Mock(pid=5555)
            with mock.patch("subprocess.Popen", return_value=fake_proc) as mock_popen:
                started = app_mod._helper_start_scan(
                    {"cmd_args": ["clamscan", "-r", "/tmp"], "log_path": str(log_file), "truncate_log": True}
                )
            self.assertEqual(started["pid"], 5555)
            self.assertEqual(log_file.read_text(encoding="utf-8"), "")
            self.assertEqual(mock_popen.call_args[1]["stderr"], subprocess.STDOUT)

    def test_freshclam_polkit_and_schedule_handlers(self) -> None:
        # _detect_freshclam_services + _helper_run_freshclam (restarts service even when freshclam errors)
        calls: list[list[str]] = []

        def fake_run(cmd: list[str], **_kw: object) -> mock.Mock:
            calls.append(cmd)
            if cmd[:2] == ["systemctl", "is-active"] and cmd[2] == "freshclam.service":
                return mock.Mock(returncode=0, stdout="active", stderr="")
            if cmd[:2] == ["systemctl", "is-active"]:
                return mock.Mock(returncode=3, stdout="inactive", stderr="")
            if cmd[:2] == ["systemctl", "stop"]:
                return mock.Mock(returncode=0, stdout="", stderr="")
            if cmd[:2] == ["systemctl", "start"]:
                return mock.Mock(returncode=0, stdout="", stderr="")
            if os.path.basename(cmd[0]) == "freshclam":
                return mock.Mock(returncode=1, stdout="Trying mirror", stderr="DNS fail")
            return mock.Mock(returncode=0, stdout="", stderr="")

        with (
            mock.patch("shutil.which", return_value="/usr/bin/freshclam"),
            mock.patch("os.path.exists", return_value=True),
            mock.patch("subprocess.run", side_effect=fake_run),
        ):
            fc = app_mod._helper_run_freshclam({})

        self.assertFalse(fc["success"])
        self.assertIn("Temporarily stopped freshclam.service.", fc["output"])
        self.assertIn("Restarted freshclam.service.", fc["output"])
        self.assertIn("DNS fail", fc["output"])

        # Missing freshclam binary raises FileNotFoundError
        with mock.patch("shutil.which", return_value=None), mock.patch("os.path.exists", return_value=False):
            with self.assertRaises(FileNotFoundError):
                app_mod._helper_run_freshclam({})

        # _helper_install_polkit_rule & _helper_set_schedule / _helper_get_schedule with temp paths
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            orig_rule = app_mod.POLKIT_RULE_PATH
            orig_svc = app_mod.SYSTEMD_SERVICE_PATH
            orig_tmr = app_mod.SYSTEMD_TIMER_PATH
            try:
                app_mod.POLKIT_RULE_PATH = str(tmp_path / "polkit" / "50-clamav.rules")
                app_mod.SYSTEMD_SERVICE_PATH = str(tmp_path / "clamav-gui-scan.service")
                app_mod.SYSTEMD_TIMER_PATH = str(tmp_path / "clamav-gui-scan.timer")

                with self.assertRaises(ValueError):
                    app_mod._helper_install_polkit_rule({"username": ""})
                with self.assertRaises(KeyError):
                    app_mod._helper_install_polkit_rule({"username": "no_such_user_xyz_999"})

                import getpass

                cur_user = getpass.getuser()
                p_res = app_mod._helper_install_polkit_rule({"username": cur_user})
                rule_txt = Path(p_res["rule_path"]).read_text(encoding="utf-8")
                self.assertIn(f'subject.user == {json.dumps(cur_user)}', rule_txt)
                self.assertIn("org.freedesktop.policykit.exec", rule_txt)
                self.assertIn(app_mod.SCRIPT_PATH, rule_txt)

                # Systemd schedule write + read back
                def fake_sys_run(cmd: list[str], **_kw: object) -> mock.Mock:
                    if cmd[:2] == ["systemctl", "is-enabled"]:
                        return mock.Mock(returncode=0, stdout="enabled\n", stderr="")
                    if cmd[:2] == ["systemctl", "list-timers"]:
                        return mock.Mock(returncode=0, stdout="Sun 2026-11-22 04:15:00 CET 6h left\n", stderr="")
                    return mock.Mock(returncode=0, stdout="", stderr="")

                with mock.patch("subprocess.run", side_effect=fake_sys_run):
                    s_res = app_mod._helper_set_schedule(
                        {
                            "enabled": True,
                            "frequency": "weekly",
                            "day_of_week": "Tue",
                            "time_of_day": "04:15",
                            "scan_type": "quick",
                            "quick_targets": ["/tmp"],
                        }
                    )
                self.assertTrue(s_res["enabled"])
                self.assertEqual(s_res["day_of_week"], "Tue")
                self.assertEqual(s_res["time_of_day"], "04:15")
                self.assertIn("2026-11-22", s_res["next_run"])
                self.assertTrue(os.path.exists(app_mod.SYSTEMD_SERVICE_PATH))
                self.assertTrue(os.path.exists(app_mod.SYSTEMD_TIMER_PATH))
            finally:
                app_mod.POLKIT_RULE_PATH = orig_rule
                app_mod.SYSTEMD_SERVICE_PATH = orig_svc
                app_mod.SYSTEMD_TIMER_PATH = orig_tmr


class TestHelperRPCSubprocessAndClient(unittest.TestCase):
    """Integration tests spawning `--helper` and verifying HelperClient error/disconnect handling."""

    def test_helper_rpc_protocol_and_security_guards(self) -> None:
        proc = subprocess.Popen(
            [sys.executable, app_mod.SCRIPT_PATH, "--helper"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
        )
        client = app_mod.HelperClient()
        try:
            assert proc.stdout is not None
            ready = proc.stdout.readline().strip()
            self.assertIn('"ready"', ready)
            client._attach(proc, os.geteuid())

            ping_res = client.call("ping")
            self.assertEqual(ping_res["pid"], proc.pid)

            with self.assertRaisesRegex(RuntimeError, "Unknown action"):
                client.call("no_such_action")

            # When helper runs as container root, non-root log/quarantine overrides must be refused
            # while non-root helper processes (UID != 0) operate inside custom temp directories.
            if os.geteuid() == 0:
                insp_empty = client.call("inspect_proc", {"pid": os.getpid(), "log_path": "", "log_offset": 0})
                self.assertTrue(insp_empty["proc"]["alive"])
                with self.assertRaises(RuntimeError):
                    client.call("inspect_proc", {"pid": os.getpid(), "log_path": app_mod.SCRIPT_PATH, "log_offset": 0})
                with self.assertRaises(RuntimeError):
                    client.call("quarantine_file", {"path": app_mod.SCRIPT_PATH, "quarantine_dir": "/tmp/evilq"})
            else:
                insp_res = client.call(
                    "inspect_proc",
                    {"pid": os.getpid(), "log_path": app_mod.SCRIPT_PATH, "log_offset": 0},
                )
                self.assertTrue(insp_res["proc"]["alive"])
                self.assertTrue(insp_res["log"]["exists"])

            # signal_proc & set_priority must refuse non-clamscan processes
            with self.assertRaises(RuntimeError):
                client.call("signal_proc", {"pid": os.getpid(), "sig": "SIGSTOP"})
            with self.assertRaises(RuntimeError):
                client.call("set_priority", {"pid": os.getpid(), "mode": "idle"})

            if os.geteuid() != 0:
                with tempfile.TemporaryDirectory() as tmpdir:
                    qdir = str(Path(tmpdir) / "q")
                    sample = Path(tmpdir) / "sample.dat"
                    sample.write_bytes(b"virus")
                    client.call("quarantine_file", {"path": str(sample), "quarantine_dir": qdir, "threat_name": "Sig.X"})
                    items = client.call("list_quarantine", {"quarantine_dir": qdir})["items"]
                    self.assertEqual(len(items), 1)
                    client.call("restore_quarantine", {"name": "sample.dat", "quarantine_dir": qdir})
                    self.assertTrue(sample.exists())
        finally:
            client.close()

    def test_helper_client_auth_wrappers_and_disconnect(self) -> None:
        client = app_mod.HelperClient()
        self.assertFalse(client.is_connected)
        with self.assertRaises(RuntimeError):
            client.call("ping")

        # Simulated sudo success (uid=0) + EOF disconnect callback
        disconnected: list[bool] = []
        client.on_disconnect = lambda: disconnected.append(True)
        fake_proc = mock.Mock()
        fake_proc.poll.return_value = None
        fake_proc.stdin = mock.Mock()
        fake_proc.stdout = mock.Mock()
        fake_proc.stdout.readline.side_effect = ['{"type": "ready", "uid": 0}\n', ""]
        fake_proc.stdout.__iter__ = mock.Mock(return_value=iter([]))
        fake_proc.stderr = mock.Mock()
        fake_proc.stderr.readline.side_effect = [""]
        with mock.patch("subprocess.Popen", return_value=fake_proc):
            ok, msg = client.start_with_sudo("secret")
        self.assertTrue(ok)
        self.assertIn("sudo", msg)

        # Wait for reader thread EOF -> invokes on_disconnect callback
        deadline = time.monotonic() + 2.0
        while not disconnected and time.monotonic() < deadline:
            time.sleep(0.02)
        self.assertEqual(disconnected, [True])
        self.assertFalse(client.is_connected)

        # sudo failure (wrong password on stderr)
        bad_proc = mock.Mock()
        bad_proc.poll.return_value = 1
        bad_proc.stdin = mock.Mock()
        bad_proc.stdout = mock.Mock()
        bad_proc.stdout.readline.side_effect = [""]
        bad_proc.stderr = mock.Mock()
        bad_proc.stderr.readline.side_effect = ["Sorry, try again.\n", ""]
        with mock.patch("subprocess.Popen", return_value=bad_proc):
            ok2, msg2 = client.start_with_sudo("wrong")
        self.assertFalse(ok2)
        self.assertIn("Sorry", msg2)

        # pkexec cancelled (rc 126)
        pk_proc = mock.Mock()
        pk_proc.poll.return_value = None
        pk_proc.stdout = mock.Mock()
        pk_proc.stdout.readline.side_effect = [""]
        pk_proc.stderr = mock.Mock()
        pk_proc.stderr.read.return_value = ""
        pk_proc.wait.return_value = 126
        with mock.patch("subprocess.Popen", return_value=pk_proc):
            ok3, msg3 = client.start_with_pkexec()
        self.assertFalse(ok3)
        self.assertIn("cancelled", msg3.lower())

        # Missing sudo / pkexec binaries degrade cleanly without raising FileNotFoundError
        with mock.patch("subprocess.Popen", side_effect=FileNotFoundError("sudo")):
            ok4, msg4 = client.start_with_sudo_nopass()
            ok5, msg5 = client.start_with_sudo("pw")
            ok6, msg6 = client.start_with_pkexec()
        self.assertFalse(ok4)
        self.assertFalse(ok5)
        self.assertFalse(ok6)
        self.assertIn("sudo", msg4)
        self.assertIn("sudo", msg5)
        self.assertIn("pkexec", msg6)


class TestLocalizationAndCLI(unittest.TestCase):
    """Tests for German/English translation completeness, locale detection, and CLI entry points."""

    def test_translation_keys_placeholders_and_fallbacks(self) -> None:
        expected_langs = {"en", "de", "es", "fr", "pt", "zh", "ja", "ru"}
        self.assertEqual(set(app_mod.TRANSLATIONS.keys()), expected_langs)
        en_dict = app_mod.TRANSLATIONS["en"]
        formatter = string.Formatter()

        for lang_code, lang_dict in app_mod.TRANSLATIONS.items():
            self.assertEqual(set(en_dict.keys()), set(lang_dict.keys()), msg=f"Key mismatch in '{lang_code}'")
            for key in en_dict:
                self.assertTrue(lang_dict[key].strip(), msg=f"Empty {lang_code} value for '{key}'")
                en_fields = {fname for _, fname, _, _ in formatter.parse(en_dict[key]) if fname is not None}
                lang_fields = {fname for _, fname, _, _ in formatter.parse(lang_dict[key]) if fname is not None}
                self.assertEqual(
                    en_fields, lang_fields, msg=f"Placeholder mismatch for '{lang_code}.{key}'"
                )

        # Fallback to English for unknown language and key name for missing key
        self.assertEqual(app_mod.tr("ko", "app_title"), en_dict["app_title"])
        self.assertEqual(app_mod.tr("de", "nonexistent_key_xyz"), "nonexistent_key_xyz")

    def test_detect_default_language(self) -> None:
        # Saved settings no longer override OS locale now that language picker is removed
        with mock.patch.dict(os.environ, {"LANG": "es_ES.UTF-8", "LC_ALL": "", "LC_MESSAGES": "", "LANGUAGE": ""}):
            self.assertEqual(app_mod.detect_default_language({"language": "de"}), "es")

        locale_cases = (
            ("en_US.UTF-8", "en"),
            ("de_AT.UTF-8", "de"),
            ("es_MX.UTF-8", "es"),
            ("fr_FR.UTF-8", "fr"),
            ("pt_BR.UTF-8", "pt"),
            ("zh_CN.UTF-8", "zh"),
            ("ja_JP.UTF-8", "ja"),
            ("ru_RU.UTF-8", "ru"),
            ("C", "en"),
        )
        for loc_str, expected in locale_cases:
            with mock.patch.dict(
                os.environ, {"LANG": loc_str, "LC_ALL": "", "LC_MESSAGES": "", "LANGUAGE": ""}
            ):
                self.assertEqual(app_mod.detect_default_language({}), expected)

        with mock.patch.dict(
            os.environ, {"LANG": "C", "LC_ALL": "", "LC_MESSAGES": "", "LANGUAGE": "xx_YY:ja_JP:en_US"}
        ):
            self.assertEqual(app_mod.detect_default_language({}), "ja")

    def test_main_cli_dispatch(self) -> None:
        with mock.patch.object(sys, "argv", ["clamav_gui.py", "--self-test"]), mock.patch.object(
            app_mod, "run_self_test", return_value=0
        ) as mock_st:
            self.assertEqual(app_mod.main(), 0)
            mock_st.assert_called_once()

        with mock.patch.object(sys, "argv", ["clamav_gui.py", "--helper"]), mock.patch.object(
            app_mod, "run_helper", return_value=0
        ) as mock_h:
            self.assertEqual(app_mod.main(), 0)
            mock_h.assert_called_once()

        with mock.patch.object(sys, "argv", ["clamav_gui.py", "--lang", "de"]), mock.patch.object(
            app_mod, "launch_gui", return_value=0
        ) as mock_gui:
            self.assertEqual(app_mod.main(), 0)
            mock_gui.assert_called_once_with(lang="de")

        with mock.patch.object(sys, "argv", ["clamav_gui.py"]), mock.patch.object(
            app_mod, "launch_gui", return_value=0
        ) as mock_gui2:
            self.assertEqual(app_mod.main(), 0)
            mock_gui2.assert_called_once_with(lang=None)


class TestDesktopEnvironmentIntegration(unittest.TestCase):
    """Tests for KDE Plasma / GNOME environment detection and file-manager reveal commands."""

    def test_detect_desktop_environment(self) -> None:
        with mock.patch.dict(os.environ, {"XDG_CURRENT_DESKTOP": "GNOME", "DESKTOP_SESSION": "gnome"}, clear=False):
            self.assertEqual(app_mod.detect_desktop_environment(), "gnome")
        with mock.patch.dict(os.environ, {"XDG_CURRENT_DESKTOP": "ubuntu:GNOME", "DESKTOP_SESSION": "ubuntu"}, clear=False):
            self.assertEqual(app_mod.detect_desktop_environment(), "gnome")
        with mock.patch.dict(os.environ, {"XDG_CURRENT_DESKTOP": "KDE", "DESKTOP_SESSION": "plasma"}, clear=False):
            self.assertEqual(app_mod.detect_desktop_environment(), "kde")
        with mock.patch.dict(
            os.environ, {"XDG_CURRENT_DESKTOP": "", "XDG_SESSION_DESKTOP": "", "DESKTOP_SESSION": ""}, clear=False
        ):
            self.assertEqual(app_mod.detect_desktop_environment(), "other")

    def test_build_reveal_file_command_kde_gnome_and_fallbacks(self) -> None:
        # KDE selects Dolphin
        with mock.patch("shutil.which", side_effect=lambda b: "/usr/bin/dolphin" if b == "dolphin" else None):
            self.assertEqual(
                app_mod.build_reveal_file_command("/tmp/suspect.bin", desktop="kde"),
                ["dolphin", "--select", "/tmp/suspect.bin"],
            )

        # GNOME selects Nautilus when present
        with mock.patch("shutil.which", side_effect=lambda b: "/usr/bin/nautilus" if b == "nautilus" else None):
            self.assertEqual(
                app_mod.build_reveal_file_command("/tmp/suspect.bin", desktop="gnome"),
                ["nautilus", "--select", "/tmp/suspect.bin"],
            )

        # GNOME uses freedesktop FileManager1 via gdbus when nautilus binary isn't invoked directly
        with mock.patch("shutil.which", side_effect=lambda b: "/usr/bin/gdbus" if b == "gdbus" else None), mock.patch.dict(
            os.environ, {"DBUS_SESSION_BUS_ADDRESS": "unix:path=/run/user/1000/bus"}
        ):
            cmd = app_mod.build_reveal_file_command("/tmp/suspect.bin", desktop="gnome")
            self.assertEqual(cmd[0], "gdbus")
            self.assertIn("org.freedesktop.FileManager1.ShowItems", cmd)
            self.assertIn("file:///tmp/suspect.bin", cmd[-2])

        # Generic fallback to xdg-open parent dir
        with mock.patch("shutil.which", return_value=None):
            self.assertEqual(
                app_mod.build_reveal_file_command("/tmp/suspect.bin", desktop="gnome"),
                ["xdg-open", "/tmp"],
            )


class TestSecurityHardening(unittest.TestCase):
    """Security regression tests for root helper privilege boundaries and input sanitization."""

    def test_validate_clamscan_args_rejects_untrusted_binaries_and_flags(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            fake_bin = Path(tmpdir) / "clamscan"
            fake_bin.write_text("#!/bin/sh\nid\n", encoding="utf-8")
            fake_bin.chmod(0o755)

            with mock.patch("os.geteuid", return_value=0):
                # Untrusted clamscan binary outside system dirs must be rejected
                with self.assertRaises(PermissionError):
                    app_mod._validate_clamscan_args([str(fake_bin), "-r", "/tmp"])

                # Disallowed flags (--tempdir, --database, --virus-event) must be rejected
                with mock.patch.object(app_mod, "_is_secure_root_owned_path", return_value=True):
                    for bad_flag in ("--tempdir=/tmp/x", "--database=/tmp/db", "--virus-event=sh", "-f"):
                        with self.assertRaises(PermissionError):
                            app_mod._validate_clamscan_args(["/usr/bin/clamscan", bad_flag, "/tmp"])

                    # Untrusted log path outside /var/log/ must be rejected
                    with self.assertRaises(PermissionError):
                        app_mod._validate_clamscan_args(["/usr/bin/clamscan", "--log=/etc/shadow", "/tmp"])

                    # Valid system scan passes
                    ok_args = app_mod._validate_clamscan_args(
                        ["/usr/bin/clamscan", "-r", "-i", f"--log={app_mod.DEFAULT_LOG_PATH}", "/tmp"]
                    )
                    self.assertTrue(os.path.basename(ok_args[0]) == "clamscan")

    def test_log_path_validation_blocks_symlinks_and_arbitrary_files_as_root(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            link_path = Path(tmpdir) / "clamav-scan.log"
            link_path.symlink_to("/etc/passwd")

            with self.assertRaises(PermissionError):
                app_mod._validate_helper_log_path(str(link_path))

            with mock.patch("os.geteuid", return_value=0):
                with self.assertRaises(PermissionError):
                    app_mod._validate_helper_log_path("/etc/shadow")
                with self.assertRaises(PermissionError):
                    app_mod._validate_helper_log_path("/tmp/not-allowed.log")
                self.assertEqual(
                    app_mod._validate_helper_log_path(app_mod.DEFAULT_LOG_PATH),
                    app_mod.DEFAULT_LOG_PATH,
                )

    def test_polkit_rule_refuses_user_writable_script_and_enforces_local_active(self) -> None:
        with mock.patch("os.geteuid", return_value=0), mock.patch.object(
            app_mod, "_is_secure_root_owned_path", side_effect=lambda p: p != app_mod.SCRIPT_PATH
        ):
            with self.assertRaises(PermissionError):
                app_mod._helper_install_polkit_rule({"username": "root"})

        # Caller mismatch under PKEXEC_UID rejected
        with mock.patch.dict(os.environ, {"PKEXEC_UID": str(os.getuid())}), mock.patch(
            "pwd.getpwuid", return_value=mock.Mock(pw_name="alice")
        ):
            with self.assertRaises(PermissionError):
                app_mod._helper_install_polkit_rule({"username": "bob"})

        # Generated rule includes subject.active && subject.local
        with tempfile.TemporaryDirectory() as tmpdir:
            orig_rule = app_mod.POLKIT_RULE_PATH
            try:
                app_mod.POLKIT_RULE_PATH = str(Path(tmpdir) / "49.rules")
                import getpass

                cur = getpass.getuser()
                res = app_mod._helper_install_polkit_rule({"username": cur})
                content = Path(res["rule_path"]).read_text(encoding="utf-8")
                self.assertIn("subject.active && subject.local", content)
            finally:
                app_mod.POLKIT_RULE_PATH = orig_rule

    def test_protected_system_paths_and_quarantine_root_confinement(self) -> None:
        for protected in ("/etc/passwd", "/usr/bin/python3", app_mod.SCRIPT_PATH):
            with self.assertRaises(PermissionError):
                app_mod._helper_delete_file({"path": protected})
            with self.assertRaises(PermissionError):
                app_mod._helper_quarantine_file({"path": protected, "quarantine_dir": "/tmp/q"})

        # Root mode rejects arbitrary quarantine_dir outside DEFAULT_QUARANTINE_DIR
        with mock.patch("os.geteuid", return_value=0):
            with self.assertRaises(PermissionError):
                app_mod._resolve_quarantine_dir("/tmp/attacker_quarantine")

        # Root-restored file from /var/secret must NOT be chowned to /home/<user>/
        with tempfile.TemporaryDirectory() as tmpdir, mock.patch("os.geteuid", return_value=1000):
            qdir = Path(tmpdir) / "q"
            qdir.mkdir()
            (qdir / "secret").write_bytes(b"rootdata")
            app_mod._save_quarantine_manifest(
                str(qdir),
                {"secret": {"original_path": "/var/secret", "threat_name": "X", "date": "2026-11-21", "size": 8}},
            )
            dest = Path(tmpdir) / "home" / "alice" / "stolen"
            with mock.patch("os.chown") as mock_chown:
                res = app_mod._helper_restore_quarantine(
                    {"name": "secret", "quarantine_dir": str(qdir), "dest_path": str(dest)}
                )
            self.assertTrue(Path(res["restored_to"]).exists())
            mock_chown.assert_not_called()

    def test_systemd_unit_rejects_directive_injection_and_gdbus_quotes(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            bad_dir = Path(tmpdir) / 'evil"\nExecStart=evil'
            bad_dir.mkdir()
            svc, _, _ = app_mod.build_systemd_schedule_units(
                "daily", "Mon", "02:00", "quick", [str(bad_dir)]
            )
            self.assertNotIn("ExecStart=evil", svc)
            self.assertIn('"/home" "/tmp"', svc)

        # GVariant quote escaping for relative paths in build_reveal_file_command
        with mock.patch("shutil.which", side_effect=lambda b: "/usr/bin/gdbus" if b == "gdbus" else None), mock.patch.dict(
            os.environ, {"DBUS_SESSION_BUS_ADDRESS": "unix:path=/tmp/bus"}
        ):
            cmd = app_mod.build_reveal_file_command("rel'file.txt", desktop="gnome")
            self.assertIn("%27", cmd[-2])

    def test_check_system_dependencies_and_virus_database(self) -> None:
        with tempfile.TemporaryDirectory() as db_dir:
            # Empty db_dir and missing binaries
            with mock.patch("shutil.which", return_value=None), mock.patch(
                "os.path.isfile", return_value=False
            ):
                deps_missing = app_mod.check_system_dependencies(db_dir=db_dir)
            self.assertFalse(deps_missing["has_clamscan"])
            self.assertFalse(deps_missing["has_freshclam"])
            self.assertFalse(deps_missing["has_virus_db"])
            self.assertEqual(deps_missing["db_files_count"], 0)
            self.assertIn("clamscan", deps_missing["missing_required"])
            self.assertIn("freshclam", deps_missing["missing_required"])
            self.assertIn("notify-send", deps_missing["missing_optional"])

            # Populate database files and mock installed tools
            (Path(db_dir) / "main.cvd").write_bytes(b"CVD")
            (Path(db_dir) / "daily.cld").write_bytes(b"CLD")
            with mock.patch("shutil.which", side_effect=lambda name: f"/usr/bin/{name}"):
                deps_ok = app_mod.check_system_dependencies(db_dir=db_dir)
            self.assertTrue(deps_ok["has_clamscan"])
            self.assertTrue(deps_ok["has_freshclam"])
            self.assertTrue(deps_ok["has_virus_db"])
            self.assertEqual(deps_ok["db_files_count"], 2)
            self.assertEqual(deps_ok["missing_required"], [])
            self.assertEqual(deps_ok["missing_optional"], [])

    def test_helper_client_timeout_nopass_pkexec_and_verify_os_script(self) -> None:
        # HelperClient call timeout raises TimeoutError
        client = app_mod.HelperClient()
        fake_proc = mock.Mock()
        fake_proc.poll.return_value = None
        fake_proc.stdin = mock.Mock()
        client._proc = fake_proc
        with self.assertRaises(TimeoutError):
            client.call("ping", timeout=0.05)
        client._proc = None

        # start_with_sudo_nopass success & fail
        nopw_ok = mock.Mock()
        nopw_ok.poll.return_value = None
        nopw_ok.stdout = mock.Mock()
        nopw_ok.stdout.__iter__ = mock.Mock(return_value=iter([]))
        nopw_ok.stdout.readline.return_value = '{"type": "ready", "uid": 0}\n'
        nopw_ok.stderr = mock.Mock()
        with mock.patch("subprocess.Popen", return_value=nopw_ok):
            ok, msg = client.start_with_sudo_nopass()
        self.assertTrue(ok)
        self.assertIn("cached", msg)
        client._proc = None

        # _helper_get_schedule reading existing timer file
        with tempfile.TemporaryDirectory() as tmpdir:
            tmr = Path(tmpdir) / "clamav.timer"
            tmr.write_text('# CLAMAV_GUI_CONFIG={"frequency":"daily","day_of_week":"Mon","time_of_day":"01:15","scan_type":"full"}\n', encoding="utf-8")
            orig_tmr = app_mod.SYSTEMD_TIMER_PATH
            try:
                app_mod.SYSTEMD_TIMER_PATH = str(tmr)
                with mock.patch("subprocess.run", return_value=mock.Mock(returncode=1, stdout="disabled", stderr="")):
                    sched = app_mod._helper_get_schedule({})
                self.assertEqual(sched["frequency"], "daily")
                self.assertEqual(sched["scan_type"], "full")
                self.assertFalse(sched["enabled"])
            finally:
                app_mod.SYSTEMD_TIMER_PATH = orig_tmr

        # packaging/verify_installed_os.py checks on temporary staged files
        sys.path.insert(0, str(Path(__file__).resolve().parent / "packaging"))
        import verify_installed_os as vos  # type: ignore[import-not-found]

        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            fake_bin = root / "clamav-security-center"
            fake_bin.write_text("#!/bin/sh\necho '[self-test] ALL CHECKS PASSED.'\n", encoding="utf-8")
            fake_bin.chmod(0o755)
            fake_alias = root / "clamav-kde-gui"
            fake_alias.symlink_to(fake_bin)
            fake_run = root / "run.sh"
            fake_run.write_text("#!/bin/sh\n", encoding="utf-8")
            fake_run.chmod(0o755)
            fake_desk = root / "clamav-kde-gui.desktop"
            fake_desk.write_text(
                f"[Desktop Entry]\nType=Application\nName=ClamAV Security Center\nName[de]=ClamAV Sicherheitszentrum\n"
                f"Exec={fake_bin}\nIcon=clamav-kde-gui\nCategories=System;Security;Qt;KDE;GNOME;\n",
                encoding="utf-8",
            )
            fake_icon = root / "clamav-kde-gui.svg"
            fake_icon.write_text("<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 64 64'/>", encoding="utf-8")
            with (
                mock.patch.object(vos, "INSTALLED_BIN", fake_bin),
                mock.patch.object(vos, "INSTALLED_ALIAS", fake_alias),
                mock.patch.object(vos, "INSTALLED_PY", Path(app_mod.SCRIPT_PATH)),
                mock.patch.object(vos, "INSTALLED_RUN", fake_run),
                mock.patch.object(vos, "INSTALLED_DESKTOP", fake_desk),
                mock.patch.object(vos, "INSTALLED_ICON", fake_icon),
                mock.patch("subprocess.run", return_value=mock.Mock(returncode=0, stdout="pkg-1.0", stderr="")),
            ):
                vos.verify_package_files("rpm")
                vos.verify_start_menu_entry("gnome")


class TestScheduleAndCancellation(unittest.TestCase):
    """Real-subprocess and filesystem tests for scan cancellation, precount cancel, and systemd schedules."""

    def test_terminate_pid_gracefully_handles_running_paused_and_sigterm_ignoring_children(self) -> None:
        # 1. Process that ignores SIGTERM -> escalates to SIGKILL and waits until exited
        ign = subprocess.Popen(
            [sys.executable, "-c", "import signal, time; signal.signal(signal.SIGTERM, signal.SIG_IGN); time.sleep(30)"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        try:
            time.sleep(0.1)
            self.assertIsNone(ign.poll())
            app_mod._terminate_pid_gracefully(ign.pid)
            rc = ign.wait(timeout=1.0)
            self.assertEqual(rc, -signal.SIGKILL)
        finally:
            if ign.poll() is None:
                ign.kill()
                ign.wait(timeout=1.0)

        # 2. SIGSTOP-paused process -> SIGTERM + SIGCONT kills it cleanly without leaving T state
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
            app_mod._terminate_pid_gracefully(paused.pid)
            rc = paused.wait(timeout=1.0)
            self.assertNotEqual(rc, None)
        finally:
            if paused.poll() is None:
                os.kill(paused.pid, signal.SIGCONT)
                paused.kill()
                paused.wait(timeout=1.0)

    def test_cancel_background_precount_stops_worker(self) -> None:
        app_mod.cancel_background_precount()
        snap = app_mod.start_background_precount(["/usr"], [], 10 * 1024 * 1024, False)
        self.assertTrue(snap["running"])
        app_mod.cancel_background_precount()
        after = app_mod.get_precount_snapshot()
        self.assertFalse(after["running"])
        self.assertFalse(after["done"])

    def test_schedule_enable_disable_roundtrip_and_sanitization(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            svc = Path(tmpdir) / "clamav-gui-scan.service"
            tmr = Path(tmpdir) / "clamav-gui-scan.timer"
            orig_svc, orig_tmr = app_mod.SYSTEMD_SERVICE_PATH, app_mod.SYSTEMD_TIMER_PATH
            try:
                app_mod.SYSTEMD_SERVICE_PATH = str(svc)
                app_mod.SYSTEMD_TIMER_PATH = str(tmr)
                cmds: list[list[str]] = []

                def _fake_run(cmd: list[str], **_kwargs: object) -> mock.Mock:
                    cmds.append(list(cmd))
                    if cmd[:2] == ["systemctl", "is-enabled"]:
                        return mock.Mock(returncode=0 if is_enabled else 1, stdout="enabled\n" if is_enabled else "disabled\n", stderr="")
                    if cmd[:2] == ["systemctl", "list-timers"]:
                        return mock.Mock(returncode=0, stdout="Wed 2026-11-25 06:15:00 CET\n", stderr="")
                    return mock.Mock(returncode=0, stdout="", stderr="")

                is_enabled = True
                with mock.patch("subprocess.run", side_effect=_fake_run):
                    res_en = app_mod._helper_set_schedule(
                        {
                            "enabled": True,
                            "frequency": "weekly",
                            "day_of_week": "Wed",
                            "time_of_day": "06:15",
                            "scan_type": "quick",
                            "quick_targets": ["/home/user/Downloads", '/tmp/bad";id'],
                        }
                    )
                self.assertTrue(res_en["enabled"])
                self.assertEqual(res_en["day_of_week"], "Wed")
                self.assertEqual(res_en["time_of_day"], "06:15")
                self.assertIn("Wed *-*-* 06:15:00", tmr.read_text(encoding="utf-8"))
                self.assertNotIn('";id', svc.read_text(encoding="utf-8"))
                self.assertIn(["systemctl", "enable", "--now", "clamav-gui-scan.timer"], cmds)

                is_enabled = False
                with mock.patch("subprocess.run", side_effect=_fake_run):
                    res_dis = app_mod._helper_set_schedule(
                        {
                            "enabled": False,
                            "frequency": "daily",
                            "day_of_week": "Mon",
                            "time_of_day": "25:99",
                            "scan_type": "full",
                            "quick_targets": [],
                        }
                    )
                self.assertFalse(res_dis["enabled"])
                self.assertEqual(res_dis["time_of_day"], "23:59")
                self.assertEqual(res_dis["next_run"], "-")
                self.assertIn('"enabled": false', tmr.read_text(encoding="utf-8"))
                self.assertIn(["systemctl", "disable", "--now", "clamav-gui-scan.timer"], cmds)
            finally:
                app_mod.SYSTEMD_SERVICE_PATH = orig_svc
                app_mod.SYSTEMD_TIMER_PATH = orig_tmr

    def test_quarantine_collision_same_second_and_restore_symlink_ancestor_guard(self) -> None:
        import datetime

        fixed_now = datetime.datetime(2026, 11, 22, 1, 30, 0)
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            qdir = root / "quarantine"
            d1 = root / "dir1"
            d2 = root / "dir2"
            d3 = root / "dir3"
            d1.mkdir()
            d2.mkdir()
            d3.mkdir()
            f1 = d1 / "sample.bin"
            f2 = d2 / "sample.bin"
            f3 = d3 / "sample.bin"
            f1.write_bytes(b"first")
            f2.write_bytes(b"second")
            f3.write_bytes(b"third")

            with mock.patch("datetime.datetime") as mock_dt:
                mock_dt.now.return_value = fixed_now
                r1 = app_mod._helper_quarantine_file({"path": str(f1), "quarantine_dir": str(qdir)})
                r2 = app_mod._helper_quarantine_file({"path": str(f2), "quarantine_dir": str(qdir)})
                r3 = app_mod._helper_quarantine_file({"path": str(f3), "quarantine_dir": str(qdir)})

            self.assertNotEqual(r1["name"], r2["name"])
            self.assertNotEqual(r2["name"], r3["name"])
            self.assertEqual(Path(r1["dest"]).read_bytes(), b"first")
            self.assertEqual(Path(r2["dest"]).read_bytes(), b"second")
            self.assertEqual(Path(r3["dest"]).read_bytes(), b"third")

            # Restore must reject symlink ancestor before creating subdirectories
            real_target_dir = root / "real_target"
            real_target_dir.mkdir()
            sym_parent = root / "sym_link"
            sym_parent.symlink_to(real_target_dir)
            with self.assertRaises(PermissionError):
                app_mod._helper_restore_quarantine(
                    {
                        "name": r1["name"],
                        "quarantine_dir": str(qdir),
                        "dest_path": str(sym_parent / "nested" / "restored.bin"),
                    }
                )
            self.assertFalse((real_target_dir / "nested").exists())
            self.assertTrue(Path(r1["dest"]).exists())


if __name__ == "__main__":
    unittest.main()
