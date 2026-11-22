"""POSIX process telemetry used by the Linux and macOS adapters."""

from __future__ import annotations

import os
import shutil
import subprocess
from typing import Any

try:
    import pwd
except ImportError:
    pwd = None


def parse_proc_uptime() -> float:
    """Read system uptime in seconds from /proc/uptime."""
    try:
        with open("/proc/uptime", "r", encoding="utf-8") as fh:
            return float(fh.read().split()[0])
    except OSError:
        return 0.0


def parse_proc_stat(pid: int) -> dict[str, Any] | None:
    """Parse world-readable fields from /proc/<pid>/stat."""
    try:
        with open(f"/proc/{pid}/stat", "r", encoding="utf-8", errors="replace") as fh:
            raw = fh.read().strip()
    except OSError:
        return None

    lparen = raw.find("(")
    rparen = raw.rfind(")")
    if lparen == -1 or rparen == -1 or rparen + 2 >= len(raw):
        return None

    comm = raw[lparen + 1 : rparen]
    rest = raw[rparen + 2 :].split()
    if len(rest) < 20:
        return None

    return {
        "comm": comm,
        "state": rest[0],
        "ppid": int(rest[1]),
        "utime": int(rest[11]),
        "stime": int(rest[12]),
        "priority": int(rest[15]),
        "nice": int(rest[16]),
        "threads": int(rest[17]),
        "starttime": int(rest[19]),
    }


def parse_proc_status(pid: int) -> dict[str, Any]:
    """Parse world-readable fields from /proc/<pid>/status."""
    info: dict[str, Any] = {
        "uid": None,
        "user": "unknown",
        "rss_kb": 0,
        "voluntary_ctxt_switches": 0,
        "nonvoluntary_ctxt_switches": 0,
    }
    try:
        with open(f"/proc/{pid}/status", "r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                if line.startswith("Uid:"):
                    parts = line.split()
                    if len(parts) >= 2:
                        uid = int(parts[1])
                        info["uid"] = uid
                        try:
                            info["user"] = pwd.getpwuid(uid).pw_name if pwd is not None else str(uid)
                        except KeyError:
                            info["user"] = str(uid)
                elif line.startswith("VmRSS:"):
                    parts = line.split()
                    if len(parts) >= 2:
                        info["rss_kb"] = int(parts[1])
                elif line.startswith("voluntary_ctxt_switches:"):
                    info["voluntary_ctxt_switches"] = int(line.split(":", 1)[1].strip())
                elif line.startswith("nonvoluntary_ctxt_switches:"):
                    info["nonvoluntary_ctxt_switches"] = int(line.split(":", 1)[1].strip())
    except OSError:
        pass
    return info


def read_proc_cmdline(pid: int) -> list[str]:
    """Read NUL-delimited /proc/<pid>/cmdline."""
    try:
        with open(f"/proc/{pid}/cmdline", "rb") as fh:
            raw = fh.read()
        return [part.decode("utf-8", errors="replace") for part in raw.split(b"\x00") if part]
    except OSError:
        return []


def inspect_linux_fds(pid: int, excluded_prefixes: tuple[str, ...]) -> dict[str, Any]:
    """Read /proc/<pid>/fd targets to determine the file currently being scanned."""
    fd_dir = f"/proc/{pid}/fd"
    real_files: list[str] = []
    tmp_files: list[str] = []

    try:
        fd_names = sorted(os.listdir(fd_dir), key=lambda name: int(name) if name.isdigit() else 999999)
    except OSError as exc:
        return {"current_file": None, "open_files": [], "tmp_count": 0, "fd_error": str(exc)}

    for fd_name in fd_names:
        if fd_name in ("0", "1", "2"):
            continue
        try:
            target = os.readlink(os.path.join(fd_dir, fd_name))
        except OSError:
            continue

        if any(target.startswith(prefix) for prefix in excluded_prefixes):
            continue
        if target.startswith("/tmp/clamav-"):
            tmp_files.append(target)
        else:
            real_files.append(target)

    current_file = real_files[-1] if real_files else (tmp_files[-1] if tmp_files else None)
    return {
        "current_file": current_file,
        "open_files": (real_files + tmp_files)[:10],
        "tmp_count": len(tmp_files),
        "fd_error": None,
    }


def _inspect_proc_io(pid: int) -> dict[str, int]:
    """Read byte counters from /proc/<pid>/io."""
    io_stats: dict[str, int] = {}
    try:
        with open(f"/proc/{pid}/io", "r", encoding="utf-8") as fh:
            for line in fh:
                if ":" in line:
                    key, val = line.split(":", 1)
                    io_stats[key.strip()] = int(val.strip())
    except OSError:
        pass
    return io_stats


def inspect_macos_fds(pid: int, excluded_prefixes: tuple[str, ...]) -> dict[str, Any]:
    """Read open files for clamscan on macOS via lsof when available."""
    lsof_bin = shutil.which("lsof")
    if not lsof_bin:
        return {"current_file": None, "open_files": [], "tmp_count": 0, "fd_error": None}
    real_files: list[str] = []
    tmp_files: list[str] = []
    mac_excluded = (*excluded_prefixes, "/System/Library/", "/usr/lib/", "/private/var/db/", "/dev/")
    try:
        res = subprocess.run(
            [lsof_bin, "-n", "-P", "-p", str(pid), "-Fn"],
            capture_output=True,
            text=True,
            timeout=2,
            check=False,
        )
        for line in res.stdout.splitlines():
            if not line.startswith("n/"):
                continue
            target = line[1:].strip()
            if any(target.startswith(pref) for pref in mac_excluded):
                continue
            if target.startswith("/tmp/clamav-") or target.startswith("/private/tmp/clamav-"):
                tmp_files.append(target)
            else:
                real_files.append(target)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {"current_file": None, "open_files": [], "tmp_count": 0, "fd_error": str(exc)}
    return {
        "current_file": real_files[-1] if real_files else None,
        "open_files": real_files[-10:],
        "tmp_count": len(tmp_files),
        "fd_error": None,
    }
