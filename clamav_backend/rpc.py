"""JSON-RPC transport for the ClamAV helper process."""

from __future__ import annotations

import json
import queue
import subprocess
import sys
import threading
import time
from collections.abc import Callable, Mapping
from typing import Any


def serve(handlers: Mapping[str, Callable], uid: int) -> int:
    """Serve JSON requests over the inherited process pipes."""
    print(json.dumps({"type": "ready", "uid": uid}), flush=True)
    for raw_line in sys.stdin:
        line = raw_line.strip()
        if not line or not line.startswith("{"):
            continue
        req_id = None
        try:
            request = json.loads(line)
            req_id = request.get("id")
            action = request.get("action")
            handler = handlers.get(action)
            if handler is None:
                raise ValueError(f"Unknown action: {action}")
            params = request.get("params")
            if params is None:
                params = {}
            if not isinstance(params, dict):
                raise ValueError("Helper parameters must be a JSON object")
            response = {"id": req_id, "ok": True, "result": handler(params)}
        except Exception as exc:
            response = {"id": req_id, "ok": False, "error": str(exc)}
        print(json.dumps(response), flush=True)
    return 0


class HelperClient:
    """Thread-safe JSON RPC client communicating with the privileged helper."""

    def __init__(
        self,
        local_command: Callable[[], list[str]],
        elevated_command: Callable[[], list[str]],
        local_access: Callable[[], bool],
        creation_flags: int,
    ) -> None:
        self._local_command = local_command
        self._elevated_command = elevated_command
        self._local_access = local_access
        self._creation_flags = creation_flags
        self._proc: subprocess.Popen[str] | None = None
        self._lock = threading.Lock()
        self._pending: dict[int, queue.Queue[dict[str, Any]]] = {}
        self._next_id = 1
        self._reader_thread: threading.Thread | None = None
        self.uid: int | None = None
        self.on_disconnect = None

    @property
    def is_connected(self) -> bool:
        return self._proc is not None and self._proc.poll() is None and self.uid is not None

    @property
    def is_root(self) -> bool:
        return self._proc is not None and self._proc.poll() is None and (self.uid == 0 or self._local_access())

    @property
    def is_user_mode(self) -> bool:
        return (
            self._proc is not None
            and self._proc.poll() is None
            and self.uid is not None
            and self.uid != 0
            and not self._local_access()
        )

    def close(self) -> None:
        with self._lock:
            proc = self._proc
            self._proc = None
            self.uid = None
            pending = list(self._pending.values())
            self._pending.clear()
        for waiter in pending:
            waiter.put({"ok": False, "error": "Root helper disconnected."})
        if proc is not None:
            try:
                if proc.stdin:
                    proc.stdin.close()
            except OSError:
                pass
            if proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait(timeout=1)
            for pipe in (proc.stdout, proc.stderr):
                if pipe is not None:
                    try:
                        pipe.close()
                    except OSError:
                        pass

    def _spawn_auth_process(self, cmd: list[str]) -> tuple[subprocess.Popen[str] | None, str]:
        """Spawn a helper or auth wrapper process cleanly, handling missing binaries."""
        try:
            popen_kwargs: dict[str, Any] = {
                "stdin": subprocess.PIPE,
                "stdout": subprocess.PIPE,
                "stderr": subprocess.PIPE,
                "text": True,
                "bufsize": 1,
            }
            if self._creation_flags:
                popen_kwargs["creationflags"] = self._creation_flags
            proc = subprocess.Popen(cmd, **popen_kwargs)
            return proc, ""
        except OSError as exc:
            return None, f"Failed to launch {cmd[0]}: {exc}"

    def start_local(self) -> tuple[bool, str]:
        """Spawn the local JSON-RPC helper directly without sudo or pkexec."""
        self.close()
        proc, spawn_err = self._spawn_auth_process(self._local_command())
        if proc is None:
            return False, spawn_err
        assert proc.stdout is not None
        line = proc.stdout.readline()
        if line.strip().startswith("{"):
            try:
                msg = json.loads(line.strip())
                if msg.get("type") == "ready":
                    self._attach(proc, int(msg.get("uid", 0)))
                    return True, "Local helper active."
            except (json.JSONDecodeError, ValueError):
                pass
        if proc.poll() is None:
            proc.terminate()
        return False, "Local helper did not report ready."

    def start_with_sudo(self, password: str) -> tuple[bool, str]:
        """Spawn helper using sudo -k -S and validate root readiness."""
        self.close()
        cmd = ["sudo", "-k", "-S", "-p", "", *self._elevated_command()]
        proc, spawn_err = self._spawn_auth_process(cmd)
        if proc is None:
            return False, spawn_err
        assert proc.stdin is not None and proc.stdout is not None and proc.stderr is not None

        stderr_lines: list[str] = []
        ready_q: queue.Queue[tuple[str, Any]] = queue.Queue()

        def _watch_stdout() -> None:
            while True:
                line = proc.stdout.readline()  # type: ignore[union-attr]
                if not line:
                    ready_q.put(("stdout_eof", None))
                    return
                stripped = line.strip()
                if stripped.startswith("{"):
                    try:
                        msg = json.loads(stripped)
                        if msg.get("type") == "ready":
                            ready_q.put(("ready", msg))
                            return
                    except json.JSONDecodeError:
                        pass

        def _watch_stderr() -> None:
            while True:
                line = proc.stderr.readline()  # type: ignore[union-attr]
                if not line:
                    return
                text = line.strip()
                if text:
                    stderr_lines.append(text)
                    ready_q.put(("stderr", text))

        threading.Thread(target=_watch_stdout, daemon=True).start()
        threading.Thread(target=_watch_stderr, daemon=True).start()

        try:
            proc.stdin.write(password + "\n")
            proc.stdin.flush()
        except OSError as exc:
            proc.terminate()
            return False, f"Failed writing password to sudo: {exc}"

        deadline = time.monotonic() + 8.0
        while time.monotonic() < deadline:
            remaining = max(0.05, deadline - time.monotonic())
            try:
                kind, payload = ready_q.get(timeout=min(0.4, remaining))
            except queue.Empty:
                if proc.poll() is not None:
                    break
                continue

            if kind == "ready":
                uid = int(payload.get("uid", -1))
                if uid == 0:
                    self._attach(proc, uid)
                    return True, "Root helper active (sudo)."
                proc.terminate()
                return False, f"Helper started with unexpected UID {uid}."

            if kind == "stderr":
                # Give stdout a brief grace window in case sudo printed a notice and still succeeded
                time.sleep(0.25)
                try:
                    kind2, payload2 = ready_q.get_nowait()
                    if kind2 == "ready" and int(payload2.get("uid", -1)) == 0:
                        self._attach(proc, 0)
                        return True, "Root helper active (sudo)."
                except queue.Empty:
                    pass
                proc.terminate()
                return False, " ".join(stderr_lines) or "Authentication failed."

            if kind == "stdout_eof":
                break

        proc.terminate()
        err = " ".join(stderr_lines).strip()
        return False, err or "Timed out waiting for sudo authentication."

    def start_with_sudo_nopass(self) -> tuple[bool, str]:
        """Attempt non-interactive sudo -n helper launch if credentials are cached or NOPASSWD."""
        self.close()
        cmd = ["sudo", "-n", *self._elevated_command()]
        proc, spawn_err = self._spawn_auth_process(cmd)
        if proc is None:
            return False, spawn_err
        assert proc.stdout is not None and proc.stderr is not None
        line = proc.stdout.readline()
        if line.strip().startswith("{"):
            try:
                msg = json.loads(line.strip())
                if msg.get("type") == "ready" and int(msg.get("uid", -1)) == 0:
                    self._attach(proc, 0)
                    return True, "Root helper active (sudo cached)."
            except json.JSONDecodeError:
                pass
        if proc.poll() is None:
            proc.terminate()
        return False, "Non-interactive sudo unavailable."

    def start_with_pkexec(self) -> tuple[bool, str]:
        """Spawn helper via pkexec (triggers KDE Polkit prompt)."""
        self.close()
        cmd = ["pkexec", *self._elevated_command()]
        proc, spawn_err = self._spawn_auth_process(cmd)
        if proc is None:
            return False, spawn_err
        assert proc.stdout is not None and proc.stderr is not None

        while True:
            line = proc.stdout.readline()
            if not line:
                err = proc.stderr.read().strip()
                rc = proc.wait()
                if rc in (126, 127) and not err:
                    err = "Polkit authentication was cancelled or unavailable."
                return False, err or f"pkexec exited with code {rc}."
            stripped = line.strip()
            if stripped.startswith("{"):
                try:
                    msg = json.loads(stripped)
                    if msg.get("type") == "ready":
                        uid = int(msg.get("uid", -1))
                        if uid == 0:
                            self._attach(proc, uid)
                            return True, "Root helper active (pkexec)."
                        proc.terminate()
                        return False, f"Helper started with unexpected UID {uid}."
                except json.JSONDecodeError:
                    continue

    def _attach(self, proc: subprocess.Popen[str], uid: int) -> None:
        with self._lock:
            self._proc = proc
            self.uid = uid
        self._reader_thread = threading.Thread(target=self._read_loop, args=(proc,), daemon=True)
        self._reader_thread.start()

    def _read_loop(self, proc: subprocess.Popen[str]) -> None:
        assert proc.stdout is not None
        for raw_line in proc.stdout:
            line = raw_line.strip()
            if not line.startswith("{"):
                continue
            try:
                msg = json.loads(line)
            except json.JSONDecodeError:
                continue
            req_id = msg.get("id")
            with self._lock:
                if self._proc is not proc:
                    return
                waiter = self._pending.pop(req_id, None)
            if waiter is not None:
                waiter.put(msg)

        with self._lock:
            if self._proc is not proc:
                return
            self._proc = None
            self.uid = None
            pending_items = list(self._pending.values())
            self._pending.clear()
        for waiter in pending_items:
            waiter.put({"ok": False, "error": "Root helper disconnected."})
        if self.on_disconnect is not None:
            self.on_disconnect()

    def call(self, action: str, params: dict[str, Any] | None = None, timeout: float = 10.0) -> dict[str, Any]:
        """Execute a synchronous RPC request against the running helper."""
        waiter: queue.Queue[dict[str, Any]] = queue.Queue()
        with self._lock:
            if self._proc is None or self._proc.poll() is not None or self._proc.stdin is None:
                raise RuntimeError("Root access is not unlocked.")
            req_id = self._next_id
            self._next_id += 1
            self._pending[req_id] = waiter
            payload = json.dumps({"id": req_id, "action": action, "params": params or {}}) + "\n"
            try:
                self._proc.stdin.write(payload)
                self._proc.stdin.flush()
            except OSError as exc:
                self._pending.pop(req_id, None)
                raise RuntimeError(f"Failed sending request to helper: {exc}") from exc

        try:
            resp = waiter.get(timeout=timeout)
        except queue.Empty as exc:
            with self._lock:
                self._pending.pop(req_id, None)
            raise TimeoutError(f"Helper request '{action}' timed out.") from exc

        if not resp.get("ok"):
            raise RuntimeError(str(resp.get("error") or f"Action '{action}' failed"))
        return dict(resp.get("result") or {})
