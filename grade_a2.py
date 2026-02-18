#!/usr/bin/env python3
"""
SYSC3303A W26 A2 — Grading Script
Checks diagrams, code-quality heuristics, and runs an end-to-end E2E test.

Overrides (env vars):
  MAIN_SERVER, MAIN_HOST, MAIN_CLIENT  : Java main class names
  HOST_PORT, SERVER_PORT               : Ports (default 5000 / 6000)
  JAVA_OPTS                            : Extra JVM args
  TIMEOUT_SECONDS                      : E2E timeout (default 25)

Usage:
  python3 grade_a2.py [--root <submission_dir>] [--keep-logs]
"""

from __future__ import annotations
import argparse
import os
import re
import sys
import time
import subprocess
import pathlib
import shutil
import random
import threading
from dataclasses import dataclass

IS_WINDOWS = sys.platform == "win32"

if not IS_WINDOWS:
    import select
    import pty

# ── colour / icon helpers ──────────────────────────────────────────────────────
RESET = "\033[0m"
BOLD = "\033[1m"
RED = "\033[31m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
CYAN = "\033[36m"
GREY = "\033[90m"

PASS_ICON = "✅"
FAIL_ICON = "❌"
WARN_ICON = "⚠️ "
INFO_ICON = "ℹ️ "
FILE_ICON = "📄"


def c(colour: str, msg: str) -> str:
    return f"{colour}{msg}{RESET}"


def log(msg: str) -> None:
    print(msg, flush=True)


def section(title: str) -> None:
    bar = "─" * 60
    log(f"\n{CYAN}{BOLD}{bar}{RESET}")
    log(f"{CYAN}{BOLD}  {title}{RESET}")
    log(f"{CYAN}{BOLD}{bar}{RESET}")


def result_line(passed: bool, label: str, detail: str = "") -> str:
    icon = PASS_ICON if passed else FAIL_ICON
    colour = GREEN if passed else RED
    detail_str = f"  {c(YELLOW, detail)}" if detail else ""
    return f"  {icon}  {c(colour, label)}{detail_str}"


# ── constants ──────────────────────────────────────────────────────────────────
DEFAULT_HOST_PORT = int(os.environ.get("HOST_PORT", "5000"))
DEFAULT_SERVER_PORT = int(os.environ.get("SERVER_PORT", "6000"))
JAVA_OPTS = os.environ.get("JAVA_OPTS", "").split()
TIMEOUT_SECONDS = float(os.environ.get("TIMEOUT_SECONDS", "25"))
ANSI_RE = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")

_NAMES = [
    "John Titor",
    "AzureDiamond",
    "Bloodninja",
    "Iwakura Lain",
    "Harold Finch",
    "Henry Dorsett Case",
    "Rick Deckard",
    "Officer K",
    "Joseph Virek",
]


def random_player_name() -> str:
    return random.choice(_NAMES) + " " + str(random.randint(100, 999))


# Diagram extensions we recognise
DIAGRAM_EXTS = {".drawio", ".png", ".jpg", ".jpeg", ".svg", ".pdf"}

CheckResult = tuple[bool, str, str]
SectionResults = dict[str, list[CheckResult]]


@dataclass
class GradeRunResult:
    root: str
    logs_dir: str
    build_dir: str
    all_results: SectionResults
    passed_checks: int
    total_checks: int
    overall_ok: bool
    return_code: int

    def to_dict(self) -> dict[str, object]:
        sections: dict[str, list[dict[str, object]]] = {}
        for section_name, items in self.all_results.items():
            sections[section_name] = [
                {"passed": passed, "label": label, "detail": detail}
                for passed, label, detail in items
            ]
        return {
            "root": self.root,
            "logs_dir": self.logs_dir,
            "build_dir": self.build_dir,
            "passed_checks": self.passed_checks,
            "total_checks": self.total_checks,
            "overall_ok": self.overall_ok,
            "return_code": self.return_code,
            "sections": sections,
        }


# Recursively find relevant .java files
def get_java_files(root: pathlib.Path, exclude_gamestate=True) -> list[pathlib.Path]:
    java_files = [p for p in root.rglob("*.java") if p.is_file()]

    # Ignore irrelevant files
    java_files = [
        p
        for p in java_files
        if not any(part == "__MACOSX" for part in p.parts)
        and (not exclude_gamestate or p.name != "GameState.java")
        and not (p.name.startswith("Test") or p.name.endswith("Test.java"))
    ]
    return java_files


# ── low-level process / IO helpers ────────────────────────────────────────────
def run_cmd(cmd: list[str], cwd: pathlib.Path, **kwargs) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, cwd=str(cwd), text=True, **kwargs)


def start_process(
    label: str,
    cmd: list[str],
    cwd: pathlib.Path,
    logfile: pathlib.Path,
    stream: bool = True,
) -> subprocess.Popen:
    if stream:
        proc = subprocess.Popen(
            cmd,
            cwd=str(cwd),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        f = open(logfile, "w", encoding="utf-8", errors="replace")

        def _reader(proc=proc, f=f, label=label):
            assert proc.stdout is not None
            for line in proc.stdout:
                f.write(line)
                f.flush()
                print(c(GREY, f"  [{label}] {line.rstrip()}"), flush=True)
            f.close()

        threading.Thread(target=_reader, daemon=True).start()
        return proc
    else:
        f = open(logfile, "w", encoding="utf-8", errors="replace")
        return subprocess.Popen(
            cmd, cwd=str(cwd), stdout=f, stderr=subprocess.STDOUT, text=True
        )


def wait_for_log(pattern: str, logfile: pathlib.Path, timeout: float) -> bool:
    """Poll logfile until the regex pattern matches or timeout elapses."""
    deadline = time.time() + timeout
    rx = re.compile(pattern)
    pos = 0
    while time.time() < deadline:
        try:
            with open(logfile, "r", encoding="utf-8", errors="ignore") as f:
                f.seek(pos)
                chunk = f.read()
                pos = f.tell()
        except FileNotFoundError:
            chunk = ""
        if chunk and rx.search(chunk):
            return True
        time.sleep(0.05)
    return False


if IS_WINDOWS:
    import queue as _queue
    try:
        from winpty import PtyProcess as _PywinptyProcess
        _HAS_PYWINPTY = True
    except Exception:
        _PywinptyProcess = None
        _HAS_PYWINPTY = False

    class _WinPty:
        """Windows substitute for a Unix pseudo-terminal (uses subprocess pipes)."""

        def __init__(self, proc: subprocess.Popen) -> None:
            self._proc = proc
            self._q: _queue.Queue[bytes] = _queue.Queue()
            self._closed = False
            threading.Thread(target=self._reader, daemon=True).start()

        def _reader(self) -> None:
            try:
                assert self._proc.stdout
                while True:
                    chunk = self._proc.stdout.read(4096)
                    if not chunk:
                        break
                    self._q.put(chunk)
            except Exception:
                pass

        def read(self, timeout: float = 0.2) -> bytes:
            try:
                return self._q.get(timeout=timeout)
            except _queue.Empty:
                return b""

        def write(self, s: str) -> None:
            if self._proc.stdin and not self._closed:
                try:
                    self._proc.stdin.write(s.encode("utf-8", errors="replace"))
                    self._proc.stdin.flush()
                except Exception:
                    pass

        def close(self) -> None:
            self._closed = True
            try:
                if self._proc.stdin:
                    self._proc.stdin.close()
            except Exception:
                pass

    class _PyWinPty:
        """Windows pseudo-terminal backed by pywinpty (if installed)."""

        def __init__(self, pty_proc) -> None:
            self._pty = pty_proc
            self._q: _queue.Queue[bytes] = _queue.Queue()
            self._closed = False
            threading.Thread(target=self._reader, daemon=True).start()

        def _reader(self) -> None:
            while not self._closed:
                try:
                    chunk = self._pty.read()
                except EOFError:
                    break
                except Exception:
                    break
                if not chunk:
                    continue
                if isinstance(chunk, str):
                    chunk = chunk.encode("utf-8", errors="replace")
                self._q.put(chunk)

        def read(self, timeout: float = 0.2) -> bytes:
            try:
                return self._q.get(timeout=timeout)
            except _queue.Empty:
                return b""

        def write(self, s: str) -> None:
            if self._closed:
                return
            try:
                self._pty.write(s)
            except Exception:
                pass

        def close(self) -> None:
            self._closed = True
            try:
                self._pty.close(force=True)
            except TypeError:
                try:
                    self._pty.close()
                except Exception:
                    pass
            except Exception:
                pass

    class _PyWinPtyProcAdapter:
        """Duck-typed process adapter so graceful_stop can treat pywinpty like Popen."""

        def __init__(self, pty_proc) -> None:
            self._pty = pty_proc

        def poll(self):
            try:
                if self._pty.isalive():
                    return None
            except Exception:
                return None
            try:
                return self._pty.exitstatus
            except Exception:
                return 0

        def terminate(self) -> None:
            try:
                self._pty.close(force=False)
            except TypeError:
                self._pty.close()
            except Exception:
                pass

        def kill(self) -> None:
            try:
                self._pty.close(force=True)
            except TypeError:
                self._pty.close()
            except Exception:
                pass


def spawn_with_pty(cmd: list[str], cwd: pathlib.Path):
    """Spawn a process attached to a pseudo-terminal; returns (proc, pty_handle).

    On Unix the pty_handle is the master file descriptor (int).
    On Windows the pty_handle is a _WinPty instance backed by subprocess pipes.
    """
    if IS_WINDOWS:
        if _HAS_PYWINPTY and _PywinptyProcess is not None:
            try:
                pty_proc = _PywinptyProcess.spawn(cmd, cwd=str(cwd))
            except TypeError:
                # Compatibility fallback for pywinpty builds that only accept cmdline.
                cmdline = subprocess.list2cmdline(cmd)
                pty_proc = _PywinptyProcess.spawn(cmdline)
            return _PyWinPtyProcAdapter(pty_proc), _PyWinPty(pty_proc)

        proc = subprocess.Popen(
            cmd,
            cwd=str(cwd),
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=False,
        )
        return proc, _WinPty(proc)
    master_fd, slave_fd = pty.openpty()
    proc = subprocess.Popen(
        cmd,
        cwd=str(cwd),
        stdin=slave_fd,
        stdout=slave_fd,
        stderr=slave_fd,
        close_fds=True,
        text=False,
    )
    os.close(slave_fd)
    return proc, master_fd


def read_pty(master_fd, timeout: float = 0.2) -> bytes:
    if IS_WINDOWS:
        return master_fd.read(timeout)
    r, _, _ = select.select([master_fd], [], [], timeout)
    if not r:
        return b""
    try:
        return os.read(master_fd, 4096)
    except OSError:
        return b""


def write_pty(master_fd, s: str) -> None:
    if IS_WINDOWS:
        # Fix CRLF requirement
        s = s.replace("\r\n", "\n").replace("\n", "\r\n")
    if IS_WINDOWS and hasattr(master_fd, "write"):
        master_fd.write(s)
    else:
        os.write(master_fd, s.encode("utf-8", errors="replace"))


def close_pty(master_fd) -> None:
    """Close a pty handle regardless of platform."""
    if IS_WINDOWS:
        master_fd.close()
    else:
        try:
            os.close(master_fd)
        except OSError:
            pass


def clean_text(b: bytes) -> str:
    t = b.decode("utf-8", errors="replace")
    t = t.replace("\r\n", "\n").replace("\r", "\n")
    return ANSI_RE.sub("", t)


def expect_output(buffer: str, regex: str) -> re.Match | None:
    return re.search(regex, buffer, flags=re.MULTILINE)


def graceful_stop(proc: subprocess.Popen, label: str, timeout: float = 2.0) -> None:
    if proc.poll() is not None:
        return
    try:
        proc.terminate()  # cross-platform; SIGTERM on Unix, TerminateProcess on Windows
    except Exception:
        return
    deadline = time.time() + timeout
    while time.time() < deadline:
        if proc.poll() is not None:
            return
        time.sleep(0.05)
    try:
        proc.kill()
    except Exception:
        pass


# ── class discovery ────────────────────────────────────────────────────────────
def discover_main_classes(root: pathlib.Path) -> dict[str, str]:
    """Heuristic: prefer filenames Client / IntermediateHost / Server."""
    env = {
        "server": os.environ.get("MAIN_SERVER", "").strip(),
        "host": os.environ.get("MAIN_HOST", "").strip(),
        "client": os.environ.get("MAIN_CLIENT", "").strip(),
    }
    if env["server"] and env["host"] and env["client"]:
        return env

    java_files = get_java_files(root)
    if not java_files:
        raise RuntimeError("No .java files found.")

    mapping: dict[str, str] = {}
    for kind, fname in [
        ("client", "Client.java"),
        ("host", "IntermediateHost.java"),
        ("host", "Host.java"),
        ("server", "Server.java"),
    ]:
        if env[kind]:
            mapping[kind] = env[kind]
            continue
        if kind in mapping:  # already resolved (e.g. IntermediateHost found first)
            continue
        hits = [p for p in java_files if p.name.lower() == fname.lower()]
        if hits:
            mapping[kind] = hits[0].stem

    if len(mapping) < 3:
        mains: list[str] = []
        for p in java_files:
            try:
                txt = p.read_text(encoding="utf-8", errors="ignore")
            except Exception:
                continue
            if "public static void main" not in txt:
                continue
            for m in re.finditer(r"^class\s+([A-Za-z_][A-Za-z0-9_]*)\b", txt, flags=re.MULTILINE):
                mains.append(m.group(1))
                break

        def pick(kind: str, prefer: list[str]):
            if env[kind]:
                return env[kind]
            for pat in prefer:
                for cls in mains:
                    if pat in cls.lower():
                        return cls
            return None

        mapping.setdefault("client", pick("client", ["client"]))
        mapping.setdefault("host", pick("host", ["host", "intermediate"]))
        mapping.setdefault("server", pick("server", ["server"]))

    missing = [k for k in ("server", "host", "client") if not mapping.get(k)]
    if missing:
        raise RuntimeError(
            "Could not infer main classes for: "
            + ", ".join(missing)
            + ". Set MAIN_SERVER/MAIN_HOST/MAIN_CLIENT env vars."
        )
    return mapping


# ══════════════════════════════════════════════════════════════════════════════
# CHECK 1 — DIAGRAMS
# ══════════════════════════════════════════════════════════════════════════════
def check_diagrams(root: pathlib.Path) -> list[tuple[bool, str, str]]:
    """
    Search for a class diagram and a sequence diagram by filename heuristic.
    For editable formats (drawio) also verify required class names appear.
    """
    results: list[tuple[bool, str, str]] = []

    all_diag = [
        p for p in root.rglob("*") if p.suffix.lower() in DIAGRAM_EXTS and p.is_file() and '__MACOSX' not in p.parts
    ]

    class_hits = [p for p in all_diag if re.search(r"(class|uml)", p.stem, re.I)]
    seq_hits = [p for p in all_diag if re.search(r"seq(uence)?", p.stem, re.I)]

    if class_hits:
        rel = class_hits[0].relative_to(root)
        results.append((True, "Class diagram found", f"{FILE_ICON} {rel}"))
    else:
        results.append(
            (
                False,
                "Class diagram NOT found",
                "Expected a diagram file with 'class' in its name",
            )
        )

    if seq_hits:
        rel = seq_hits[0].relative_to(root)
        results.append((True, "Sequence diagram found", f"{FILE_ICON} {rel}"))
    else:
        results.append(
            (
                False,
                "Sequence diagram NOT found",
                "Expected a diagram file with 'seq' / 'sequence' in its name",
            )
        )

    # For .drawio: verify required class names appear inside the file text
    required_names = ["Client", "IntermediateHost", "Server", "GameState"]
    # "Host" is accepted as an alias for "IntermediateHost"
    _host_aliases = {"IntermediateHost": ["IntermediateHost", "Host"]}
    editable = [p for p in all_diag if p.suffix.lower() in {".drawio"}]
    names_found: set[str] = set()
    for dp in editable:
        try:
            content = dp.read_text(encoding="utf-8", errors="ignore")
            for name in required_names:
                aliases = _host_aliases.get(name, [name])
                if any(alias in content for alias in aliases):
                    names_found.add(name)
        except Exception:
            pass

    if editable:
        missing = [n for n in required_names if n not in names_found]
        if not missing:
            results.append(
                (
                    True,
                    "All required class names present in diagram source",
                    f"Checked: {', '.join(required_names)}",
                )
            )
        else:
            results.append(
                (
                    False,
                    "Some required class names missing from diagram source",
                    f"Not found in .drawio: {', '.join(missing)}",
                )
            )
    else:
        results.append(
            (
                True,
                "Diagram name-consistency check skipped (no .drawio)",
                "Only image-format diagrams found — cannot inspect content",
            )
        )

    return results


# ══════════════════════════════════════════════════════════════════════════════
# CHECK 2 — CODE QUALITY
# ══════════════════════════════════════════════════════════════════════════════
_JAVADOC_PAT = re.compile(r"/\*\*")
_COMMENT_PAT = re.compile(r"(//[^\n]*|/\*[\s\S]*?\*/)", re.MULTILINE)
_METHOD_PAT = re.compile(
    r"(?:(?:public|protected|private|static|final|synchronized|abstract)\s+)+"
    r"[\w<>\[\]]+\s+\w+\s*\([^)]*\)\s*(?:throws\s+[\w,\s]+)?\s*\{",
    re.MULTILINE,
)
_CLASS_PAT = re.compile(r"^public class\s+([A-Za-z_][A-Za-z0-9_]*)", re.MULTILINE)

MAX_METHOD_LINES = 80  # methods longer than this are flagged
MAX_METHODS_CLASS = 15  # more than this per class → possible god-class
MIN_COMMENT_RATIO = 0.05  # at least 5 % of non-blank lines should be comments


class JavaFileStats:
    """Parse a single .java file and collect quality metrics."""

    def __init__(self, path: pathlib.Path) -> None:
        self.path = path
        self.text = path.read_text(encoding="utf-8", errors="ignore")
        self.lines = self.text.splitlines()
        self.non_blank_lines = [ln for ln in self.lines if ln.strip()]
        self.comment_line_count = self._count_comment_lines()
        self.has_javadoc = bool(_JAVADOC_PAT.search(self.text))
        self.class_name = self._class_name()
        self.method_stats = self._method_lengths()
        self.long_methods = [
            (sig, ln) for sig, ln in self.method_stats if ln > MAX_METHOD_LINES
        ]

    def _class_name(self) -> str:
        m = _CLASS_PAT.search(self.text)
        return m.group(1) if m else self.path.stem

    def _count_comment_lines(self) -> int:
        stripped = re.sub(r'"(?:[^"\\]|\\.)*"', '""', self.text)
        count = 0
        for m in _COMMENT_PAT.finditer(stripped):
            count += m.group(0).count("\n") + 1
        return count

    def comment_ratio(self) -> float:
        return self.comment_line_count / max(len(self.non_blank_lines), 1)

    def _method_lengths(self) -> list[tuple[str, int]]:
        """Return (short_sig, line_count) for every method body found."""
        results = []
        for m in _METHOD_PAT.finditer(self.text):
            sig = m.group(0).split("{")[0].strip()[:65]
            start = m.end() - 1  # position of opening '{'
            depth = 0
            end = start
            for end, ch in enumerate(self.text[start:], start):
                if ch == "{":
                    depth += 1
                elif ch == "}":
                    depth -= 1
                    if depth == 0:
                        break
            body = self.text[start : end + 1]
            line_count = body.count("\n") + 1
            results.append((sig, line_count))
        return results


def check_code_quality(root: pathlib.Path) -> list[tuple[bool, str, str]]:
    java_files = get_java_files(root)
    if not java_files:
        return [(False, "No .java files found", "")]

    results: list[tuple[bool, str, str]] = []
    stats_list = [JavaFileStats(p) for p in java_files]
    found_classes = {s.class_name for s in stats_list}

    # (a) Required source files present
    # "Host" is accepted as an alias for "IntermediateHost"
    _host_aliases_code = {"IntermediateHost": {"IntermediateHost", "Host"}}
    for req in sorted(["Client", "IntermediateHost", "Server"]):
        accepted = _host_aliases_code.get(req, {req})
        matched = [s for s in stats_list if s.class_name in accepted]
        found = bool(matched)
        display = req
        if found:
            chosen = sorted(matched, key=lambda s: str(s.path))[0]
            detail = str(chosen.path.relative_to(root))
        else:
            detail = f"No class named '{display}' (or alias) found"
        results.append((found, f"Source file present: {display}", detail))

    # (b) JavaDoc present in every class
    for s in stats_list:
        results.append(
            (
                s.has_javadoc,
                f"JavaDoc present: {s.class_name}",
                str(s.path.relative_to(root)) if not s.has_javadoc else "",
            )
        )

    # (c) Comment density per file
    for s in stats_list:
        ratio = s.comment_ratio()
        ok = ratio >= MIN_COMMENT_RATIO
        results.append(
            (
                ok,
                f"Comment density: {s.class_name}  ({ratio:.0%} of non-blank lines)",
                f"Below {MIN_COMMENT_RATIO:.0%} minimum" if not ok else "",
            )
        )

    # (d) Method length — SRP proxy: no single method should do everything
    all_long: list[str] = []
    for s in stats_list:
        for sig, ln in s.long_methods:
            all_long.append(f"{s.class_name}: '{sig[:55]}…' ({ln} lines)")
    if all_long:
        results.append(
            (
                False,
                f"Long methods detected ({len(all_long)} method(s) > {MAX_METHOD_LINES} lines)",
                "; ".join(all_long[:3]) + (" …" if len(all_long) > 3 else ""),
            )
        )
    else:
        results.append(
            (
                True,
                f"All method bodies at most {MAX_METHOD_LINES} lines (SRP proxy check)",
                "",
            )
        )

    # (e) Methods per class — rough god-class check
    for s in stats_list:
        n = len(s.method_stats)
        ok = n <= MAX_METHODS_CLASS
        results.append(
            (
                ok,
                f"Method count: {s.class_name}  ({n} methods)",
                f"Possible god-class (> {MAX_METHODS_CLASS} methods)" if not ok else "",
            )
        )

    return results


# ══════════════════════════════════════════════════════════════════════════════
# CHECK 3 — COMPILATION
# ══════════════════════════════════════════════════════════════════════════════
def check_compilation(root: pathlib.Path, build: pathlib.Path) -> tuple[bool, str]:
    java_paths = get_java_files(root, exclude_gamestate=False)
    if not java_paths:
        raise RuntimeError("No .java files to compile.")

    java_files = [str(p.relative_to(root)) for p in java_paths]
    build.mkdir(parents=True, exist_ok=True)
    cmd = ["javac", "-encoding", "UTF-8", "-d", str(build)] + java_files
    cp = run_cmd(cmd, cwd=root, capture_output=True)
    if cp.returncode != 0:
        return False, (cp.stdout or "") + (cp.stderr or "")
    return True, ""


# ══════════════════════════════════════════════════════════════════════════════
# CHECK 4 — END-TO-END TEST
# ══════════════════════════════════════════════════════════════════════════════
def run_e2e(
    root: pathlib.Path,
    build: pathlib.Path,
    logs: pathlib.Path,
    mains: dict[str, str],
) -> list[tuple[bool, str, str]]:

    results: list[tuple[bool, str, str]] = []
    server_log = logs / "server.log"
    host_log = logs / "host.log"
    client_log = logs / "client.log"

    server_cmd = ["java"] + JAVA_OPTS + ["-cp", str(build), mains["server"]]
    host_cmd = ["java"] + JAVA_OPTS + ["-cp", str(build), mains["host"]]
    client_cmd = ["java"] + JAVA_OPTS + ["-cp", str(build), mains["client"]]

    player_name = random_player_name()

    # ── start server ──────────────────────────────────────────────────────────
    server = start_process("Server", server_cmd, cwd=root, logfile=server_log)
    srv_banner = wait_for_log(str(DEFAULT_SERVER_PORT), server_log, timeout=4.0)
    results.append(
        (
            srv_banner,
            "Server printed startup banner with port number",
            "Banner not detected (continuing anyway)" if not srv_banner else "",
        )
    )

    # ── start host ────────────────────────────────────────────────────────────
    host = start_process("Host", host_cmd, cwd=root, logfile=host_log)
    host_banner = wait_for_log(str(DEFAULT_HOST_PORT), host_log, timeout=4.0)
    results.append(
        (
            host_banner,
            "IntermediateHost printed startup banner with port number",
            "Banner not detected (continuing anyway)" if not host_banner else "",
        )
    )

    proc, mfd = spawn_with_pty(client_cmd, cwd=root)
    buf = ""
    start = time.time()

    def pump(until: float) -> None:
        nonlocal buf
        while time.time() < until:
            chunk = read_pty(mfd, timeout=0.2)
            if chunk:
                txt = clean_text(chunk)
                buf += txt
                for line in txt.splitlines():
                    if line.strip():
                        print(c(GREY, f"  [Client] {line}"), flush=True)
                with open(client_log, "a", encoding="utf-8", errors="replace") as f:
                    f.write(txt)
            else:
                break

    def stop_all() -> None:
        graceful_stop(proc, "Client")
        graceful_stop(host, "Host")
        graceful_stop(server, "Server")

    # ── JOIN ──────────────────────────────────────────────────────────────────
    pump(time.time() + 0.8)
    write_pty(mfd, f"{player_name}\n")

    joined_id = None
    while time.time() - start < TIMEOUT_SECONDS:
        pump(time.time() + 0.5)
        m = expect_output(buf, r"JOINED:(\d+)")
        if m:
            joined_id = int(m.group(1))
            break

    if joined_id is None:
        results.append(
            (
                False,
                "JOIN: server responded JOINED:<id>",
                "Did not receive JOINED:<playerId> in client output",
            )
        )
        stop_all()
        return results
    results.append(
        (True, f"JOIN: received JOINED:{joined_id} for player '{player_name}'", "")
    )

    # ── MOVE ──────────────────────────────────────────────────────────────────
    write_pty(mfd, "MOVE 5 5\n")
    move_ok = False
    while time.time() - start < TIMEOUT_SECONDS:
        pump(time.time() + 0.5)
        if "MOVE_OK" in buf:
            move_ok = True
            break

    results.append(
        (
            move_ok,
            "MOVE 5 5: server responded MOVE_OK",
            "Did not observe MOVE_OK" if not move_ok else "",
        )
    )
    if not move_ok:
        stop_all()
        return results

    # ── PICKUP ────────────────────────────────────────────────────────────────
    write_pty(mfd, "PICKUP 200\n")
    pickup_ok = False
    while time.time() - start < TIMEOUT_SECONDS:
        pump(time.time() + 0.5)
        if "PICKUP_OK" in buf:
            pickup_ok = True
            break
        if "PICKUP_FAIL" in buf:
            break

    results.append(
        (
            pickup_ok,
            "PICKUP 200: server responded PICKUP_OK",
            (
                "Did not observe PICKUP_OK (HealthPack should be at (5,5))"
                if not pickup_ok
                else ""
            ),
        )
    )
    if not pickup_ok:
        stop_all()
        return results

    # ── STATE ─────────────────────────────────────────────────────────────────
    # Expected: player at (5,5) with 120 HP (100 base + 20 from HealthPack).
    #           LootBox 200 consumed; LootBox 201 (Ammo at (10,2)) remains.
    write_pty(mfd, "STATE\n")
    state_ok = False
    while time.time() - start < TIMEOUT_SECONDS:
        pump(time.time() + 0.5)
        player_ok = f"({joined_id},5,5,120,{player_name})" in buf
        loot_ok = "(201,10,2,Ammo,5)" in buf
        if player_ok and loot_ok:
            state_ok = True
            break

    results.append(
        (
            state_ok,
            "STATE: correct player position/HP and remaining loot after MOVE+PICKUP",
            (
                f"Expected ({joined_id},5,5,120,{player_name}) and (201,10,2,Ammo,5)"
                if not state_ok
                else ""
            ),
        )
    )

    # ── SECOND CLIENT — concurrent-join smoke-test ────────────────────────────
    player2_name = random_player_name()
    while player2_name == player_name:
        player2_name = random_player_name()

    proc2, mfd2 = spawn_with_pty(client_cmd, cwd=root)
    buf2 = ""

    def pump2(until: float) -> None:
        nonlocal buf2
        while time.time() < until:
            chunk = read_pty(mfd2, timeout=0.2)
            if chunk:
                txt2 = clean_text(chunk)
                buf2 += txt2
                for line in txt2.splitlines():
                    if line.strip():
                        print(c(GREY, f"  [Client2] {line}"), flush=True)
            else:
                break

    pump2(time.time() + 0.8)
    write_pty(mfd2, f"{player2_name}\n")

    joined2 = None
    while time.time() - start < TIMEOUT_SECONDS:
        pump2(time.time() + 0.5)
        m2 = expect_output(buf2, r"JOINED:(\d+)")
        if m2:
            joined2 = int(m2.group(1))
            break

    second_ok = joined2 is not None and joined2 != joined_id
    results.append(
        (
            second_ok,
            f"Second concurrent client '{player2_name}' joined with unique ID",
            f"joined_id={joined2}" if not second_ok else f"JOINED:{joined2}",
        )
    )

    graceful_stop(proc2, "Client2")
    close_pty(mfd2)

    # ── QUIT ──────────────────────────────────────────────────────────────────
    write_pty(mfd, "QUIT\n")
    pump(time.time() + 0.8)
    close_pty(mfd)
    stop_all()

    results.append(
        (True, "E2E flow completed (JOIN -> MOVE -> PICKUP -> STATE -> QUIT)", "")
    )
    return results


# ══════════════════════════════════════════════════════════════════════════════
# RESULTS PRINTER
# ══════════════════════════════════════════════════════════════════════════════
def print_detailed_results(all_results: dict[str, list[tuple[bool, str, str]]]) -> None:
    """Print per-section result lines with headers — called once at the end."""
    for sec_name, items in all_results.items():
        section(f"RESULTS · {sec_name.upper()}")
        for passed, label, detail in items:
            log(result_line(passed, label, detail))


# ══════════════════════════════════════════════════════════════════════════════
# SUMMARY PRINTER
# ══════════════════════════════════════════════════════════════════════════════
def print_summary(all_results: dict[str, list[tuple[bool, str, str]]]) -> None:
    grand_pass = 0
    grand_total = 0
    for sec_name, items in all_results.items():
        passed = sum(1 for p, _, _ in items if p)
        total = len(items)
        ratio = f"{passed}/{total}"
        colour = GREEN if passed == total else (YELLOW if passed > 0 else RED)
        icon = (
            PASS_ICON if passed == total else (WARN_ICON if passed > 0 else FAIL_ICON)
        )
        log(f"  {icon}  {BOLD}{sec_name:<22}{RESET}  {c(colour, ratio)}")
        for p, label, detail in items:
            if not p:
                bullet = f"      ❌ {c(RED, label)}"
                if detail:
                    bullet += f"  {c(YELLOW, detail)}"
                log(bullet)
        grand_pass += passed
        grand_total += total

    bar = "─" * 60
    overall_colour = (
        GREEN
        if grand_pass == grand_total
        else (YELLOW if grand_pass > grand_total // 2 else RED)
    )
    log(f"\n{CYAN}{bar}{RESET}")
    log(
        f"  {BOLD}TOTAL{RESET}                     "
        f"{c(overall_colour, f'{grand_pass}/{grand_total} checks passed')}"
    )
    log(f"{CYAN}{bar}{RESET}\n")
    log(f" {INFO_ICON} Remember to check README, diagrams and code quality manually.")


# ══════════════════════════════════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════════════════════════════════
def open_file(path: pathlib.Path) -> None:
    """Open *path* with the OS default viewer (non-blocking)."""
    try:
        if IS_WINDOWS:
            os.startfile(str(path))
        elif sys.platform == "darwin":
            subprocess.Popen(
                ["open", str(path)],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        else:
            subprocess.Popen(
                ["xdg-open", str(path)],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
    except Exception as exc:
        log(f"  {WARN_ICON} Could not open {path.name}: {exc}")


def open_diagrams(root: pathlib.Path) -> None:
    """Find class / sequence diagrams and open them in the default viewer."""
    all_diag = [
        p for p in root.rglob("*") if p.suffix.lower() in DIAGRAM_EXTS and p.is_file() and '__MACOSX' not in p.parts
    ]
    class_hits = [p for p in all_diag if re.search(r"class", p.stem, re.I)]
    seq_hits = [p for p in all_diag if re.search(r"seq(uence)?", p.stem, re.I)]
    opened: list[pathlib.Path] = []
    for hits in (class_hits, seq_hits):
        if hits:
            open_file(hits[0])
            opened.append(hits[0])
    if opened:
        log(f"  {INFO_ICON} Opened diagram(s): {', '.join(p.name for p in opened)}")
    else:
        log(f"  {INFO_ICON} No diagram files found to open")


def _count_totals(all_results: SectionResults) -> tuple[int, int]:
    passed = 0
    total = 0
    for items in all_results.values():
        passed += sum(1 for p, _, _ in items if p)
        total += len(items)
    return passed, total


def _build_run_result(
    root: pathlib.Path,
    build: pathlib.Path,
    logs: pathlib.Path,
    all_results: SectionResults,
) -> GradeRunResult:
    passed, total = _count_totals(all_results)
    overall_ok = all(p for items in all_results.values() for p, _, _ in items)
    return GradeRunResult(
        root=str(root),
        logs_dir=str(logs),
        build_dir=str(build),
        all_results=all_results,
        passed_checks=passed,
        total_checks=total,
        overall_ok=overall_ok,
        return_code=0 if overall_ok else 1,
    )


def grade_submission(
    root: str | pathlib.Path = ".",
    *,
    keep_logs: bool = False,
    no_open_diagrams: bool = False,
) -> GradeRunResult:
    root = pathlib.Path(root).resolve()
    if not root.exists():
        raise RuntimeError(f"Root not found: {root}")

    build = root / ".a2_build"
    logs = root / ".a2_logs"
    if logs.exists():
        shutil.rmtree(logs, ignore_errors=True)
    logs.mkdir(parents=True, exist_ok=True)

    all_results: SectionResults = {}

    # ── 1. Diagrams ───────────────────────────────────────────────────────────
    section("1 · DIAGRAMS")
    diag = check_diagrams(root)
    all_results["Diagrams"] = diag
    if not no_open_diagrams:
        open_diagrams(root)

    # ── 2. Code Quality ───────────────────────────────────────────────────────
    section("2 · CODE QUALITY")
    quality = check_code_quality(root)
    all_results["Code Quality"] = quality

    # ── 3. Compilation ────────────────────────────────────────────────────────
    section("3 · COMPILATION")
    compile_ok, compile_err = check_compilation(root, build)
    all_results["Compilation"] = [
        (
            compile_ok,
            "All .java sources compile without errors",
            compile_err[:300] if compile_err else "",
        )
    ]
    if not compile_ok:
        log(f"\n{RED}{compile_err[:800]}{RESET}")
        print_detailed_results(all_results)
        section("FINAL SUMMARY")
        print_summary(all_results)
        return _build_run_result(root, build, logs, all_results)

    # ── 4. E2E ────────────────────────────────────────────────────────────────
    section("4 · END-TO-END TEST  (Client <-> IntermediateHost <-> Server)")
    try:
        mains = discover_main_classes(root)
    except RuntimeError as exc:
        log(f"{FAIL_ICON} {RED}{exc}{RESET}")
        all_results["E2E"] = [(False, str(exc), "")]
        print_detailed_results(all_results)
        section("FINAL SUMMARY")
        print_summary(all_results)
        return _build_run_result(root, build, logs, all_results)

    log(f"  {INFO_ICON} Player name randomised each run")
    log(
        f"  {INFO_ICON} Classes:  client={c(CYAN, mains['client'])}"
        f"  host={c(CYAN, mains['host'])}"
        f"  server={c(CYAN, mains['server'])}"
    )

    e2e = run_e2e(root, build, logs, mains)
    all_results["E2E"] = e2e

    log(f"\n  {INFO_ICON} Logs -> {logs}/client.log  *  host.log  *  server.log")

    # ── Final summary ─────────────────────────────────────────────────────────
    print_detailed_results(all_results)
    section("FINAL SUMMARY")
    print_summary(all_results)

    if not keep_logs:
        shutil.rmtree(build, ignore_errors=True)
        # Logs are intentionally kept to aid TA review.

    return _build_run_result(root, build, logs, all_results)


def main() -> int:
    ap = argparse.ArgumentParser(description="SYSC3303 A2 grader")
    ap.add_argument("--root", default=".", help="Submission root directory")
    ap.add_argument(
        "--keep-logs",
        action="store_true",
        help="Keep .a2_build / .a2_logs directories after run",
    )
    ap.add_argument(
        "--no-open-diagrams",
        action="store_true",
        help="Skip automatically opening diagram files in the default viewer",
    )
    args = ap.parse_args()
    result = grade_submission(
        root=args.root,
        keep_logs=args.keep_logs,
        no_open_diagrams=args.no_open_diagrams,
    )
    return result.return_code


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        raise SystemExit(130)
