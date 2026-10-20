"""End-to-end regression tests for the provisioned two-Raspberry-Pi deployment.

These tests exercise the whole path a real Pi takes:

    provision.py  ->  secure_launcher.py (verify)  ->  pi_node.py (execute)

Two nodes are provisioned into a temporary directory, then a real server and a
real client are run as two concurrent subprocesses over ``127.0.0.1`` on a free
ephemeral port. Nothing is written into the repository, no fixed port is ever
used, and every subprocess is killed in a ``finally`` so the suite cannot hang.
Each test additionally runs under a hard wall-clock deadline.
"""

from __future__ import annotations

import argparse
import contextlib
import io
import json
import os
import re
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path

# Make the suite runnable from ANY working directory: ``unittest discover -s
# <dir>`` puts the *start* directory on sys.path, not the repository root, so
# ``import provision`` would otherwise only resolve when the current directory
# happens to be the repository root.
REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import provision as provision_module  # noqa: E402

VALIDATION_DIR = REPO_ROOT / "Validation"
ARTIFACT = REPO_ROOT / "pi_node.py"
LAUNCHER = "secure_launcher.py"

CLIENT_MESSAGE = "telemetry from pi-a: temperature=21.5C"
SERVER_REPLY = "ack from pi-b: command accepted"

HOST = "127.0.0.1"
NODE_TIMEOUT = 10.0
STARTUP_DEADLINE = 15.0
SHUTDOWN_GRACE = 10.0
NO_SOCKET_WINDOW = 1.5
EXCHANGE_DEADLINE = 60.0
DISCOVERY_DEADLINE = 300.0

# Set in the environment of the discovery subprocess so the test below does not
# recursively spawn itself (and so it does not spawn itself forever).
DISCOVERY_GUARD = "SECURE_CHANNEL_DISCOVERY_SUBPROCESS"


@contextlib.contextmanager
def hard_deadline(seconds, label="test"):
    """Fail the test rather than let it hang the suite.

    Uses ``SIGALRM`` (Unix only) so the deadline is honoured even if a child
    process wedges. The exception unwinds through the test's ``finally`` blocks,
    which kill every subprocess.
    """
    if not hasattr(signal, "SIGALRM") or threading.current_thread() is not threading.main_thread():
        yield
        return

    def handler(signum, frame):
        raise AssertionError(f"{label} exceeded its {seconds:.0f}s deadline")

    previous = signal.signal(signal.SIGALRM, handler)
    signal.setitimer(signal.ITIMER_REAL, seconds)
    try:
        yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous)


def free_port():
    """Reserve a free loopback port by binding port 0, then release it."""
    probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        probe.bind((HOST, 0))
        return probe.getsockname()[1]
    finally:
        probe.close()


def parse_events(text):
    """Every line of *text* that is a JSON object, as a list of dicts."""
    events = []
    for line in text.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            value = json.loads(line)
        except ValueError:
            continue
        if isinstance(value, dict):
            events.append(value)
    return events


def events_named(events, name):
    """The events whose ``event`` field is *name*."""
    return [event for event in events if event.get("event") == name]


class Process:
    """A node subprocess whose output is captured in files.

    Files (rather than pipes) let the test watch for the server's ``listening``
    line while it is still running, without ever blocking on a full pipe.
    """

    def __init__(self, label, command, cwd, log_dir):
        self.label = label
        self.command = list(command)
        self.stdout_path = Path(log_dir) / f"{label}.out"
        self.stderr_path = Path(log_dir) / f"{label}.err"
        self._stdout = open(self.stdout_path, "w", encoding="utf-8")
        self._stderr = open(self.stderr_path, "w", encoding="utf-8")
        self.process = subprocess.Popen(
            self.command,
            cwd=str(cwd),
            stdout=self._stdout,
            stderr=self._stderr,
            text=True,
        )

    def stdout(self):
        """Everything the process has written to stdout so far."""
        return self._read(self.stdout_path)

    def stderr(self):
        """Everything the process has written to stderr so far."""
        return self._read(self.stderr_path)

    @staticmethod
    def _read(path):
        try:
            return path.read_text(encoding="utf-8", errors="replace")
        except FileNotFoundError:  # pragma: no cover - defensive
            return ""

    def wait_for_output(self, needle, deadline):
        """Wait until *needle* appears on stdout, or the process exits."""
        end = time.monotonic() + deadline
        while True:
            if needle in self.stdout():
                return True
            if self.process.poll() is not None:
                return needle in self.stdout()
            if time.monotonic() >= end:
                return False
            time.sleep(0.05)

    def wait(self, timeout):
        """Wait for exit, killing the process and failing on timeout."""
        try:
            return self.process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            self.kill()
            raise AssertionError(
                f"the {self.label} did not exit within {timeout}s\n"
                f"command: {' '.join(self.command)}\n"
                f"stdout:\n{self.stdout()}\nstderr:\n{self.stderr()}"
            )

    def kill(self):
        """Kill the process if it is still running."""
        if self.process.poll() is None:
            self.process.kill()
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:  # pragma: no cover - defensive
                pass

    def close(self):
        """Kill the process (if needed) and close its log files."""
        self.kill()
        self._stdout.close()
        self._stderr.close()


class DeploymentTestCase(unittest.TestCase):
    """Shared plumbing: a temporary workspace, provisioning, and process launch."""

    def setUp(self):
        self.workspace = Path(tempfile.mkdtemp(prefix="integration-test-"))
        self.addCleanup(shutil.rmtree, str(self.workspace), True)
        self.logs = self.workspace / "logs"
        self.logs.mkdir()

    def provision_pair(self):
        """Provision a throwaway pi-a/pi-b pair and return the deployment dir."""
        output = self.workspace / "deployment"
        args = argparse.Namespace(
            firmware=str(ARTIFACT), output=str(output), manufacturer_key=None
        )
        with contextlib.redirect_stdout(io.StringIO()):
            provision_module.provision(args)
        return output

    def launcher_command(self, node_dir, role, port, extra=()):
        """The exact command line an operator would use on a Pi."""
        return [
            sys.executable,
            str(Path(node_dir) / LAUNCHER),
            "--config",
            str(node_dir),
            "--role",
            role,
            "--host",
            HOST,
            "--port",
            str(port),
            "--timeout",
            str(int(NODE_TIMEOUT)),
            *extra,
        ]

    def start(self, label, node_dir, role, port, extra=()):
        """Start one provisioned node through its own secure launcher."""
        return Process(
            label,
            self.launcher_command(node_dir, role, port, extra),
            cwd=node_dir,
            log_dir=self.logs,
        )

    def run_exchange(self, output, client_extra=(), server_extra=(), attempts=3):
        """Run a full exchange on a fresh free port; always kills both processes.

        The port is reserved with ``bind(0)`` and released immediately, so a
        race with another process is possible (though unlikely). If the server
        dies because the port was taken, the whole exchange is retried on a new
        port instead of failing the test.
        """
        result = None
        for _ in range(attempts):
            result = self._exchange_on_port(
                output, free_port(), client_extra, server_extra
            )
            if result["listening"] or "Address already in use" not in result["server_err"]:
                break

        self.assertTrue(
            result["listening"],
            "the server never reported that it was listening\n"
            f"stdout:\n{result['server_out']}\nstderr:\n{result['server_err']}",
        )
        return result

    def _exchange_on_port(self, output, port, client_extra, server_extra):
        """One attempt at a full exchange; always kills both processes."""
        server = self.start("server", output / "pi-b", "server", port, extra=server_extra)
        client = None
        result = {
            "listening": False,
            "server_rc": None,
            "server_out": "",
            "server_err": "",
            "client_rc": None,
            "client_out": "",
            "client_err": "",
        }
        try:
            if not server.wait_for_output('"listening"', STARTUP_DEADLINE):
                server.wait(5)
                result.update(
                    server_rc=server.process.returncode,
                    server_out=server.stdout(),
                    server_err=server.stderr(),
                )
                return result

            result["listening"] = True
            client = self.start(
                "client", output / "pi-a", "client", port, extra=client_extra
            )
            result["client_rc"] = client.wait(NODE_TIMEOUT + SHUTDOWN_GRACE)
            result["server_rc"] = server.wait(NODE_TIMEOUT + SHUTDOWN_GRACE)
            result.update(
                server_out=server.stdout(),
                server_err=server.stderr(),
                client_out=client.stdout(),
                client_err=client.stderr(),
            )
            return result
        finally:
            if client is not None:
                client.close()
            server.close()


class TestNormalExchange(DeploymentTestCase):
    """The happy path: two provisioned Pis complete an authenticated exchange."""

    def test_two_nodes_exchange_authenticated_messages(self):
        """Both nodes boot, establish a channel, and swap authenticated messages"""
        with hard_deadline(EXCHANGE_DEADLINE, "normal exchange"):
            output = self.provision_pair()
            result = self.run_exchange(
                output,
                client_extra=("--message", CLIENT_MESSAGE),
                server_extra=("--reply", SERVER_REPLY),
            )

        context = (
            f"\nserver rc={result['server_rc']}\n{result['server_out']}"
            f"\n{result['server_err']}"
            f"\nclient rc={result['client_rc']}\n{result['client_out']}"
            f"\n{result['client_err']}"
        )

        self.assertEqual(result["server_rc"], 0, f"the server failed{context}")
        self.assertEqual(result["client_rc"], 0, f"the client failed{context}")

        server_events = parse_events(result["server_out"])
        client_events = parse_events(result["client_out"])

        for name, events in (("server", server_events), ("client", client_events)):
            boot = events_named(events, "secure_boot")
            self.assertTrue(boot, f"the {name} never reported secure boot{context}")
            self.assertEqual(boot[-1].get("status"), "PASS", f"{name} secure boot{context}")

            channel = events_named(events, "secure_channel")
            self.assertTrue(channel, f"the {name} never established a channel{context}")
            self.assertEqual(channel[-1].get("status"), "ESTABLISHED", context)

        server_received = events_named(server_events, "received")
        self.assertEqual(
            len(server_received), 1, f"the server printed no received event{context}"
        )
        self.assertEqual(
            server_received[0].get("plaintext"),
            CLIENT_MESSAGE,
            f"the server decrypted the wrong plaintext{context}",
        )

        client_received = events_named(client_events, "received")
        self.assertEqual(
            len(client_received), 1, f"the client printed no received event{context}"
        )
        self.assertEqual(
            client_received[0].get("plaintext"),
            SERVER_REPLY,
            f"the client decrypted the wrong reply{context}",
        )

        self.assertEqual(result["server_err"], "", f"the server wrote to stderr{context}")
        self.assertEqual(result["client_err"], "", f"the client wrote to stderr{context}")

    def test_the_launcher_verifies_before_it_executes(self):
        """secure_boot PASS names the artifact that was then executed"""
        with hard_deadline(EXCHANGE_DEADLINE, "normal exchange"):
            output = self.provision_pair()
            result = self.run_exchange(
                output,
                client_extra=("--message", CLIENT_MESSAGE),
                server_extra=("--reply", SERVER_REPLY),
            )

        boot = events_named(parse_events(result["server_out"]), "secure_boot")
        self.assertTrue(boot, f"no secure_boot event\n{result['server_out']}")
        self.assertEqual(boot[-1].get("artifact"), "pi_node.py")
        self.assertEqual(len(boot[-1].get("sha256", "")), 64)
        # The artifact really ran: only pi_node.py emits this event.
        self.assertTrue(
            events_named(parse_events(result["server_out"]), "listening"),
            f"the verified artifact never executed\n{result['server_out']}",
        )


class TestTamperedExchange(DeploymentTestCase):
    """A tampered packet must be rejected and must kill the exchange."""

    def test_tampered_packet_is_rejected_by_the_peer(self):
        """The server must refuse the tampered packet and never print a plaintext"""
        with hard_deadline(EXCHANGE_DEADLINE, "tampered exchange"):
            output = self.provision_pair()
            result = self.run_exchange(
                output,
                client_extra=("--tamper", "--message", CLIENT_MESSAGE),
                server_extra=("--reply", SERVER_REPLY),
            )

        context = (
            f"\nserver rc={result['server_rc']}\n{result['server_out']}"
            f"\n{result['server_err']}"
            f"\nclient rc={result['client_rc']}\n{result['client_out']}"
            f"\n{result['client_err']}"
        )

        self.assertNotEqual(result["server_rc"], 0, f"the server accepted tampering{context}")
        self.assertNotEqual(result["client_rc"], 0, f"the client reported success{context}")

        self.assertIn(
            "ASCON integrity verification failed",
            result["server_err"],
            f"the server did not report an ASCON integrity failure{context}",
        )
        server_errors = events_named(parse_events(result["server_err"]), "error")
        self.assertTrue(server_errors, f"the server printed no error event{context}")

        server_events = parse_events(result["server_out"])
        leaked = [
            event
            for event in server_events
            if event.get("event") == "received" and "plaintext" in event
        ]
        self.assertEqual(
            leaked, [], f"the server decrypted a tampered packet{context}"
        )
        self.assertFalse(
            events_named(server_events, "sent"),
            f"the server replied to a tampered packet{context}",
        )

        # The channel itself was established before the tampering was detected.
        channel = events_named(server_events, "secure_channel")
        self.assertTrue(channel, f"the session was never established{context}")
        self.assertEqual(channel[-1].get("status"), "ESTABLISHED", context)

        self.assertIn(
            "rejected",
            result["client_err"],
            f"the client did not report the rejection{context}",
        )
        self.assertNotIn(
            SERVER_REPLY,
            result["client_out"],
            f"the client received a reply it should never have seen{context}",
        )


class TestModifiedArtifact(DeploymentTestCase):
    """Regression: the launcher used to verify a file it never executed."""

    def test_modified_artifact_fails_secure_boot_and_opens_no_socket(self):
        """A modified artifact must not boot and must not open a socket"""
        with hard_deadline(EXCHANGE_DEADLINE, "modified artifact"):
            output = self.provision_pair()
            node_dir = output / "pi-b"
            artifact = node_dir / "pi_node.py"

            original = artifact.read_bytes()
            tampered = bytearray(original)
            tampered[len(tampered) // 2] ^= 0x01
            artifact.write_bytes(bytes(tampered))
            self.assertNotEqual(artifact.read_bytes(), original)

            port = free_port()
            listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            listener.bind((HOST, port))
            listener.listen(1)
            listener.settimeout(NO_SOCKET_WINDOW)
            try:
                process = self.start("modified", node_dir, "server", port)
                try:
                    returncode = process.wait(STARTUP_DEADLINE)
                    stdout = process.stdout()
                    stderr = process.stderr()
                finally:
                    process.close()

                context = f"\nrc={returncode}\nstdout:\n{stdout}\nstderr:\n{stderr}"
                self.assertNotEqual(
                    returncode, 0, f"a modified artifact booted anyway{context}"
                )

                boot = events_named(parse_events(stderr), "secure_boot")
                self.assertTrue(boot, f"no secure_boot event on stderr{context}")
                self.assertEqual(boot[-1].get("status"), "FAIL", context)

                self.assertFalse(
                    events_named(parse_events(stdout), "secure_boot"),
                    f"a PASS was printed for a modified artifact{context}",
                )
                for event_name in ("listening", "connected", "secure_channel"):
                    self.assertFalse(
                        events_named(parse_events(stdout), event_name),
                        f"the modified artifact reached {event_name!r}{context}",
                    )

                with self.assertRaises(
                    socket.timeout,
                    msg=f"the modified artifact opened a connection{context}",
                ):
                    listener.accept()
            finally:
                listener.close()

    def test_unmodified_artifact_still_boots(self):
        """Positive control: the same run succeeds while the artifact is intact"""
        with hard_deadline(EXCHANGE_DEADLINE, "control exchange"):
            output = self.provision_pair()
            port = free_port()
            process = self.start("control", output / "pi-b", "server", port)
            try:
                self.assertTrue(
                    process.wait_for_output('"listening"', STARTUP_DEADLINE),
                    "the intact artifact did not boot\n"
                    f"stdout:\n{process.stdout()}\nstderr:\n{process.stderr()}",
                )
                boot = events_named(parse_events(process.stdout()), "secure_boot")
                self.assertEqual(boot[-1].get("status"), "PASS")
            finally:
                process.close()


class TestValidationDiscovery(unittest.TestCase):
    """Regression: discovery only worked when cwd was the repository root."""

    def test_discovery_works_from_a_different_working_directory(self):
        """`unittest discover -s <repo>/Validation` passes from another cwd"""
        if os.environ.get(DISCOVERY_GUARD):
            self.skipTest("already running inside the guarded discovery subprocess")

        command = [
            sys.executable,
            "-m",
            "unittest",
            "discover",
            "-s",
            str(VALIDATION_DIR),
            "-p",
            "Test_*.py",
        ]
        environment = dict(os.environ)
        environment[DISCOVERY_GUARD] = "1"

        with hard_deadline(DISCOVERY_DEADLINE, "cross-directory discovery"):
            completed = subprocess.run(
                command,
                cwd=tempfile.gettempdir(),
                capture_output=True,
                text=True,
                timeout=DISCOVERY_DEADLINE - 20,
                env=environment,
            )

        blockers = sorted(
            set(
                re.findall(
                    r"Failed to import test module: (\S+)", completed.stderr
                )
            )
        )
        hint = (
            "test modules that cannot be imported from another working "
            f"directory: {', '.join(blockers)}"
            if blockers
            else ""
        )
        report = f"stdout:\n{completed.stdout}\nstderr:\n{completed.stderr}\n{hint}"
        self.assertEqual(
            completed.returncode,
            0,
            f"discovery from {tempfile.gettempdir()} failed:\n{report}",
        )

        counts = [
            int(line.split()[1])
            for line in completed.stderr.splitlines()
            if line.startswith("Ran ") and line.split()[1].isdigit()
        ]
        self.assertTrue(counts, f"discovery ran no tests at all:\n{report}")
        self.assertGreater(counts[-1], 0, f"discovery found no tests:\n{report}")


if __name__ == "__main__":
    unittest.main()
