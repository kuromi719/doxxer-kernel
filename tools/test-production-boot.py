"""Exercise the real (non-TEST_MODE) boot and early session in headless QEMU.

Requires Python 3.10+ and Pillow. Unlike test.ps1, this deliberately waits for the
five-second trace hold and the thirty-second logo period.
"""

from __future__ import annotations

import argparse
import json
import shutil
import socket
import subprocess
import tempfile
import time
from pathlib import Path

from PIL import Image


ROOT = Path(__file__).resolve().parent.parent
QEMU = Path(r"C:\Program Files\qemu\qemu-system-x86_64.exe")
FIRMWARE = Path(r"C:\Program Files\qemu\share\edk2-x86_64-code.fd")
WORDMARK = ROOT / "assets" / "boot-wordmark.png"


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def wait_for(predicate, seconds: float, description: str) -> None:
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(0.1)
    raise TimeoutError(f"Timed out waiting for {description}")


class Qmp:
    def __init__(self, port: int):
        deadline = time.monotonic() + 10
        while True:
            try:
                self.socket = socket.create_connection(("127.0.0.1", port), 1)
                break
            except OSError:
                if time.monotonic() >= deadline:
                    raise
                time.sleep(0.1)
        self.socket.settimeout(5)
        self.file = self.socket.makefile("rwb", buffering=0)
        self._response()
        self.execute("qmp_capabilities")

    def _response(self) -> dict:
        while True:
            line = self.file.readline()
            if not line:
                raise ConnectionError("QMP connection closed")
            item = json.loads(line)
            if "event" not in item:
                return item

    def execute(self, name: str, arguments: dict | None = None) -> dict:
        request = {"execute": name}
        if arguments is not None:
            request["arguments"] = arguments
        self.file.write((json.dumps(request) + "\n").encode("ascii"))
        result = self._response()
        require("error" not in result, f"QMP {name} failed: {result}")
        return result

    def screenshot(self, path: Path) -> Image.Image:
        # QEMU screendump emits a portable pixmap; Pillow decodes it here.
        self.execute("screendump", {"filename": path.as_posix()})
        with Image.open(path) as screenshot:
            return screenshot.convert("RGB")

    def close(self) -> None:
        self.file.close()
        self.socket.close()


def free_port() -> int:
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return listener.getsockname()[1]


def serial_count(path: Path) -> int:
    try:
        return path.read_bytes().count(b"DOXXER_BOOT_START")
    except FileNotFoundError:
        return 0


def assert_exact_logo(image: Image.Image, reference: Image.Image) -> None:
    require(image.width >= reference.width and image.height >= reference.height,
            f"Framebuffer {image.size} is too small for the native wordmark")
    expected = Image.new("RGB", image.size, (4, 3, 6))
    expected.paste(reference, ((image.width - reference.width) // 2,
                               (image.height - reference.height) // 2))
    require(image.tobytes() == expected.tobytes(),
            "Production framebuffer differs from centered reference wordmark")


def is_exact_logo(image: Image.Image, reference: Image.Image) -> bool:
    try:
        assert_exact_logo(image, reference)
        return True
    except AssertionError:
        return False


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--media", choices=("disk", "iso"), default="disk")
    args = parser.parse_args()
    artifact = ROOT / "dist" / ("doxxer-uefi.img" if args.media == "disk" else "doxxer.iso")
    for path in (QEMU, FIRMWARE, WORDMARK, artifact):
        require(path.is_file(), f"Missing required file: {path}")
    with Image.open(WORDMARK) as source:
        reference = source.convert("RGB")

    log_dir = ROOT / "build" / "test-logs"
    log_dir.mkdir(parents=True, exist_ok=True)
    evidence = log_dir / f"production-{args.media}"
    evidence.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="production-boot-", dir=log_dir) as temporary:
        temp = Path(temporary)
        local_artifact = temp / artifact.name
        shutil.copy2(artifact, local_artifact)
        serial = temp / "serial.log"
        port = free_port()
        command = [str(QEMU), "-machine", "q35", "-cpu", "max", "-smp", "4",
                   "-m", "512M", "-display", "none", "-monitor", "none",
                   "-drive", f"if=pflash,format=raw,readonly=on,file={FIRMWARE}",
                   "-device", "intel-iommu,intremap=off",
                   "-serial", f"file:{serial}",
                   "-qmp", f"tcp:127.0.0.1:{port},server=on,wait=off"]
        command += (["-drive", f"format=raw,file={local_artifact}"]
                    if args.media == "disk" else ["-cdrom", str(local_artifact)])
        with (temp / "qemu-stderr.log").open("wb") as errors:
            process = subprocess.Popen(command, stdout=subprocess.DEVNULL, stderr=errors)
            qmp = None
            try:
                qmp = Qmp(port)
                wait_for(lambda: serial_count(serial) >= 1, 40, "DOXXER_BOOT_START")
                wait_for(lambda: b"DOXXER_BOOT_OK" in serial.read_bytes(), 60,
                         "successful production boot")
                ready_at = time.monotonic()
                trace = qmp.screenshot(temp / "trace.ppm")
                trace.save(evidence / "trace.png")
                require(not is_exact_logo(trace, reference),
                        "Logo appeared before the required trace hold")
                # Leave one second of scheduling tolerance around the nominal
                # five-second hold; a screenshot at +4s must still show trace.
                wait_for(lambda: time.monotonic() - ready_at >= 4, 5,
                         "near-end trace hold")
                early = qmp.screenshot(temp / "early.ppm")
                early.save(evidence / "early.png")
                require(not is_exact_logo(early, reference),
                        "Logo appeared before the near-end five-second trace hold")
                wait_for(lambda: time.monotonic() - ready_at >= 6, 7, "logo transition")
                logo = qmp.screenshot(temp / "logo.ppm")
                logo.save(evidence / "logo.png")
                assert_exact_logo(logo, reference)
                # Logo must remain through almost all of the nominal 30s
                # interval, not merely appear once before an early handoff.
                wait_for(lambda: time.monotonic() - ready_at >= 34, 30,
                         "near-end logo hold")
                near_end_logo = qmp.screenshot(temp / "logo-near-end.ppm")
                near_end_logo.save(evidence / "logo-near-end.png")
                assert_exact_logo(near_end_logo, reference)
                wait_for(lambda: time.monotonic() - ready_at >= 37, 35,
                         "thirty-second logo hold and desktop handoff")
                def desktop_ready() -> bool:
                    output = serial.read_bytes()
                    require(b"DOXXER_PANIC" not in output and b"[ERROR]" not in output,
                            "Kernel panicked during user-session handoff; see serial.log")
                    return b"DOXXER_DESKTOP_READY" in output

                wait_for(desktop_ready, 10, "early desktop serial marker")
                serial_text = serial.read_bytes()
                user_started = serial_text.find(b"DOXXER_USER_SESSION_STARTED")
                desktop_ready = serial_text.find(b"DOXXER_DESKTOP_READY")
                require(0 <= user_started < desktop_ready,
                        "Early desktop was drawn without a verified user-mode session")
                desktop = qmp.screenshot(temp / "desktop.ppm")
                desktop.save(evidence / "desktop.png")
                require(not is_exact_logo(desktop, reference),
                        "Logo remained after desktop readiness marker")
                require(desktop.getpixel((0, 0)) == (22, 16, 35),
                        "Early desktop panel was not rendered")
                # Prove repeated user/kernel crossings, not merely one good
                # syscall followed by a stalled or dead ring-3 loop.
                wait_for(lambda: b"DOXXER_USER_HEARTBEAT_16" in serial.read_bytes(),
                         10, "sixteen successful user syscalls")
                time.sleep(2)
                require(b"DOXXER_PANIC" not in serial.read_bytes(),
                        "Kernel panicked shortly after desktop readiness")
                stable_desktop = qmp.screenshot(temp / "desktop-stable.ppm")
                stable_desktop.save(evidence / "desktop-stable.png")
                require(stable_desktop.getpixel((0, 0)) == (22, 16, 35),
                        "Early desktop surface changed unexpectedly")
                # Set-1 code 0x03 is the '2' key, not F5. It must not restart.
                qmp.execute("send-key", {"keys": [{"type": "qcode", "data": "2"}]})
                time.sleep(1)
                require(serial_count(serial) == 1,
                        "Non-F5 key unexpectedly restarted the guest")
                qmp.execute("send-key", {"keys": [{"type": "qcode", "data": "f5"}]})
                wait_for(lambda: serial_count(serial) >= 2, 15, "F5 guest reboot")
                require(process.poll() is None, "QEMU exited instead of restarting guest")
                print(f"Production {args.media} boot passed: trace hold, exact logo, "
                      "30-second transition, early desktop surface, F5 restart.")
            finally:
                if qmp is not None:
                    try:
                        qmp.execute("quit")
                    except (OSError, ConnectionError):
                        pass
                    qmp.close()
                try:
                    process.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=3)
                if serial.exists():
                    shutil.copy2(serial, evidence / "serial.log")
                shutil.copy2(temp / "qemu-stderr.log", evidence / "qemu-stderr.log")


if __name__ == "__main__":
    main()
