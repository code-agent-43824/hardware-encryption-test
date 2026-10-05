"""Run the packaged application against an isolated portable SoftHSM token."""

import argparse
import hashlib
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import zipfile


DEMO_PIN = "12345678"


def run(command, *, env, input_text=None, timeout=60):
    result = subprocess.run(
        command, input=input_text, text=True, encoding="utf-8", errors="replace",
        capture_output=True, env=env, timeout=timeout, check=False,
    )
    if result.returncode:
        raise RuntimeError(f"{Path(command[0]).name} exited {result.returncode}\n{result.stdout[-6000:]}\n{result.stderr[-2000:]}")
    return result.stdout


def verify_archive(archive, checksums):
    expected = {}
    for line in checksums.read_text(encoding="utf-8").splitlines():
        digest, filename = line.split(maxsplit=1)
        expected[filename.lstrip("*")] = digest.lower()
    if archive.name not in expected:
        raise RuntimeError(f"No SHA-256 for {archive.name}")
    with archive.open("rb") as stream:
        actual = hashlib.file_digest(stream, "sha256").hexdigest()
    if actual != expected[archive.name]:
        raise RuntimeError(f"SHA-256 mismatch for {archive.name}")


def input_sequence(module):
    lines = [str(module)]
    for algorithm, key_id in enumerate(("01", "02", "03")):
        lines += ["2", DEMO_PIN, str(algorithm), key_id, f"ci-key-{key_id}"]
    lines += ["1"]  # Find all three pairs.
    for pair_index in range(3):
        lines += ["4", DEMO_PIN, "", "1", "0", str(pair_index)]
    for mode in ("0", "1"):
        for algorithm in ("0", "1", "2"):
            lines += ["5", DEMO_PIN, "", "1", "0", mode, algorithm]
    for _ in range(3):
        lines += ["3", DEMO_PIN, "0", "y"]
    lines += ["1", "0"]  # Confirm the token is empty, then exit.
    return "\n".join(lines) + "\n"


def check_output(output):
    expected = {
        "Пара создана:": 3,
        "Самопроверка подписи: успешно": 3,
        "Самопроверка расшифрованием: успешно": 6,
        "Пара удалена:": 3,
        "Пары не найдены": 1,
        "CKA_TOKEN=FALSE": 3,
        "CKA_TOKEN=TRUE": 3,
    }
    for marker, count in expected.items():
        actual = output.count(marker)
        if actual != count:
            raise RuntimeError(f"Expected {count} × {marker!r}, got {actual}\n{output[-8000:]}")
    for marker in ("Ошибка:", "Неожиданная ошибка:"):
        if marker in output:
            raise RuntimeError(f"Unexpected {marker!r}\n{output[-8000:]}")
    if "Token model: Rutoken ECP" not in output:
        raise RuntimeError(f"Fake Rutoken identity not found\n{output[:3000]}")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--app", type=Path, required=True)
    parser.add_argument("--softhsm-zip", type=Path, required=True)
    parser.add_argument("--checksums", type=Path, required=True)
    args = parser.parse_args()
    app = args.app.resolve()
    if not (app.is_file() and (app.parent / "lorem-500kb.txt").is_file()):
        raise RuntimeError("Compiled app or bundled sample file missing")
    verify_archive(args.softhsm_zip, args.checksums)

    with tempfile.TemporaryDirectory(prefix="fake-rutoken-") as directory:
        root = Path(directory)
        module_dir = root / "portable"
        with zipfile.ZipFile(args.softhsm_zip) as archive:
            archive.extractall(module_dir)
        if sys.platform == "win32":
            module_name, util_name = "softhsm2.dll", "softhsm2-util.exe"
        elif sys.platform == "darwin":
            module_name, util_name = "libsofthsm2.dylib", "softhsm2-util"
        else:
            module_name, util_name = "libsofthsm2.so", "softhsm2-util"
        module, util = module_dir / module_name, module_dir / util_name
        if not (module.is_file() and util.is_file()):
            raise RuntimeError("Portable SoftHSM module or initializer missing")
        if os.name != "nt":
            app.chmod(app.stat().st_mode | 0o111)
            util.chmod(util.stat().st_mode | 0o111)

        config = root / "softhsm.conf"
        config.write_text(
            "directories.tokendir = tokens\nobjectstore.backend = file\n"
            "log.level = ERROR\nFAKE_RUTOKEN_ECP = true\n", encoding="utf-8",
        )
        env = os.environ.copy()
        env["SOFTHSM2_CONF"] = str(config)
        # Windows CI pipes otherwise select cp1252, which cannot print Russian prompts.
        env["PYTHONIOENCODING"] = "utf-8"
        run([str(util), "--init-token", "--slot", "0", "--label", "ci-token",
             "--so-pin", DEMO_PIN, "--pin", DEMO_PIN], env=env)
        output = run([str(app)], env=env, input_text=input_sequence(module), timeout=300)
        check_output(output)
    print("Fake Rutoken E2E: 3 key pairs, 3 signatures, 6 encryption modes, 3 deletions passed")


if __name__ == "__main__":
    main()
