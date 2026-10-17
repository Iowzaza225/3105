#!/usr/bin/env python3
"""Apply a reviewed v13 on-device pairing delta after the Build 12 overlay.

Fails closed if the tarball checksum or base patch context doesn't match.
Never stores pairing credentials, generated PINs, or user data in GitHub.
"""
import base64
import hashlib
import io
import pathlib
import subprocess
import sys
import tarfile
import tempfile

EXPECTED_SHA256 = "c907f3cb549b69f3c807788b6dc1aee0dab106c28f3c78058026328dc72cb2bd"

def main():
    if len(sys.argv) != 3:
        raise SystemExit("Usage: apply_pairing_overlay.py EXTRACTED_ROOT PAIRING_DELTA")
    root = pathlib.Path(sys.argv[1]).resolve()
    encoded = pathlib.Path(sys.argv[2]).read_text()
    raw = base64.b64decode("".join(encoded.split()), validate=True)
    got = hashlib.sha256(raw).hexdigest()
    if got != EXPECTED_SHA256:
        raise SystemExit("On-device pairing overlay checksum mismatch: " + got)
    with tempfile.TemporaryDirectory() as tmp:
        tmp = pathlib.Path(tmp)
        with tarfile.open(fileobj=io.BytesIO(raw), mode="r:gz") as tf:
            entries = tf.getmembers()
            if len(entries) != 5:
                raise SystemExit("Unexpected number of pairing patches")
            for ent in entries:
                if not ent.isfile() or not ent.name.endswith(".diff"):
                    raise SystemExit("Unsafe or unexpected delta entry")
                p = pathlib.PurePosixPath(ent.name[:-5])
                if p.is_absolute() or ".." in p.parts or not p.parts[0] == "ThreeOneOSFive":
                    raise SystemExit("Unsafe pairing patch path")
                if not root.joinpath(*p.parts).is_file():
                    raise SystemExit("Base source missing: " + str(p))
                diff = tf.extractfile(ent).read()
                patch_file = tmp / "update.diff"
                patch_file.write_bytes(diff)
                print("Applying on-device pairing:", p, flush=True)
                subprocess.run(["patch", "--fuzz=0", "-p1", "--batch", "-i", str(patch_file)],
                               cwd=root, check=True)
    info = root / "ThreeOneOSFive/Info.plist"
    assert "NSBonjourServices" in info.read_text()
    objc = root / "ThreeOneOSFive/native/RuizenNativeBridge.m"
    assert "al_pairing_run_host" in objc.read_text()
    print("Build 13 on-device pairing overlay applied; iOS device test still required")

if __name__ == "__main__":
    main()
