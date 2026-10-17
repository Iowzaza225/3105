#!/usr/bin/env python3
"""Apply the exact changed Swift/Xcode files from the reviewed iOS 27 source ZIP.

The repo's original Build 10 archive remains untouched. The delta stores new
files and unified diffs for changed files to keep the GitHub repo lightweight.
"""
import base64
import hashlib
import io
import pathlib
import subprocess
import sys
import tarfile
import tempfile

EXPECTED_DELTA_SHA256 = "cfe37d3e42f04d9b8c0d3dca6df612a05fda08cf3f6da4531ec556cd1c5d855b"

def main():
    if len(sys.argv) != 3:
        raise SystemExit("Usage: apply_source_overlay.py EXTRACTED_SOURCE_ROOT DELTA_B64")
    root = pathlib.Path(sys.argv[1]).resolve()
    delta_path = pathlib.Path(sys.argv[2]).resolve()
    assert (root / "ThreeOneOSFive.xcodeproj" / "project.pbxproj").exists(), "Xcode project missing"
    raw = base64.b64decode("".join(delta_path.read_text().split()), validate=True)
    digest = hashlib.sha256(raw).hexdigest()
    if digest != EXPECTED_DELTA_SHA256:
        raise SystemExit(f"Delta digest mismatch: {digest}")

    with tempfile.TemporaryDirectory() as temp, tarfile.open(fileobj=io.BytesIO(raw), mode="r:gz") as tf:
        temp = pathlib.Path(temp)
        entries = sorted(tf.getmembers(), key=lambda m: m.name)
        if not entries:
            raise SystemExit("Empty source overlay")
        for entry in entries:
            if not entry.isfile():
                raise SystemExit(f"Unexpected archive entry: {entry.name}")
            name = entry.name
            is_patch = name.endswith(".diff")
            relative = pathlib.PurePosixPath(name[:-5] if is_patch else name)
            if relative.is_absolute() or ".." in relative.parts:
                raise SystemExit(f"Unsafe entry path: {name}")
            path = root.joinpath(*relative.parts)
            if not path.resolve().is_relative_to(root):
                raise SystemExit(f"Escaping source root: {name}")
            contents = tf.extractfile(entry).read()
            if is_patch:
                if not path.is_file():
                    raise SystemExit(f"Patch base file missing: {relative}")
                patch_file = temp / "patch.diff"
                patch_file.write_bytes(contents)
                print(f"Applying diff: {relative}", flush=True)
                subprocess.run(["patch", "-p1", "-N", "-i", str(patch_file)], cwd=root, check=True)
            else:
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(contents)
                print(f"Added: {relative}", flush=True)

    required = [
        "ThreeOneOSFive/native/RuizenNativeBridge.m",
        "ThreeOneOSFive/helpers/RuizenDeviceReadiness.swift",
        "ThreeOneOSFive/views/RuizenApplyPreflightView.swift",
        "scripts/enable_airlift_macos.sh",
    ]
    for p in required:
        assert (root / p).is_file(), f"Required source missing: {p}"
    print("RUIZEN iOS 27 source overlay applied. Native linkage is a separate build step.")

if __name__ == "__main__":
    main()
