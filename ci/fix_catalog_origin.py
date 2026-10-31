#!/usr/bin/env python3
"""Recognize the current server catalog origin during cache import.

Importing two alternatives is allowed; PatchTransaction.apply continues to
reject overlapping active targets. No restore, apply, or receipt code changes.
"""
from pathlib import Path
import sys
root = Path(sys.argv[1])
p = root / "ThreeOneOSFive/helpers/PatchProjectLibrary.swift"
s = p.read_text()
old = 'let isServerManaged = origin?.repositoryName == "HTVINTEX Server"'
new = 'let isServerManaged = origin?.repositoryName == "HTVINTEX Server" || origin?.repositoryName == "RUIZEN"'
assert s.count(old) == 1
s = s.replace(old, new, 1)
p.write_text(s)
view = (root / "ThreeOneOSFive/views/PatchProjectsView.swift").read_text()
assert 'repositoryName: "RUIZEN"' in view
assert 'if !isServerManaged, let occupiedPath = overlappingTargetPath(' in s
transaction = (root / "ThreeOneOSFive/helpers/PatchTransaction.swift").read_text()
assert 'let occupied = appliedTargetKeys(' in transaction
assert 'if occupied.contains(occupancyKey)' in transaction
print("Verified catalog origin fix: cache alternatives allowed for RUIZEN server, local import policy and active transaction conflict protection retained")
