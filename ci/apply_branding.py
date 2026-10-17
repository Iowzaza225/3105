#!/usr/bin/env python3
"""Apply RUIZEN display branding after the existing source overlays."""
import hashlib
import pathlib
import plistlib
import shutil
import sys

root = pathlib.Path(sys.argv[1]).resolve()
asset = pathlib.Path(sys.argv[2]).resolve()
app = root / 'ThreeOneOSFive'
entry = app / 'App.swift'
original = entry.read_text()
# Keep the license gate and its checks. Only replace the post-license root view.
assert original.count('StockGateView()') == 1
entry.write_text(original.replace('StockGateView()', 'ContentView()', 1))
for p in app.rglob('*'):
    if p.suffix in ('.swift', '.strings'):
        text = p.read_text()
        updated = text.replace('VIPERX', 'RUIZEN').replace('RUIZEN CLIENT', 'RUIZENCLIENT').replace('RUIZEN-CLIENT', 'RUIZENCLIENT')
        if p.name == 'DesignSystem.swift':
            updated = updated.replace('Text(" CLIENT")', 'Text("CLIENT")')
        if updated != text:
            p.write_text(updated)
info_path = app / 'Info.plist'
info = plistlib.loads(info_path.read_bytes())
info['CFBundleDisplayName'] = 'RUIZENCLIENT'
info['CFBundleName'] = 'RUIZENCLIENT'
info['CFBundleVersion'] = '14'
info_path.write_bytes(plistlib.dumps(info))
shutil.copyfile(asset, app / 'Assets.xcassets/HTVLogo.imageset/HTVLogo.jpeg')
# Guards cover routing, display strings, licensing identity and asset provenance.
source = entry.read_text()
assert 'StockGateView()' not in source
assert 'if !showOnboarding && licenseManager.requiresLicenseGate' in source
assert source.count('"appId": "ruizenclient"') == 2
start = original.index('@MainActor\nfinal class HTVLicenseManager')
end = original.index('private enum HTVLicenseError')
assert original[start:end] == source[source.index('@MainActor\nfinal class HTVLicenseManager'):source.index('private enum HTVLicenseError')]
for p in app.rglob('*'):
    if p.suffix in ('.swift', '.strings'):
        assert 'VIPERX' not in p.read_text(), str(p)
assert 'Text("CLIENT")' in (app/'views/DesignSystem.swift').read_text()
assert hashlib.sha256(asset.read_bytes()).digest() == hashlib.sha256((app/'Assets.xcassets/HTVLogo.imageset/HTVLogo.jpeg').read_bytes()).digest()
print('Verified RUIZENCLIENT Build 14: direct Home after license, unchanged license checks, no VIPERX display strings, new supplied logo')
