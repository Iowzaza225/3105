#!/usr/bin/env python3
"""RUIZEN Build17: separate iOS 27 AirLift support from kernel exploit support;
share pairing/tunnel state with Settings and apply flow; gate unsafe old writes.
"""
from pathlib import Path
import sys
root=Path(sys.argv[1])
support=root/'ThreeOneOSFive/helpers/SupportPolicy.swift'
kernel=root/'ThreeOneOSFive/helpers/KernelExploit.swift'
app=root/'ThreeOneOSFive/App.swift'
ctl=root/'ThreeOneOSFive/helpers/RuizenPairingController.swift'
view=root/'ThreeOneOSFive/views/RuizenPairingView.swift'
settings=root/'ThreeOneOSFive/views/SettingsView.swift'
home=root/'ThreeOneOSFive/views/RepositoryHomeView.swift'
def one(s,a,b):
    n=s.count(a)
    if n!=1: raise SystemExit(f'Build17 support anchor count {n} expected 1: {a[:110]!r}')
    return s.replace(a,b,1)

s=support.read_text()
s=one(s,'    static let verifiedIOS26Range = "26.0–26.6.1"',
'''    static let verifiedIOS26Range = "26.0–26.6.1"
    // This is a transport-verified iOS release, not a kernel exploit claim.
    static let verifiedAirLiftIOS27ReleaseBuilds: Set<String> = ["24A446"]

    static func supportsAirLift(major: Int, minor: Int, patch: Int, build: String) -> Bool {
        guard major == 27 else { return false }
        if minor == 0 && patch == 1 && verifiedAirLiftIOS27ReleaseBuilds.contains(build) {
            return true
        }
        if minor == 0 && patch == 0 && iOS27BetaNumber(for: build) != nil {
            return true
        }
        return false
    }
''')
s=one(s,
'''        guard major == 27, minor == 0, patch == 0 else { return false }
        return iOS27BetaNumber(for: build) != nil''',
'''        return supportsAirLift(major: major, minor: minor, patch: patch, build: build)''')
support.write_text(s)

s=kernel.read_text()
s=one(s,
'''        ExploitSupportPolicy.isSupported(
            major: major,''',
'''        // AirLift support on iOS 27 does NOT imply the legacy kernel
        // exploit or sandbox escape is safe on that build.
        guard major < 27 else { return false }
        return ExploitSupportPolicy.isSupported(
            major: major,''')
kernel.write_text(s)

s=app.read_text()
s=one(s,
'''        guard applicable else { return }

        refreshKernelExploitStatus()''',
'''        guard applicable else {
            exploitStatus = .notStarted
            log("app: iOS 27 AirLift transport selected; kernel exploit disabled")
            return
        }

        refreshKernelExploitStatus()''')
s=one(s,
'''    func runKernelExploitIfNeeded() {
        refreshKernelExploitStatus()''',
'''    func runKernelExploitIfNeeded() {
        guard kernelExploitApplicable else {
            log("app: kernel exploit is not applicable on this iOS release")
            return
        }
        refreshKernelExploitStatus()''')
app.write_text(s)

s=ctl.read_text()
s=one(s,
'    @Published private(set) var status = "ยังไม่ได้จับคู่"',
'''    static let shared = RuizenPairingController()
    @Published private(set) var status = "ยังไม่ได้จับคู่"''')
ctl.write_text(s)

s=view.read_text()
s=one(s,'    @StateObject private var pairing = RuizenPairingController()',
      '    @ObservedObject private var pairing = RuizenPairingController.shared')
view.write_text(s)

s=settings.read_text()
s=one(s,
'    @State private var showPairingSheet = false',
'''    @State private var showPairingSheet = false
    @ObservedObject private var pairing = RuizenPairingController.shared''')
s=one(s,
'''            Text("จัดการการสร้างและนำเข้า Pairing Record; การตรวจสอบ Tunnel เป็นอีกขั้นตอน")
                .font(.caption)
                .foregroundStyle(.secondary)''',
'''            Text("AirLift: จับคู่และยืนยัน RSD เพื่อใช้การส่งไฟล์ผ่านสิทธิ์ของอุปกรณ์")
                .font(.caption)
                .foregroundStyle(.secondary)
            HStack {
                Text("Pairing")
                Spacer()
                Text(pairing.recordExists ? "Ready" : "Not paired")
                    .foregroundStyle(pairing.recordExists ? .green : .orange)
            }
            .font(.subheadline.weight(.semibold))
            HStack {
                Text("RSD / Tunnel")
                Spacer()
                Text(pairing.rsdHandshakeStatus.contains("RSD สำเร็จ") ? "Verified this session" : "Needs verification")
                    .foregroundStyle(pairing.rsdHandshakeStatus.contains("RSD สำเร็จ") ? .green : .orange)
            }
            .font(.subheadline.weight(.semibold))
            Text("รองรับ iOS 27.0.1 ผ่าน AirLift ไม่ได้หมายถึงปลดล็อกไฟล์ทุกแอป; Apply Patch จะตรวจสิทธิ์ของเป้าหมายแยกต่างหาก")
                .font(.caption)
                .foregroundStyle(.secondary)''')
s=one(s,
'''            if !ExploitSupportPolicy.verifiedIOS27Builds.isEmpty {''',
'''            if !ExploitSupportPolicy.verifiedAirLiftIOS27ReleaseBuilds.isEmpty {
                Divider().overlay(AppTheme.hairline)
                supportRow(title: "iOS 27.0.1", value: "24A446 • AirLift")
            }
            if !ExploitSupportPolicy.verifiedIOS27Builds.isEmpty {''')
settings.write_text(s)

s=home.read_text()
s=one(s,'value: appState.isSupported ? "พร้อม" : "ตรวจสอบ",',
'''value: appState.isSupported
                        ? (ExploitSupportPolicy.supportsAirLift(
                            major: AppInfo.versionTuple.major, minor: AppInfo.versionTuple.minor,
                            patch: AppInfo.versionTuple.patch, build: AppInfo.osBuild)
                           ? "AirLift" : "พร้อม") : "ตรวจสอบ",''')
home.write_text(s)
print("Build17: version compatibility, kernel segregation, shared Pairing state, Settings integrated")
