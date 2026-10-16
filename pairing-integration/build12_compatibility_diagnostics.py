#!/usr/bin/env python3
"""Build 12: iOS 27 compatibility checks, without claiming sandbox or RSD access."""
from pathlib import Path
import sys
root=Path(sys.argv[1])
ctl=root/'ThreeOneOSFive/helpers/RuizenPairingController.swift'
view=root/'ThreeOneOSFive/views/RuizenPairingView.swift'
def one(s,old,new):
    if s.count(old)!=1: raise RuntimeError(f"Missing unique marker: {old[:80]!r}")
    return s.replace(old,new,1)
s=ctl.read_text()
s=one(s,'    private var activeTransportConnection: NWConnection?\n','''    @Published private(set) var recordInspection = "ยังไม่ได้ตรวจไฟล์ Pairing"
    @Published private(set) var iosBuildAssessment = "ยังไม่ได้ตรวจ iOS"
    @Published private(set) var sandboxCheck = "ยังไม่ได้ตรวจพื้นที่แอป"
    @Published private(set) var protocolAssessment = "RSD / Pair-Verify / ATC ยังไม่ได้ยืนยัน"
    private var activeTransportConnection: NWConnection?
''')
# The earlier probe used legacy port 62078; RSD on iOS27 commonly uses 49152.
# A TCP connection is NEVER treated as RSD/Pair-Verify success.
if '62078' not in s: raise RuntimeError('Missing previous probe port')
s=s.replace('62078','49152')
s=one(s,'RUIZEN CLIENT Build 11 | iOS ','RUIZEN CLIENT Build 12 | iOS ')
s=one(s,'    func testTransportReachability() {','''    func inspectBuild12Capability() {
        let v = ProcessInfo.processInfo.operatingSystemVersion
        let os = "iOS \(v.majorVersion).\(v.minorVersion).\(v.patchVersion)"
        if v.majorVersion == 27 && v.minorVersion == 0 && v.patchVersion == 1 {
            iosBuildAssessment = "\(os): 3105 Beta 5 มีรายงานใช้งานได้ แต่ RUIZEN ยังไม่ยืนยันระบบเขียนไฟล์"
        } else if v.majorVersion >= 27 {
            iosBuildAssessment = "\(os): RUIZEN ยังไม่ผ่านการยืนยัน Pair-Verify / Tunnel / FileService"
        } else {
            iosBuildAssessment = "\(os): ใช้นโยบายรองรับเดิมของแอป ไม่ใช้ Pairing แทนสิทธิ์เข้าถึงไฟล์"
        }
        if let data = try? Data(contentsOf: Self.recordURL), !data.isEmpty {
            if let raw = try? PropertyListSerialization.propertyList(from: data, format: nil),
               let fields = raw as? [String: Any] {
                recordInspection = "อ่านโครงสร้าง Plist ได้ (\(fields.count) ฟิลด์, \(data.count) ไบต์) — ยังไม่ใช่ Pair-Verify"
            } else {
                recordInspection = "ไฟล์มี \(data.count) ไบต์ แต่ยังตรวจรูปแบบไม่ได้ — ยังไม่ใช่ Pair-Verify"
            }
        } else {
            recordInspection = "ยังไม่มีไฟล์ Pairing ในแอป"
        }
        let bytes = Data("RUIZEN_BUILD12_LOCAL_TEST".utf8)
        let file = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        do {
            try bytes.write(to: file, options: .atomic)
            let readback = try Data(contentsOf: file)
            sandboxCheck = (bytes == readback)
                ? "อ่าน-เขียน Sandbox ของ RUIZEN ผ่าน (ไม่ใช่ไฟล์เกม)"
                : "อ่าน-เขียน Sandbox ของ RUIZEN ไม่ตรงกัน"
        } catch {
            sandboxCheck = "Sandbox test failed: \(error.localizedDescription)"
        }
        try? FileManager.default.removeItem(at: file)
        protocolAssessment = "RSD handshake / Pair-Verify / ATC / สิทธิ์แก้ไฟล์ภายนอกแอป: ยังไม่ได้ทดสอบ"
    }

    var build12Report: String {
        "\(diagnosticSummary)\\nRecord: \(recordInspection)\\niOS: \(iosBuildAssessment)\\nApp sandbox: \(sandboxCheck)\\nProtocol: \(protocolAssessment)"
    }

    func testTransportReachability() {''')
ctl.write_text(s)
s=view.read_text()
anchor='''                    if pairing.recordExists {
                        VStack(alignment: .leading, spacing: 10) {'''
repl='''                    if pairing.recordExists {
                        VStack(alignment: .leading, spacing: 10) {
                            Label("Build 12 • ตรวจตามความสามารถจริง", systemImage: "checkmark.shield")
                                .font(.headline)
                            Text(pairing.iosBuildAssessment)
                            Text(pairing.recordInspection)
                            Text(pairing.sandboxCheck)
                            Text(pairing.protocolAssessment)
                                .foregroundStyle(.orange)
                            Button {
                                pairing.inspectBuild12Capability()
                            } label: {
                                Label("ตรวจ Pairing / iOS / Sandbox", systemImage: "checklist")
                            }
                            .buttonStyle(.borderedProminent)
                            .disabled(pairing.working)
                            Button {
                                UIPasteboard.general.string = pairing.build12Report
                            } label: {
                                Label("คัดลอกรายงาน Build 12 (ไม่รวมกุญแจ)", systemImage: "doc.on.doc")
                            }
                            .buttonStyle(.bordered)
                            Text("TCP บนพอร์ต 49152 ไม่ใช่ผลยืนยัน Pair-Verify, RSD หรือสิทธิ์แก้ไฟล์")
                                .font(.caption)
                                .foregroundStyle(.secondary)
                        }
                        .htvCard()

                        VStack(alignment: .leading, spacing: 10) {'''
s=one(s,anchor,repl)
s=one(s,'            .onAppear { pairing.refresh() }','            .onAppear { pairing.refresh(); pairing.inspectBuild12Capability() }')
view.write_text(s)
print('RUIZEN Build12 diagnostics installed')
