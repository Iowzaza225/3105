#!/usr/bin/env python3
"""Non-privileged TCP reachability diagnostics. Not a Pair-Verify or RSD test."""
from pathlib import Path
import sys

root=Path(sys.argv[1])
ctl=root/'ThreeOneOSFive/helpers/RuizenPairingController.swift'
view=root/'ThreeOneOSFive/views/RuizenPairingView.swift'
def one(source,old,new):
    assert source.count(old)==1, ("Unexpected source anchor",old)
    return source.replace(old,new,1)

s=ctl.read_text()
s=one(s,'import Foundation\nimport UIKit\n','import Foundation\nimport UIKit\nimport Network\n')
s=one(s,'    @Published private(set) var recordDescription = ""\n','''    @Published private(set) var recordDescription = ""
    @Published private(set) var transportChecking = false
    @Published private(set) var transportStatus = "ยังไม่ได้ทดสอบ TCP (ไม่ใช่การตรวจสอบ Tunnel/RSD)"
    @Published private(set) var transportEndpoint = "ไม่ทราบ"
    private var activeTransportConnection: NWConnection?
    private var transportEpoch: UInt64 = 0

    /// Excludes the sensitive pairing record and cryptographic keys.
    var diagnosticSummary: String {
        let v = ProcessInfo.processInfo.operatingSystemVersion
        return "RUIZEN CLIENT Build 11 | iOS \(v.majorVersion).\(v.minorVersion).\(v.patchVersion)\nPairing: \(recordDescription)\nTCP: \(transportStatus)\nEndpoint: \(transportEndpoint)\nRSD Pair-Verify: NOT TESTED\nFilesystem / exploit support: NOT TESTED"
    }
''')
s=one(s,'''            refresh()
            wasPairedThisRun = false
            pin = nil
            status = "ลบไฟล์จับคู่ในแอปแล้ว (ไม่ได้ยกเลิกความเชื่อถือใน Settings)"''','''            resetTransportProbe()
            refresh()
            wasPairedThisRun = false
            pin = nil
            status = "ลบไฟล์จับคู่ในแอปแล้ว (ไม่ได้ยกเลิกความเชื่อถือใน Settings)"''')
s=one(s,'''            try data.write(to: Self.recordURL, options: [.atomic, .completeFileProtectionUnlessOpen])
            refresh()''','''            try data.write(to: Self.recordURL, options: [.atomic, .completeFileProtectionUnlessOpen])
            resetTransportProbe()
            refresh()''')
s=one(s,'''        working = false
        pin = nil
        refresh()
        if canceled {''','''        working = false
        pin = nil
        resetTransportProbe()
        refresh()
        if canceled {''')
s=one(s,'    private func beginBackgroundTask() {','''    /// A local TCP socket probe only; it does not prove RSD, Pair-Verify,
    /// an authenticated tunnel, or access beyond this app's sandbox.
    func testTransportReachability() {
        guard recordExists, !working, !transportChecking else { return }
        transportEpoch &+= 1
        transportChecking = true
        transportStatus = "กำลังทดสอบช่องทาง TCP ในเครื่อง (ไม่ใช่ Tunnel)…"
        transportEndpoint = "กำลังตรวจ"
        probeEndpoint(index: 0, epoch: transportEpoch)
    }

    private func resetTransportProbe() {
        transportEpoch &+= 1
        activeTransportConnection?.cancel()
        activeTransportConnection = nil
        transportChecking = false
        transportStatus = "ยังไม่ได้ทดสอบ TCP (ไม่ใช่การตรวจสอบ Tunnel/RSD)"
        transportEndpoint = "ไม่ทราบ"
    }

    private func probeEndpoint(index: Int, epoch: UInt64) {
        guard transportChecking, epoch == transportEpoch else { return }
        let addresses = ["10.7.0.1", "127.0.0.1"]
        guard index < addresses.count else {
            transportChecking = false
            transportStatus = "ยังเปิด TCP ไปยัง endpoint ที่ตรวจไม่ได้ — เช็ก Wi-Fi และ LocalDevVPN"
            transportEndpoint = "10.7.0.1:62078 และ 127.0.0.1:62078"
            return
        }

        let host = addresses[index]
        guard let port = NWEndpoint.Port(rawValue: 62078) else {
            transportChecking = false
            transportStatus = "ไม่สามารถกำหนดพอร์ตตรวจได้"
            return
        }
        let connection = NWConnection(host: NWEndpoint.Host(host), port: port, using: .tcp)
        activeTransportConnection = connection
        let queue = DispatchQueue(label: "com.ruizen.pairing.probe")
        var finished = false // all completions on the same serial queue

        let complete: (Bool) -> Void = { ready in
            guard !finished else { return }
            finished = true
            connection.stateUpdateHandler = nil
            connection.cancel()
            Task { @MainActor [weak self] in
                guard let self, self.transportEpoch == epoch else { return }
                self.activeTransportConnection = nil
                if ready {
                    self.transportChecking = false
                    self.transportEndpoint = "\(host):62078"
                    self.transportStatus = "เปิด TCP ได้ที่ \(host):62078 — ยังไม่ยืนยัน Pair-Verify หรือ RSD Tunnel"
                } else {
                    self.probeEndpoint(index: index + 1, epoch: epoch)
                }
            }
        }
        connection.stateUpdateHandler = { state in
            switch state {
            case .ready:
                complete(true)
            case .failed(_), .cancelled:
                complete(false)
            default:
                break
            }
        }
        connection.start(queue: queue)
        queue.asyncAfter(deadline: .now() + 3.5) {
            complete(false)
        }
    }

    private func beginBackgroundTask() {''')
ctl.write_text(s)
s=view.read_text()
s=one(s,'''                    if pairing.recordExists {
                        Button(role: .destructive)''','''                    if pairing.recordExists {
                        VStack(alignment: .leading, spacing: 10) {
                            Text("วินิจฉัยการเชื่อมต่อ")
                                .font(.headline)
                            Text(pairing.transportStatus)
                                .font(.subheadline)
                                .foregroundStyle(.secondary)
                                .fixedSize(horizontal: false, vertical: true)
                            Text("ตรวจเฉพาะการเปิด TCP ไม่ได้ยืนยัน Pair-Verify, RSD, Tunnel หรือสิทธิ์แก้ไฟล์")
                                .font(.caption)
                                .foregroundStyle(.orange)
                            Button {
                                pairing.testTransportReachability()
                            } label: {
                                Label(pairing.transportChecking ? "กำลังตรวจ TCP…" : "ตรวจ TCP ที่ใช้งานได้", systemImage: "network")
                            }
                            .buttonStyle(.bordered)
                            .disabled(pairing.transportChecking || pairing.working)
                            Button {
                                UIPasteboard.general.string = pairing.diagnosticSummary
                            } label: {
                                Label("คัดลอกผลตรวจ (ไม่รวมกุญแจจับคู่)", systemImage: "doc.on.doc")
                            }
                            .buttonStyle(.bordered)
                        }
                        .htvCard()

                        Button(role: .destructive)''')
view.write_text(s)
print('Applied safe pairing transport diagnostics')
