#!/usr/bin/env python3
"""Add a read-only RPPairing port-49152 listener diagnostic to Build 12.
This is deliberately NOT Pair-Verify, RSD, or filesystem access.
"""
from pathlib import Path
import sys

root = Path(sys.argv[1])
controller = root / "ThreeOneOSFive/helpers/RuizenPairingController.swift"
view = root / "ThreeOneOSFive/views/RuizenPairingView.swift"

def single(src: str, old: str, new: str) -> str:
    amount = src.count(old)
    if amount != 1:
        raise SystemExit(f"Expected one patch anchor, found {amount}: {old!r}")
    return src.replace(old, new, 1)

s=controller.read_text()
s=single(s,
    '    @Published private(set) var transportEndpoint = "ไม่ทราบ"\n',
    '''    @Published private(set) var transportEndpoint = "ไม่ทราบ"
    @Published private(set) var rsdChecking = false
    @Published private(set) var rsdStatus = "ยังไม่ได้ตรวจ Remote Pairing TCP 49152"
    @Published private(set) var rsdEndpoint = "ยังไม่พบ"
    private var activeRsdConnection: NWConnection?
    private var rsdEpoch: UInt64 = 0
''')
s=single(s,
    r'\nRSD Pair-Verify: NOT TESTED\n',
    r'\nRPPairing 49152: \(rsdStatus)\nRPPairing endpoint: \(rsdEndpoint)\nRSD Pair-Verify: NOT TESTED\n')
s=single(s,
    '    private func resetTransportProbe() {\n',
    '    private func resetTransportProbe() {\n        resetRsdProbe()\n')
marker='    private func beginBackgroundTask() {'
code=r'''    /// Probe known LocalDevVPN remote-pairing listeners only.
    /// A successful TCP connection DOES NOT prove an authenticated tunnel.
    func testRsdListener() {
        guard recordExists, !working, !rsdChecking else { return }
        rsdEpoch &+= 1
        rsdChecking = true
        rsdStatus = "กำลังตรวจ Remote Pairing listener พอร์ต 49152…"
        rsdEndpoint = "กำลังตรวจ"
        probeRsdListener(index: 0, epoch: rsdEpoch)
    }

    private func resetRsdProbe() {
        rsdEpoch &+= 1
        activeRsdConnection?.cancel()
        activeRsdConnection = nil
        rsdChecking = false
        rsdStatus = "ยังไม่ได้ตรวจ Remote Pairing TCP 49152"
        rsdEndpoint = "ยังไม่พบ"
    }

    private func probeRsdListener(index: Int, epoch: UInt64) {
        guard rsdChecking, epoch == rsdEpoch else { return }
        let hosts = ["10.7.0.1", "10.7.0.2", "10.7.0.3"]
        guard index < hosts.count else {
            rsdChecking = false
            rsdStatus = "ไม่พบ TCP listener ที่ 49152 ในเส้นทาง LocalDevVPN ที่ตรวจ — ต้องตรวจการประกาศ RPPairing เพิ่ม"
            rsdEndpoint = "10.7.0.1–10.7.0.3:49152 (ไม่มี endpoint ที่เชื่อมสำเร็จ)"
            return
        }

        let host = hosts[index]
        guard let port = NWEndpoint.Port(rawValue: 49152) else {
            rsdChecking = false
            rsdStatus = "พอร์ต Remote Pairing ไม่ถูกต้อง"
            return
        }
        let connection = NWConnection(host: NWEndpoint.Host(host), port: port, using: .tcp)
        activeRsdConnection = connection
        let queue = DispatchQueue(label: "com.ruizen.pairing.rsd-probe")
        var completed = false // only accessed on serial callback queue

        let finish: (Bool) -> Void = { reachable in
            guard !completed else { return }
            completed = true
            connection.stateUpdateHandler = nil
            connection.cancel()
            Task { @MainActor [weak self] in
                guard let self, self.rsdEpoch == epoch else { return }
                self.activeRsdConnection = nil
                if reachable {
                    self.rsdChecking = false
                    self.rsdEndpoint = "\(host):49152"
                    self.rsdStatus = "พบ Remote Pairing TCP listener — ยังไม่ยืนยัน Pair-Verify / RSD / การเขียนไฟล์"
                } else {
                    self.probeRsdListener(index: index + 1, epoch: epoch)
                }
            }
        }
        connection.stateUpdateHandler = { state in
            switch state {
            case .ready:
                finish(true)
            case .failed(_), .cancelled:
                finish(false)
            default:
                break
            }
        }
        connection.start(queue: queue)
        queue.asyncAfter(deadline: .now() + 3.0) {
            finish(false)
        }
    }

'''
s=single(s,marker,code+marker)
controller.write_text(s)

s=view.read_text()
needle='''                            .disabled(pairing.transportChecking || pairing.working)
                            Button {
                                UIPasteboard.general.string = pairing.diagnosticSummary
'''
replacement='''                            .disabled(pairing.transportChecking || pairing.working)
                            Text("Lockdown TCP 62078 ผ่าน ไม่ได้แปลว่า Remote Pairing ผ่าน")
                                .font(.caption)
                                .foregroundStyle(.secondary)
                            Text(pairing.rsdStatus)
                                .font(.subheadline)
                                .foregroundStyle(.secondary)
                                .fixedSize(horizontal: false, vertical: true)
                            Button {
                                pairing.testRsdListener()
                            } label: {
                                Label(pairing.rsdChecking ? "กำลังตรวจ 49152…" : "ตรวจ Remote Pairing TCP (49152)", systemImage: "point.3.connected.trianglepath.dotted")
                            }
                            .buttonStyle(.bordered)
                            .disabled(pairing.rsdChecking || pairing.working)
                            Button {
                                UIPasteboard.general.string = pairing.diagnosticSummary
'''
s=single(s,needle,replacement)
view.write_text(s)
print("Applied Build12 remote pairing TCP reachability probe")
