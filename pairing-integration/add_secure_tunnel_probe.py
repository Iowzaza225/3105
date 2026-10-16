#!/usr/bin/env python3
"""Build14: verify existing RPPairing, negotiate TCP listener, TLS-PSK and CDTunnel.
Read-only connection diagnostics. No RSD service calls or filesystem access.
"""
from pathlib import Path
import sys
root=Path(sys.argv[1])
rust=root/'pairing-native/src/lib.rs'
header=root/'pairing-native/include/ruizen_pairing.h'
ctl=root/'ThreeOneOSFive/helpers/RuizenPairingController.swift'
view=root/'ThreeOneOSFive/views/RuizenPairingView.swift'
def replace_once(s,a,b):
    if s.count(a)!=1: raise SystemExit(f'Expected one patch anchor; count={s.count(a)}: {a[:110]!r}')
    return s.replace(a,b,1)

src=rust.read_text()
src += r'''

// Build 14: authenticated RPPairing -> dynamically-created TCP listener ->
// TLS-PSK -> CDTunnel handshake. Does not route packets, perform RSD, or touch files.
// Never returns/logs secret key material, UDID, or private addresses.
use idevice::remote_pairing::connect_tls_psk_tunnel_native;

async fn probe_tunnel(path: String, host: String, port: u16) -> Result<String, (i32, String)> {
    let data = std::fs::read(path).map_err(|_| (1, "Could not read the existing pairing record".to_string()))?;
    let mut record = RpPairingFile::from_bytes(&data)
        .map_err(|_| (1, "Stored pairing record is not valid".to_string()))?;
    let sock = tokio::time::timeout(Duration::from_secs(6),
        tokio::net::TcpStream::connect((host.as_str(), port)))
        .await.map_err(|_| (2, "Pairing TCP timed out".to_string()))?
        .map_err(|_| (2, "Pairing TCP connect failed".to_string()))?;
    let mut client = RemotePairingClient::new(RpPairingSocket::new(sock), "RUIZEN CLIENT");
    tokio::time::timeout(Duration::from_secs(12), client.attempt_pair_verify())
        .await.map_err(|_| (3, "RPPairing initial handshake timed out".to_string()))?
        .map_err(|_| (3, "RPPairing initial handshake rejected".to_string()))?;
    tokio::time::timeout(Duration::from_secs(12), client.validate_pairing(&mut record))
        .await.map_err(|_| (4, "Pair-Verify timed out".to_string()))?
        .map_err(|_| (4, "Pair-Verify failed for existing record".to_string()))?;

    // This listener port is returned dynamically by the authenticated device.
    // Do not assume 49152 is the data tunnel port (it is the pairing port).
    let listener_port = tokio::time::timeout(Duration::from_secs(12), client.create_tcp_listener())
        .await.map_err(|_| (5, "Remote listener request timed out".to_string()))?
        .map_err(|_| (5, "Remote listener request rejected".to_string()))?;
    if listener_port == 0 {
        return Err((5, "Device returned invalid TCP tunnel listener port".to_string()));
    }

    let tunnel_sock = tokio::time::timeout(Duration::from_secs(8),
        tokio::net::TcpStream::connect((host.as_str(), listener_port)))
        .await.map_err(|_| (6, "Dynamic tunnel TCP connection timed out".to_string()))?
        .map_err(|_| (6, "Dynamic tunnel TCP listener not reachable".to_string()))?;

    // The PSK is obtained from the successful Pair-Verify; never exported.
    let secret = client.encryption_key().to_vec();
    let tunnel = tokio::time::timeout(Duration::from_secs(20),
        connect_tls_psk_tunnel_native(tunnel_sock, &secret))
        .await.map_err(|_| (7, "TLS-PSK / CDTunnel handshake timed out".to_string()))?
        .map_err(|_| (7, "TLS-PSK / CDTunnel handshake failed".to_string()))?;

    if tunnel.info.server_rsd_port == 0 {
        return Err((8, "CDTunnel connected but no RSD port was advertised".to_string()));
    }
    Ok(format!(
        "Authenticated TLS-PSK/CDTunnel established; RSD port {} advertised. RSD handshake NOT TESTED; file access NOT TESTED",
        tunnel.info.server_rsd_port
    ))
}

/// # Safety
/// input pointers are NUL-terminated C strings; output points to writable RPVerifyResult.
/// This is a read-only handshake probe; all returned messages are redacted.
#[no_mangle]
pub unsafe extern "C" fn rp_tunnel_readonly_probe(
    path: *const c_char, host: *const c_char, port: u16, out: *mut RPVerifyResult,
) -> i32 {
    if out.is_null() { return 2; }
    (*out) = RPVerifyResult {stage: 0, status: ptr::null_mut()};
    if path.is_null() || host.is_null() || port == 0 {
        (*out).stage = 1;
        (*out).status = into_c("Invalid tunnel probe arguments");
        return 1;
    }
    let path = as_string(path, "");
    let host = as_string(host, "");
    let worker = std::thread::Builder::new().stack_size(8*1024*1024).spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread().enable_all().build()
            .map_err(|_| (0, "Could not initialize tunnel worker".to_string()))?;
        rt.block_on(probe_tunnel(path, host, port))
    });
    let outcome = match worker {
        Ok(join) => join.join().unwrap_or_else(|_| Err((0, "Tunnel worker panicked".to_string()))),
        Err(_) => Err((0, "Failed to start tunnel worker".to_string())),
    };
    match outcome {
        Ok(message) => {
            (*out).stage = 9;
            (*out).status = into_c(message);
            0
        },
        Err((stage, message)) => {
            (*out).stage = stage;
            (*out).status = into_c(message);
            1
        }
    }
}
'''
rust.write_text(src)

h=header.read_text()
h=replace_once(h,'void rp_verify_result_free(RPVerifyResult *out);',
'''void rp_verify_result_free(RPVerifyResult *out);
// Read-only, no file access. Returns stage 9 only after secure CDTunnel handshake.
int32_t rp_tunnel_readonly_probe(const char *record_path, const char *host,
        uint16_t pairing_port, RPVerifyResult *out);''')
header.write_text(h)

s=ctl.read_text()
s=replace_once(s, '    @Published private(set) var pairVerifyStatus = "ยังไม่ได้ยืนยันตัวตนกับ Remote Pairing"\n',
'''    @Published private(set) var pairVerifyStatus = "ยังไม่ได้ยืนยันตัวตนกับ Remote Pairing"
    @Published private(set) var cdTunnelChecking = false
    @Published private(set) var cdTunnelStatus = "ยังไม่ได้ทดสอบ TLS-PSK / CDTunnel"
    private var cdTunnelEpoch: UInt64 = 0
''')
s=replace_once(s,r'\nRSD handshake: NOT TESTED\n',
r'\nCDTunnel: \(cdTunnelStatus)\nRSD handshake: NOT TESTED\n')
s=replace_once(s, '    private func resetRsdProbe() {\n',
'''    private func resetRsdProbe() {
        cdTunnelEpoch &+= 1
        cdTunnelChecking = false
        cdTunnelStatus = "ยังไม่ได้ทดสอบ TLS-PSK / CDTunnel"
''')
marker='    private func beginBackgroundTask() {'
add=r'''    /// Tests authenticating a new dynamic tunnel. Never reads/writes device files.
    func testSecureTunnel() {
        guard recordExists, !working, !cdTunnelChecking else { return }
        cdTunnelEpoch &+= 1
        let epoch = cdTunnelEpoch
        cdTunnelChecking = true
        cdTunnelStatus = "กำลังขอ Listener, เชื่อม TLS-PSK และทำ CDTunnel handshake…"
        #if RUIZEN_PAIRING_ENABLED
        let path = Self.recordURL.path
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            var output = RPVerifyResult()
            let rc = path.withCString { pathPtr in
                "10.7.0.1".withCString { hostPtr in
                    rp_tunnel_readonly_probe(pathPtr, hostPtr, 49152, &output)
                }
            }
            let stage = output.stage
            let detail = output.status.map { String(cString: $0) } ?? "Unknown result"
            rp_verify_result_free(&output)
            DispatchQueue.main.async { [weak self] in
                guard let self, self.cdTunnelEpoch == epoch else { return }
                self.cdTunnelChecking = false
                if rc == 0 && stage == 9 {
                    self.cdTunnelStatus = "ผ่าน TLS-PSK/CDTunnel: \(detail)"
                } else {
                    self.cdTunnelStatus = "Tunnel ไม่ผ่าน (ขั้น \(stage)): \(detail)"
                }
            }
        }
        #else
        cdTunnelChecking = false
        cdTunnelStatus = "ไม่ได้เชื่อม Rust Tunnel Module"
        #endif
    }

'''
s=replace_once(s,marker,add+marker)
ctl.write_text(s)

s=view.read_text()
marker='''                            Button {
                                UIPasteboard.general.string = pairing.diagnosticSummary
'''
addition='''                            Text(pairing.cdTunnelStatus)
                                .font(.subheadline)
                                .foregroundStyle(.secondary)
                                .fixedSize(horizontal: false, vertical: true)
                            Button {
                                pairing.testSecureTunnel()
                            } label: {
                                Label(pairing.cdTunnelChecking ? "กำลังทดสอบ Tunnel…" : "ทดสอบ TLS-PSK / CDTunnel", systemImage: "network.badge.shield.half.filled")
                            }
                            .buttonStyle(.bordered)
                            .disabled(pairing.cdTunnelChecking || pairing.working)
                            Button {
                                UIPasteboard.general.string = pairing.diagnosticSummary
'''
s=replace_once(s,marker,addition)
view.write_text(s)
print("Build14: dynamic listener + authenticated TLS/CDTunnel probe integrated")
