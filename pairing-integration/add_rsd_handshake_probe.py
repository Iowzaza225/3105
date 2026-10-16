#!/usr/bin/env python3
"""Add read-only RSD XPC handshake on top of Build14's authenticated CDTunnel.
No filesystem operations. The earlier CDTunnel-only test remains available.
"""
from pathlib import Path
import sys
root=Path(sys.argv[1])
rust=root/'pairing-native/src/lib.rs'
header=root/'pairing-native/include/ruizen_pairing.h'
ctl=root/'ThreeOneOSFive/helpers/RuizenPairingController.swift'
view=root/'ThreeOneOSFive/views/RuizenPairingView.swift'
manifest=root/'pairing-native/Cargo.toml'
def one(s,old,new):
    if s.count(old)!=1:
        raise SystemExit(f"Expected one anchor, found {s.count(old)}: {old[:80]!r}")
    return s.replace(old,new,1)

m=manifest.read_text()
m=one(m,'features = ["remote_pairing", "ring"]','features = ["remote_pairing", "ring", "rsd", "tunnel_tcp_stack"]')
manifest.write_text(m)

r=rust.read_text()
r=one(r,'use idevice::remote_pairing::connect_tls_psk_tunnel_native;',
'''use idevice::remote_pairing::connect_tls_psk_tunnel_native;
use idevice::rsd::RsdHandshake;
use idevice::tcp::adapter::Adapter;
use std::net::IpAddr;''')
r=one(r,'async fn probe_tunnel(path: String, host: String, port: u16) -> Result<String, (i32, String)> {',
      'async fn probe_tunnel(path: String, host: String, port: u16, check_rsd: bool) -> Result<String, (i32, String)> {')
old='''    Ok(format!(
        "Authenticated TLS-PSK/CDTunnel established; RSD port {} advertised. RSD handshake NOT TESTED; file access NOT TESTED",
        tunnel.info.server_rsd_port
    ))
}'''
new='''    if !check_rsd {
        return Ok(format!(
            "Authenticated TLS-PSK/CDTunnel established; RSD port {} advertised. RSD handshake NOT TESTED; file access NOT TESTED",
            tunnel.info.server_rsd_port
        ));
    }
    let info = tunnel.info.clone();
    let client_ip: IpAddr = info.client_address.parse()
        .map_err(|_| (9, "Invalid client IP returned in CDTunnel handshake".to_string()))?;
    let device_ip: IpAddr = info.server_address.parse()
        .map_err(|_| (9, "Invalid device IP returned in CDTunnel handshake".to_string()))?;
    // jktcp handles software TCP packets within the already-authenticated
    // tunnel. No OS TUN device, kernel exploit, or filesystem access.
    let mut adapter = Adapter::new(Box::new(tunnel.into_inner()), client_ip, device_ip);
    adapter.set_mss((info.mtu as usize).saturating_sub(60));
    let mut handle = adapter.to_async_handle();
    let rsd_stream = tokio::time::timeout(Duration::from_secs(15),
        handle.connect(info.server_rsd_port))
        .await.map_err(|_| (10, "RSD TCP over CDTunnel timed out".to_string()))?
        .map_err(|_| (10, "RSD TCP over CDTunnel failed".to_string()))?;
    let map = tokio::time::timeout(Duration::from_secs(20), RsdHandshake::new(rsd_stream))
        .await.map_err(|_| (11, "RSD RemoteXPC handshake timed out".to_string()))?
        .map_err(|_| (11, "RSD RemoteXPC handshake failed".to_string()))?;
    // Don't expose UUID, service names, identifiers, entitlements or keys.
    Ok(format!(
        "RSD handshake passed; {} advertised services (names hidden). File access NOT TESTED",
        map.services.len()
    ))
}'''
r=one(r,old,new)
r=one(r,'rt.block_on(probe_tunnel(path, host, port))','rt.block_on(probe_tunnel(path, host, port, false))')
r += r'''

// Build15: read-only RSD service discovery over authenticated CDTunnel.
// All returned data is non-sensitive counts/status, never a pairing secret.
#[no_mangle]
pub unsafe extern "C" fn rp_rsd_readonly_probe(
    path: *const c_char, host: *const c_char, port: u16, out: *mut RPVerifyResult,
) -> i32 {
    if out.is_null() { return 2; }
    (*out) = RPVerifyResult {stage: 0, status: ptr::null_mut()};
    if path.is_null() || host.is_null() || port == 0 {
        (*out).stage = 1;
        (*out).status = into_c("Invalid RSD probe arguments");
        return 1;
    }
    let path = as_string(path, "");
    let host = as_string(host, "");
    let worker = std::thread::Builder::new().stack_size(8*1024*1024).spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread().enable_all().build()
            .map_err(|_| (0, "Could not initialize RSD worker".to_string()))?;
        rt.block_on(probe_tunnel(path,host,port,true))
    });
    let outcome = match worker {
        Ok(w) => w.join().unwrap_or_else(|_| Err((0, "RSD worker panicked".to_string()))),
        Err(_) => Err((0, "Could not start RSD worker".to_string())),
    };
    match outcome {
        Ok(message) => {
            (*out).stage = 15;
            (*out).status = into_c(message);
            0
        }
        Err((stage,message)) => {
            (*out).stage = stage;
            (*out).status = into_c(message);
            1
        }
    }
}
'''
rust.write_text(r)

h=header.read_text()
h=one(h,'int32_t rp_tunnel_readonly_probe(const char *record_path, const char *host,\n        uint16_t pairing_port, RPVerifyResult *out);',
'''int32_t rp_tunnel_readonly_probe(const char *record_path, const char *host,
        uint16_t pairing_port, RPVerifyResult *out);
int32_t rp_rsd_readonly_probe(const char *record_path, const char *host,
        uint16_t pairing_port, RPVerifyResult *out);''')
header.write_text(h)

s=ctl.read_text()
s=one(s,'    @Published private(set) var cdTunnelStatus = "ยังไม่ได้ทดสอบ TLS-PSK / CDTunnel"\n',
'''    @Published private(set) var cdTunnelStatus = "ยังไม่ได้ทดสอบ TLS-PSK / CDTunnel"
    @Published private(set) var rsdChecking = false
    @Published private(set) var rsdStatus = "ยังไม่ได้ทดสอบ RSD handshake"
    private var rsdHandshakeEpoch: UInt64 = 0
''')
# Note: Build12 already defines rsdChecking for TCP port listener; use distinct names instead.
s=s.replace('    @Published private(set) var rsdChecking = false\n    @Published private(set) var rsdStatus = "ยังไม่ได้ทดสอบ RSD handshake"\n    private var rsdHandshakeEpoch: UInt64 = 0\n',
'''    @Published private(set) var rsdHandshakeChecking = false
    @Published private(set) var rsdHandshakeStatus = "ยังไม่ได้ทดสอบ RSD handshake"
    private var rsdHandshakeEpoch: UInt64 = 0
''')
s=one(s,r'\nRSD handshake: NOT TESTED\n', r'\nRSD handshake: \(rsdHandshakeStatus)\n')
s=one(s,'    private func resetRsdProbe() {\n',
'''    private func resetRsdProbe() {
        rsdHandshakeEpoch &+= 1
        rsdHandshakeChecking = false
        rsdHandshakeStatus = "ยังไม่ได้ทดสอบ RSD handshake"
''')
anchor='    private func beginBackgroundTask() {'
code=r'''    /// Authenticated RSD service discovery, without reading or changing files.
    func testRsdHandshake() {
        guard recordExists, !working, !rsdHandshakeChecking else { return }
        rsdHandshakeEpoch &+= 1
        let epoch = rsdHandshakeEpoch
        rsdHandshakeChecking = true
        rsdHandshakeStatus = "กำลังสร้าง Tunnel และทำ RSD handshake…"
        #if RUIZEN_PAIRING_ENABLED
        let path = Self.recordURL.path
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            var output = RPVerifyResult()
            let rc = path.withCString { p in
                "10.7.0.1".withCString { h in
                    rp_rsd_readonly_probe(p, h, 49152, &output)
                }
            }
            let stage = output.stage
            let detail = output.status.map { String(cString: $0) } ?? "Unknown result"
            rp_verify_result_free(&output)
            DispatchQueue.main.async { [weak self] in
                guard let self, self.rsdHandshakeEpoch == epoch else { return }
                self.rsdHandshakeChecking = false
                self.rsdHandshakeStatus = (rc == 0 && stage == 15)
                    ? "RSD สำเร็จ: \(detail)"
                    : "RSD ไม่สำเร็จ (ขั้น \(stage)): \(detail)"
            }
        }
        #else
        rsdHandshakeChecking = false
        rsdHandshakeStatus = "ไม่ได้เชื่อม Rust RSD module"
        #endif
    }

'''
s=one(s,anchor,code+anchor)
ctl.write_text(s)
s=view.read_text()
anchor='''                            Button {
                                UIPasteboard.general.string = pairing.diagnosticSummary
'''
replace='''                            Text(pairing.rsdHandshakeStatus)
                                .font(.subheadline)
                                .foregroundStyle(.secondary)
                                .fixedSize(horizontal: false, vertical: true)
                            Button {
                                pairing.testRsdHandshake()
                            } label: {
                                Label(pairing.rsdHandshakeChecking ? "กำลังทดสอบ RSD…" : "ทดสอบ RSD handshake", systemImage: "network")
                            }
                            .buttonStyle(.bordered)
                            .disabled(pairing.rsdHandshakeChecking || pairing.working)
                            Button {
                                UIPasteboard.general.string = pairing.diagnosticSummary
'''
s=one(s,anchor,replace)
view.write_text(s)
print("Build15 read-only authenticated RSD handshake probe integrated")
