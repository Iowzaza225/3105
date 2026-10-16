#!/usr/bin/env python3
"""Build16: truly write and read back a *new*, tiny AFC file within PublicStaging.
Only runs on the explicit test button. Does not access app/game containers,
run kernel exploits, modify existing files, or bypass the device's permissions.
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
    n=s.count(old)
    if n!=1: raise SystemExit(f'Build16 anchor mismatch ({n}): {old[:90]!r}')
    return s.replace(old,new,1)

m=manifest.read_text()
m=one(m,'features = ["remote_pairing", "ring", "rsd", "tunnel_tcp_stack"]',
      'features = ["remote_pairing", "ring", "rsd", "tunnel_tcp_stack", "afc"]')
manifest.write_text(m)

r=rust.read_text()
r=one(r,'use idevice::rsd::RsdHandshake;',
'''use idevice::rsd::RsdHandshake;
use idevice::afc::{AfcClient, opcode::AfcFopenMode};
use std::time::{SystemTime, UNIX_EPOCH};''')
r=one(r,
 'async fn probe_tunnel(path: String, host: String, port: u16, check_rsd: bool) -> Result<String, (i32, String)> {',
 'async fn probe_tunnel(path: String, host: String, port: u16, check_rsd: bool, check_afc_write: bool) -> Result<String, (i32, String)> {')
r=one(r,
'rt.block_on(probe_tunnel(path, host, port, false))',
'rt.block_on(probe_tunnel(path, host, port, false, false))')
r=one(r,
'rt.block_on(probe_tunnel(path,host,port,true))',
'rt.block_on(probe_tunnel(path,host,port,true,false))')
old='''    // Don't expose UUID, service names, identifiers, entitlements or keys.
    Ok(format!(
        "RSD handshake passed; {} advertised services (names hidden). File access NOT TESTED",
        map.services.len()
    ))'''
new='''    if check_afc_write {
        // AFC is an OS-authorized transport limited to the areas that the
        // device itself exposes. Do NOT fall back to an unauthorized filesystem
        // route when it isn't advertised.
        if !map.services.contains_key("com.apple.afc.shim.remote") {
            return Err((16, "RSD passed, but AFC shim service was NOT advertised. No file was written".to_string()));
        }
        let mut service_map = map;
        let mut afc = tokio::time::timeout(Duration::from_secs(20),
            service_map.connect::<AfcClient>(&mut handle))
            .await.map_err(|_| (17, "AFC service connection timed out; nothing written".to_string()))?
            .map_err(|_| (17, "AFC service connect/check-in denied; nothing written".to_string()))?;

        // Use only an established OS-approved staging area. No arbitrary path
        // input, no parent traversal, no game app or private system directories.
        afc.list_dir("PublicStaging").await
            .map_err(|_| (18, "PublicStaging is unavailable or denied by AFC; nothing written".to_string()))?;
        let nanos = SystemTime::now().duration_since(UNIX_EPOCH)
            .unwrap_or_default().as_nanos();
        let filename = format!("PublicStaging/RUIZEN_BUILD16_TEST_{}.txt", nanos);
        let bytes = format!(
            "RUIZEN_BUILD16_AFC_WRITE_READBACK\\\\nnonce={}\\\\n",
            nanos
        ).into_bytes();

        let mut writer = tokio::time::timeout(Duration::from_secs(12),
            afc.open(filename.clone(), AfcFopenMode::WrOnly))
            .await.map_err(|_| (19, "AFC test-file open for write timed out".to_string()))?
            .map_err(|_| (19, "AFC denied writing a new staging file".to_string()))?;
        tokio::time::timeout(Duration::from_secs(12), writer.write_entire(&bytes))
            .await.map_err(|_| (20, "AFC test-file write timed out".to_string()))?
            .map_err(|_| (20, "AFC test-file write was rejected".to_string()))?;
        writer.close().await
            .map_err(|_| (21, "AFC failed to close the written file".to_string()))?;

        let mut reader = tokio::time::timeout(Duration::from_secs(12),
            afc.open(filename.clone(), AfcFopenMode::RdOnly))
            .await.map_err(|_| (22, "AFC test-file reopen timed out".to_string()))?
            .map_err(|_| (22, "AFC test-file reopen failed".to_string()))?;
        let recovered = tokio::time::timeout(Duration::from_secs(12),
            reader.read_n(bytes.len()))
            .await.map_err(|_| (23, "AFC test-file read-back timed out".to_string()))?
            .map_err(|_| (23, "AFC test-file read-back failed".to_string()))?;
        reader.close().await
            .map_err(|_| (24, "AFC failed to close the read-back file".to_string()))?;
        if recovered != bytes {
            return Err((25, "AFC file was written, but read-back bytes did NOT match".to_string()));
        }
        // Intentionally leave the unique, small test file in PublicStaging
        // so the user can verify a physical write happened. Do not touch any
        // other file. The path contains only a random-ish timestamp.
        return Ok(format!(
            "WRITE SUCCESS + READBACK VERIFIED via AFC: {} bytes at {} (AFC PublicStaging only; other app containers NOT TESTED)",
            bytes.len(), filename
        ));
    }
    // Don't expose UUID, service names, identifiers, entitlements or keys.
    Ok(format!(
        "RSD handshake passed; {} advertised services (names hidden). File access NOT TESTED",
        map.services.len()
    ))'''
r=one(r,old,new)
r += r'''

// Build16: Only explicit user-initiated write + read-back through authorized AFC.
// Does not accept destination paths; never accesses another app's data.
#[no_mangle]
pub unsafe extern "C" fn rp_afc_staging_write_verify(
    path: *const c_char, host: *const c_char, port: u16, out: *mut RPVerifyResult,
) -> i32 {
    if out.is_null() { return 2; }
    (*out) = RPVerifyResult {stage: 0, status: ptr::null_mut()};
    if path.is_null() || host.is_null() || port == 0 {
        (*out).stage = 1;
        (*out).status = into_c("Invalid AFC test arguments");
        return 1;
    }
    let path = as_string(path, "");
    let host = as_string(host, "");
    let worker = std::thread::Builder::new().stack_size(8*1024*1024).spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread().enable_all().build()
            .map_err(|_| (0, "Unable to initialize AFC test worker".to_string()))?;
        rt.block_on(probe_tunnel(path,host,port,true,true))
    });
    let outcome = match worker {
        Ok(w) => w.join().unwrap_or_else(|_| Err((0, "AFC test worker panicked".to_string()))),
        Err(_) => Err((0, "Unable to start AFC test worker".to_string())),
    };
    match outcome {
        Ok(message) => {
            (*out).stage = 26;
            (*out).status = into_c(message);
            0
        },
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
h=one(h,
'''int32_t rp_rsd_readonly_probe(const char *record_path, const char *host,
        uint16_t pairing_port, RPVerifyResult *out);''',
'''int32_t rp_rsd_readonly_probe(const char *record_path, const char *host,
        uint16_t pairing_port, RPVerifyResult *out);
// Writes a NEW file only to AFC PublicStaging and compares read-back.
int32_t rp_afc_staging_write_verify(const char *record_path, const char *host,
        uint16_t pairing_port, RPVerifyResult *out);''')
header.write_text(h)

s=ctl.read_text()
s=one(s,
'    @Published private(set) var rsdHandshakeStatus = "ยังไม่ได้ทดสอบ RSD handshake"\n',
'''    @Published private(set) var rsdHandshakeStatus = "ยังไม่ได้ทดสอบ RSD handshake"
    @Published private(set) var afcWriteChecking = false
    @Published private(set) var afcWriteStatus = "ยังไม่ได้ทดสอบ AFC เขียนไฟล์จริง"
    private var afcWriteEpoch: UInt64 = 0
''')
s=one(s,r'\nFilesystem / exploit support: NOT TESTED',
r'\nAFC PublicStaging write/read-back: \(afcWriteStatus)\nOther app containers / exploit support: NOT TESTED')
s=one(s,'    private func resetRsdProbe() {\n',
'''    private func resetRsdProbe() {
        afcWriteEpoch &+= 1
        afcWriteChecking = false
        afcWriteStatus = "ยังไม่ได้ทดสอบ AFC เขียนไฟล์จริง"
''')
marker='    private func beginBackgroundTask() {'
swift=r'''    /// Real AFC write/read-back to a NEW, tiny OS-authorized PublicStaging file.
    /// Do not run without user explicitly pressing the test button.
    func testAfcFileWrite() {
        guard recordExists, !working, !afcWriteChecking else { return }
        afcWriteEpoch &+= 1
        let epoch = afcWriteEpoch
        afcWriteChecking = true
        afcWriteStatus = "กำลังยืนยัน Pairing → RSD → AFC → เขียนไฟล์ → อ่านกลับ…"
        #if RUIZEN_PAIRING_ENABLED
        let path = Self.recordURL.path
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            var output = RPVerifyResult()
            let rc = path.withCString { p in
                "10.7.0.1".withCString { h in
                    rp_afc_staging_write_verify(p, h, 49152, &output)
                }
            }
            let stage = output.stage
            let detail = output.status.map { String(cString: $0) } ?? "Unknown result"
            rp_verify_result_free(&output)
            DispatchQueue.main.async { [weak self] in
                guard let self, self.afcWriteEpoch == epoch else { return }
                self.afcWriteChecking = false
                self.afcWriteStatus = (rc == 0 && stage == 26)
                    ? "ลงไฟล์ทดสอบจริงสำเร็จ: \(detail)"
                    : "ทดสอบ AFC ไม่สำเร็จ (ขั้น \(stage)): \(detail)"
            }
        }
        #else
        afcWriteChecking = false
        afcWriteStatus = "ไม่ได้เชื่อม Rust AFC module"
        #endif
    }

'''
s=one(s,marker,swift+marker)
ctl.write_text(s)
s=view.read_text()
marker='''                            Button {
                                UIPasteboard.general.string = pairing.diagnosticSummary
'''
new='''                            Text(pairing.afcWriteStatus)
                                .font(.subheadline)
                                .foregroundStyle(.secondary)
                                .fixedSize(horizontal: false, vertical: true)
                            Text("เขียนไฟล์ทดสอบใหม่ขนาดเล็กใน AFC PublicStaging เท่านั้น ไม่แก้ไฟล์เกมหรือข้อมูลแอปอื่น")
                                .font(.caption)
                                .foregroundStyle(.orange)
                            Button {
                                pairing.testAfcFileWrite()
                            } label: {
                                Label(pairing.afcWriteChecking ? "กำลังลงไฟล์ทดสอบ…" : "ทดสอบลงไฟล์จริง + อ่านกลับ (AFC)", systemImage: "doc.badge.arrow.up")
                            }
                            .buttonStyle(.borderedProminent)
                            .disabled(pairing.afcWriteChecking || pairing.working)
                            Button {
                                UIPasteboard.general.string = pairing.diagnosticSummary
'''
s=one(s,marker,new)
view.write_text(s)
print("Build16 AFC real file-write/read-back integration applied")
