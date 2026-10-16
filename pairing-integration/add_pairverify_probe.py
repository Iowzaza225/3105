#!/usr/bin/env python3
"""Build13: read-only cryptographic RPPairing Pair-Verify diagnostic. Does not create tunnel or access files."""
from pathlib import Path
import sys
root=Path(sys.argv[1])
rust=root/'pairing-native/src/lib.rs'
header=root/'pairing-native/include/ruizen_pairing.h'
ctl=root/'ThreeOneOSFive/helpers/RuizenPairingController.swift'
view=root/'ThreeOneOSFive/views/RuizenPairingView.swift'
def once(s,a,b):
    if s.count(a)!=1: raise SystemExit(f'Anchor mismatch {s.count(a)}: {a[:100]!r}')
    return s.replace(a,b,1)

r=rust.read_text()
r += r'''

// Build13: verify an existing pairing record against the on-device listener.
// This never performs a new pair-setup or writes a pairing record.
// All status strings are redacted; no credentials, device identifiers or keys returned.
use idevice::remote_pairing::RemotePairingClient;

#[repr(C)]
pub struct RPVerifyResult {
    pub stage: i32,
    pub status: *mut c_char,
}

async fn verify_record(path: String, host: String, port: u16) -> Result<(), (i32, String)> {
    let data = std::fs::read(path).map_err(|_| (1, "Cannot read pairing record".to_string()))?;
    let mut record = RpPairingFile::from_bytes(&data)
        .map_err(|_| (1, "Pairing record is not a valid RPPairing plist".to_string()))?;
    // Strict read-only diagnosis: no fallback to Pair-Setup.
    let tcp = tokio::time::timeout(Duration::from_secs(6),
        tokio::net::TcpStream::connect((host.as_str(), port)))
        .await.map_err(|_| (2, "Remote pairing TCP timeout".to_string()))?
        .map_err(|_| (2, "Remote pairing TCP connection failed".to_string()))?;
    let mut client = RemotePairingClient::new(RpPairingSocket::new(tcp), "RUIZEN CLIENT");
    tokio::time::timeout(Duration::from_secs(12), client.attempt_pair_verify())
        .await.map_err(|_| (3, "RPPairing handshake response timeout".to_string()))?
        .map_err(|_| (3, "RPPairing initial handshake rejected".to_string()))?;
    tokio::time::timeout(Duration::from_secs(12), client.validate_pairing(&mut record))
        .await.map_err(|_| (4, "Pair-Verify timeout".to_string()))?
        .map_err(|_| (4, "Pair-Verify rejected: existing record may not match this listener".to_string()))?;
    Ok(())
}

/// # Safety
/// Input pointers must point to valid NUL-terminated C strings; out must be writable.
/// The input record remains unchanged and is never returned or logged.
#[no_mangle]
pub unsafe extern "C" fn rp_verify_existing_record(
    path: *const c_char, host: *const c_char, port: u16, out: *mut RPVerifyResult,
) -> i32 {
    if out.is_null() { return 2; }
    (*out) = RPVerifyResult { stage: 0, status: ptr::null_mut() };
    if path.is_null() || host.is_null() || port == 0 {
        (*out).stage = 1;
        (*out).status = into_c("Invalid verify arguments");
        return 1;
    }
    let path = as_string(path, "");
    let host = as_string(host, "");
    let worker = std::thread::Builder::new().stack_size(8*1024*1024).spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread().enable_all().build()
            .map_err(|_| (0, "Cannot initialize verify worker".to_string()))?;
        rt.block_on(verify_record(path, host, port))
    });
    let outcome = match worker {
        Ok(w) => w.join().unwrap_or_else(|_| Err((0, "Pair-Verify worker panicked".to_string()))),
        Err(_) => Err((0, "Could not start verify worker".to_string())),
    };
    match outcome {
        Ok(()) => {
            (*out).stage = 5;
            (*out).status = into_c("Pair-Verify passed — RSD tunnel and file access NOT tested");
            0
        }
        Err((stage, message)) => {
            (*out).stage = stage;
            (*out).status = into_c(message);
            1
        }
    }
}

/// # Safety: must receive status pointer from rp_verify_existing_record.
#[no_mangle]
pub unsafe extern "C" fn rp_verify_result_free(out: *mut RPVerifyResult) {
    if out.is_null() { return; }
    if !(*out).status.is_null() { let _ = CString::from_raw((*out).status); }
    (*out) = RPVerifyResult {stage: 0, status: ptr::null_mut()};
}
'''
rust.write_text(r)
h=header.read_text()
h=once(h,'void rp_pair_result_free(RPHostResult *out);',
'''void rp_pair_result_free(RPHostResult *out);

// Read-only Pair-Verify against an existing pairing record and TCP listener.
// Does not create a tunnel, read files or create/rewrite credentials.
typedef struct RPVerifyResult {
    int32_t stage;
    char *status;
} RPVerifyResult;
int32_t rp_verify_existing_record(const char *record_path, const char *host, uint16_t port, RPVerifyResult *out);
void rp_verify_result_free(RPVerifyResult *out);''')
header.write_text(h)

s=ctl.read_text()
s=once(s,'    @Published private(set) var rsdEndpoint = "ยังไม่พบ"\n',
'''    @Published private(set) var rsdEndpoint = "ยังไม่พบ"
    @Published private(set) var pairVerifyChecking = false
    @Published private(set) var pairVerifyStatus = "ยังไม่ได้ยืนยันตัวตนกับ Remote Pairing"
    private var pairVerifyEpoch: UInt64 = 0
''')
# This was previously a hardcoded diagnostic label in Build11/12.
s=once(s,'return "RUIZEN CLIENT Build 11 | iOS ', 'return "RUIZEN CLIENT Build \\(Bundle.main.object(forInfoDictionaryKey: "CFBundleVersion") as? String ?? "unknown") | iOS ')
s=once(s, r'\nRSD Pair-Verify: NOT TESTED\n', r'\nPair-Verify: \(pairVerifyStatus)\nRSD handshake: NOT TESTED\n')
s=once(s,'    private func resetRsdProbe() {\n',
'''    private func resetRsdProbe() {
        pairVerifyEpoch &+= 1
        pairVerifyChecking = false
        pairVerifyStatus = "ยังไม่ได้ยืนยันตัวตนกับ Remote Pairing"
''')
target='    private func beginBackgroundTask() {'
new=r'''    /// Cryptographic Pair-Verify only. Does not attempt Pair-Setup or RSD tunnel.
    func verifyExistingPairing() {
        guard recordExists, !working, !pairVerifyChecking else { return }
        pairVerifyEpoch &+= 1
        let epoch = pairVerifyEpoch
        pairVerifyChecking = true
        pairVerifyStatus = "กำลังตรวจ Pair-Verify กับ 10.7.0.1:49152…"
        #if RUIZEN_PAIRING_ENABLED
        let path = Self.recordURL.path
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            var output = RPVerifyResult()
            let rc = path.withCString { pathPtr in
                "10.7.0.1".withCString { hostPtr in
                    rp_verify_existing_record(pathPtr, hostPtr, 49152, &output)
                }
            }
            let stage = output.stage
            let detail = output.status.map { String(cString: $0) } ?? "Unknown result"
            rp_verify_result_free(&output)
            DispatchQueue.main.async { [weak self] in
                guard let self, self.pairVerifyEpoch == epoch else { return }
                self.pairVerifyChecking = false
                if rc == 0 && stage == 5 {
                    self.pairVerifyStatus = "ยืนยัน Pair-Verify สำเร็จ — ยังไม่ได้เชื่อม RSD และยังไม่ได้ตรวจเขียนไฟล์"
                } else {
                    self.pairVerifyStatus = "Pair-Verify ไม่สำเร็จ (ขั้น \(stage)): \(detail)"
                }
            }
        }
        #else
        pairVerifyChecking = false
        pairVerifyStatus = "ไม่ได้เชื่อม Rust Pair-Verify Module"
        #endif
    }

'''
s=once(s,target,new+target)
ctl.write_text(s)
v=view.read_text()
target='''                            Button {
                                UIPasteboard.general.string = pairing.diagnosticSummary
'''
addition='''                            Text(pairing.pairVerifyStatus)
                                .font(.subheadline)
                                .foregroundStyle(.secondary)
                                .fixedSize(horizontal: false, vertical: true)
                            Button {
                                pairing.verifyExistingPairing()
                            } label: {
                                Label(pairing.pairVerifyChecking ? "กำลังตรวจ Pair-Verify…" : "ยืนยัน Pair-Verify ด้วยไฟล์เดิม", systemImage: "checkmark.shield")
                            }
                            .buttonStyle(.bordered)
                            .disabled(pairing.pairVerifyChecking || pairing.working)
                            Button {
                                UIPasteboard.general.string = pairing.diagnosticSummary
'''
v=once(v,target,addition)
view.write_text(v)
print("Build13: native read-only RPPairing verification wired into Swift UI")
