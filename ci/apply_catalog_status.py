#!/usr/bin/env python3
"""Keep catalog download failures visible and retryable instead of permanent spinners."""
from pathlib import Path
import sys
root=Path(sys.argv[1]);p=root/'ThreeOneOSFive/views/PatchProjectsView.swift';s=p.read_text()
def once(old,new):
 global s
 assert s.count(old)==1, old[:100]
 s=s.replace(old,new,1)
once('    private func refreshServerCatalog() async {\n        do {','''    private func refreshServerCatalog() async {
        guard !serverCatalog.isLoading else { return }
        serverCatalog.beginSync()
        do {''')
once('''                do {
                    let previousLocalID = serverCatalog.localPackageID(forRemoteID: remote.id)''','''                do {
                    serverCatalog.beginDownload(remote.id)
                    let previousLocalID = serverCatalog.localPackageID(forRemoteID: remote.id)''')
once('''                    warnings.append("\\(remote.name): \\(error.localizedDescription)")''','''                    serverCatalog.recordDownloadFailure(remote.id, error: error)
                    warnings.append("\\(remote.name): \\(error.localizedDescription)")''')
once('''                Text("กำลังเตรียมไฟล์…")
                    .font(.caption2.weight(.semibold))
                    .foregroundStyle(AppTheme.accent)''','''                if let failure = serverCatalog.downloadErrors[remote.id] {
                    Text(failure)
                        .font(.caption2.weight(.semibold))
                        .foregroundStyle(.orange)
                        .fixedSize(horizontal: false, vertical: true)
                    Button("ลองโหลดใหม่") {
                        Task { await refreshServerCatalog() }
                    }
                    .buttonStyle(.bordered)
                    .disabled(serverCatalog.isLoading)
                } else {
                    Text(serverCatalog.currentDownloadID == remote.id
                         ? "กำลังดาวน์โหลดไฟล์…"
                         : (serverCatalog.isLoading ? "รอคิวดาวน์โหลด" : "ยังไม่ได้ดาวน์โหลด"))
                        .font(.caption2.weight(.semibold))
                        .foregroundStyle(AppTheme.accent)
                    if !serverCatalog.isLoading {
                        Button("ดาวน์โหลด / ลองใหม่") {
                            Task { await refreshServerCatalog() }
                        }
                        .buttonStyle(.bordered)
                    }
                }''')
once('''            ProgressView().controlSize(.small)
        }
        .htvCard(padding: 14)''','''            if serverCatalog.currentDownloadID == remote.id {
                ProgressView().controlSize(.small)
            } else if serverCatalog.downloadErrors[remote.id] != nil {
                Image(systemName: "exclamationmark.triangle.fill")
                    .foregroundStyle(.orange)
            }
        }
        .htvCard(padding: 14)''')
once('''    @Published private(set) var errorMessage: String?

    private let mappingKey''','''    @Published private(set) var errorMessage: String?
    @Published private(set) var downloadErrors: [String: String] = [:]
    @Published private(set) var currentDownloadID: String?

    func beginSync() {
        isLoading = true
        errorMessage = nil
    }

    func beginDownload(_ id: String) {
        currentDownloadID = id
        downloadErrors.removeValue(forKey: id)
    }

    func recordDownloadFailure(_ id: String, error: Error) {
        downloadErrors[id] = error.localizedDescription
    }

    private let mappingKey''')
once('''        remoteToLocal[remoteID] = packageID.uuidString
        fingerprints[remoteID] = fingerprint''','''        remoteToLocal[remoteID] = packageID.uuidString
        downloadErrors.removeValue(forKey: remoteID)
        fingerprints[remoteID] = fingerprint''')
once('''    func finishSync(warning: String? = nil) {
        isLoading = false''','''    func finishSync(warning: String? = nil) {
        currentDownloadID = nil
        isLoading = false''')
once('''    func fail(_ error: Error) {
        isLoading = false''','''    func fail(_ error: Error) {
        currentDownloadID = nil
        for item in items where downloadErrors[item.id] == nil {
            downloadErrors[item.id] = error.localizedDescription
        }
        isLoading = false''')
p.write_text(s)
p=root/'ThreeOneOSFive/helpers/PatchProjectStore.swift';s=p.read_text();start=s.index('    func importRemotePackageSilently(');end=s.index('\n    func ',start+8);old=s[start:end];new=old.replace('''        guard let http = response as? HTTPURLResponse,
              (200..<300).contains(http.statusCode),
              let finalURL = http.url,
              PatchImportRoute.validatedRemoteURL(finalURL) != nil else {
            throw PatchPackageError.remoteImportFailed
        }''','''        guard let http = response as? HTTPURLResponse else {
            throw NSError(domain: "RUIZENCatalog", code: -1, userInfo: [NSLocalizedDescriptionKey: "ไม่ได้รับคำตอบจากเซิร์ฟเวอร์"])
        }
        guard (200..<300).contains(http.statusCode) else {
            throw NSError(domain: "RUIZENCatalog", code: http.statusCode, userInfo: [NSLocalizedDescriptionKey: "ดาวน์โหลดไม่สำเร็จ (HTTP \\(http.statusCode)) กรุณาลองใหม่"])
        }
        guard let finalURL = http.url, PatchImportRoute.validatedRemoteURL(finalURL) != nil else {
            throw PatchPackageError.remoteImportFailed
        }''');assert new!=old
new=new.replace('''                throw PatchPackageError.remoteImportFailed
            }
        }

        var data''','''                throw NSError(domain: "RUIZENCatalog", code: -2, userInfo: [NSLocalizedDescriptionKey: "ไฟล์ดาวน์โหลดไม่ตรงกับ SHA-256 ที่ระบุ กรุณาตรวจไฟล์เวอร์ชันล่าสุด"])
            }
        }

        var data''')
new=new.replace('''        if summary.isPasswordProtected {
            throw PatchPackageError.invalidPasswordOrCorruptedPackage
        }''','''        if summary.isPasswordProtected {
            throw NSError(domain: "RUIZENCatalog", code: -3, userInfo: [NSLocalizedDescriptionKey: "ไฟล์นี้มีรหัสผ่าน จึงนำเข้าอัตโนมัติไม่ได้"])
        }''')
s=s[:start]+new+s[end:];p.write_text(s)
print('Verified catalog state patch: per-file failures, active download only, retry, HTTP/hash/password diagnostics; package protection retained')
