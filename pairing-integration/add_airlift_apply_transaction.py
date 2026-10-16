#!/usr/bin/env python3
"""Connect RUIZEN's existing DevicePatchService to the native OS-authorized
AirLift Documents transport for iOS 27, with local pre-write backup journal,
readback verification and restore. Legacy OS paths stay unchanged.
"""
from pathlib import Path
import sys
root=Path(sys.argv[1])
file=root/'ThreeOneOSFive/helpers/DevicePatchService.swift'
view=root/'ThreeOneOSFive/views/PatchProjectsView.swift'
def one(s,a,b):
    if s.count(a)!=1:
        raise SystemExit(f'Build17 Swift patch anchor count={s.count(a)}: {a[:90]!r}')
    return s.replace(a,b,1)

s=file.read_text()
s=one(s,
'''    static func apply(project: PatchProject) throws -> PatchTransactionReceipt {
        let bundleIDs''',
'''    static func apply(project: PatchProject) throws -> PatchTransactionReceipt {
        if AirLiftDocumentsTransaction.selectedForCurrentIOS {
            return try AirLiftDocumentsTransaction.apply(project: project)
        }
        let bundleIDs''')
s=one(s,
'''    static func inspectRestore(receipt: PatchTransactionReceipt) throws -> PatchRestoreInspection {
        let bundleIDs''',
'''    static func inspectRestore(receipt: PatchTransactionReceipt) throws -> PatchRestoreInspection {
        if AirLiftDocumentsTransaction.owns(receipt) {
            return try AirLiftDocumentsTransaction.inspect(receipt)
        }
        let bundleIDs''')
s=one(s,
'''        allowChangedTargets: Bool = false
    ) throws {
        let bundleIDs = try PatchTransaction.requiredBundleIdentifiers(for: receipt)
        try withResolvedContainers''',
'''        allowChangedTargets: Bool = false
    ) throws {
        if AirLiftDocumentsTransaction.owns(receipt) {
            try AirLiftDocumentsTransaction.restore(receipt, allowChangedTargets: allowChangedTargets)
            return
        }
        let bundleIDs = try PatchTransaction.requiredBundleIdentifiers(for: receipt)
        try withResolvedContainers''')
s=one(s,
'''        project: PatchProject
    ) throws {
        let bundleIDs = try PatchTransaction.requiredBundleIdentifiers(for: receipt)
        try withResolvedContainers''',
'''        project: PatchProject
    ) throws {
        if AirLiftDocumentsTransaction.owns(receipt) {
            try AirLiftDocumentsTransaction.reset(receipt)
            return
        }
        let bundleIDs = try PatchTransaction.requiredBundleIdentifiers(for: receipt)
        try withResolvedContainers''')
s=one(s,
'''    static func latestReceipt(projectID: UUID) -> PatchTransactionReceipt? {
        guard let backupRoot''',
'''    static func latestReceipt(projectID: UUID) -> PatchTransactionReceipt? {
        if let airLiftReceipt = AirLiftDocumentsTransaction.latestReceipt(projectID: projectID) {
            return airLiftReceipt
        }
        guard let backupRoot''')

s += r'''

// RUIZEN AIRLIFT TRANSACTION ROUTE
// Unlike the legacy local FileManager transaction, this uses the OS-vended
// HouseArrest Documents AFC scope over authenticated RSD. It cannot access
// another app's private directories without explicit device authorization.
// Every original is backed up locally BEFORE any remote write is attempted.
private enum AirLiftDocumentsTransaction {
    struct Snapshot: Codable {
        var bundleID: String
        var relativePath: String
        var original: Data?
        var replacement: Data
    }
    struct Journal: Codable {
        var id: UUID
        var projectID: UUID
        var state: String
        var snapshots: [Snapshot]
    }

    static var selectedForCurrentIOS: Bool {
        let v = AppInfo.versionTuple
        return ExploitSupportPolicy.supportsAirLift(
            major: v.major, minor: v.minor, patch: v.patch, build: AppInfo.osBuild
        )
    }

    private static func journalURL(_ projectID: UUID) throws -> URL {
        let base = try PatchProjectLibrary.backupRootURL()
            .appendingPathComponent("AirLift", isDirectory: true)
            .appendingPathComponent(projectID.uuidString, isDirectory: true)
        try FileManager.default.createDirectory(at: base, withIntermediateDirectories: true)
        return base.appendingPathComponent("journal.json")
    }

    static func owns(_ receipt: PatchTransactionReceipt) -> Bool {
        guard let backupRoot = try? PatchProjectLibrary.backupRootURL() else {return false}
        let prefix = backupRoot.appendingPathComponent("AirLift", isDirectory: true).path + "/"
        return receipt.journalURL.standardizedFileURL.path.hasPrefix(prefix)
    }

    private static func load(_ receipt: PatchTransactionReceipt) throws -> Journal {
        let bytes = try Data(contentsOf: receipt.journalURL)
        let journal = try JSONDecoder().decode(Journal.self, from: bytes)
        guard journal.projectID == receipt.projectID, journal.id == receipt.id else {
            throw PatchPackageError.invalidProject
        }
        return journal
    }

    private static func save(_ journal: Journal, at url: URL) throws {
        let bytes = try JSONEncoder().encode(journal)
        try bytes.write(to: url, options: [.atomic, .completeFileProtectionUnlessOpen])
    }

    static func latestReceipt(projectID: UUID) -> PatchTransactionReceipt? {
        guard let url = try? journalURL(projectID),
              let bytes = try? Data(contentsOf: url),
              let journal = try? JSONDecoder().decode(Journal.self, from: bytes),
              journal.projectID == projectID,
              journal.state == "applied" || journal.state == "prepared"
        else {return nil}
        return PatchTransactionReceipt(id: journal.id, projectID: projectID, journalURL: url)
    }

    private static func validate(_ rule: PatchRule) throws {
        let identifier = try PatchPathValidator.canonicalBundleIdentifier(rule.bundleID)
        let relativePath = try PatchPathValidator.canonicalRelativePath(rule.relativePath)
        guard identifier == rule.bundleID,
              relativePath == rule.relativePath,
              relativePath.hasPrefix("Documents/"),
              rule.hasReplacement,
              rule.replacementData.count <= 8 * 1024 * 1024
        else {throw PatchPackageError.unsafeTargetPath}
    }

    private static func operate(
        bundleID: String, path: String, operation: UInt32, data: Data = Data()
    ) throws -> Data? {
        #if RUIZEN_PAIRING_ENABLED
        let pairPath = FileManager.default.urls(
            for: .applicationSupportDirectory, in: .userDomainMask
        )[0].appendingPathComponent("RuizenPairing", isDirectory: true)
            .appendingPathComponent("pairingFile.plist").path
        guard FileManager.default.fileExists(atPath: pairPath) else {
            throw AirLiftPatchError("กรุณา Pair on this iPhone ใน Settings ของ RUIZEN ก่อนลงไฟล์")
        }
        var result = RPAirLiftFileResult()
        let rc: Int32 = pairPath.withCString { p in
            bundleID.withCString { b in
                path.withCString { t in
                    data.withUnsafeBytes { raw in
                        rp_airlift_documents_file_op(
                            p, b, t, operation,
                            raw.bindMemory(to: UInt8.self).baseAddress,
                            data.count, &result
                        )
                    }
                }
            }
        }
        let stage = result.stage
        let description = result.message.map { String(cString: $0) } ?? "Unknown AirLift error"
        let found = result.found == 1
        let value: Data
        if let pointer = result.data, result.data_len > 0 {
            value = Data(bytes: pointer, count: result.data_len)
        } else {
            value = Data()
        }
        rp_airlift_file_result_free(&result)
        guard rc == 0 && stage == 50 else {
            throw AirLiftPatchError("AirLift ขั้น \(stage): \(description)")
        }
        return found ? value : nil
        #else
        throw AirLiftPatchError("ไม่ได้เชื่อมระบบ AirLift native ในบิลด์นี้")
        #endif
    }

    private static func remoteRead(_ snapshot: Snapshot) throws -> Data? {
        try operate(bundleID: snapshot.bundleID, path: snapshot.relativePath, operation: 0)
    }
    private static func remoteWrite(_ snapshot: Snapshot, bytes: Data) throws {
        let result = try operate(bundleID: snapshot.bundleID,
                                 path: snapshot.relativePath, operation: 1, data: bytes)
        guard result != nil else {throw AirLiftPatchError("เขียนไฟล์ไม่ได้รับการยืนยัน")}
    }
    private static func remoteRestore(_ snapshot: Snapshot) throws {
        if let backup = snapshot.original {
            try remoteWrite(snapshot, bytes: backup)
        } else {
            _ = try operate(bundleID: snapshot.bundleID,
                            path: snapshot.relativePath, operation: 2)
        }
    }

    static func apply(project: PatchProject) throws -> PatchTransactionReceipt {
        guard !project.rules.isEmpty, project.rules.count <= 50 else {
            throw PatchPackageError.invalidProject
        }
        guard latestReceipt(projectID: project.id) == nil else {
            throw PatchPackageError.projectAlreadyApplied
        }
        // Initial release intentionally disallows adding directory trees through
        // unverified remote APIs. Parent folders must already exist.
        let requestPaths = project.directories.map { $0.bundleID + "/" + $0.relativePath }
        guard requestPaths.isEmpty else {
            throw AirLiftPatchError(
                "แพตช์นี้ต้องสร้างโฟลเดอร์เพิ่มซึ่งยังไม่ได้ทดสอบใน AirLift; ไม่มีไฟล์ถูกแก้ไข"
            )
        }
        var seen = Set<String>()
        var snapshots: [Snapshot] = []
        for rule in project.rules {
            try validate(rule)
            let key = rule.bundleID + "\u{0}" + rule.relativePath
            guard seen.insert(key).inserted else {throw PatchPackageError.duplicateTarget}
            snapshots.append(Snapshot(
                bundleID: rule.bundleID, relativePath: rule.relativePath,
                original: nil, replacement: rule.replacementData
            ))
        }
        // PRE-FLIGHT: read every original before committing any device write.
        for index in snapshots.indices {
            snapshots[index].original = try remoteRead(snapshots[index])
        }

        let url = try journalURL(project.id)
        var journal = Journal(id: UUID(), projectID: project.id,
                              state: "prepared", snapshots: snapshots)
        try save(journal, at: url)
        var attempted = 0
        do {
            for item in snapshots {
                // Count this write BEFORE running it so partial writes are
                // included in the recovery operation.
                attempted += 1
                try remoteWrite(item, bytes: item.replacement)
            }
            journal.state = "applied"
            try save(journal, at: url)
            return PatchTransactionReceipt(id: journal.id,projectID: project.id,journalURL: url)
        } catch {
            var rollbackSucceeded = true
            for i in (0..<attempted).reversed() {
                do {try remoteRestore(snapshots[i])}
                catch { rollbackSucceeded = false }
            }
            if rollbackSucceeded {
                journal.state = "rolledBack"
                try? save(journal, at: url)
            }
            throw error
        }
    }

    static func inspect(_ receipt: PatchTransactionReceipt) throws -> PatchRestoreInspection {
        let journal = try load(receipt)
        var changes: [PatchTargetChange] = []
        for item in journal.snapshots {
            let observed = try remoteRead(item)
            if observed != item.replacement {
                changes.append(PatchTargetChange(
                    bundleID: item.bundleID, relativePath: item.relativePath,
                    kind: observed == nil ? .missing : .modified
                ))
            }
        }
        return PatchRestoreInspection(changedTargets: changes)
    }

    static func restore(_ receipt: PatchTransactionReceipt,
                        allowChangedTargets: Bool) throws {
        var journal = try load(receipt)
        guard journal.state == "applied" || journal.state == "prepared" else {return}
        if journal.state == "applied" && !allowChangedTargets {
            let changes = try inspect(receipt).changedTargets
            guard changes.isEmpty else {
                throw PatchPackageError.restoreTargetsChanged(changes.map(\.displayPath))
            }
        }
        for item in journal.snapshots.reversed() {
            try remoteRestore(item)
        }
        journal.state = "restored"
        try save(journal, at: receipt.journalURL)
    }

    static func reset(_ receipt: PatchTransactionReceipt) throws {
        let journal = try load(receipt)
        guard journal.state == "applied" else {throw PatchPackageError.resetFailed}
        for item in journal.snapshots {
            try remoteWrite(item, bytes: item.replacement)
        }
    }
}

private struct AirLiftPatchError: LocalizedError {
    let reason: String
    init(_ reason: String) {self.reason = reason}
    var errorDescription: String? {reason}
}
'''
file.write_text(s)

# Reuse localization infrastructure for concrete native transport errors.
s=view.read_text()
needle='''            } catch let error as PatchPackageError {
                await MainActor.run {'''
replacement='''            } catch let error as AirLiftPatchError {
                await MainActor.run {
                    workingProjectIDs.remove(item.id)
                    if !enabled {
                        userDisabledProjectIDs.insert(item.id)
                        saveUserDisabledProjectIDs()
                    }
                    syncActiveStates()
                    store.alert = PatchStoreAlert(
                        titleKey: "common.failed",
                        messageKey: "patch.airlift_transport_error",
                        messageArgument: error.localizedDescription
                    )
                }
            } catch let error as PatchPackageError {
                await MainActor.run {'''
# AirLiftPatchError must be visible from PatchProjectsView.
file.write_text(file.read_text().replace('private struct AirLiftPatchError: LocalizedError {','struct AirLiftPatchError: LocalizedError {'))
start = s.index("    private func setServerPatchEnabled(")
pre, block = s[:start], s[start:]
if block.count(needle) < 1:
    raise SystemExit("Apply action catch anchor missing")
block = block.replace(needle, replacement, 1)
s = pre + block
view.write_text(s)
for lang in ['en','vi','zh-Hans']:
    strings=root/f'ThreeOneOSFive/{lang}.lproj/Localizable.strings'
    with strings.open('a') as out:
        out.write('\n"patch.airlift_transport_error" = "AirLift: %@";\n')
print("Build17: DevicePatchService routes verified iOS27.0.1 to transactional, OS-authorized HouseArrest Documents AFC")
