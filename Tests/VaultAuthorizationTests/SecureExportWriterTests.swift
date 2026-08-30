import Foundation
import Testing
@testable import VaultService

@Test func secureExportWriterCreatesOwnerOnlyFileAndDoesNotOverwrite() throws {
    let root = FileManager.default.temporaryDirectory.resolvingSymlinksInPath()
        .appendingPathComponent("SVLTSecureExportWriter-\(UUID().uuidString)", isDirectory: true)
    try FileManager.default.createDirectory(
        at: root,
        withIntermediateDirectories: false,
        attributes: [.posixPermissions: 0o700]
    )
    defer { try? FileManager.default.removeItem(at: root) }

    let destination = root.appendingPathComponent("result.txt")
    try SecureExportWriter().write(Data("opaque test output".utf8), to: destination, under: root)

    let attributes = try FileManager.default.attributesOfItem(atPath: destination.path)
    let mode = (attributes[.posixPermissions] as? NSNumber)?.intValue ?? 0
    #expect(mode & 0o777 == 0o600)
    #expect(try String(contentsOf: destination, encoding: .utf8) == "opaque test output")

    #expect(throws: SecureExportWriterError.fileAlreadyExists) {
        try SecureExportWriter().write(Data("replacement".utf8), to: destination, under: root)
    }
    #expect(try String(contentsOf: destination, encoding: .utf8) == "opaque test output")
}

@Test func secureExportWriterRejectsSymlinkTargetWithoutTouchingOutsideFile() throws {
    let temporaryRoot = FileManager.default.temporaryDirectory.resolvingSymlinksInPath()
    let root = temporaryRoot
        .appendingPathComponent("SVLTSecureExportWriter-\(UUID().uuidString)", isDirectory: true)
    let outside = temporaryRoot
        .appendingPathComponent("SVLTSecureExportWriter-outside-\(UUID().uuidString)")
    try FileManager.default.createDirectory(
        at: root,
        withIntermediateDirectories: false,
        attributes: [.posixPermissions: 0o700]
    )
    try Data("outside".utf8).write(to: outside)
    defer {
        try? FileManager.default.removeItem(at: root)
        try? FileManager.default.removeItem(at: outside)
    }

    let link = root.appendingPathComponent("link.txt")
    try FileManager.default.createSymbolicLink(at: link, withDestinationURL: outside)

    #expect(throws: SecureExportWriterError.fileAlreadyExists) {
        try SecureExportWriter().write(Data("should not escape".utf8), to: link, under: root)
    }
    #expect(try String(contentsOf: outside, encoding: .utf8) == "outside")
}

@Test func secureExportWriterRejectsSymlinkedAncestorAndReportsCapabilityUnavailable() throws {
    let temporaryRoot = FileManager.default.temporaryDirectory.resolvingSymlinksInPath()
    let parent = temporaryRoot
        .appendingPathComponent("SVLTSecureExportWriter-parent-\(UUID().uuidString)", isDirectory: true)
    let realRoot = parent.appendingPathComponent("Exports", isDirectory: true)
    let alias = temporaryRoot
        .appendingPathComponent("SVLTSecureExportWriter-alias-\(UUID().uuidString)", isDirectory: true)
    try FileManager.default.createDirectory(
        at: realRoot,
        withIntermediateDirectories: true,
        attributes: [.posixPermissions: 0o700]
    )
    try FileManager.default.createSymbolicLink(at: alias, withDestinationURL: parent)
    defer {
        try? FileManager.default.removeItem(at: alias)
        try? FileManager.default.removeItem(at: parent)
    }

    let aliasedRoot = alias.appendingPathComponent("Exports", isDirectory: true)
    #expect(!SecureExportWriter().canWrite(to: aliasedRoot))
    #expect(throws: SecureExportWriterError.invalidRoot) {
        try SecureExportWriter().write(
            Data("must stay inside the real root".utf8),
            to: aliasedRoot.appendingPathComponent("result.txt"),
            under: aliasedRoot
        )
    }
}
