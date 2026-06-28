import Testing
@testable import VaultCore

@Test func markdownReferenceScannerFindsCanonicalReferencesIncludingBeforePunctuation() {
    let references = MarkdownReferenceScanner.references(in: """
    First ref: secret://0123456789ABCDEFGHJKMNPQRS.
    Second ref: `secret://01J33333333333333333333333`
    """)

    #expect(references == [
        "secret://0123456789ABCDEFGHJKMNPQRS",
        "secret://01J33333333333333333333333"
    ])
}

@Test func markdownReferenceScannerRejectsEmbeddedReferenceTokens() {
    let references = MarkdownReferenceScanner.references(in: """
    prefixsecret://0123456789ABCDEFGHJKMNPQRS
    secret://01J33333333333333333333333
    """)

    #expect(references == [
        "secret://01J33333333333333333333333"
    ])
}

@Test func markdownReferenceScannerRejectsLongerReferenceTokens() {
    let references = MarkdownReferenceScanner.references(in: """
    secret://0123456789ABCDEFGHJKMNPQRSABC
    secret://01J33333333333333333333333
    """)

    #expect(references == [
        "secret://01J33333333333333333333333"
    ])
}
