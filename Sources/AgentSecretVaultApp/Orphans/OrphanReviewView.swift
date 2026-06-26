import SwiftUI
import VaultCore

public struct OrphanReviewView: View {
    private let candidates: [OrphanCandidate]
    private let requestPermanentDelete: (OrphanCandidate) -> Void
    @State private var candidatePendingDeletion: OrphanCandidate?
    @State private var isConfirmingDeletion = false

    public init(
        candidates: [OrphanCandidate],
        requestPermanentDelete: @escaping (OrphanCandidate) -> Void
    ) {
        self.candidates = candidates
        self.requestPermanentDelete = requestPermanentDelete
    }

    public var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text("Orphan Review")
                .font(.title2)

            Text("Candidates are never deleted by scanning. Permanent deletion must go through the highest-risk authorization path and explicit confirmation.")
                .foregroundStyle(.secondary)

            if candidates.isEmpty {
                ContentUnavailableView(
                    "No orphan candidates",
                    systemImage: "checkmark.shield",
                    description: Text("All stored records are referenced by the scanned Markdown roots.")
                )
            } else {
                List(candidates) { candidate in
                    HStack {
                        VStack(alignment: .leading) {
                            Text("secret://\(candidate.id)")
                                .font(.system(.body, design: .monospaced))
                            Text("Versions: \(candidate.versions.map(String.init).joined(separator: ", "))")
                                .font(.caption)
                                .foregroundStyle(.secondary)
                        }

                        Spacer()

                        Button("Request permanent delete", role: .destructive) {
                            candidatePendingDeletion = candidate
                            isConfirmingDeletion = true
                        }
                    }
                }
            }
        }
        .padding(20)
        .frame(minWidth: 640, minHeight: 360)
        .confirmationDialog(
            "Permanently delete all versions?",
            isPresented: $isConfirmingDeletion,
            titleVisibility: .visible
        ) {
            if let candidatePendingDeletion {
                Button("Request highest-risk authorization", role: .destructive) {
                    requestPermanentDelete(candidatePendingDeletion)
                }
            }

            Button("Cancel", role: .cancel) {}
        } message: {
            if let candidatePendingDeletion {
                Text("This only requests deletion for secret://\(candidatePendingDeletion.id). The caller must authorize and delete all versions explicitly.")
            }
        }
    }
}
