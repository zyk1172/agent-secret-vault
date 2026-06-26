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
        VStack(alignment: .leading, spacing: 20) {
            header

            if candidates.isEmpty {
                emptyState
            } else {
                candidateList
            }
        }
        .padding(28)
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
        .background(Color(nsColor: .windowBackgroundColor))
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

    private var header: some View {
        VStack(alignment: .leading, spacing: 8) {
            Label("Orphan Review · 孤立记录检查", systemImage: "tray.full")
                .font(.largeTitle.weight(.bold))
            Text(VaultUICopy.orphanReviewSafety.english)
                .foregroundStyle(.secondary)
            Text(VaultUICopy.orphanReviewSafety.chinese)
                .foregroundStyle(.secondary)
            Text("\(candidates.count) candidate\(candidates.count == 1 ? "" : "s") found")
                .font(.caption.weight(.semibold))
                .foregroundStyle(candidates.isEmpty ? .green : .orange)
        }
    }

    private var emptyState: some View {
        ContentUnavailableView(
            "No orphan candidates",
            systemImage: "checkmark.shield",
            description: Text("All stored records are referenced by the scanned Markdown roots. 已扫描的 Markdown 根目录仍引用所有存储记录。")
        )
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }

    private var candidateList: some View {
        List(candidates) { candidate in
            VStack(alignment: .leading, spacing: 10) {
                HStack(alignment: .firstTextBaseline) {
                    Text("secret://\(candidate.id)")
                        .font(.system(.body, design: .monospaced))
                    Spacer()
                    Button("Request permanent delete", role: .destructive) {
                        candidatePendingDeletion = candidate
                        isConfirmingDeletion = true
                    }
                }

                Text("Versions: \(candidate.versions.map(String.init).joined(separator: ", "))")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                Text("Deletion requires a separate highest-risk authorization. 删除前必须再次完成最高风险级别授权。")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            .padding(.vertical, 8)
        }
        .clipShape(RoundedRectangle(cornerRadius: 16, style: .continuous))
    }
}
