import SwiftUI
import VaultIPC

public struct OrphanReviewView: View {
    private let result: OrphanScanResult?
    private let requestPermanentDelete: (String) -> Void
    @State private var referencePendingDeletion: String?
    @State private var isConfirmingDeletion = false

    public init(
        result: OrphanScanResult?,
        requestPermanentDelete: @escaping (String) -> Void
    ) {
        self.result = result
        self.requestPermanentDelete = requestPermanentDelete
    }

    public var body: some View {
        VStack(alignment: .leading, spacing: 20) {
            header

            if let result {
                if result.missingRecords.isEmpty && result.unreferencedRecords.isEmpty {
                    emptyState
                } else {
                    resultList(result)
                }
            } else {
                notScannedState
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
            if let referencePendingDeletion {
                Button("Request highest-risk authorization", role: .destructive) {
                    requestPermanentDelete(referencePendingDeletion)
                }
            }

            Button("Cancel", role: .cancel) {}
        } message: {
            if let referencePendingDeletion {
                Text("This only requests deletion authorization for \(referencePendingDeletion). The caller must complete highest-risk authorization before deleting any encrypted record.")
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
            statusText
        }
    }

    @ViewBuilder
    private var statusText: some View {
        if let result {
            let issueCount = result.missingRecords.count + result.unreferencedRecords.count
            Text("\(issueCount) issue\(issueCount == 1 ? "" : "s") found")
                .font(.caption.weight(.semibold))
                .foregroundStyle(issueCount == 0 ? .green : .orange)
        } else {
            Text("Scan has not run")
                .font(.caption.weight(.semibold))
                .foregroundStyle(.secondary)
        }
    }

    private var notScannedState: some View {
        ContentUnavailableView(
            "No scan results yet",
            systemImage: "magnifyingglass",
            description: Text("Run an orphan scan from the plugin to compare Markdown references with encrypted records. 请先从插件发起扫描。")
        )
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }

    private var emptyState: some View {
        ContentUnavailableView(
            "No orphan issues",
            systemImage: "checkmark.shield",
            description: Text("No Markdown references are missing records, and no encrypted records are unreferenced by Markdown.")
        )
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }

    private func resultList(_ result: OrphanScanResult) -> some View {
        List {
            if !result.missingRecords.isEmpty {
                Section("Missing record referenced in Markdown") {
                    ForEach(result.missingRecords, id: \.self) { reference in
                        VStack(alignment: .leading, spacing: 6) {
                            Text(reference)
                                .font(.system(.body, design: .monospaced))
                            Text("Markdown contains this reference, but the encrypted record is not present.")
                                .font(.caption)
                                .foregroundStyle(.secondary)
                        }
                        .padding(.vertical, 6)
                    }
                }
            }

            if !result.unreferencedRecords.isEmpty {
                Section("Encrypted record not referenced by Markdown") {
                    ForEach(result.unreferencedRecords, id: \.self) { reference in
                        VStack(alignment: .leading, spacing: 10) {
                            HStack(alignment: .firstTextBaseline) {
                                Text(reference)
                                    .font(.system(.body, design: .monospaced))
                                Spacer()
                                Button("Request highest-risk authorization", role: .destructive) {
                                    referencePendingDeletion = reference
                                    isConfirmingDeletion = true
                                }
                            }
                            Text("Deletion is not performed here. It requires separate highest-risk authorization. 此处不会直接删除；删除前必须单独完成最高风险授权。")
                                .font(.caption)
                                .foregroundStyle(.secondary)
                        }
                        .padding(.vertical, 6)
                    }
                }
            }
        }
        .clipShape(RoundedRectangle(cornerRadius: 16, style: .continuous))
    }
}
