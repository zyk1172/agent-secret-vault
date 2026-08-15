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
        VStack(alignment: .leading, spacing: 16) {
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
        .padding(20)
        .frame(maxWidth: .infinity, alignment: .topLeading)
        .background(Color(nsColor: .controlBackgroundColor), in: RoundedRectangle(cornerRadius: 22, style: .continuous))
        .confirmationDialog(
            "确认删除这条加密记录？",
            isPresented: $isConfirmingDeletion,
            titleVisibility: .visible
        ) {
            if let referencePendingDeletion {
                Button("请求高风险授权", role: .destructive) {
                    requestPermanentDelete(referencePendingDeletion)
                }
            }

            Button("取消", role: .cancel) {}
        } message: {
            if let referencePendingDeletion {
                Text("确认后会先请求本机高风险授权，再删除 \(referencePendingDeletion)。")
            }
        }
    }

    private var header: some View {
        VStack(alignment: .leading, spacing: 8) {
            Label("记录维护", systemImage: "tray.full")
                .font(.title3.weight(.semibold))
            Text(VaultUICopy.orphanReviewSafety.chinese)
                .foregroundStyle(.secondary)
            statusText
        }
    }

    @ViewBuilder
    private var statusText: some View {
        if let result {
            let issueCount = result.missingRecords.count + result.unreferencedRecords.count
            Text(issueCount == 0 ? "未发现问题" : "发现 \(issueCount) 个需要检查的项目")
                .font(.caption.weight(.semibold))
                .foregroundStyle(issueCount == 0 ? .green : .orange)
        } else {
            Text("尚未扫描")
                .font(.caption.weight(.semibold))
                .foregroundStyle(.secondary)
        }
    }

    private var notScannedState: some View {
        ContentUnavailableView(
            "暂无扫描结果",
            systemImage: "magnifyingglass",
            description: Text("请先在 Obsidian 插件中发起扫描，用来比对笔记引用和本机加密记录。")
        )
        .frame(maxWidth: .infinity, minHeight: 120)
    }

    private var emptyState: some View {
        ContentUnavailableView(
            "没有发现孤立记录",
            systemImage: "checkmark.shield",
            description: Text("笔记中的密文引用都有对应记录，本机加密记录也都被笔记引用。")
        )
        .frame(maxWidth: .infinity, minHeight: 120)
    }

    private func resultList(_ result: OrphanScanResult) -> some View {
        List {
            if !result.missingRecords.isEmpty {
                Section("笔记引用缺少本机记录") {
                    ForEach(result.missingRecords, id: \.self) { reference in
                        VStack(alignment: .leading, spacing: 6) {
                            Text(reference)
                                .font(.system(.body, design: .monospaced))
                            Text("笔记里存在这个密文引用，但本机没有对应加密记录。")
                                .font(.caption)
                                .foregroundStyle(.secondary)
                        }
                        .padding(.vertical, 6)
                    }
                }
            }

            if !result.unreferencedRecords.isEmpty {
                Section("本机记录未被笔记引用") {
                    ForEach(result.unreferencedRecords, id: \.self) { reference in
                        VStack(alignment: .leading, spacing: 10) {
                            HStack(alignment: .firstTextBaseline) {
                                Text(reference)
                                    .font(.system(.body, design: .monospaced))
                                Spacer()
                                Button("请求删除授权", role: .destructive) {
                                    referencePendingDeletion = reference
                                    isConfirmingDeletion = true
                                }
                            }
                            Text("确认后立即请求本机高风险授权并删除。")
                                .font(.caption)
                                .foregroundStyle(.secondary)
                        }
                        .padding(.vertical, 6)
                    }
                }
            }
        }
        .frame(minHeight: 180, maxHeight: 320)
        .clipShape(RoundedRectangle(cornerRadius: 16, style: .continuous))
    }
}
