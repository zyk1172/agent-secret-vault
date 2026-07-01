import SwiftUI

public struct OverviewGuideView: View {
    public init() {}

    public var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 24) {
                hero
                usageGuide
                securityBoundaries
            }
            .padding(28)
        }
        .background(Color(nsColor: .windowBackgroundColor))
    }

    private var hero: some View {
        VStack(alignment: .leading, spacing: 12) {
            Label("总览", systemImage: "lock.shield")
                .font(.subheadline.weight(.semibold))
                .foregroundStyle(.secondary)

            Text(VaultUICopy.overviewPromise.chinese)
                .font(.system(size: 34, weight: .bold, design: .default))
                .lineLimit(3)
                .minimumScaleFactor(0.8)

            Text(VaultUICopy.overviewSubtitle.chinese)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
        }
        .padding(24)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(.regularMaterial, in: RoundedRectangle(cornerRadius: 24, style: .continuous))
    }

    private var usageGuide: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("使用方法")
                .font(.title3.weight(.semibold))

            LazyVGrid(columns: Array(repeating: GridItem(.flexible(), spacing: 12), count: 4), spacing: 12) {
                ForEach(VaultUICopy.usageSteps) { step in
                    InstructionStepCard(step: step)
                }
            }
        }
    }

    private var securityBoundaries: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("安全边界")
                .font(.title3.weight(.semibold))

            LazyVGrid(columns: [GridItem(.flexible()), GridItem(.flexible())], spacing: 12) {
                ForEach(VaultUICopy.securityBoundaries) { boundary in
                    SecurityBoundaryCard(boundary: boundary)
                }
            }
        }
    }
}
