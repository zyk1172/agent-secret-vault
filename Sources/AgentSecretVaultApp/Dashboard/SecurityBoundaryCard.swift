import SwiftUI

public struct SecurityBoundaryCard: View {
    private let boundary: SecurityBoundaryCopy

    public init(boundary: SecurityBoundaryCopy) {
        self.boundary = boundary
    }

    public var body: some View {
        HStack(alignment: .top, spacing: 12) {
            Image(systemName: boundary.symbolName)
                .font(.title3)
                .foregroundStyle(boundary.isLimitation ? .orange : .green)
                .frame(width: 28)

            VStack(alignment: .leading, spacing: 4) {
                Text(boundary.englishTitle)
                    .font(.headline)
                Text(boundary.chineseTitle)
                    .font(.subheadline.weight(.semibold))
                Text(boundary.englishBody)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                Text(boundary.chineseBody)
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
        }
        .padding(14)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(.thinMaterial, in: RoundedRectangle(cornerRadius: 16, style: .continuous))
    }
}
