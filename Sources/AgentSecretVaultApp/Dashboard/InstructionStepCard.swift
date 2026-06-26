import SwiftUI

public struct InstructionStepCard: View {
    private let step: UsageStepCopy

    public init(step: UsageStepCopy) {
        self.step = step
    }

    public var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            Text("\(step.id)")
                .font(.headline.monospacedDigit())
                .foregroundStyle(.white)
                .frame(width: 30, height: 30)
                .background(Circle().fill(Color.accentColor))

            VStack(alignment: .leading, spacing: 4) {
                Text(step.englishTitle)
                    .font(.headline)
                Text(step.chineseTitle)
                    .font(.subheadline.weight(.semibold))
                    .foregroundStyle(.primary)
                Text(step.englishBody)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                Text(step.chineseBody)
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
        }
        .frame(maxWidth: .infinity, minHeight: 172, alignment: .topLeading)
        .padding(16)
        .background(.background, in: RoundedRectangle(cornerRadius: 18, style: .continuous))
        .overlay {
            RoundedRectangle(cornerRadius: 18, style: .continuous)
                .stroke(.quaternary, lineWidth: 1)
        }
    }
}
