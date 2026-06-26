import SwiftUI

public struct SecureViewerView: View {
    @Bindable private var model: SecureViewerModel
    @State private var isConfirmingCopy = false

    public init(model: SecureViewerModel) {
        self.model = model
    }

    public var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text("Secure Viewer")
                .font(.title2)

            Group {
                if let displayText = model.displayText {
                    Text(displayText)
                        .font(.system(.body, design: .monospaced))
                        .textSelection(.disabled)
                        .padding()
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .background(.quaternary)
                        .clipShape(RoundedRectangle(cornerRadius: 8))
                } else {
                    ContentUnavailableView(
                        "No plaintext loaded",
                        systemImage: "lock",
                        description: Text("Open a secret reference to view it temporarily.")
                    )
                }
            }

            HStack {
                Button("Copy for 60 seconds") {
                    isConfirmingCopy = true
                }
                .disabled(model.displayText == nil)

                Button("Close") {
                    model.close()
                }
            }
        }
        .padding(20)
        .frame(minWidth: 520, minHeight: 320)
        .onDisappear {
            model.close()
        }
        .confirmationDialog(
            "Copy plaintext to the clipboard for 60 seconds?",
            isPresented: $isConfirmingCopy,
            titleVisibility: .visible
        ) {
            Button("Copy for 60 seconds") {
                model.copyFor60SecondsAfterConfirmation()
            }

            Button("Cancel", role: .cancel) {}
        } message: {
            Text("Only copy when you are ready to paste immediately. The app will clear the clipboard only if nothing else has replaced it.")
        }
    }
}
