import Foundation

@MainActor
public enum SensitiveIndexSelectionStore {
    private static let selectedPathKey = "selectedSensitiveIndexPath"

    public static func selectedURL(defaults: UserDefaults = .standard) -> URL? {
        guard let path = defaults.string(forKey: selectedPathKey), !path.isEmpty else {
            return nil
        }
        return URL(fileURLWithPath: path)
    }

    public static func save(_ url: URL, defaults: UserDefaults = .standard) {
        defaults.set(url.path, forKey: selectedPathKey)
    }

    public static func clear(defaults: UserDefaults = .standard) {
        defaults.removeObject(forKey: selectedPathKey)
    }
}
