import Foundation

@MainActor
public enum SensitiveIndexSelectionStore {
    private static let selectedPathKey = "selectedSensitiveIndexPath"
    private static let scanRootPathKey = "selectedSensitiveScanRootPath"

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

    public static func selectedScanRootURL(defaults: UserDefaults = .standard) -> URL? {
        guard let path = defaults.string(forKey: scanRootPathKey), !path.isEmpty else {
            return nil
        }
        return URL(fileURLWithPath: path)
    }

    public static func saveScanRoot(_ url: URL, defaults: UserDefaults = .standard) {
        defaults.set(url.path, forKey: scanRootPathKey)
    }
}
