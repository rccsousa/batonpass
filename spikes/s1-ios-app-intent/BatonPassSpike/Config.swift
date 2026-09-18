import Foundation

enum Config {
    static let defaultEndpoint = "http://100.64.0.10:8787/clip"
    static let timeout: TimeInterval = 10

    private static let endpointKey = "batonpass.endpoint"

    static var endpoint: String {
        get { UserDefaults.standard.string(forKey: endpointKey) ?? defaultEndpoint }
        set { UserDefaults.standard.set(newValue, forKey: endpointKey) }
    }
}
