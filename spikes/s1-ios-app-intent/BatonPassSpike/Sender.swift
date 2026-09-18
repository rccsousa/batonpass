import Foundation

struct SendError: LocalizedError {
    let errorDescription: String?

    init(_ message: String) { errorDescription = message }
}

enum Sender {
    private struct Payload: Encodable {
        let text: String
        let utf8Length: Int
        let characterCount: Int
        let sentAt: String
        let source: String
    }

    private static let session: URLSession = {
        let configuration = URLSessionConfiguration.ephemeral
        // Must stay false. With waitsForConnectivity, a Tailscale drop makes the
        // request hang until the resource timeout instead of failing, and the
        // intent would sit there holding its background execution budget.
        configuration.waitsForConnectivity = false
        configuration.timeoutIntervalForRequest = Config.timeout
        configuration.timeoutIntervalForResource = Config.timeout
        configuration.requestCachePolicy = .reloadIgnoringLocalAndRemoteCacheData
        return URLSession(configuration: configuration)
    }()

    static func post(text: String, to endpoint: String) async throws -> String {
        guard let url = URL(string: endpoint), url.scheme != nil, url.host != nil else {
            throw SendError("Invalid endpoint URL: \(endpoint)")
        }

        let payload = Payload(
            text: text,
            utf8Length: text.utf8.count,
            characterCount: text.count,
            sentAt: ISO8601DateFormatter().string(from: Date()),
            source: "ios-app-intent"
        )

        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.timeoutInterval = Config.timeout
        request.setValue("application/json; charset=utf-8", forHTTPHeaderField: "Content-Type")
        request.httpBody = try JSONEncoder().encode(payload)

        let (data, response) = try await session.data(for: request)

        guard let http = response as? HTTPURLResponse else {
            throw SendError("No HTTP response from \(endpoint)")
        }
        guard (200..<300).contains(http.statusCode) else {
            throw SendError("Receiver returned HTTP \(http.statusCode)")
        }
        return String(data: data, encoding: .utf8) ?? "<non-utf8 reply>"
    }
}
