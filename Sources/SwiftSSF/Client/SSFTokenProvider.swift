import Foundation

/// Supplies bearer tokens for authenticating to a transmitter's management API.
///
/// SSF 1.0 §7.1 lets a transmitter advertise the authorization schemes it
/// accepts (`authorization_schemes` in transmitter metadata). A token provider
/// encapsulates whatever flow produces a valid access token for the configured
/// scheme — a static long-lived token, an OAuth 2.0 client-credentials grant
/// with refresh, etc. — so the HTTP client stays agnostic to how the token is
/// obtained.
public protocol SSFTokenProvider: Sendable {
    /// Return a bearer token to place in the `Authorization` header.
    ///
    /// Called before each management-API request, so implementations that hold
    /// short-lived tokens can refresh transparently. Implementations should
    /// cache internally rather than minting a new token on every call.
    func accessToken() async throws -> String

    /// The `spec_urn` of the authorization scheme this provider implements
    /// (e.g. `"urn:ietf:rfc:6749"` for OAuth 2.0), or `nil` if unknown.
    ///
    /// When set, the receiver validates it against the transmitter's advertised
    /// `authorization_schemes` and logs a warning on mismatch.
    var schemeURN: String? { get }
}

public extension SSFTokenProvider {
    var schemeURN: String? { nil }
}

/// Trivial provider that always returns the same static bearer token.
///
/// This is the default when a caller configures a plain `authToken`. It keeps
/// the pre-existing single-static-token behaviour available without any OAuth
/// machinery.
public struct StaticTokenProvider: SSFTokenProvider {
    private let token: String

    public var schemeURN: String?

    /// - Parameters:
    ///   - token: the bearer token to send on every request.
    ///   - schemeURN: the advertised scheme this token satisfies, if known.
    public init(token: String, schemeURN: String? = nil) {
        self.token = token
        self.schemeURN = schemeURN
    }

    public func accessToken() async throws -> String {
        token
    }
}
