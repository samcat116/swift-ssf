import Foundation
import AsyncHTTPClient
import NIOFoundationCompat
import NIOHTTP1
import NIO
import Logging

/// HTTP client for communicating with SSF transmitters.
///
/// Endpoint URLs come from the transmitter's configuration metadata
/// (SSF 1.0 §7); nothing except the discovery document location is derived
/// from the issuer URL.
public actor SSFHTTPClient {
    private let httpClient: HTTPClient
    private let issuerURL: URL
    private let authToken: String?
    private let logger = Logger(label: "SwiftSSF.HTTPClient")
    private let jsonDecoder: JSONDecoder
    private let jsonEncoder: JSONEncoder

    /// Whether this instance created (and therefore owns) its HTTPClient
    private let ownsHTTPClient: Bool

    public init(baseURL: URL, authToken: String? = nil, httpClient: HTTPClient? = nil) {
        self.issuerURL = baseURL
        self.authToken = authToken
        self.ownsHTTPClient = (httpClient == nil)
        self.httpClient = httpClient ?? HTTPClient(eventLoopGroupProvider: .singleton)

        self.jsonDecoder = JSONDecoder()
        self.jsonEncoder = JSONEncoder()

        // Configure JSON coding
        jsonDecoder.dateDecodingStrategy = .secondsSince1970
        jsonEncoder.dateEncodingStrategy = .secondsSince1970
    }

    deinit {
        // Only shut down a client we created; an injected client is shared
        // and belongs to the caller. Capture the client (not self) so the
        // task doesn't outlive deinit with a dangling self reference.
        if ownsHTTPClient {
            let client = httpClient
            Task { try? await client.shutdown() }
        }
    }

    // MARK: - Generic HTTP Methods

    /// Perform a GET request against an absolute URL
    public func get<T: Codable>(
        url: URL,
        responseType: T.Type,
        queryItems: [URLQueryItem] = []
    ) async throws -> T {
        var request = HTTPClientRequest(url: try appendQuery(url, queryItems).absoluteString)
        request.method = .GET
        addAuthenticationHeaders(&request)
        request.headers.add(name: "Accept", value: "application/json")

        return try await performRequest(request, responseType: responseType)
    }

    /// Perform a request with a JSON body against an absolute URL
    public func send<T: Codable, U: Codable>(
        _ method: HTTPMethod,
        url: URL,
        body: T,
        responseType: U.Type
    ) async throws -> U {
        var request = HTTPClientRequest(url: url.absoluteString)
        request.method = method
        addAuthenticationHeaders(&request)
        addJSONHeaders(&request)

        let bodyData = try jsonEncoder.encode(body)
        request.body = .bytes(ByteBuffer(data: bodyData))

        return try await performRequest(request, responseType: responseType)
    }

    /// Perform a DELETE request against an absolute URL
    public func delete(url: URL, queryItems: [URLQueryItem] = []) async throws {
        var request = HTTPClientRequest(url: try appendQuery(url, queryItems).absoluteString)
        request.method = .DELETE
        addAuthenticationHeaders(&request)

        let response = try await httpClient.execute(request, timeout: .seconds(30))
        try await handleErrorResponse(response)
    }

    // MARK: - Stream Management API (SSF 1.0 §8.1.1)

    /// Read a stream configuration: GET {configuration_endpoint}?stream_id=...
    public func getStream(endpoint: URL, id: String) async throws -> StreamConfiguration {
        return try await get(
            url: endpoint,
            responseType: StreamConfiguration.self,
            queryItems: [URLQueryItem(name: "stream_id", value: id)]
        )
    }

    /// List all of the receiver's streams: GET {configuration_endpoint}
    public func listStreams(endpoint: URL) async throws -> [StreamConfiguration] {
        return try await get(url: endpoint, responseType: [StreamConfiguration].self)
    }

    /// Create a stream: POST {configuration_endpoint}
    public func createStream(endpoint: URL, _ request: CreateStreamRequest) async throws -> StreamConfiguration {
        return try await send(.POST, url: endpoint, body: request, responseType: StreamConfiguration.self)
    }

    /// Update parts of a stream: PATCH {configuration_endpoint}
    public func updateStream(endpoint: URL, _ request: UpdateStreamRequest) async throws -> StreamConfiguration {
        return try await send(.PATCH, url: endpoint, body: request, responseType: StreamConfiguration.self)
    }

    /// Replace a stream configuration: PUT {configuration_endpoint}
    public func replaceStream(endpoint: URL, _ configuration: StreamConfiguration) async throws -> StreamConfiguration {
        return try await send(.PUT, url: endpoint, body: configuration, responseType: StreamConfiguration.self)
    }

    /// Delete a stream: DELETE {configuration_endpoint}?stream_id=...
    public func deleteStream(endpoint: URL, id: String) async throws {
        try await delete(url: endpoint, queryItems: [URLQueryItem(name: "stream_id", value: id)])
    }

    // MARK: - Stream Status (SSF 1.0 §8.1.2)

    /// Read stream status: GET {status_endpoint}?stream_id=...
    public func getStreamStatus(endpoint: URL, id: String) async throws -> StreamStatusResponse {
        return try await get(
            url: endpoint,
            responseType: StreamStatusResponse.self,
            queryItems: [URLQueryItem(name: "stream_id", value: id)]
        )
    }

    /// Update stream status: POST {status_endpoint}
    public func setStreamStatus(endpoint: URL, _ request: StreamStatusResponse) async throws -> StreamStatusResponse {
        return try await send(.POST, url: endpoint, body: request, responseType: StreamStatusResponse.self)
    }

    // MARK: - Subjects (SSF 1.0 §8.1.3)

    /// Add subject: POST {add_subject_endpoint}
    public func addSubject(endpoint: URL, _ request: AddSubjectRequest) async throws {
        let _: EmptyResponse = try await send(.POST, url: endpoint, body: request, responseType: EmptyResponse.self)
    }

    /// Remove subject: POST {remove_subject_endpoint}
    public func removeSubject(endpoint: URL, _ request: RemoveSubjectRequest) async throws {
        let _: EmptyResponse = try await send(.POST, url: endpoint, body: request, responseType: EmptyResponse.self)
    }

    // MARK: - Verification (SSF 1.0 §8.1.4)

    /// Request stream verification: POST {verification_endpoint}.
    /// A successful request returns 204; the verification event arrives
    /// asynchronously over the stream.
    public func verifyStream(endpoint: URL, _ request: VerificationRequest) async throws {
        let _: EmptyResponse = try await send(.POST, url: endpoint, body: request, responseType: EmptyResponse.self)
    }

    // MARK: - Event Polling (RFC 8936)

    /// Poll for events: POST to the stream's delivery endpoint
    public func pollEvents(endpoint: URL, _ request: PollRequest) async throws -> PollResponse {
        return try await send(.POST, url: endpoint, body: request, responseType: PollResponse.self)
    }

    // MARK: - Discovery (SSF 1.0 §7.1.1)

    /// Fetch transmitter configuration metadata from the well-known location
    public func getConfiguration() async throws -> TransmitterConfiguration {
        let url = try Self.wellKnownConfigurationURL(for: issuerURL)
        return try await get(url: url, responseType: TransmitterConfiguration.self)
    }

    /// Build the discovery URL: "/.well-known/ssf-configuration" is inserted
    /// between the host and any path component of the issuer URL.
    static func wellKnownConfigurationURL(for issuer: URL) throws -> URL {
        guard var components = URLComponents(url: issuer, resolvingAgainstBaseURL: false) else {
            throw SSFError.configurationError("Invalid issuer URL")
        }

        let issuerPath = components.path == "/" ? "" : components.path
        components.path = "/.well-known/ssf-configuration" + issuerPath
        components.query = nil
        components.fragment = nil

        guard let url = components.url else {
            throw SSFError.configurationError("Failed to build discovery URL")
        }
        return url
    }

    // MARK: - Private Methods

    private func appendQuery(_ url: URL, _ queryItems: [URLQueryItem]) throws -> URL {
        guard !queryItems.isEmpty else { return url }

        guard var components = URLComponents(url: url, resolvingAgainstBaseURL: false) else {
            throw SSFError.configurationError("Invalid URL")
        }

        components.queryItems = (components.queryItems ?? []) + queryItems

        guard let result = components.url else {
            throw SSFError.configurationError("Failed to build URL")
        }
        return result
    }

    private func addAuthenticationHeaders(_ request: inout HTTPClientRequest) {
        if let authToken = authToken {
            request.headers.add(name: "Authorization", value: "Bearer \(authToken)")
        }
    }

    private func addJSONHeaders(_ request: inout HTTPClientRequest) {
        request.headers.add(name: "Content-Type", value: "application/json")
        request.headers.add(name: "Accept", value: "application/json")
    }

    private func performRequest<T: Codable>(
        _ request: HTTPClientRequest,
        responseType: T.Type
    ) async throws -> T {
        logger.debug("Performing \(request.method) request to \(request.url)")

        do {
            let response = try await httpClient.execute(request, timeout: .seconds(30))
            try await handleErrorResponse(response)

            if T.self == EmptyResponse.self {
                return EmptyResponse() as! T
            }

            let body = try await response.body.collect(upTo: 1024 * 1024) // 1MB limit
            let data = Data(buffer: body)

            return try jsonDecoder.decode(T.self, from: data)
        } catch let error as SSFError {
            throw error
        } catch let error as DecodingError {
            throw SSFError.jsonParsingError(error)
        } catch {
            throw SSFError.networkError(error)
        }
    }

    private func handleErrorResponse(_ response: HTTPClientResponse) async throws {
        guard response.status.code >= 400 else { return }

        let body = try await response.body.collect(upTo: 1024 * 1024)
        let data = Data(buffer: body)

        // Try to parse as SSF error response
        if let errorResponse = try? jsonDecoder.decode(SSFHTTPError.self, from: data) {
            switch response.status.code {
            case 401:
                throw SSFError.authenticationFailed(errorResponse.error_description ?? errorResponse.error)
            case 403:
                throw SSFError.authorizationFailed(errorResponse.error_description ?? errorResponse.error)
            case 404:
                if errorResponse.error == SSFErrorCode.streamNotFound.rawValue {
                    throw SSFError.streamNotFound(errorResponse.error_description ?? "Stream not found")
                } else {
                    throw SSFError.httpError(statusCode: Int(response.status.code), message: errorResponse.error_description)
                }
            case 500...599:
                throw SSFError.serverError(errorResponse.error_description ?? errorResponse.error)
            default:
                throw SSFError.httpError(statusCode: Int(response.status.code), message: errorResponse.error_description)
            }
        } else {
            // Generic HTTP error
            let message = String(data: data, encoding: .utf8)
            throw SSFError.httpError(statusCode: Int(response.status.code), message: message)
        }
    }
}

// MARK: - Response Types

/// Empty response for operations that don't return data
public struct EmptyResponse: Codable, Sendable {
    public init() {}
}

/// RFC 8936 poll request body
public struct PollRequest: Codable, Sendable {
    /// Maximum number of SETs to return; 0 makes this an ack-only request
    public let maxEvents: Int?

    /// false (the spec default) holds the request open until SETs are
    /// available (long polling); true returns immediately
    public let returnImmediately: Bool?

    /// jti values of SETs (from a previous poll) to acknowledge
    public let ack: [String]?

    /// jti values of SETs that failed to process, with their errors
    public let setErrs: [String: SETErrorStatus]?

    public init(
        maxEvents: Int? = nil,
        returnImmediately: Bool? = nil,
        ack: [String]? = nil,
        setErrs: [String: SETErrorStatus]? = nil
    ) {
        self.maxEvents = maxEvents
        self.returnImmediately = returnImmediately
        self.ack = ack
        self.setErrs = setErrs
    }
}

/// RFC 8936 poll response body
public struct PollResponse: Codable, Sendable {
    /// SETs keyed by their jti
    public let sets: [String: String]

    /// Whether more events are available immediately
    public let moreAvailable: Bool?

    public init(sets: [String: String], moreAvailable: Bool? = nil) {
        self.sets = sets
        self.moreAvailable = moreAvailable
    }
}

/// Transmitter configuration metadata (SSF 1.0 §7.1)
public struct TransmitterConfiguration: Codable, Sendable {
    /// Issuer URL (REQUIRED)
    public let issuer: URL

    /// SSF spec version implemented by the transmitter (e.g. "1_0")
    public let spec_version: String?

    /// JWKS endpoint
    public let jwks_uri: URL?

    /// Supported delivery method URIs
    public let delivery_methods_supported: [String]?

    /// Stream configuration endpoint
    public let configuration_endpoint: URL?

    /// Stream status endpoint
    public let status_endpoint: URL?

    /// Add subject endpoint
    public let add_subject_endpoint: URL?

    /// Remove subject endpoint
    public let remove_subject_endpoint: URL?

    /// Verification endpoint
    public let verification_endpoint: URL?

    /// Complex Subject members the transmitter requires ("user", "device", ...)
    public let critical_subject_members: [String]?

    /// Authorization schemes supported for the management API
    public let authorization_schemes: [AuthorizationScheme]?

    /// Whether newly created streams start with all ("ALL") or no ("NONE") subjects
    public let default_subjects: String?

    public init(
        issuer: URL,
        spec_version: String? = nil,
        jwks_uri: URL? = nil,
        delivery_methods_supported: [String]? = nil,
        configuration_endpoint: URL? = nil,
        status_endpoint: URL? = nil,
        add_subject_endpoint: URL? = nil,
        remove_subject_endpoint: URL? = nil,
        verification_endpoint: URL? = nil,
        critical_subject_members: [String]? = nil,
        authorization_schemes: [AuthorizationScheme]? = nil,
        default_subjects: String? = nil
    ) {
        self.issuer = issuer
        self.spec_version = spec_version
        self.jwks_uri = jwks_uri
        self.delivery_methods_supported = delivery_methods_supported
        self.configuration_endpoint = configuration_endpoint
        self.status_endpoint = status_endpoint
        self.add_subject_endpoint = add_subject_endpoint
        self.remove_subject_endpoint = remove_subject_endpoint
        self.verification_endpoint = verification_endpoint
        self.critical_subject_members = critical_subject_members
        self.authorization_schemes = authorization_schemes
        self.default_subjects = default_subjects
    }
}

/// An authorization scheme advertised in transmitter metadata
public struct AuthorizationScheme: Codable, Sendable {
    /// Identifier for the scheme, e.g. "urn:ietf:rfc:6749"
    public let spec_urn: String

    public init(spec_urn: String) {
        self.spec_urn = spec_urn
    }
}
