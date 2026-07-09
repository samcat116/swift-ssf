import Foundation
import AsyncHTTPClient
import NIOCore
import Crypto
import Logging

/// Configuration for SSF Receiver
public struct SSFReceiverConfiguration: Sendable {
    /// The transmitter's issuer URL (used for discovery)
    public let transmitterURL: URL

    /// Authentication token for API calls
    public let authToken: String?

    /// Expected issuer URL (defaults to transmitterURL)
    public let expectedIssuer: URL?

    /// Expected audience identifiers
    public let expectedAudience: [String]?

    /// Accept SETs without verifying their signature.
    ///
    /// This defaults to `false` and should stay `false` outside of tests:
    /// with verification disabled, anyone who can reach the receiver can
    /// inject fabricated security events.
    public let allowUnverifiedTokens: Bool

    /// HTTP client configuration
    public let httpClient: HTTPClient?

    /// Logging level
    public let logLevel: Logger.Level

    public init(
        transmitterURL: URL,
        authToken: String? = nil,
        expectedIssuer: URL? = nil,
        expectedAudience: [String]? = nil,
        allowUnverifiedTokens: Bool = false,
        httpClient: HTTPClient? = nil,
        logLevel: Logger.Level = .info
    ) {
        self.transmitterURL = transmitterURL
        self.authToken = authToken
        self.expectedIssuer = expectedIssuer ?? transmitterURL
        self.expectedAudience = expectedAudience
        self.allowUnverifiedTokens = allowUnverifiedTokens
        self.httpClient = httpClient
        self.logLevel = logLevel
    }
}

/// Event handler protocol for processing received security events
public protocol SSFEventHandler: Sendable {
    /// Handle a received security event
    func handleEvent(_ token: SecurityEventToken) async throws

    /// Handle event processing errors
    func handleError(_ error: SSFError, token: SecurityEventToken?) async
}

/// Result of a single poll request
public struct PollResult: Sendable {
    /// Number of SETs successfully processed and acknowledged
    public let processed: Int

    /// Number of SETs that failed processing (reported via setErrs)
    public let failed: Int

    /// Whether the transmitter has more events available right now
    public let moreAvailable: Bool
}

/// Main SSF Receiver implementation
public actor SSFReceiver {
    private let configuration: SSFReceiverConfiguration
    private let httpClient: SSFHTTPClient
    private let jwtProcessor: JWTProcessor
    private let jwksClient: JWKSClient
    private let logger: Logger

    private var cachedConfiguration: TransmitterConfiguration?

    /// The HTTPClient this receiver created and must shut down; nil when the
    /// caller injected their own client.
    private let ownedHTTPClient: HTTPClient?

    public init(configuration: SSFReceiverConfiguration) {
        self.configuration = configuration

        let httpClientInstance: HTTPClient
        if let injected = configuration.httpClient {
            httpClientInstance = injected
            self.ownedHTTPClient = nil
        } else {
            httpClientInstance = HTTPClient(eventLoopGroupProvider: .singleton)
            self.ownedHTTPClient = httpClientInstance
        }

        self.httpClient = SSFHTTPClient(
            baseURL: configuration.transmitterURL,
            authToken: configuration.authToken,
            httpClient: httpClientInstance
        )

        self.jwtProcessor = JWTProcessor()
        self.jwksClient = JWKSClient(httpClient: httpClientInstance)

        var logger = Logger(label: "SwiftSSF.Receiver")
        logger.logLevel = configuration.logLevel
        self.logger = logger
    }

    deinit {
        // Backstop for callers that never call shutdown(). Capture the client
        // (not self) so the task doesn't outlive deinit.
        if let client = ownedHTTPClient {
            Task { try? await client.shutdown() }
        }
    }

    /// Shut down resources owned by this receiver. Safe to call once when the
    /// receiver is no longer needed; injected HTTP clients are not touched.
    public func shutdown() async throws {
        if let client = ownedHTTPClient {
            try await client.shutdown()
        }
    }

    // MARK: - Stream Management (SSF 1.0 §8.1.1)

    /// Create a new event stream
    public func createStream(
        eventsRequested: [String]? = nil,
        delivery: DeliveryConfiguration? = nil,
        description: String? = nil
    ) async throws -> StreamConfiguration {
        logger.info("Creating new event stream")

        let request = CreateStreamRequest(
            events_requested: eventsRequested,
            delivery: delivery,
            description: description
        )

        return try await httpClient.createStream(endpoint: try await endpoint(\.configuration_endpoint, "configuration_endpoint"), request)
    }

    /// Get an existing stream's configuration
    public func getStream(id: String) async throws -> StreamConfiguration {
        return try await httpClient.getStream(endpoint: try await endpoint(\.configuration_endpoint, "configuration_endpoint"), id: id)
    }

    /// List all of this receiver's streams
    public func listStreams() async throws -> [StreamConfiguration] {
        return try await httpClient.listStreams(endpoint: try await endpoint(\.configuration_endpoint, "configuration_endpoint"))
    }

    /// Update parts of a stream (PATCH semantics)
    public func updateStream(
        id: String,
        eventsRequested: [String]? = nil,
        delivery: DeliveryConfiguration? = nil,
        description: String? = nil
    ) async throws -> StreamConfiguration {
        let request = UpdateStreamRequest(
            stream_id: id,
            events_requested: eventsRequested,
            delivery: delivery,
            description: description
        )

        return try await httpClient.updateStream(endpoint: try await endpoint(\.configuration_endpoint, "configuration_endpoint"), request)
    }

    /// Replace a stream's full configuration (PUT semantics)
    public func replaceStream(_ stream: StreamConfiguration) async throws -> StreamConfiguration {
        return try await httpClient.replaceStream(endpoint: try await endpoint(\.configuration_endpoint, "configuration_endpoint"), stream)
    }

    /// Delete a stream
    public func deleteStream(id: String) async throws {
        logger.info("Deleting stream \(id)")
        try await httpClient.deleteStream(endpoint: try await endpoint(\.configuration_endpoint, "configuration_endpoint"), id: id)
    }

    // MARK: - Stream Status (SSF 1.0 §8.1.2)

    /// Get stream status
    public func getStreamStatus(id: String) async throws -> StreamStatusResponse {
        return try await httpClient.getStreamStatus(endpoint: try await endpoint(\.status_endpoint, "status_endpoint"), id: id)
    }

    /// Update stream status
    @discardableResult
    public func setStreamStatus(
        id: String,
        status: StreamStatus,
        reason: String? = nil
    ) async throws -> StreamStatusResponse {
        let request = StreamStatusResponse(stream_id: id, status: status, reason: reason)
        return try await httpClient.setStreamStatus(endpoint: try await endpoint(\.status_endpoint, "status_endpoint"), request)
    }

    // MARK: - Subjects (SSF 1.0 §8.1.3)

    /// Add a subject to a stream
    public func addSubject(streamId: String, subject: SubjectIdentifier, verified: Bool? = nil) async throws {
        logger.debug("Adding subject to stream \(streamId)")
        let request = AddSubjectRequest(stream_id: streamId, subject: subject, verified: verified)
        try await httpClient.addSubject(endpoint: try await endpoint(\.add_subject_endpoint, "add_subject_endpoint"), request)
    }

    /// Remove a subject from a stream
    public func removeSubject(streamId: String, subject: SubjectIdentifier) async throws {
        logger.debug("Removing subject from stream \(streamId)")
        let request = RemoveSubjectRequest(stream_id: streamId, subject: subject)
        try await httpClient.removeSubject(endpoint: try await endpoint(\.remove_subject_endpoint, "remove_subject_endpoint"), request)
    }

    // MARK: - Verification (SSF 1.0 §8.1.4)

    /// Request stream verification. The transmitter responds 204 and delivers
    /// the result asynchronously as a verification event over the stream,
    /// echoing `state` for correlation.
    public func verifyStream(id: String, state: String? = nil) async throws {
        logger.info("Requesting verification for stream \(id)")
        let request = VerificationRequest(stream_id: id, state: state)
        try await httpClient.verifyStream(endpoint: try await endpoint(\.verification_endpoint, "verification_endpoint"), request)
    }

    // MARK: - Event Processing

    /// Poll a stream's delivery endpoint once (RFC 8936).
    ///
    /// Successfully handled SETs are acknowledged (and failures reported via
    /// setErrs) with a follow-up ack-only request, so a crash between receipt
    /// and handling means redelivery rather than loss.
    ///
    /// - Parameter timeout: HTTP request timeout for the polling request. For
    ///   long polling (`returnImmediately: false`) pass a value that exceeds
    ///   the transmitter's hold time; the default suits immediate polls.
    @discardableResult
    public func pollEvents(
        endpoint: URL,
        maxEvents: Int = 100,
        returnImmediately: Bool = true,
        timeout: TimeAmount = SSFHTTPClient.defaultTimeout,
        handler: SSFEventHandler
    ) async throws -> PollResult {
        logger.debug("Polling events from \(endpoint)")

        let response = try await httpClient.pollEvents(endpoint: endpoint, PollRequest(
            maxEvents: maxEvents,
            returnImmediately: returnImmediately
        ), timeout: timeout)

        var acks: [String] = []
        var errs: [String: SETErrorStatus] = [:]

        for (jti, setToken) in response.sets {
            do {
                let securityEventToken = try await parseAndValidateToken(setToken)
                try await handler.handleEvent(securityEventToken)
                acks.append(jti)
            } catch {
                logger.error("Failed to process event \(jti): \(error)")
                let ssfError = error as? SSFError ?? SSFError.unknown(error)
                await handler.handleError(ssfError, token: nil)
                errs[jti] = SETErrorStatus(reporting: ssfError)
            }
        }

        // Acknowledge outcomes with an ack-only request (maxEvents: 0)
        if !acks.isEmpty || !errs.isEmpty {
            _ = try await httpClient.pollEvents(endpoint: endpoint, PollRequest(
                maxEvents: 0,
                returnImmediately: true,
                ack: acks.isEmpty ? nil : acks,
                setErrs: errs.isEmpty ? nil : errs
            ))
            logger.debug("Acknowledged \(acks.count) events, reported \(errs.count) failures")
        }

        return PollResult(
            processed: acks.count,
            failed: errs.count,
            moreAvailable: response.moreAvailable ?? false
        )
    }

    /// Poll a stream once, using its configured poll delivery endpoint
    @discardableResult
    public func pollEvents(
        stream: StreamConfiguration,
        maxEvents: Int = 100,
        returnImmediately: Bool = true,
        timeout: TimeAmount = SSFHTTPClient.defaultTimeout,
        handler: SSFEventHandler
    ) async throws -> PollResult {
        guard let delivery = stream.delivery, delivery.method == .poll,
              let endpoint = delivery.endpoint_url else {
            throw SSFError.invalidStreamConfiguration("Stream \(stream.stream_id) has no poll delivery endpoint")
        }

        return try await pollEvents(
            endpoint: endpoint,
            maxEvents: maxEvents,
            returnImmediately: returnImmediately,
            timeout: timeout,
            handler: handler
        )
    }

    /// Process a single SET token.
    ///
    /// Throws when validation or handling fails so that delivery layers can
    /// report the failure to the transmitter (RFC 8935 error responses /
    /// RFC 8936 setErrs) instead of silently acknowledging a bad SET.
    /// The handler's `handleError` is still notified before the rethrow.
    @discardableResult
    public func processSecurityEventToken(
        _ token: String,
        handler: SSFEventHandler
    ) async throws -> SecurityEventToken {
        do {
            let securityEventToken = try await parseAndValidateToken(token)
            try await handler.handleEvent(securityEventToken)
            return securityEventToken
        } catch {
            logger.error("Failed to process security event token: \(error)")
            let ssfError = error as? SSFError ?? SSFError.unknown(error)
            await handler.handleError(ssfError, token: nil)
            throw ssfError
        }
    }

    // MARK: - Discovery

    /// Get transmitter configuration
    public func getTransmitterConfiguration() async throws -> TransmitterConfiguration {
        if let cached = cachedConfiguration {
            return cached
        }

        logger.info("Fetching transmitter configuration")
        let config = try await httpClient.getConfiguration()
        cachedConfiguration = config
        return config
    }

    /// Get supported delivery methods
    public func getSupportedDeliveryMethods() async throws -> [String] {
        let config = try await getTransmitterConfiguration()
        return config.delivery_methods_supported ?? []
    }

    // MARK: - Private Methods

    /// Resolve a management endpoint from transmitter metadata
    private func endpoint(
        _ keyPath: KeyPath<TransmitterConfiguration, URL?>,
        _ name: String
    ) async throws -> URL {
        let config = try await getTransmitterConfiguration()
        guard let url = config[keyPath: keyPath] else {
            throw SSFError.missingConfiguration("Transmitter metadata has no \(name)")
        }
        return url
    }

    private func parseAndValidateToken(_ token: String) async throws -> SecurityEventToken {
        let key = try await validationKey(for: token)

        return try await jwtProcessor.parseSecurityEventToken(
            token,
            expectedIssuer: configuration.expectedIssuer,
            expectedAudience: configuration.expectedAudience,
            key: key
        )
    }

    /// Resolve the verification key for a SET. Fails closed: unless the
    /// configuration explicitly allows unverified tokens, an unresolvable
    /// key is an error, never a silent skip.
    private func validationKey(for token: String) async throws -> JWTVerificationKey? {
        if configuration.allowUnverifiedTokens {
            logger.warning("allowUnverifiedTokens is enabled; accepting SET without signature verification")
            return nil
        }

        let (header, _) = try await jwtProcessor.parseJWT(token)
        let config = try await getTransmitterConfiguration()

        guard let jwksURI = config.jwks_uri else {
            throw SSFError.missingConfiguration("Transmitter metadata has no jwks_uri; cannot verify SETs")
        }

        return try await jwksClient.verificationKey(forKeyID: header.kid, jwksURI: jwksURI)
    }

    /// Clear cached data
    public func clearCache() async {
        cachedConfiguration = nil
        await jwksClient.clearCache()
        logger.debug("Cleared all caches")
    }
}

// MARK: - Default Event Handler

/// Simple logging event handler for development and testing
public struct LoggingEventHandler: SSFEventHandler {
    private let logger = Logger(label: "SwiftSSF.LoggingEventHandler")

    public init() {}

    public func handleEvent(_ token: SecurityEventToken) async throws {
        logger.info("Received security event from \(token.payload.iss)")
        logger.debug("Event details: \(token.payload.events)")
    }

    public func handleError(_ error: SSFError, token: SecurityEventToken?) async {
        logger.error("Error processing event: \(error.localizedDescription)")
        if let token = token {
            logger.debug("Failed token issuer: \(token.payload.iss)")
        }
    }
}
