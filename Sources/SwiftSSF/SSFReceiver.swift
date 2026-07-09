import Foundation
import AsyncHTTPClient
import Crypto
import Logging

/// Configuration for SSF Receiver
public struct SSFReceiverConfiguration: Sendable {
    /// The transmitter's base URL
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
    
    // MARK: - Stream Management
    
    /// Create a new event stream
    public func createStream(
        audience: [String],
        eventsRequested: [String],
        delivery: DeliveryConfiguration,
        description: String? = nil
    ) async throws -> EventStream {
        logger.info("Creating new event stream")
        
        let request = CreateStreamRequest(
            aud: audience,
            events_requested: eventsRequested,
            delivery: delivery,
            description: description
        )
        
        return try await httpClient.createStream(request)
    }
    
    /// Get an existing stream
    public func getStream(id: String) async throws -> EventStream {
        return try await httpClient.getStream(id: id)
    }
    
    /// Update a stream
    public func updateStream(
        id: String,
        eventsRequested: [String]? = nil,
        delivery: DeliveryConfiguration? = nil,
        status: StreamStatus? = nil,
        description: String? = nil
    ) async throws -> EventStream {
        let request = UpdateStreamRequest(
            events_requested: eventsRequested,
            delivery: delivery,
            status: status,
            description: description
        )
        
        return try await httpClient.updateStream(id, request)
    }
    
    /// Delete a stream
    public func deleteStream(id: String) async throws {
        logger.info("Deleting stream \(id)")
        try await httpClient.deleteStream(id: id)
    }
    
    /// Get stream status
    public func getStreamStatus(id: String) async throws -> StreamStatus {
        return try await httpClient.getStreamStatus(id: id)
    }
    
    /// Add a subject to a stream
    public func addSubject(streamId: String, subject: SubjectIdentifier) async throws {
        logger.debug("Adding subject to stream \(streamId)")
        try await httpClient.addSubject(streamId: streamId, subject: subject)
    }
    
    /// Remove a subject from a stream
    public func removeSubject(streamId: String, subject: SubjectIdentifier) async throws {
        logger.debug("Removing subject from stream \(streamId)")
        try await httpClient.removeSubject(streamId: streamId, subject: subject)
    }
    
    /// Verify a stream
    public func verifyStream(id: String, state: String? = nil) async throws -> VerificationResponse {
        logger.info("Verifying stream \(id)")
        return try await httpClient.verifyStream(streamId: id, state: state)
    }
    
    // MARK: - Event Processing
    
    /// Poll for events from a stream
    public func pollEvents(
        streamId: String,
        maxEvents: Int = 100,
        handler: SSFEventHandler
    ) async throws -> Int {
        logger.debug("Polling events from stream \(streamId)")
        
        let response = try await httpClient.pollEvents(streamId: streamId, maxEvents: maxEvents)
        var processedEvents = 0
        var processedEventIds: [String] = []
        
        for setToken in response.sets {
            do {
                let securityEventToken = try await parseAndValidateToken(setToken)
                try await handler.handleEvent(securityEventToken)
                processedEvents += 1
                processedEventIds.append(securityEventToken.payload.jti)
            } catch {
                logger.error("Failed to process event: \(error)")
                let ssfError = error as? SSFError ?? SSFError.unknown(error)
                await handler.handleError(ssfError, token: nil)
            }
        }
        
        // Acknowledge processed events
        if !processedEventIds.isEmpty {
            try await httpClient.acknowledgeEvents(streamId: streamId, eventIds: processedEventIds)
            logger.debug("Acknowledged \(processedEventIds.count) events")
        }
        
        return processedEvents
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
    
    /// Get supported events from transmitter
    public func getSupportedEvents() async throws -> [String] {
        let config = try await getTransmitterConfiguration()
        return config.events_supported ?? []
    }
    
    /// Get supported delivery methods
    public func getSupportedDeliveryMethods() async throws -> [String] {
        let config = try await getTransmitterConfiguration()
        return config.delivery_methods_supported
    }
    
    // MARK: - Private Methods
    
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

        return try await jwksClient.verificationKey(forKeyID: header.kid, jwksURI: config.jwks_uri)
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