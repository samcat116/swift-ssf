import Foundation
import AsyncHTTPClient
import NIOCore
import Crypto
import Logging

/// Configuration for SSF Receiver
public struct SSFReceiverConfiguration: Sendable {
    /// The transmitter's issuer URL (used for discovery)
    public let transmitterURL: URL

    /// Authentication token for API calls.
    ///
    /// Convenience for the single-static-token case; equivalent to supplying a
    /// `StaticTokenProvider`. Ignored when `tokenProvider` is also set.
    public let authToken: String?

    /// Supplies bearer tokens for the management API (SSF 1.0 §7.1).
    ///
    /// Takes precedence over `authToken`. Plug in an OAuth 2.0
    /// client-credentials flow, token refresh, etc. When its `schemeURN` is
    /// set, the receiver validates it against the transmitter's advertised
    /// `authorization_schemes` and warns on mismatch.
    public let tokenProvider: SSFTokenProvider?

    /// Expected issuer URL (defaults to transmitterURL)
    public let expectedIssuer: URL?

    /// Expected audience identifiers
    public let expectedAudience: [String]?

    /// How the SET's `aud` claim is matched against `expectedAudience`.
    public let audienceValidation: AudienceValidation

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
        tokenProvider: SSFTokenProvider? = nil,
        expectedIssuer: URL? = nil,
        expectedAudience: [String]? = nil,
        audienceValidation: AudienceValidation = .anyOverlap,
        allowUnverifiedTokens: Bool = false,
        httpClient: HTTPClient? = nil,
        logLevel: Logger.Level = .info
    ) {
        self.transmitterURL = transmitterURL
        self.authToken = authToken
        self.tokenProvider = tokenProvider
        self.expectedIssuer = expectedIssuer ?? transmitterURL
        self.expectedAudience = expectedAudience
        self.audienceValidation = audienceValidation
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

    /// The token provider actually used for the management API, resolved from
    /// `configuration.tokenProvider` (preferred) or a `StaticTokenProvider`
    /// wrapping `configuration.authToken`.
    private let tokenProvider: SSFTokenProvider?

    private var cachedConfiguration: TransmitterConfiguration?

    /// Active `lifecycleEvents()` subscriptions, keyed by an incrementing id so
    /// they can be removed on termination.
    private var lifecycleContinuations: [Int: AsyncStream<StreamLifecycleEvent>.Continuation] = [:]
    private var nextLifecycleID = 0

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

        let resolvedProvider = configuration.tokenProvider
            ?? configuration.authToken.map { StaticTokenProvider(token: $0) }
        self.tokenProvider = resolvedProvider

        self.httpClient = SSFHTTPClient(
            baseURL: configuration.transmitterURL,
            tokenProvider: resolvedProvider,
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
        finishLifecycleObservers()
        if let client = ownedHTTPClient {
            try await client.shutdown()
        }
    }

    /// Finish all lifecycle observers so their `for await` loops end.
    private func finishLifecycleObservers() {
        for continuation in lifecycleContinuations.values {
            continuation.finish()
        }
        lifecycleContinuations.removeAll()
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

    /// Request verification and await the matching verification event.
    ///
    /// Fires a verification request, then waits for the transmitter to deliver
    /// the correlated verification event over the stream, echoing `state`. When
    /// `state` is omitted a unique value is generated so correlation is always
    /// reliable.
    ///
    /// The verification event is delivered like any other SET, so a delivery
    /// mechanism for the stream (e.g. a running `PollEventDelivery`, or the push
    /// server, or `processSecurityEventToken`) must be active to receive it —
    /// this call only correlates the result, it does not poll on its own.
    ///
    /// An event is accepted only when both the echoed `state` and the SET's
    /// stream id (its opaque `sub_id`) match, so a reused `state` across streams
    /// can't resolve to another stream's event. Transmitters that omit the
    /// stream `sub_id` on verification events won't satisfy this call.
    ///
    /// - Throws: `SSFError.verificationTimeout` if no matching event arrives
    ///   within `timeout` seconds.
    @discardableResult
    public func verifyStreamAndAwaitEvent(
        id: String,
        state: String? = nil,
        timeout: TimeInterval = 30
    ) async throws -> VerificationEvent {
        let correlationState = state ?? UUID().uuidString

        // Subscribe before firing so a fast transmitter can't deliver the
        // verification event before we're listening. The request itself is sent
        // inside the task group so that `group.cancelAll()` always tears the
        // subscription down — including when `verifyStream` throws — instead of
        // leaving a dead continuation registered on the receiver.
        let events = lifecycleEvents()

        return try await withThrowingTaskGroup(of: VerificationEvent?.self) { group in
            group.addTask {
                for await event in events {
                    // Require both the echoed state and the SET's stream id to
                    // match, so a reused state can't accept another stream's
                    // verification event (or a malformed one with no stream id).
                    if case .verified(let verification) = event.payload,
                       verification.state == correlationState,
                       event.streamID == id {
                        return verification
                    }
                }
                return nil
            }
            group.addTask {
                try? await Task.sleep(nanoseconds: UInt64(timeout * 1_000_000_000))
                return nil
            }

            defer { group.cancelAll() }

            // Now that a consumer is attached (and buffering), fire the request.
            // A failure here propagates out, and the deferred cancelAll cancels
            // the consumer task so its subscription is finished and removed.
            try await verifyStream(id: id, state: correlationState)

            let first = try await group.next() ?? nil
            if let verification = first {
                return verification
            }
            throw SSFError.verificationTimeout(
                "No verification event with state \"\(correlationState)\" for stream \(id) within \(timeout)s"
            )
        }
    }

    // MARK: - Stream Lifecycle Observation

    /// Observe framework-level stream lifecycle events (`stream-updated` and
    /// `verification`) as this receiver processes SETs.
    ///
    /// Each call returns an independent stream; every subscriber sees every
    /// event. Delivery layers such as `PollEventDelivery` use this to react to
    /// status changes automatically, and applications can use it to drive their
    /// own stream-health logic. The stream finishes when the receiver is shut
    /// down.
    public func lifecycleEvents() -> AsyncStream<StreamLifecycleEvent> {
        AsyncStream { continuation in
            let id = nextLifecycleID
            nextLifecycleID += 1
            lifecycleContinuations[id] = continuation
            continuation.onTermination = { [weak self] _ in
                guard let self else { return }
                Task { await self.removeLifecycleContinuation(id) }
            }
        }
    }

    private func removeLifecycleContinuation(_ id: Int) {
        lifecycleContinuations.removeValue(forKey: id)
    }

    /// Number of active `lifecycleEvents()` subscriptions. Test hook for
    /// verifying subscriptions are torn down and don't leak.
    internal var lifecycleSubscriberCount: Int {
        lifecycleContinuations.count
    }

    /// Extract SSF framework events from a validated SET and fan them out to all
    /// current `lifecycleEvents()` subscribers.
    private func broadcastLifecycleEvents(from token: SecurityEventToken, pollEndpoint: URL?) {
        guard !lifecycleContinuations.isEmpty else { return }

        let streamID = token.payload.sub_id?.streamIdentifier

        if let updated = try? token.payload.event(SSFEventTypes.streamUpdated, as: StreamUpdatedEvent.self) {
            emitLifecycleEvent(StreamLifecycleEvent(payload: .statusChanged(updated), streamID: streamID, pollEndpoint: pollEndpoint))
        }

        if let verification = try? token.payload.event(SSFEventTypes.verification, as: VerificationEvent.self) {
            emitLifecycleEvent(StreamLifecycleEvent(payload: .verified(verification), streamID: streamID, pollEndpoint: pollEndpoint))
        }
    }

    private func emitLifecycleEvent(_ event: StreamLifecycleEvent) {
        for continuation in lifecycleContinuations.values {
            continuation.yield(event)
        }
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
                broadcastLifecycleEvents(from: securityEventToken, pollEndpoint: endpoint)
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
            do {
                _ = try await httpClient.pollEvents(endpoint: endpoint, PollRequest(
                    maxEvents: 0,
                    returnImmediately: true,
                    ack: acks.isEmpty ? nil : acks,
                    setErrs: errs.isEmpty ? nil : errs
                ))
            } catch {
                // Surface ack failures distinctly. The ack-only request uses an
                // immediate timeout, so on long-poll streams a failure here would
                // otherwise look identical to a benign empty long-poll timeout.
                throw SSFError.acknowledgementFailed(error)
            }
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
            broadcastLifecycleEvents(from: securityEventToken, pollEndpoint: nil)
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
        validateAuthorizationScheme(against: config)
        cachedConfiguration = config
        return config
    }

    /// Warn (but don't fail) when the configured token provider declares a
    /// scheme the transmitter doesn't advertise in `authorization_schemes`
    /// (SSF 1.0 §7.1). A missing `authorization_schemes` field or a provider
    /// without a declared `schemeURN` is treated as "nothing to check".
    private func validateAuthorizationScheme(against config: TransmitterConfiguration) {
        guard let schemeURN = tokenProvider?.schemeURN,
              let advertised = config.authorization_schemes else {
            return
        }

        if !advertised.contains(where: { $0.spec_urn == schemeURN }) {
            let supported = advertised.map(\.spec_urn).joined(separator: ", ")
            logger.warning(
                "Configured authorization scheme \(schemeURN) is not among the transmitter's advertised authorization_schemes [\(supported)]"
            )
        }
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
            audienceValidation: configuration.audienceValidation,
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
