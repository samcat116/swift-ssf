import Foundation
import SwiftSSF
import Logging

/// Example SSF Receiver Application
///
/// This example demonstrates how to use SwiftSSF to create a receiver
/// that can handle both poll and push-based event delivery.

@main
struct ExampleSSFReceiver {
    static func main() async throws {
        // Configure logging
        LoggingSystem.bootstrap(StreamLogHandler.standardOutput)
        let logger = Logger(label: "ExampleSSFReceiver")

        logger.info("Starting SwiftSSF Example Receiver")

        // Configuration - replace with your actual transmitter details
        let config = SSFReceiverConfiguration(
            transmitterURL: URL(string: "https://your-transmitter.example.com")!,
            authToken: "your_auth_token_here",
            expectedAudience: ["your-receiver-id"],
            logLevel: .debug
        )

        // Create the SSF receiver
        let receiver = SSFReceiver(configuration: config)

        // Create a custom event handler
        let eventHandler = ExampleEventHandler()

        do {
            // Example 1: Create a stream for CAEP events with poll delivery.
            // For poll streams the transmitter supplies the endpoint_url.
            logger.info("Example 1: Creating CAEP stream with poll delivery")

            let caepStream = try await receiver.createStream(
                eventsRequested: [
                    CAEPEventTypes.sessionRevoked,
                    CAEPEventTypes.credentialChange,
                ],
                delivery: DeliveryConfiguration(method: .poll),
                description: "CAEP events for security monitoring"
            )

            logger.info("Created CAEP stream: \(caepStream.stream_id)")

            // Start polling for events using the transmitter-supplied endpoint
            let pollService = try await receiver.startPolling(
                stream: caepStream,
                configuration: PollDeliveryConfiguration(pollInterval: 10.0),
                eventHandler: eventHandler
            )

            logger.info("Started polling for CAEP events")

            // Example 2: Create a stream for RISC events with push delivery.
            // For push streams the receiver supplies its own endpoint.
            logger.info("Example 2: Creating RISC stream with push delivery")

            let riscStream = try await receiver.createStream(
                eventsRequested: [
                    RISCEventTypes.accountDisabled,
                    RISCEventTypes.credentialCompromise,
                ],
                delivery: DeliveryConfiguration(
                    method: .push,
                    endpoint_url: URL(string: "https://your-receiver.example.com:8080/ssf/events")!,
                    authorization_header: "Bearer your_webhook_auth_token"
                ),
                description: "RISC events for account security"
            )

            logger.info("Created RISC stream: \(riscStream.stream_id)")

            // Start push server for receiving events
            let pushService = try await receiver.startPushServer(
                configuration: PushDeliveryConfiguration(
                    port: 8080,
                    webhookPath: "/ssf/events",
                    expectedAuthHeader: "Bearer your_webhook_auth_token"
                ),
                eventHandler: eventHandler
            )

            logger.info("Started push server on port 8080")

            // Example 3: Demonstrate stream management
            logger.info("Example 3: Stream management operations")

            // Add a subject to the CAEP stream
            let userSubject = SubjectIdentifier.email("user@example.com")
            try await receiver.addSubject(streamId: caepStream.stream_id, subject: userSubject)
            logger.info("Added subject to CAEP stream")

            // Get stream status
            let status = try await receiver.getStreamStatus(id: caepStream.stream_id)
            logger.info("CAEP stream status: \(status.status)")

            // Request stream verification; the transmitter responds 204 and
            // delivers a verification event over the stream (handled by
            // ExampleEventHandler below)
            try await receiver.verifyStream(id: caepStream.stream_id, state: "example-verification")
            logger.info("Requested stream verification")

            // Example 4: Multi-stream polling
            logger.info("Example 4: Multi-stream polling manager")

            let multiPollManager = MultiStreamPollManager()

            if let pollEndpoint = caepStream.delivery?.endpoint_url {
                await multiPollManager.addStream(
                    caepStream.stream_id,
                    endpoint: pollEndpoint,
                    receiver: receiver,
                    configuration: PollDeliveryConfiguration(pollInterval: 15.0),
                    eventHandler: eventHandler
                )
                logger.info("Added stream to multi-poll manager")
            }

            // Run for a demo period
            logger.info("Running receiver for 60 seconds...")
            try await Task.sleep(nanoseconds: 60_000_000_000) // 60 seconds

            // Cleanup
            logger.info("Cleaning up...")

            await pollService.stop()
            try await pushService.stop()
            await multiPollManager.stopAll()
            try await receiver.shutdown()

            logger.info("SwiftSSF Example Receiver completed successfully")

        } catch {
            logger.error("Example failed with error: \(error)")
            throw error
        }
    }
}

/// Example event handler that processes security events
struct ExampleEventHandler: SSFEventHandler {
    private let logger = Logger(label: "ExampleEventHandler")

    func handleEvent(_ token: SecurityEventToken) async throws {
        logger.info("📨 Received security event from \(token.payload.iss)")
        logger.info("🆔 Event ID: \(token.payload.jti)")

        if let subject = token.payload.sub_id {
            logger.info("👤 Subject format: \(subject.format)")
            if let email = subject.string("email") {
                logger.info("👤 Subject email: \(email)")
            }
            if let user = subject.subject("user") {
                logger.info("👤 Complex subject user: \(user.format)")
            }
        }

        // Process each event in the token
        for eventType in token.payload.eventTypes {
            logger.info("🔔 Processing event type: \(eventType)")
            try await handleSpecificEvent(eventType: eventType, payload: token.payload)
        }

        logger.info("✅ Successfully processed security event")
    }

    func handleError(_ error: SSFError, token: SecurityEventToken?) async {
        logger.error("❌ Error processing event: \(error.localizedDescription)")

        // Handle different types of errors
        switch error {
        case .signatureVerificationFailed:
            logger.warning("🔐 Signature verification failed - possible security issue")
        case .tokenExpired:
            logger.warning("⏰ Token has expired")
        case .networkError(let underlyingError):
            logger.warning("🌐 Network error: \(underlyingError.localizedDescription)")
        case .authenticationFailed(let message):
            logger.error("🔑 Authentication failed: \(message)")
        default:
            logger.error("🚨 Unhandled error type")
        }
    }

    private func handleSpecificEvent(eventType: String, payload: SecurityEventPayload) async throws {
        switch eventType {
        case CAEPEventTypes.sessionRevoked:
            logger.info("🚪 Session revoked - terminating user sessions")
            // Implement session termination logic

        case CAEPEventTypes.credentialChange:
            if let event = try payload.event(eventType, as: CredentialChangeEvent.self) {
                logger.info("🔑 Credential change: \(event.credential_type) \(event.change_type)")
            }
            // Implement credential change handling

        case CAEPEventTypes.deviceComplianceChange:
            if let event = try payload.event(eventType, as: DeviceComplianceChangeEvent.self) {
                logger.info("📱 Device compliance: \(event.previous_status) -> \(event.current_status)")
            }
            // Implement device compliance handling

        case RISCEventTypes.accountDisabled:
            logger.info("🚫 Account disabled - blocking access")
            // Implement account blocking logic

        case RISCEventTypes.credentialCompromise:
            if let event = try payload.event(eventType, as: CredentialCompromiseEvent.self) {
                logger.info("⚠️ Credential compromise: \(event.credential_type) - forcing reset")
            }
            // Implement credential compromise handling

        case SSFEventTypes.verification:
            let event = try payload.event(eventType, as: VerificationEvent.self)
            logger.info("✔️ Stream verification event received (state: \(event?.state ?? "none"))")

        case SSFEventTypes.streamUpdated:
            if let event = try payload.event(eventType, as: StreamUpdatedEvent.self) {
                logger.info("🔄 Stream status changed to \(event.status)")
            }

        default:
            logger.debug("📝 No specific handling for \(eventType)")
        }
    }
}

/// Alternative simplified example using just polling
func simplePollExample() async throws {
    let logger = Logger(label: "SimplePollExample")

    // Simple configuration for polling
    let config = SSFReceiverConfiguration(
        transmitterURL: URL(string: "https://transmitter.example.com")!,
        authToken: "your_token"
    )

    let receiver = SSFReceiver(configuration: config)
    let eventHandler = LoggingEventHandler()

    logger.info("Starting simple polling example")

    // Poll an existing stream once, using its configured poll endpoint
    let stream = try await receiver.getStream(id: "your_stream_id")
    let result = try await receiver.pollEvents(
        stream: stream,
        maxEvents: 50,
        handler: eventHandler
    )

    logger.info("Processed \(result.processed) events (\(result.failed) failures)")
}

/// Alternative simplified example using just push delivery
func simplePushExample() async throws {
    let logger = Logger(label: "SimplePushExample")

    let config = SSFReceiverConfiguration(
        transmitterURL: URL(string: "https://transmitter.example.com")!
    )

    let receiver = SSFReceiver(configuration: config)
    let eventHandler = LoggingEventHandler()

    logger.info("Starting simple push server example")

    // Start a simple push server
    _ = try await receiver.startPushServer(
        configuration: PushDeliveryConfiguration(port: 8080),
        eventHandler: eventHandler
    )

    logger.info("Push server running on port 8080")

    // Keep running until interrupted
    try await Task.sleep(nanoseconds: UInt64.max)
}
