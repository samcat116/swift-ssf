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
        
        // Example 1: Create a stream for CAEP events with poll delivery
        logger.info("Example 1: Creating CAEP stream with poll delivery")
        
        let pollDeliveryConfig = DeliveryConfiguration(
            method: .poll,
            endpoint_url: URL(string: "https://your-transmitter.example.com/poll")!
        )
        
        do {
            let caepStream = try await receiver.createStream(
                audience: ["your-receiver-id"],
                eventsRequested: [
                    "https://schemas.openid.net/secevent/caep/session-revoked",
                    "https://schemas.openid.net/secevent/caep/credential-change"
                ],
                delivery: pollDeliveryConfig,
                description: "CAEP events for security monitoring"
            )
            
            logger.info("Created CAEP stream: \(caepStream.id)")
            
            // Start polling for events
            let pollService = await receiver.startPolling(
                streamId: caepStream.id,
                configuration: PollDeliveryConfiguration(pollInterval: 10.0), // Poll every 10 seconds
                eventHandler: eventHandler
            )
            
            logger.info("Started polling for CAEP events")
            
            // Example 2: Create a stream for RISC events with push delivery
            logger.info("Example 2: Creating RISC stream with push delivery")
            
            let pushDeliveryConfig = DeliveryConfiguration(
                method: .push,
                endpoint_url: URL(string: "https://your-receiver.example.com:8080/ssf/events")!,
                authorization_header: "Bearer your_webhook_auth_token"
            )
            
            let riscStream = try await receiver.createStream(
                audience: ["your-receiver-id"],
                eventsRequested: [
                    "https://schemas.openid.net/secevent/risc/account-disabled",
                    "https://schemas.openid.net/secevent/risc/credential-compromise"
                ],
                delivery: pushDeliveryConfig,
                description: "RISC events for account security"
            )
            
            logger.info("Created RISC stream: \(riscStream.id)")
            
            // Start push server for receiving events
            let pushServerConfig = PushDeliveryConfiguration(
                port: 8080,
                webhookPath: "/ssf/events",
                validateAuthorization: true,
                expectedAuthHeader: "Bearer your_webhook_auth_token"
            )
            
            let pushService = try await receiver.startPushServer(
                configuration: pushServerConfig,
                eventHandler: eventHandler
            )
            
            logger.info("Started push server on port 8080")
            
            // Example 3: Demonstrate stream management
            logger.info("Example 3: Stream management operations")
            
            // Add a subject to the CAEP stream
            let userSubject = SubjectIdentifier.simple("user@example.com")
            try await receiver.addSubject(streamId: caepStream.id, subject: userSubject)
            logger.info("Added subject to CAEP stream")
            
            // Get stream status
            let status = try await receiver.getStreamStatus(id: caepStream.id)
            logger.info("CAEP stream status: \(status)")
            
            // Verify the stream
            let verificationResult = try await receiver.verifyStream(id: caepStream.id)
            logger.info("Stream verification: \(verificationResult.status)")
            
            // Example 4: Multi-stream polling
            logger.info("Example 4: Multi-stream polling manager")
            
            let multiPollManager = MultiStreamPollManager()
            
            await multiPollManager.addStream(
                caepStream.id,
                receiver: receiver,
                configuration: PollDeliveryConfiguration(pollInterval: 15.0),
                eventHandler: eventHandler
            )
            
            logger.info("Added stream to multi-poll manager")
            
            // Run for a demo period
            logger.info("Running receiver for 60 seconds...")
            try await Task.sleep(nanoseconds: 60_000_000_000) // 60 seconds
            
            // Cleanup
            logger.info("Cleaning up...")
            
            await pollService.stop()
            try await pushService.stop()
            await multiPollManager.stopAll()
            
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
            switch subject {
            case .simple(let id):
                logger.info("👤 Subject: \(id)")
            case .complex(let complex):
                logger.info("👤 Subject: \(complex.format) = \(complex.value)")
            }
        }
        
        // Process each event in the token
        for (eventType, event) in token.payload.events {
            logger.info("🔔 Processing event type: \(eventType)")
            
            // Handle different event types
            await handleSpecificEvent(eventType: eventType, event: event)
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
    
    private func handleSpecificEvent(eventType: String, event: SecurityEvent) async {
        // Handle CAEP events
        if eventType.contains("caep") {
            if eventType.contains("session-revoked") {
                logger.info("🚪 Session revoked - terminating user sessions")
                // Implement session termination logic
            } else if eventType.contains("credential-change") {
                logger.info("🔑 Credential change detected - updating security policies")
                // Implement credential change handling
            } else if eventType.contains("device-compliance-change") {
                logger.info("📱 Device compliance changed - updating device policies")
                // Implement device compliance handling
            }
        }
        
        // Handle RISC events
        if eventType.contains("risc") {
            if eventType.contains("account-disabled") {
                logger.info("🚫 Account disabled - blocking access")
                // Implement account blocking logic
            } else if eventType.contains("credential-compromise") {
                logger.info("⚠️ Credential compromise - forcing password reset")
                // Implement credential compromise handling
            }
        }
        
        // Add more specific event handling as needed
        logger.debug("📝 Event processing completed for \(eventType)")
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
    
    // Poll for events from an existing stream
    let streamId = "your_stream_id"
    
    logger.info("Starting simple polling example")
    
    // Poll once for events
    let eventsProcessed = try await receiver.pollEvents(
        streamId: streamId,
        maxEvents: 50,
        handler: eventHandler
    )
    
    logger.info("Processed \(eventsProcessed) events")
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
    let pushService = try await receiver.startPushServer(
        configuration: PushDeliveryConfiguration(port: 8080),
        eventHandler: eventHandler
    )
    
    logger.info("Push server running on port 8080")
    
    // Keep running until interrupted
    try await Task.sleep(nanoseconds: UInt64.max)
}