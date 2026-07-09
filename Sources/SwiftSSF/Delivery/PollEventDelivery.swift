import Foundation
import Logging

/// Configuration for poll-based event delivery (RFC 8936)
public struct PollDeliveryConfiguration: Sendable {
    /// Polling interval in seconds (skipped while the transmitter reports
    /// more events available)
    public let pollInterval: TimeInterval

    /// Maximum number of events to fetch per poll
    public let maxEventsPerPoll: Int

    /// Whether the transmitter should respond immediately even when no
    /// events are available. `false` enables long polling (the RFC 8936
    /// default); make sure the HTTP client timeout accommodates it.
    public let returnImmediately: Bool

    /// Maximum number of poll errors before stopping
    public let maxConsecutiveErrors: Int

    /// Backoff strategy for errors
    public let errorBackoffStrategy: BackoffStrategy

    /// Whether to continue polling after errors
    public let continueOnError: Bool

    /// React to `stream-updated` events for this stream: pause polling while the
    /// transmitter reports the stream `paused` or `disabled`, and resume when it
    /// goes back to `enabled`. Avoids hammering a dead stream. Defaults to
    /// `true`.
    public let reactToStreamStatus: Bool

    public init(
        pollInterval: TimeInterval = 30.0,
        maxEventsPerPoll: Int = 100,
        returnImmediately: Bool = true,
        maxConsecutiveErrors: Int = 5,
        errorBackoffStrategy: BackoffStrategy = .exponential(base: 2.0, maxDelay: 300.0, multiplier: 1.0),
        continueOnError: Bool = true,
        reactToStreamStatus: Bool = true
    ) {
        self.pollInterval = pollInterval
        self.maxEventsPerPoll = maxEventsPerPoll
        self.returnImmediately = returnImmediately
        self.maxConsecutiveErrors = maxConsecutiveErrors
        self.errorBackoffStrategy = errorBackoffStrategy
        self.continueOnError = continueOnError
        self.reactToStreamStatus = reactToStreamStatus
    }
}

/// Backoff strategies for error handling
public enum BackoffStrategy: Sendable {
    /// No backoff - retry immediately
    case none

    /// Fixed delay between retries
    case fixed(delay: TimeInterval)

    /// Exponential backoff
    case exponential(base: Double, maxDelay: TimeInterval, multiplier: Double)

    /// Linear backoff
    case linear(increment: TimeInterval, maxDelay: TimeInterval)

    /// Calculate delay for given attempt number
    func delay(for attempt: Int) -> TimeInterval {
        switch self {
        case .none:
            return 0
        case .fixed(let delay):
            return delay
        case .exponential(let base, let maxDelay, let multiplier):
            let delay = multiplier * pow(base, Double(attempt))
            return min(delay, maxDelay)
        case .linear(let increment, let maxDelay):
            let delay = increment * Double(attempt)
            return min(delay, maxDelay)
        }
    }
}

/// Poll-based event delivery service
public actor PollEventDelivery {
    private let receiver: SSFReceiver
    private let endpoint: URL
    private let configuration: PollDeliveryConfiguration
    private let eventHandler: SSFEventHandler
    private let logger = Logger(label: "SwiftSSF.PollEventDelivery")

    private var isRunning = false
    private var pollTask: Task<Void, Never>?
    private var statusObserverTask: Task<Void, Never>?
    private var consecutiveErrors = 0

    /// The transmitter-reported status that stopped this delivery, or nil while
    /// it is running or after a manual `stop()`.
    private var stoppedStatus: StreamStatus?

    /// - Parameter endpoint: the stream's poll delivery endpoint
    ///   (`delivery.endpoint_url` from the stream configuration)
    public init(
        receiver: SSFReceiver,
        endpoint: URL,
        configuration: PollDeliveryConfiguration = PollDeliveryConfiguration(),
        eventHandler: SSFEventHandler
    ) {
        self.receiver = receiver
        self.endpoint = endpoint
        self.configuration = configuration
        self.eventHandler = eventHandler
    }

    /// Start polling for events
    public func start() async {
        guard !isRunning else {
            logger.warning("Poll delivery is already running")
            return
        }

        isRunning = true
        stoppedStatus = nil
        consecutiveErrors = 0

        logger.info("Starting poll-based event delivery from \(endpoint)")

        // Subscribe to lifecycle events before starting the poll loop so the
        // observer can't miss a status change the very first poll delivers.
        if configuration.reactToStreamStatus {
            let events = await receiver.lifecycleEvents()
            statusObserverTask = Task {
                await observeStreamStatus(events)
            }
        }

        pollTask = Task {
            await runPollingLoop()
        }
    }

    /// Stop polling for events
    public func stop() async {
        guard isRunning else {
            logger.warning("Poll delivery is not running")
            return
        }

        logger.info("Stopping poll-based event delivery from \(endpoint)")
        stoppedStatus = nil
        teardown()
    }

    /// Cancel the poll loop and status observer. Leaves `stoppedStatus` intact
    /// so callers can tell an auto-stop from a manual one.
    private func teardown() {
        isRunning = false
        pollTask?.cancel()
        pollTask = nil
        statusObserverTask?.cancel()
        statusObserverTask = nil
    }

    /// Check if polling is currently running
    public var running: Bool {
        return isRunning
    }

    /// The transmitter-reported status (`paused`/`disabled`) that caused this
    /// delivery to stop itself, or nil while running or after a manual `stop()`.
    /// Poll delivery can't observe a later re-enable once it has stopped, so an
    /// application that wants to resume should re-check the stream status and
    /// call `start()` again.
    public var stoppedByTransmitterStatus: StreamStatus? {
        return stoppedStatus
    }

    /// Get current consecutive error count
    public var errorCount: Int {
        return consecutiveErrors
    }

    // MARK: - Private Methods

    private func runPollingLoop() async {
        while isRunning && !Task.isCancelled {
            do {
                let result = try await receiver.pollEvents(
                    endpoint: endpoint,
                    maxEvents: configuration.maxEventsPerPoll,
                    returnImmediately: configuration.returnImmediately,
                    handler: eventHandler
                )

                // Reset error count on successful poll
                if consecutiveErrors > 0 {
                    logger.info("Polling recovered after \(consecutiveErrors) consecutive errors")
                    consecutiveErrors = 0
                }

                if result.processed > 0 || result.failed > 0 {
                    logger.debug("Poll cycle processed \(result.processed) events, \(result.failed) failures")
                }

                // The status observer may have requested a graceful stop while
                // this poll was handling/acking its SETs. Exit now the ack is
                // done, without polling again.
                if !isRunning { break }

                // Drain immediately while the transmitter has more events
                if result.moreAvailable {
                    continue
                }

                // Wait for next poll interval
                try await Task.sleep(nanoseconds: UInt64(configuration.pollInterval * 1_000_000_000))

            } catch is CancellationError {
                break
            } catch {
                // A manual stop() cancels the in-flight poll; the HTTP client
                // surfaces that as a wrapped error. Treat only genuine
                // cancellation as a clean exit. A status-triggered stop clears
                // isRunning without cancelling, so a real ack failure there must
                // still be reported, not swallowed.
                if Task.isCancelled {
                    break
                }

                consecutiveErrors += 1
                let ssfError = error as? SSFError ?? SSFError.unknown(error)

                logger.error("Poll error (\(consecutiveErrors)/\(configuration.maxConsecutiveErrors)): \(ssfError.localizedDescription)")

                // Notify error handler
                await eventHandler.handleError(ssfError, token: nil)

                // Check if we should stop due to too many errors
                if consecutiveErrors >= configuration.maxConsecutiveErrors {
                    if configuration.continueOnError {
                        logger.warning("Maximum consecutive errors reached, but continuing due to configuration")
                        consecutiveErrors = 0  // Reset to avoid infinite error state
                    } else {
                        logger.error("Maximum consecutive errors reached, stopping poll delivery")
                        await stop()
                        break
                    }
                }

                // Apply backoff strategy
                let backoffDelay = configuration.errorBackoffStrategy.delay(for: consecutiveErrors)
                if backoffDelay > 0 {
                    logger.debug("Applying backoff delay of \(backoffDelay) seconds")
                    try? await Task.sleep(nanoseconds: UInt64(backoffDelay * 1_000_000_000))
                }
            }
        }

        logger.info("Poll delivery loop ended for \(endpoint)")
    }

    /// Watch the receiver's lifecycle events and stop polling when the
    /// transmitter reports this stream `paused` or `disabled`, so we don't keep
    /// hitting a stream that won't deliver events.
    private func observeStreamStatus(_ events: AsyncStream<StreamLifecycleEvent>) async {
        for await event in events {
            if Task.isCancelled || !isRunning { break }

            // Only react to status changes delivered on our own poll endpoint.
            guard event.pollEndpoint == endpoint,
                  case .statusChanged(let updated) = event.payload else {
                continue
            }

            switch updated.status {
            case .paused, .disabled:
                let detail = updated.reason.map { " (\($0))" } ?? ""
                logger.info("Transmitter reported stream \(updated.status.rawValue)\(detail); stopping polling for \(endpoint)")
                stoppedStatus = updated.status
                // Request a graceful stop rather than cancelling the in-flight
                // poll: the SET carrying this status is broadcast before it is
                // handled and acked, so cancelling now would abort its ack and
                // let the transmitter redeliver it. Clearing isRunning makes the
                // poll loop exit after its current cycle completes.
                isRunning = false
                return
            case .enabled:
                continue  // already polling; nothing to do
            }
        }
    }
}

/// Convenience extensions for common polling scenarios
extension SSFReceiver {
    /// Start a polling service for a stream's poll delivery endpoint
    public func startPolling(
        endpoint: URL,
        configuration: PollDeliveryConfiguration = PollDeliveryConfiguration(),
        eventHandler: SSFEventHandler
    ) async -> PollEventDelivery {
        let pollService = PollEventDelivery(
            receiver: self,
            endpoint: endpoint,
            configuration: configuration,
            eventHandler: eventHandler
        )

        await pollService.start()
        return pollService
    }

    /// Start a polling service for a stream, using its configured poll endpoint
    public func startPolling(
        stream: StreamConfiguration,
        configuration: PollDeliveryConfiguration = PollDeliveryConfiguration(),
        eventHandler: SSFEventHandler
    ) async throws -> PollEventDelivery {
        guard let delivery = stream.delivery, delivery.method == .poll,
              let endpoint = delivery.endpoint_url else {
            throw SSFError.invalidStreamConfiguration("Stream \(stream.stream_id) has no poll delivery endpoint")
        }

        return await startPolling(
            endpoint: endpoint,
            configuration: configuration,
            eventHandler: eventHandler
        )
    }
}

/// Multi-stream poll manager
public actor MultiStreamPollManager {
    private var pollServices: [String: PollEventDelivery] = [:]
    private let logger = Logger(label: "SwiftSSF.MultiStreamPollManager")

    public init() {}

    /// Add a stream to be polled
    public func addStream(
        _ streamId: String,
        endpoint: URL,
        receiver: SSFReceiver,
        configuration: PollDeliveryConfiguration = PollDeliveryConfiguration(),
        eventHandler: SSFEventHandler
    ) async {
        if pollServices[streamId] != nil {
            logger.warning("Stream \(streamId) is already being polled")
            return
        }

        let pollService = PollEventDelivery(
            receiver: receiver,
            endpoint: endpoint,
            configuration: configuration,
            eventHandler: eventHandler
        )

        pollServices[streamId] = pollService
        await pollService.start()

        logger.info("Added stream \(streamId) to poll manager")
    }

    /// Remove a stream from polling
    public func removeStream(_ streamId: String) async {
        guard let pollService = pollServices[streamId] else {
            logger.warning("Stream \(streamId) is not being polled")
            return
        }

        await pollService.stop()
        pollServices.removeValue(forKey: streamId)

        logger.info("Removed stream \(streamId) from poll manager")
    }

    /// Stop all polling services
    public func stopAll() async {
        logger.info("Stopping all poll services")

        for (streamId, pollService) in pollServices {
            await pollService.stop()
            logger.debug("Stopped polling for stream \(streamId)")
        }

        pollServices.removeAll()
    }

    /// Get status of all polling services
    public func getStatus() async -> [String: Bool] {
        var status: [String: Bool] = [:]

        for (streamId, pollService) in pollServices {
            status[streamId] = await pollService.running
        }

        return status
    }

    /// Get error counts for all services
    public func getErrorCounts() async -> [String: Int] {
        var errorCounts: [String: Int] = [:]

        for (streamId, pollService) in pollServices {
            errorCounts[streamId] = await pollService.errorCount
        }

        return errorCounts
    }
}
