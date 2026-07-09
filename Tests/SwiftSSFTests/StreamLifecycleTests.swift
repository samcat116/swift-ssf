import XCTest
@testable import SwiftSSF
import Foundation
import Crypto
import NIO
import NIOHTTP1

/// A minimal in-process SSF transmitter used to drive lifecycle reactions:
/// serves discovery, answers verification requests with 204, and hands out
/// queued SETs from its poll endpoint.
final class MockTransmitter: @unchecked Sendable {
    private let group: EventLoopGroup
    private var channel: Channel?
    private let state: SharedState

    /// Thread-safe backing store shared with the channel handlers.
    final class SharedState: @unchecked Sendable {
        private let lock = NSLock()
        private var _queued: [String] = []
        /// SET to enqueue for delivery whenever a verification request arrives.
        private var _onVerify: String?
        private var _verifyCount = 0
        /// Bodies of ack-only poll requests (maxEvents: 0), for asserting that
        /// delivered SETs were acknowledged.
        private var _ackBodies: [String] = []

        func enqueue(_ set: String) {
            lock.lock(); defer { lock.unlock() }
            _queued.append(set)
        }

        func recordAck(_ body: String) {
            lock.lock(); defer { lock.unlock() }
            _ackBodies.append(body)
        }

        var ackBodies: [String] {
            lock.lock(); defer { lock.unlock() }
            return _ackBodies
        }

        func setOnVerify(_ set: String?) {
            lock.lock(); defer { lock.unlock() }
            _onVerify = set
        }

        var verifyCount: Int {
            lock.lock(); defer { lock.unlock() }
            return _verifyCount
        }

        /// Called by the /verify handler.
        func recordVerify() {
            lock.lock(); defer { lock.unlock() }
            _verifyCount += 1
            if let set = _onVerify { _queued.append(set) }
        }

        /// Drain and return all queued SETs.
        func drain() -> [String] {
            lock.lock(); defer { lock.unlock() }
            let out = _queued
            _queued.removeAll()
            return out
        }
    }

    init() {
        self.group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        self.state = SharedState()
    }

    var baseURL: URL {
        let port = channel?.localAddress?.port ?? 0
        return URL(string: "http://127.0.0.1:\(port)")!
    }

    func enqueue(_ set: String) { state.enqueue(set) }
    func deliverOnVerify(_ set: String?) { state.setOnVerify(set) }
    var verifyCount: Int { state.verifyCount }
    var ackBodies: [String] { state.ackBodies }

    func start() async throws {
        let state = self.state
        let bootstrap = ServerBootstrap(group: group)
            .serverChannelOption(ChannelOptions.socketOption(.so_reuseaddr), value: 1)
            .childChannelInitializer { channel in
                channel.pipeline.configureHTTPServerPipeline().flatMap {
                    channel.pipeline.addHandler(Handler(state: state))
                }
            }
        channel = try await bootstrap.bind(host: "127.0.0.1", port: 0).get()
    }

    func stop() async throws {
        try await channel?.close()
        try await group.shutdownGracefully()
    }

    /// Discovery document that points every endpoint back at this server.
    private static func configJSON(base: String) -> String {
        """
        {
          "issuer": "\(base)",
          "jwks_uri": "\(base)/jwks",
          "configuration_endpoint": "\(base)/streams",
          "status_endpoint": "\(base)/status",
          "verification_endpoint": "\(base)/verify"
        }
        """
    }

    final class Handler: ChannelInboundHandler, @unchecked Sendable {
        typealias InboundIn = HTTPServerRequestPart
        typealias OutboundOut = HTTPServerResponsePart

        private let state: SharedState
        private var head: HTTPRequestHead?
        private var body: ByteBuffer?

        init(state: SharedState) { self.state = state }

        func channelRead(context: ChannelHandlerContext, data: NIOAny) {
            switch unwrapInboundIn(data) {
            case .head(let head):
                self.head = head
                self.body = context.channel.allocator.buffer(capacity: 0)
            case .body(var buffer):
                self.body?.writeBuffer(&buffer)
            case .end:
                respond(context: context)
            }
        }

        private func respond(context: ChannelHandlerContext) {
            guard let head = head else { return }
            let base = "http://127.0.0.1:\(context.channel.localAddress?.port ?? 0)"
            let path = head.uri.split(separator: "?").first.map(String.init) ?? head.uri

            switch path {
            case "/.well-known/ssf-configuration":
                writeJSON(context: context, status: .ok, body: MockTransmitter.configJSON(base: base))

            case "/verify":
                state.recordVerify()
                writeEmpty(context: context, status: .noContent)

            case "/poll":
                // Ack-only requests (maxEvents: 0) return nothing further.
                let bodyString = body.map { String(buffer: $0) } ?? ""
                if bodyString.contains("\"maxEvents\":0") {
                    state.recordAck(bodyString)
                    writeJSON(context: context, status: .ok, body: "{\"sets\":{}}")
                    return
                }
                let sets = state.drain()
                var entries: [String] = []
                for (i, set) in sets.enumerated() {
                    entries.append("\"jti-\(i)\":\"\(set)\"")
                }
                writeJSON(context: context, status: .ok, body: "{\"sets\":{\(entries.joined(separator: ","))}}")

            default:
                writeEmpty(context: context, status: .notFound)
            }
        }

        private func writeJSON(context: ChannelHandlerContext, status: HTTPResponseStatus, body: String) {
            var headers = HTTPHeaders()
            headers.add(name: "Content-Type", value: "application/json")
            headers.add(name: "Content-Length", value: String(body.utf8.count))
            headers.add(name: "Connection", value: "close")
            context.write(wrapOutboundOut(.head(HTTPResponseHead(version: .http1_1, status: status, headers: headers))), promise: nil)
            var buffer = context.channel.allocator.buffer(capacity: body.utf8.count)
            buffer.writeString(body)
            context.write(wrapOutboundOut(.body(.byteBuffer(buffer))), promise: nil)
            context.writeAndFlush(wrapOutboundOut(.end(nil))).whenComplete { _ in context.close(promise: nil) }
        }

        private func writeEmpty(context: ChannelHandlerContext, status: HTTPResponseStatus) {
            var headers = HTTPHeaders()
            headers.add(name: "Content-Length", value: "0")
            headers.add(name: "Connection", value: "close")
            context.write(wrapOutboundOut(.head(HTTPResponseHead(version: .http1_1, status: status, headers: headers))), promise: nil)
            context.writeAndFlush(wrapOutboundOut(.end(nil))).whenComplete { _ in context.close(promise: nil) }
        }
    }
}

final class StreamLifecycleTests: XCTestCase {
    private let signingKey = P256.Signing.PrivateKey()

    /// Build a signed SET carrying a single framework event.
    private func makeSET(issuer: URL, events: [String: [String: AnyCodable]]) async throws -> String {
        let processor = JWTProcessor()
        let token = try await processor.createSecurityEventToken(
            issuer: issuer,
            audience: ["receiver"],
            events: events,
            privateKey: signingKey
        )
        return token.rawToken
    }

    private func makeReceiver(transmitter: MockTransmitter) -> SSFReceiver {
        SSFReceiver(configuration: .init(
            transmitterURL: transmitter.baseURL,
            allowUnverifiedTokens: true
        ))
    }

    // MARK: - Broadcasting

    func testBroadcastsStreamUpdatedEvent() async throws {
        let issuer = URL(string: "https://tr.example.com")!
        let receiver = SSFReceiver(configuration: .init(transmitterURL: issuer, allowUnverifiedTokens: true))

        var iterator = await receiver.lifecycleEvents().makeAsyncIterator()

        let set = try await makeSET(issuer: issuer, events: [
            SSFEventTypes.streamUpdated: ["status": AnyCodable("paused"), "reason": AnyCodable("maintenance")]
        ])
        _ = try await receiver.processSecurityEventToken(set, handler: RecordingEventHandler())

        let event = await iterator.next()
        guard case .statusChanged(let updated)? = event?.payload else {
            return XCTFail("Expected statusChanged, got \(String(describing: event?.payload))")
        }
        XCTAssertEqual(updated.status, .paused)
        XCTAssertEqual(updated.reason, "maintenance")
        XCTAssertNil(event?.pollEndpoint) // processed directly, no poll context
    }

    func testBroadcastsVerificationEvent() async throws {
        let issuer = URL(string: "https://tr.example.com")!
        let receiver = SSFReceiver(configuration: .init(transmitterURL: issuer, allowUnverifiedTokens: true))

        var iterator = await receiver.lifecycleEvents().makeAsyncIterator()

        let set = try await makeSET(issuer: issuer, events: [
            SSFEventTypes.verification: ["state": AnyCodable("abc-123")]
        ])
        _ = try await receiver.processSecurityEventToken(set, handler: RecordingEventHandler())

        let event = await iterator.next()
        guard case .verified(let verification)? = event?.payload else {
            return XCTFail("Expected verified, got \(String(describing: event?.payload))")
        }
        XCTAssertEqual(verification.state, "abc-123")
    }

    func testNonFrameworkEventIsNotBroadcast() async throws {
        let issuer = URL(string: "https://tr.example.com")!
        let receiver = SSFReceiver(configuration: .init(transmitterURL: issuer, allowUnverifiedTokens: true))

        var iterator = await receiver.lifecycleEvents().makeAsyncIterator()

        // A CAEP event carries no framework lifecycle signal.
        let caep = try await makeSET(issuer: issuer, events: [CAEPEventTypes.sessionRevoked: [:]])
        _ = try await receiver.processSecurityEventToken(caep, handler: RecordingEventHandler())

        // Then a framework event; the iterator should yield the framework one first.
        let updated = try await makeSET(issuer: issuer, events: [
            SSFEventTypes.streamUpdated: ["status": AnyCodable("disabled")]
        ])
        _ = try await receiver.processSecurityEventToken(updated, handler: RecordingEventHandler())

        let event = await iterator.next()
        guard case .statusChanged(let status)? = event?.payload else {
            return XCTFail("Expected statusChanged, got \(String(describing: event?.payload))")
        }
        XCTAssertEqual(status.status, .disabled)
    }

    // MARK: - verifyStreamAndAwaitEvent

    func testVerifyStreamAndAwaitEventReturnsCorrelatedEvent() async throws {
        let transmitter = MockTransmitter()
        try await transmitter.start()
        defer { Task { try? await transmitter.stop() } }

        let receiver = makeReceiver(transmitter: transmitter)
        let issuer = transmitter.baseURL
        let pollEndpoint = issuer.appendingPathComponent("poll")

        // The transmitter delivers a verification event echoing our state once
        // a verification request arrives.
        let state = "correlation-42"
        let verificationSET = try await makeSET(issuer: issuer, events: [
            SSFEventTypes.verification: ["state": AnyCodable(state)]
        ])
        transmitter.deliverOnVerify(verificationSET)

        // A poll loop must be running to actually receive the event.
        let poller = await receiver.startPolling(
            endpoint: pollEndpoint,
            configuration: PollDeliveryConfiguration(pollInterval: 0.1),
            eventHandler: RecordingEventHandler()
        )
        defer { Task { await poller.stop() } }

        let event = try await receiver.verifyStreamAndAwaitEvent(id: "stream-1", state: state, timeout: 10)
        XCTAssertEqual(event.state, state)
        XCTAssertEqual(transmitter.verifyCount, 1)
    }

    func testVerifyStreamAndAwaitEventTimesOut() async throws {
        let transmitter = MockTransmitter()
        try await transmitter.start()
        defer { Task { try? await transmitter.stop() } }

        let receiver = makeReceiver(transmitter: transmitter)

        // No verification event is ever delivered, so the await must time out.
        do {
            _ = try await receiver.verifyStreamAndAwaitEvent(id: "stream-1", state: "never", timeout: 0.5)
            XCTFail("Expected a verification timeout")
        } catch let error as SSFError {
            guard case .verificationTimeout = error else {
                return XCTFail("Expected .verificationTimeout, got \(error)")
            }
        }
    }

    // MARK: - PollEventDelivery auto-reaction

    func testPollDeliveryStopsOnStreamPaused() async throws {
        let transmitter = MockTransmitter()
        try await transmitter.start()
        defer { Task { try? await transmitter.stop() } }

        let receiver = makeReceiver(transmitter: transmitter)
        let issuer = transmitter.baseURL
        let pollEndpoint = issuer.appendingPathComponent("poll")

        // The first poll delivers a stream-updated(paused) event.
        transmitter.enqueue(try await makeSET(issuer: issuer, events: [
            SSFEventTypes.streamUpdated: ["status": AnyCodable("paused"), "reason": AnyCodable("rate limit")]
        ]))

        let poller = await receiver.startPolling(
            endpoint: pollEndpoint,
            configuration: PollDeliveryConfiguration(pollInterval: 0.1),
            eventHandler: RecordingEventHandler()
        )
        defer { Task { await poller.stop() } }

        // Wait for the reaction to stop the loop.
        try await waitFor(timeout: 5) { await !poller.running }

        let running = await poller.running
        let stoppedBy = await poller.stoppedByTransmitterStatus
        XCTAssertFalse(running, "Poller should stop after a paused status")
        XCTAssertEqual(stoppedBy, .paused)

        // The status SET must have been acknowledged before the poller stopped,
        // otherwise the transmitter would redeliver it and re-trigger the stop.
        let acks = transmitter.ackBodies
        XCTAssertTrue(acks.contains { $0.contains("jti-0") },
                      "Expected the stream-updated SET (jti-0) to be acked; acks=\(acks)")
    }

    func testPollDeliveryStopsOnStreamDisabled() async throws {
        let transmitter = MockTransmitter()
        try await transmitter.start()
        defer { Task { try? await transmitter.stop() } }

        let receiver = makeReceiver(transmitter: transmitter)
        let issuer = transmitter.baseURL
        let pollEndpoint = issuer.appendingPathComponent("poll")

        transmitter.enqueue(try await makeSET(issuer: issuer, events: [
            SSFEventTypes.streamUpdated: ["status": AnyCodable("disabled")]
        ]))

        let poller = await receiver.startPolling(
            endpoint: pollEndpoint,
            configuration: PollDeliveryConfiguration(pollInterval: 0.1),
            eventHandler: RecordingEventHandler()
        )
        defer { Task { await poller.stop() } }

        try await waitFor(timeout: 5) { await !poller.running }
        let stoppedBy = await poller.stoppedByTransmitterStatus
        XCTAssertEqual(stoppedBy, .disabled)
    }

    func testPollDeliveryIgnoresStatusWhenReactionDisabled() async throws {
        let transmitter = MockTransmitter()
        try await transmitter.start()
        defer { Task { try? await transmitter.stop() } }

        let receiver = makeReceiver(transmitter: transmitter)
        let issuer = transmitter.baseURL
        let pollEndpoint = issuer.appendingPathComponent("poll")

        transmitter.enqueue(try await makeSET(issuer: issuer, events: [
            SSFEventTypes.streamUpdated: ["status": AnyCodable("disabled")]
        ]))

        let poller = await receiver.startPolling(
            endpoint: pollEndpoint,
            configuration: PollDeliveryConfiguration(pollInterval: 0.1, reactToStreamStatus: false),
            eventHandler: RecordingEventHandler()
        )
        defer { Task { await poller.stop() } }

        // Give the poll loop time to receive and process the event.
        try await Task.sleep(nanoseconds: 500_000_000)
        let running = await poller.running
        let stoppedBy = await poller.stoppedByTransmitterStatus
        XCTAssertTrue(running, "Poller must keep running when reactToStreamStatus is false")
        XCTAssertNil(stoppedBy)
    }

    // MARK: - Helpers

    /// Poll a condition until it holds or the timeout elapses.
    private func waitFor(timeout: TimeInterval, _ condition: @Sendable () async -> Bool) async throws {
        let deadline = Date().addingTimeInterval(timeout)
        while Date() < deadline {
            if await condition() { return }
            try await Task.sleep(nanoseconds: 50_000_000)
        }
        XCTFail("Condition not met within \(timeout)s")
    }
}
