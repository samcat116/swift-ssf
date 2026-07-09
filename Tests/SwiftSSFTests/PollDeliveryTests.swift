import XCTest
@testable import SwiftSSF
import Foundation
import AsyncHTTPClient
import NIO
import NIOCore
import NIOHTTP1

/// Minimal HTTP server for poll tests.
///
/// It accepts connections and reads requests but, by default, never sends a
/// response — the client connection is held open until the client's own
/// request timeout fires. That reproduces an RFC 8936 long poll where the
/// transmitter holds the connection open with no events to deliver.
final class HangingPollServer {
    private let group: EventLoopGroup
    private var channel: Channel?

    init() {
        self.group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
    }

    var port: Int { channel?.localAddress?.port ?? 0 }

    func start() async throws {
        let bootstrap = ServerBootstrap(group: group)
            .serverChannelOption(ChannelOptions.backlog, value: 256)
            .serverChannelOption(ChannelOptions.socketOption(.so_reuseaddr), value: 1)
            .childChannelInitializer { channel in
                channel.pipeline.configureHTTPServerPipeline().flatMap {
                    channel.pipeline.addHandler(HangingHandler())
                }
            }
        self.channel = try await bootstrap.bind(host: "127.0.0.1", port: 0).get()
    }

    func stop() async throws {
        try? await channel?.close().get()
        try await group.shutdownGracefully()
    }
}

/// Reads the request to completion but deliberately never responds.
private final class HangingHandler: ChannelInboundHandler {
    typealias InboundIn = HTTPServerRequestPart

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        // Intentionally drop every request part and send nothing back.
        _ = unwrapInboundIn(data)
    }
}

final class PollDeliveryTests: XCTestCase {
    private let transmitterURL = URL(string: "https://transmitter.example.com")!

    private func makeReceiver() -> SSFReceiver {
        SSFReceiver(configuration: .init(
            transmitterURL: transmitterURL,
            allowUnverifiedTokens: true
        ))
    }

    /// A long-poll request whose client timeout elapses surfaces as the
    /// distinct `connectionTimeout` case, not a generic network error.
    func testLongPollTimeoutSurfacesAsConnectionTimeout() async throws {
        let server = HangingPollServer()
        try await server.start()

        let receiver = makeReceiver()
        let endpoint = URL(string: "http://127.0.0.1:\(server.port)/poll")!
        let handler = RecordingEventHandler()

        do {
            _ = try await receiver.pollEvents(
                endpoint: endpoint,
                returnImmediately: false,
                timeout: .milliseconds(300),
                handler: handler
            )
            XCTFail("Expected the long poll to time out")
        } catch let error as SSFError {
            if case .connectionTimeout = error {} else {
                XCTFail("Expected .connectionTimeout, got \(error)")
            }
        }

        try await receiver.shutdown()
        try await server.stop()
    }

    /// While long polling, repeated request timeouts are treated as empty
    /// polls: no error reaches the handler and the consecutive-error count
    /// used for backoff/stop stays at zero.
    func testPollLoopTreatsLongPollTimeoutAsEmptyPoll() async throws {
        let server = HangingPollServer()
        try await server.start()

        let receiver = makeReceiver()
        let endpoint = URL(string: "http://127.0.0.1:\(server.port)/poll")!
        let handler = RecordingEventHandler()

        let delivery = PollEventDelivery(
            receiver: receiver,
            endpoint: endpoint,
            configuration: PollDeliveryConfiguration(
                returnImmediately: false,
                longPollTimeout: 0.3,
                maxConsecutiveErrors: 2,
                continueOnError: false
            ),
            eventHandler: handler
        )

        await delivery.start()

        // Long enough for several 300ms timeouts to elapse. If timeouts were
        // treated as errors, maxConsecutiveErrors (2) with continueOnError
        // false would have stopped the loop by now.
        try await Task.sleep(nanoseconds: 1_200_000_000)

        let running = await delivery.running
        let errorCount = await delivery.errorCount

        await delivery.stop()

        XCTAssertTrue(running, "Poll loop should still be running after long-poll timeouts")
        XCTAssertEqual(errorCount, 0, "Long-poll timeouts must not count as errors")
        XCTAssertTrue(handler.errors.isEmpty, "No error should be reported to the handler on a long-poll timeout")

        try await receiver.shutdown()
        try await server.stop()
    }
}
