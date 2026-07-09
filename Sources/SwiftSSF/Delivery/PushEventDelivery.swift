import Foundation
import NIO
import NIOHTTP1
import NIOFoundationCompat
import Logging

/// Configuration for push-based event delivery server (RFC 8935)
public struct PushDeliveryConfiguration: Sendable {
    /// Port to listen on
    public let port: Int

    /// Host to bind to
    public let host: String

    /// Path for the webhook endpoint
    public let webhookPath: String

    /// Maximum request body size in bytes
    public let maxBodySize: Int

    /// Request timeout in seconds
    public let requestTimeout: TimeInterval

    /// Expected Authorization header value. When set, requests whose
    /// Authorization header doesn't match are rejected with 401.
    /// RFC 8935 strongly recommends authenticating transmitters.
    public let expectedAuthHeader: String?

    public init(
        port: Int = 8080,
        host: String = "0.0.0.0",
        webhookPath: String = "/ssf/events",
        maxBodySize: Int = 1024 * 1024, // 1MB
        requestTimeout: TimeInterval = 30.0,
        expectedAuthHeader: String? = nil
    ) {
        self.port = port
        self.host = host
        self.webhookPath = webhookPath
        self.maxBodySize = maxBodySize
        self.requestTimeout = requestTimeout
        self.expectedAuthHeader = expectedAuthHeader
    }
}

/// Push-based event delivery server implementing RFC 8935
/// (Push-Based Security Event Token Delivery Using HTTP).
public actor PushEventDelivery {
    private let receiver: SSFReceiver
    private let configuration: PushDeliveryConfiguration
    private let eventHandler: SSFEventHandler
    private let logger = Logger(label: "SwiftSSF.PushEventDelivery")

    private let eventLoopGroup: EventLoopGroup
    /// Set when this instance created the group and must shut it down
    private let ownedEventLoopGroup: EventLoopGroup?
    private var serverChannel: Channel?

    public init(
        receiver: SSFReceiver,
        configuration: PushDeliveryConfiguration = PushDeliveryConfiguration(),
        eventHandler: SSFEventHandler,
        eventLoopGroup: EventLoopGroup? = nil
    ) {
        self.receiver = receiver
        self.configuration = configuration
        self.eventHandler = eventHandler
        if let eventLoopGroup = eventLoopGroup {
            self.eventLoopGroup = eventLoopGroup
            self.ownedEventLoopGroup = nil
        } else {
            let group = MultiThreadedEventLoopGroup(numberOfThreads: System.coreCount)
            self.eventLoopGroup = group
            self.ownedEventLoopGroup = group
        }
    }

    deinit {
        ownedEventLoopGroup?.shutdownGracefully { _ in }
    }

    /// Start the push delivery server
    public func start() async throws {
        guard serverChannel == nil else {
            logger.warning("Push delivery server is already running")
            return
        }

        logger.info("Starting push delivery server on \(configuration.host):\(configuration.port)")

        let receiver = self.receiver
        let configuration = self.configuration
        let eventHandler = self.eventHandler

        let bootstrap = ServerBootstrap(group: eventLoopGroup)
            .serverChannelOption(ChannelOptions.backlog, value: 256)
            .serverChannelOption(ChannelOptions.socketOption(.so_reuseaddr), value: 1)
            .childChannelInitializer { channel in
                channel.pipeline.configureHTTPServerPipeline().flatMap {
                    channel.pipeline.addHandler(
                        SSFWebhookHandler(
                            receiver: receiver,
                            configuration: configuration,
                            eventHandler: eventHandler
                        )
                    )
                }
            }
            .childChannelOption(ChannelOptions.socketOption(.so_reuseaddr), value: 1)
            .childChannelOption(ChannelOptions.maxMessagesPerRead, value: 1)

        do {
            serverChannel = try await bootstrap.bind(host: configuration.host, port: configuration.port).get()
            logger.info("Push delivery server started successfully")
        } catch {
            logger.error("Failed to start push delivery server: \(error)")
            throw SSFError.serverError("Failed to start server: \(error.localizedDescription)")
        }
    }

    /// Stop the push delivery server
    public func stop() async throws {
        guard let channel = serverChannel else {
            logger.warning("Push delivery server is not running")
            return
        }

        logger.info("Stopping push delivery server")

        try await channel.close()
        serverChannel = nil

        logger.info("Push delivery server stopped")
    }

    /// Get the server's listening address
    public var localAddress: SocketAddress? {
        return serverChannel?.localAddress
    }

    /// Check if the server is running
    public var isRunning: Bool {
        return serverChannel != nil
    }
}

/// HTTP handler for RFC 8935 SET delivery requests
final class SSFWebhookHandler: ChannelInboundHandler {
    typealias InboundIn = HTTPServerRequestPart
    typealias OutboundOut = HTTPServerResponsePart

    private enum State {
        case idle
        case collecting(ByteBuffer)
        /// A response has already been sent for this request; drain the rest
        case done
    }

    private let receiver: SSFReceiver
    private let configuration: PushDeliveryConfiguration
    private let eventHandler: SSFEventHandler
    private let logger = Logger(label: "SwiftSSF.WebhookHandler")

    private var state: State = .idle

    init(
        receiver: SSFReceiver,
        configuration: PushDeliveryConfiguration,
        eventHandler: SSFEventHandler
    ) {
        self.receiver = receiver
        self.configuration = configuration
        self.eventHandler = eventHandler
    }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        let part = unwrapInboundIn(data)

        switch part {
        case .head(let head):
            handleRequestHead(context: context, head: head)

        case .body(let buffer):
            handleRequestBody(context: context, buffer: buffer)

        case .end:
            handleRequestEnd(context: context)
        }
    }

    private func handleRequestHead(context: ChannelHandlerContext, head: HTTPRequestHead) {
        // Validate request path
        guard head.uri == configuration.webhookPath else {
            reject(context: context, status: .notFound, err: "invalid_request", description: "Unknown path")
            return
        }

        // Validate HTTP method
        guard head.method == .POST else {
            reject(context: context, status: .methodNotAllowed, err: "invalid_request", description: "SET delivery uses POST")
            return
        }

        // Authenticate the transmitter if configured
        if let expectedAuth = configuration.expectedAuthHeader {
            guard head.headers.first(name: "Authorization") == expectedAuth else {
                reject(context: context, status: .unauthorized, err: "authentication_failed",
                       description: "Missing or invalid Authorization header")
                return
            }
        }

        // RFC 8935 §2.1: the SET is the entire request body, delivered with
        // Content-Type application/secevent+jwt
        let contentType = head.headers.first(name: "Content-Type")?.lowercased() ?? ""
        guard contentType.hasPrefix("application/secevent+jwt") else {
            reject(context: context, status: .badRequest, err: "invalid_request",
                   description: "Content-Type must be application/secevent+jwt")
            return
        }

        state = .collecting(context.channel.allocator.buffer(capacity: 0))
    }

    private func handleRequestBody(context: ChannelHandlerContext, buffer: ByteBuffer) {
        guard case .collecting(var body) = state else { return }

        // Check body size limit
        if body.readableBytes + buffer.readableBytes > configuration.maxBodySize {
            reject(context: context, status: .payloadTooLarge, err: "invalid_request",
                   description: "Request body too large")
            return
        }

        var buffer = buffer
        body.writeBuffer(&buffer)
        state = .collecting(body)
    }

    private func handleRequestEnd(context: ChannelHandlerContext) {
        guard case .collecting(let body) = state else {
            // Request was already rejected during head/body handling
            state = .idle
            return
        }
        state = .done

        let token = String(buffer: body).trimmingCharacters(in: .whitespacesAndNewlines)
        guard !token.isEmpty else {
            sendResponse(context: context, status: .badRequest,
                         error: SETErrorStatus(err: "invalid_request", description: "Empty request body"))
            return
        }

        let receiver = self.receiver
        let eventHandler = self.eventHandler
        let eventLoop = context.eventLoop
        let promise = eventLoop.makePromise(of: SETErrorStatus?.self)

        promise.completeWithTask {
            do {
                try await receiver.processSecurityEventToken(token, handler: eventHandler)
                return nil
            } catch {
                return SETErrorStatus(reporting: error)
            }
        }

        promise.futureResult.whenComplete { [weak self] result in
            guard let self = self else { return }
            switch result {
            case .success(nil):
                self.sendResponse(context: context, status: .accepted, error: nil)
            case .success(let error):
                self.sendResponse(context: context, status: .badRequest, error: error)
            case .failure:
                self.sendResponse(context: context, status: .badRequest,
                                  error: SETErrorStatus(err: "invalid_request", description: "Failed to process SET"))
            }
        }
    }

    private func reject(
        context: ChannelHandlerContext,
        status: HTTPResponseStatus,
        err: String,
        description: String
    ) {
        state = .done
        sendResponse(context: context, status: status, error: SETErrorStatus(err: err, description: description))
    }

    /// Send a 202 (error == nil) or an RFC 8935 JSON error response
    private func sendResponse(
        context: ChannelHandlerContext,
        status: HTTPResponseStatus,
        error: SETErrorStatus?
    ) {
        guard context.eventLoop.inEventLoop else {
            context.eventLoop.execute { self.sendResponse(context: context, status: status, error: error) }
            return
        }

        var headers = HTTPHeaders()
        headers.add(name: "Connection", value: "close")

        var body: ByteBuffer?
        if let error = error, let encoded = try? JSONEncoder().encode(error) {
            headers.add(name: "Content-Type", value: "application/json")
            headers.add(name: "Content-Length", value: String(encoded.count))
            body = context.channel.allocator.buffer(bytes: encoded)
        } else {
            headers.add(name: "Content-Length", value: "0")
        }

        let responseHead = HTTPResponseHead(version: .http1_1, status: status, headers: headers)
        context.write(wrapOutboundOut(.head(responseHead)), promise: nil)

        if let body = body {
            context.write(wrapOutboundOut(.body(.byteBuffer(body))), promise: nil)
        }

        context.writeAndFlush(wrapOutboundOut(.end(nil))).whenComplete { _ in
            context.close(promise: nil)
        }
    }

    func errorCaught(context: ChannelHandlerContext, error: Error) {
        logger.error("Webhook handler error: \(error)")
        context.close(promise: nil)
    }
}

// MARK: - Convenience Extensions

extension SSFReceiver {
    /// Start a push delivery server
    public func startPushServer(
        configuration: PushDeliveryConfiguration = PushDeliveryConfiguration(),
        eventHandler: SSFEventHandler,
        eventLoopGroup: EventLoopGroup? = nil
    ) async throws -> PushEventDelivery {
        let pushService = PushEventDelivery(
            receiver: self,
            configuration: configuration,
            eventHandler: eventHandler,
            eventLoopGroup: eventLoopGroup
        )

        try await pushService.start()
        return pushService
    }
}

/// Multi-endpoint push server for handling multiple streams
public actor MultiStreamPushServer {
    private let eventLoopGroup: EventLoopGroup
    /// Set when this instance created the group and must shut it down
    private let ownedEventLoopGroup: EventLoopGroup?
    private var pushServers: [String: PushEventDelivery] = [:]
    private let logger = Logger(label: "SwiftSSF.MultiStreamPushServer")

    public init(eventLoopGroup: EventLoopGroup? = nil) {
        if let eventLoopGroup = eventLoopGroup {
            self.eventLoopGroup = eventLoopGroup
            self.ownedEventLoopGroup = nil
        } else {
            let group = MultiThreadedEventLoopGroup(numberOfThreads: System.coreCount)
            self.eventLoopGroup = group
            self.ownedEventLoopGroup = group
        }
    }

    deinit {
        ownedEventLoopGroup?.shutdownGracefully { _ in }
    }

    /// Add a push server for a specific stream
    public func addStream(
        _ streamId: String,
        receiver: SSFReceiver,
        configuration: PushDeliveryConfiguration,
        eventHandler: SSFEventHandler
    ) async throws {
        if pushServers[streamId] != nil {
            logger.warning("Stream \(streamId) already has a push server")
            return
        }

        let pushService = PushEventDelivery(
            receiver: receiver,
            configuration: configuration,
            eventHandler: eventHandler,
            eventLoopGroup: eventLoopGroup
        )

        try await pushService.start()
        pushServers[streamId] = pushService

        logger.info("Added push server for stream \(streamId) on port \(configuration.port)")
    }

    /// Remove a push server for a stream
    public func removeStream(_ streamId: String) async throws {
        guard let pushService = pushServers[streamId] else {
            logger.warning("Stream \(streamId) does not have a push server")
            return
        }

        try await pushService.stop()
        pushServers.removeValue(forKey: streamId)

        logger.info("Removed push server for stream \(streamId)")
    }

    /// Stop all push servers
    public func stopAll() async throws {
        logger.info("Stopping all push servers")

        for (streamId, pushService) in pushServers {
            try await pushService.stop()
            logger.debug("Stopped push server for stream \(streamId)")
        }

        pushServers.removeAll()
    }

    /// Get status of all push servers
    public func getStatus() async -> [String: Bool] {
        var status: [String: Bool] = [:]

        for (streamId, pushService) in pushServers {
            status[streamId] = await pushService.isRunning
        }

        return status
    }
}
