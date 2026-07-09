import XCTest
@testable import SwiftSSF
import Foundation
import Crypto
import AsyncHTTPClient
import NIO
import NIOHTTP1

/// Records which events/errors reached the handler
final class RecordingEventHandler: SSFEventHandler, @unchecked Sendable {
    private let lock = NSLock()
    private var _events: [SecurityEventToken] = []
    private var _errors: [SSFError] = []

    var events: [SecurityEventToken] {
        lock.lock(); defer { lock.unlock() }
        return _events
    }

    var errors: [SSFError] {
        lock.lock(); defer { lock.unlock() }
        return _errors
    }

    func handleEvent(_ token: SecurityEventToken) async throws {
        lock.lock(); defer { lock.unlock() }
        _events.append(token)
    }

    func handleError(_ error: SSFError, token: SecurityEventToken?) async {
        lock.lock(); defer { lock.unlock() }
        _errors.append(error)
    }
}

final class PushDeliveryTests: XCTestCase {
    private let transmitterURL = URL(string: "https://transmitter.example.com")!

    /// Start a push server on an ephemeral port; caller must stop it.
    private func startServer(
        handler: RecordingEventHandler,
        expectedAuthHeader: String? = nil
    ) async throws -> (server: PushEventDelivery, port: Int) {
        let receiver = SSFReceiver(configuration: .init(
            transmitterURL: transmitterURL,
            allowUnverifiedTokens: true
        ))
        let server = PushEventDelivery(
            receiver: receiver,
            configuration: PushDeliveryConfiguration(
                port: 0,
                host: "127.0.0.1",
                webhookPath: "/ssf/events",
                expectedAuthHeader: expectedAuthHeader
            ),
            eventHandler: handler
        )
        try await server.start()
        guard let port = await server.localAddress?.port else {
            throw SSFError.serverError("Server has no bound port")
        }
        return (server, port)
    }

    private func makeValidSET() async throws -> String {
        let processor = JWTProcessor()
        let token = try await processor.createSecurityEventToken(
            issuer: transmitterURL,
            audience: ["receiver"],
            events: ["https://schemas.openid.net/secevent/ssf/event-type/verification": [:]],
            privateKey: P256.Signing.PrivateKey()
        )
        return token.rawToken
    }

    private struct Response {
        let status: UInt
        let contentType: String?
        let body: String
    }

    private func post(
        port: Int,
        path: String = "/ssf/events",
        contentType: String = "application/secevent+jwt",
        authorization: String? = nil,
        body: String
    ) async throws -> Response {
        let client = HTTPClient(eventLoopGroupProvider: .singleton)
        do {
            var request = HTTPClientRequest(url: "http://127.0.0.1:\(port)\(path)")
            request.method = .POST
            request.headers.add(name: "Content-Type", value: contentType)
            request.headers.add(name: "Accept", value: "application/json")
            if let authorization = authorization {
                request.headers.add(name: "Authorization", value: authorization)
            }
            request.body = .bytes(ByteBuffer(string: body))

            let response = try await client.execute(request, timeout: .seconds(10))
            let bodyBuffer = try await response.body.collect(upTo: 1024 * 1024)
            try await client.shutdown()
            return Response(
                status: response.status.code,
                contentType: response.headers.first(name: "Content-Type"),
                body: String(buffer: bodyBuffer)
            )
        } catch {
            try? await client.shutdown()
            throw error
        }
    }

    // MARK: - Tests

    func testValidSETReturns202() async throws {
        let handler = RecordingEventHandler()
        let (server, port) = try await startServer(handler: handler)

        let response = try await post(port: port, body: try await makeValidSET())

        XCTAssertEqual(response.status, 202)
        XCTAssertTrue(response.body.isEmpty)
        XCTAssertEqual(handler.events.count, 1)

        try await server.stop()
    }

    func testInvalidSETReturns400WithErrorBody() async throws {
        let handler = RecordingEventHandler()
        let (server, port) = try await startServer(handler: handler)

        let response = try await post(port: port, body: "not-a-jwt")

        XCTAssertEqual(response.status, 400)
        XCTAssertEqual(response.contentType, "application/json")

        let error = try JSONDecoder().decode(PushErrorResponse.self, from: Data(response.body.utf8))
        XCTAssertEqual(error.err, "invalid_request")
        XCTAssertTrue(handler.events.isEmpty)

        try await server.stop()
    }

    func testWrongContentTypeRejected() async throws {
        let handler = RecordingEventHandler()
        let (server, port) = try await startServer(handler: handler)
        let set = try await makeValidSET()

        // The old implementation expected {"SET": ...} JSON; RFC 8935 requires
        // the raw SET body with application/secevent+jwt
        let response = try await post(
            port: port,
            contentType: "application/json",
            body: "{\"SET\": \"\(set)\"}"
        )

        XCTAssertEqual(response.status, 400)
        XCTAssertTrue(handler.events.isEmpty)

        try await server.stop()
    }

    func testUnauthorizedRequestIsNotProcessed() async throws {
        let handler = RecordingEventHandler()
        let (server, port) = try await startServer(handler: handler, expectedAuthHeader: "Bearer secret")
        let set = try await makeValidSET()

        let response = try await post(port: port, authorization: "Bearer wrong", body: set)

        XCTAssertEqual(response.status, 401)
        let error = try JSONDecoder().decode(PushErrorResponse.self, from: Data(response.body.utf8))
        XCTAssertEqual(error.err, "authentication_failed")

        // Regression: the old handler kept processing the SET after sending 401
        XCTAssertTrue(handler.events.isEmpty)
        XCTAssertTrue(handler.errors.isEmpty)

        try await server.stop()
    }

    func testAuthorizedRequestIsProcessed() async throws {
        let handler = RecordingEventHandler()
        let (server, port) = try await startServer(handler: handler, expectedAuthHeader: "Bearer secret")
        let set = try await makeValidSET()

        let response = try await post(port: port, authorization: "Bearer secret", body: set)

        XCTAssertEqual(response.status, 202)
        XCTAssertEqual(handler.events.count, 1)

        try await server.stop()
    }

    func testWrongPathRejected() async throws {
        let handler = RecordingEventHandler()
        let (server, port) = try await startServer(handler: handler)

        let response = try await post(port: port, path: "/other", body: try await makeValidSET())

        XCTAssertEqual(response.status, 404)
        XCTAssertTrue(handler.events.isEmpty)

        try await server.stop()
    }

    func testErrorCodeMapping() {
        XCTAssertEqual(SSFWebhookHandler.errorResponse(for: SSFError.signatureVerificationFailed).err, "invalid_key")
        XCTAssertEqual(SSFWebhookHandler.errorResponse(for: SSFError.verificationKeyUnavailable("x")).err, "invalid_key")
        XCTAssertEqual(
            SSFWebhookHandler.errorResponse(for: SSFError.invalidIssuer(expected: "a", actual: "b")).err,
            "invalid_issuer")
        XCTAssertEqual(
            SSFWebhookHandler.errorResponse(for: SSFError.invalidAudience(expected: ["a"], actual: nil)).err,
            "invalid_audience")
        XCTAssertEqual(SSFWebhookHandler.errorResponse(for: SSFError.invalidJWT("x")).err, "invalid_request")
    }
}
