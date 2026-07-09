# SwiftSSF

A cross-platform Swift framework for implementing [OpenID Shared Signals Framework (SSF) 1.0](https://openid.net/specs/openid-sharedsignals-framework-1_0-final.html) receivers. This framework enables Swift applications running on macOS and Linux to receive and process security events through the SSF protocol.

## Features

- 🔄 Typed models for [CAEP 1.0](https://openid.net/specs/openid-caep-1_0-final.html) and [RISC 1.0](https://openid.net/specs/openid-risc-1_0-final.html) event types, plus SSF verification and stream-updated events
- 📡 Push ([RFC 8935](https://www.rfc-editor.org/rfc/rfc8935)) and poll ([RFC 8936](https://www.rfc-editor.org/rfc/rfc8936)) event delivery
- 🔐 SET (RFC 8417) validation: mandatory signature verification (ES256/RS256), `typ` enforcement, issuer/audience checks, JWKS fetching with key-rotation handling
- 🧭 Transmitter discovery via `/.well-known/ssf-configuration`; all management calls use metadata-advertised endpoints
- 👤 RFC 9493 subject identifiers, including SSF complex subjects
- ⚡ Built on Swift-NIO for high performance

## Quick Start

```swift
import SwiftSSF

// Create an SSF receiver pointed at the transmitter's issuer URL
let receiver = SSFReceiver(configuration: .init(
    transmitterURL: URL(string: "https://transmitter.example.com")!,
    authToken: "your_auth_token",
    expectedAudience: ["your-receiver-id"]
))

// Create a stream requesting CAEP events over poll delivery
// (the transmitter supplies the poll endpoint)
let stream = try await receiver.createStream(
    eventsRequested: [CAEPEventTypes.sessionRevoked],
    delivery: DeliveryConfiguration(method: .poll)
)

// Poll it once...
let result = try await receiver.pollEvents(stream: stream, handler: LoggingEventHandler())
print("Processed \(result.processed) events")

// ...or continuously
let poller = try await receiver.startPolling(stream: stream, eventHandler: LoggingEventHandler())

// For long polling (RFC 8936), the transmitter holds the request open until
// events arrive. Disable returnImmediately and give the request a timeout that
// exceeds the transmitter's hold time; a timeout is treated as an empty poll.
let longPoller = try await receiver.startPolling(
    stream: stream,
    configuration: PollDeliveryConfiguration(
        returnImmediately: false,
        longPollTimeout: 300   // seconds; should exceed the transmitter hold time
    ),
    eventHandler: LoggingEventHandler()
)
```

For push delivery, run the built-in RFC 8935 endpoint and hand its URL to the transmitter:

```swift
let server = try await receiver.startPushServer(
    configuration: PushDeliveryConfiguration(
        port: 8080,
        webhookPath: "/ssf/events",
        expectedAuthHeader: "Bearer webhook_secret"   // strongly recommended
    ),
    eventHandler: MyEventHandler()
)
```

Handle events by conforming to `SSFEventHandler`:

```swift
struct MyEventHandler: SSFEventHandler {
    func handleEvent(_ token: SecurityEventToken) async throws {
        if let event = try token.payload.event(CAEPEventTypes.sessionRevoked, as: SessionRevokedEvent.self) {
            // terminate the subject's sessions
        }
    }

    func handleError(_ error: SSFError, token: SecurityEventToken?) async {
        // log / alert
    }
}
```

See [Sources/ExampleReceiver](./Sources/ExampleReceiver/main.swift) for a complete example including stream management, subjects, and verification.

## Security notes

- SET signatures are always verified (ES256 and RS256) against the transmitter's JWKS. `allowUnverifiedTokens` exists for tests only.
- Tokens must carry `typ: "secevent+jwt"`; ordinary JWTs are rejected.
- Configure `expectedAuthHeader` on the push server so only your transmitter can deliver events.

## Requirements

- Swift 5.9+
- macOS 10.15+ / iOS 13+ / Linux

## Installation

Add SwiftSSF to your Swift package dependencies:

```swift
dependencies: [
    .package(url: "https://github.com/samcat116/swift-ssf.git", from: "1.0.0")
]
```

## Specification coverage

| Specification | Status |
| --- | --- |
| SSF 1.0 Final (discovery, stream management, status, subjects, verification) | ✅ |
| RFC 8935 push delivery (receiver side) | ✅ |
| RFC 8936 poll delivery (incl. ack/setErrs, moreAvailable) | ✅ |
| RFC 8417 SET validation | ✅ |
| RFC 9493 subject identifiers (incl. complex subjects) | ✅ |
| CAEP 1.0 / RISC 1.0 event types | ✅ typed models |

## License

MIT License
