import Foundation

/// Stream Configuration (SSF 1.0 §8.1.1)
public struct StreamConfiguration: Codable, Sendable {
    /// Transmitter-supplied unique identifier for the stream
    public let stream_id: String

    /// Issuer URL - identifies the transmitter
    public let iss: URL

    /// Audience - identifies the intended receiver(s).
    /// The spec allows a string or an array of strings on the wire.
    public let aud: [String]

    /// Events the transmitter can transmit
    public let events_supported: [String]?

    /// Events requested by the receiver
    public let events_requested: [String]?

    /// Events the transmitter will actually transmit (transmitter-supplied;
    /// REQUIRED in the spec, optional here to tolerate draft-era transmitters)
    public let events_delivered: [String]?

    /// Event delivery configuration
    public let delivery: DeliveryConfiguration?

    /// Minimum seconds between verification requests the transmitter accepts
    public let min_verification_interval: Int?

    /// Receiver-supplied description of the stream
    public let description: String?

    /// Seconds of inactivity after which the transmitter may shut the stream down
    public let inactivity_timeout: Int?

    public init(
        stream_id: String,
        iss: URL,
        aud: [String],
        events_supported: [String]? = nil,
        events_requested: [String]? = nil,
        events_delivered: [String]? = nil,
        delivery: DeliveryConfiguration? = nil,
        min_verification_interval: Int? = nil,
        description: String? = nil,
        inactivity_timeout: Int? = nil
    ) {
        self.stream_id = stream_id
        self.iss = iss
        self.aud = aud
        self.events_supported = events_supported
        self.events_requested = events_requested
        self.events_delivered = events_delivered
        self.delivery = delivery
        self.min_verification_interval = min_verification_interval
        self.description = description
        self.inactivity_timeout = inactivity_timeout
    }

    private enum CodingKeys: String, CodingKey {
        case stream_id, iss, aud, events_supported, events_requested,
             events_delivered, delivery, min_verification_interval,
             description, inactivity_timeout
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        self.stream_id = try container.decode(String.self, forKey: .stream_id)
        self.iss = try container.decode(URL.self, forKey: .iss)

        // "aud" may be a single string or an array of strings
        if let singleAudience = try? container.decode(String.self, forKey: .aud) {
            self.aud = [singleAudience]
        } else {
            self.aud = try container.decode([String].self, forKey: .aud)
        }

        self.events_supported = try container.decodeIfPresent([String].self, forKey: .events_supported)
        self.events_requested = try container.decodeIfPresent([String].self, forKey: .events_requested)
        self.events_delivered = try container.decodeIfPresent([String].self, forKey: .events_delivered)
        self.delivery = try container.decodeIfPresent(DeliveryConfiguration.self, forKey: .delivery)
        self.min_verification_interval = try container.decodeIfPresent(Int.self, forKey: .min_verification_interval)
        self.description = try container.decodeIfPresent(String.self, forKey: .description)
        self.inactivity_timeout = try container.decodeIfPresent(Int.self, forKey: .inactivity_timeout)
    }
}

/// Event delivery configuration
public struct DeliveryConfiguration: Codable, Sendable {
    /// Delivery method (push or poll)
    public let method: DeliveryMethod

    /// For push: the receiver's endpoint, supplied by the receiver.
    /// For poll: the transmitter's poll endpoint, supplied by the transmitter
    /// (omit when requesting a poll stream).
    public let endpoint_url: URL?

    /// Authorization header the transmitter should send with push deliveries
    public let authorization_header: String?

    public init(
        method: DeliveryMethod,
        endpoint_url: URL? = nil,
        authorization_header: String? = nil
    ) {
        self.method = method
        self.endpoint_url = endpoint_url
        self.authorization_header = authorization_header
    }
}

/// Event delivery methods
public enum DeliveryMethod: String, Codable, CaseIterable, Sendable {
    /// Push-based delivery (RFC 8935)
    case push = "urn:ietf:rfc:8935"

    /// Poll-based delivery (RFC 8936)
    case poll = "urn:ietf:rfc:8936"
}

/// Stream status (SSF 1.0 §8.1.2: enabled, paused, disabled)
public enum StreamStatus: String, Codable, CaseIterable, Sendable {
    /// The transmitter transmits events over the stream
    case enabled

    /// The transmitter holds events and does not transmit them
    case paused

    /// The transmitter neither transmits nor holds events
    case disabled
}

/// Stream status endpoint response/update body: {stream_id, status, reason?}
public struct StreamStatusResponse: Codable, Sendable {
    public let stream_id: String
    public let status: StreamStatus
    public let reason: String?

    public init(stream_id: String, status: StreamStatus, reason: String? = nil) {
        self.stream_id = stream_id
        self.status = status
        self.reason = reason
    }
}

/// Stream creation request (POST to the configuration endpoint).
/// All fields are receiver-supplied; the transmitter fills in the rest.
public struct CreateStreamRequest: Codable, Sendable {
    /// Events requested
    public let events_requested: [String]?

    /// Delivery configuration
    public let delivery: DeliveryConfiguration?

    /// Optional description
    public let description: String?

    public init(
        events_requested: [String]? = nil,
        delivery: DeliveryConfiguration? = nil,
        description: String? = nil
    ) {
        self.events_requested = events_requested
        self.delivery = delivery
        self.description = description
    }
}

/// Stream update request (PATCH to the configuration endpoint).
/// Identifies the stream in the body per SSF 1.0 §8.1.1.3.
public struct UpdateStreamRequest: Codable, Sendable {
    /// The stream to update
    public let stream_id: String

    /// Events requested (optional update)
    public let events_requested: [String]?

    /// Delivery configuration (optional update)
    public let delivery: DeliveryConfiguration?

    /// Description (optional update)
    public let description: String?

    public init(
        stream_id: String,
        events_requested: [String]? = nil,
        delivery: DeliveryConfiguration? = nil,
        description: String? = nil
    ) {
        self.stream_id = stream_id
        self.events_requested = events_requested
        self.delivery = delivery
        self.description = description
    }
}

/// Add subject request: {stream_id, subject, verified?}
public struct AddSubjectRequest: Codable, Sendable {
    /// The stream to add the subject to
    public let stream_id: String

    /// Subject to add
    public let subject: SubjectIdentifier

    /// Whether the receiver has verified its relationship with this subject
    public let verified: Bool?

    public init(stream_id: String, subject: SubjectIdentifier, verified: Bool? = nil) {
        self.stream_id = stream_id
        self.subject = subject
        self.verified = verified
    }
}

/// Remove subject request: {stream_id, subject}
public struct RemoveSubjectRequest: Codable, Sendable {
    /// The stream to remove the subject from
    public let stream_id: String

    /// Subject to remove
    public let subject: SubjectIdentifier

    public init(stream_id: String, subject: SubjectIdentifier) {
        self.stream_id = stream_id
        self.subject = subject
    }
}

/// Stream verification request: {stream_id, state?}.
///
/// The transmitter responds 204 No Content and delivers the result
/// asynchronously as a verification event
/// (https://schemas.openid.net/secevent/ssf/event-type/verification)
/// over the stream itself, echoing `state` for correlation.
public struct VerificationRequest: Codable, Sendable {
    /// The stream to verify
    public let stream_id: String

    /// Arbitrary string the transmitter must echo back in the verification event
    public let state: String?

    public init(stream_id: String, state: String? = nil) {
        self.stream_id = stream_id
        self.state = state
    }
}
