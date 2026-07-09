import Foundation

// MARK: - Event Type URIs

/// SSF framework event types (SSF 1.0)
public enum SSFEventTypes {
    /// Stream verification event, delivered in response to a verification request
    public static let verification = "https://schemas.openid.net/secevent/ssf/event-type/verification"

    /// Notifies the receiver that the transmitter changed the stream's status
    public static let streamUpdated = "https://schemas.openid.net/secevent/ssf/event-type/stream-updated"

    public static let all = [verification, streamUpdated]
}

/// CAEP 1.0 event types
public enum CAEPEventTypes {
    public static let sessionRevoked = "https://schemas.openid.net/secevent/caep/event-type/session-revoked"
    public static let tokenClaimsChange = "https://schemas.openid.net/secevent/caep/event-type/token-claims-change"
    public static let credentialChange = "https://schemas.openid.net/secevent/caep/event-type/credential-change"
    public static let assuranceLevelChange = "https://schemas.openid.net/secevent/caep/event-type/assurance-level-change"
    public static let deviceComplianceChange = "https://schemas.openid.net/secevent/caep/event-type/device-compliance-change"
    public static let sessionEstablished = "https://schemas.openid.net/secevent/caep/event-type/session-established"
    public static let sessionPresented = "https://schemas.openid.net/secevent/caep/event-type/session-presented"
    public static let riskLevelChange = "https://schemas.openid.net/secevent/caep/event-type/risk-level-change"

    public static let all = [
        sessionRevoked, tokenClaimsChange, credentialChange, assuranceLevelChange,
        deviceComplianceChange, sessionEstablished, sessionPresented, riskLevelChange,
    ]
}

/// RISC 1.0 event types
public enum RISCEventTypes {
    public static let accountCredentialChangeRequired = "https://schemas.openid.net/secevent/risc/event-type/account-credential-change-required"
    public static let accountPurged = "https://schemas.openid.net/secevent/risc/event-type/account-purged"
    public static let accountDisabled = "https://schemas.openid.net/secevent/risc/event-type/account-disabled"
    public static let accountEnabled = "https://schemas.openid.net/secevent/risc/event-type/account-enabled"
    public static let identifierChanged = "https://schemas.openid.net/secevent/risc/event-type/identifier-changed"
    public static let identifierRecycled = "https://schemas.openid.net/secevent/risc/event-type/identifier-recycled"
    public static let credentialCompromise = "https://schemas.openid.net/secevent/risc/event-type/credential-compromise"
    public static let optIn = "https://schemas.openid.net/secevent/risc/event-type/opt-in"
    public static let optOutInitiated = "https://schemas.openid.net/secevent/risc/event-type/opt-out-initiated"
    public static let optOutCancelled = "https://schemas.openid.net/secevent/risc/event-type/opt-out-cancelled"
    public static let optOutEffective = "https://schemas.openid.net/secevent/risc/event-type/opt-out-effective"
    public static let recoveryActivated = "https://schemas.openid.net/secevent/risc/event-type/recovery-activated"
    public static let recoveryInformationChanged = "https://schemas.openid.net/secevent/risc/event-type/recovery-information-changed"

    /// Deprecated in RISC 1.0; new implementations must use CAEP session-revoked
    public static let sessionsRevoked = "https://schemas.openid.net/secevent/risc/event-type/sessions-revoked"

    public static let all = [
        accountCredentialChangeRequired, accountPurged, accountDisabled, accountEnabled,
        identifierChanged, identifierRecycled, credentialCompromise,
        optIn, optOutInitiated, optOutCancelled, optOutEffective,
        recoveryActivated, recoveryInformationChanged,
    ]
}

// MARK: - Typed event access

extension SecurityEventPayload {
    /// Decode the payload of a specific event type into a typed struct.
    /// Returns nil when the SET doesn't contain that event type.
    public func event<T: Decodable>(_ type: String, as: T.Type) throws -> T? {
        guard let raw = events[type] else { return nil }
        let data = try JSONEncoder().encode(raw)
        return try JSONDecoder().decode(T.self, from: data)
    }

    /// The event type URIs present in this SET
    public var eventTypes: [String] {
        Array(events.keys)
    }
}

// MARK: - SSF Events

/// Payload of the SSF verification event
public struct VerificationEvent: Codable, Sendable {
    /// Echoes the state from the verification request
    public let state: String?

    public init(state: String? = nil) {
        self.state = state
    }
}

/// Payload of the SSF stream-updated event
public struct StreamUpdatedEvent: Codable, Sendable {
    /// The new stream status
    public let status: StreamStatus

    /// Optional human-readable reason for the change
    public let reason: String?

    public init(status: StreamStatus, reason: String? = nil) {
        self.status = status
        self.reason = reason
    }
}

/// A framework-level signal an `SSFReceiver` surfaces while processing SETs,
/// so applications can react to stream lifecycle changes without re-parsing
/// SETs themselves. Observe these via `SSFReceiver.lifecycleEvents()`.
public struct StreamLifecycleEvent: Sendable {
    /// What the transmitter signalled.
    public enum Payload: Sendable {
        /// The transmitter changed the stream's status (`stream-updated`).
        case statusChanged(StreamUpdatedEvent)

        /// A verification result arrived (`verification`), echoing the `state`
        /// from the corresponding verification request for correlation.
        case verified(VerificationEvent)
    }

    /// The framework event carried by the SET.
    public let payload: Payload

    /// The poll delivery endpoint the carrying SET arrived on, or `nil` when the
    /// SET was received by push or processed directly with no poll context.
    /// Poll-based reactors use this to match events to their own stream.
    public let pollEndpoint: URL?

    public init(payload: Payload, pollEndpoint: URL? = nil) {
        self.payload = payload
        self.pollEndpoint = pollEndpoint
    }
}

// MARK: - CAEP Event Types (CAEP 1.0)

/// Session of the subject was revoked. All fields are the CAEP common
/// optional claims; the event has no required members of its own.
public struct SessionRevokedEvent: Codable, Sendable {
    public let initiating_entity: String?
    public let reason_admin: [String: String]?
    public let reason_user: [String: String]?
    public let event_timestamp: Int64?

    public init(
        initiating_entity: String? = nil,
        reason_admin: [String: String]? = nil,
        reason_user: [String: String]? = nil,
        event_timestamp: Int64? = nil
    ) {
        self.initiating_entity = initiating_entity
        self.reason_admin = reason_admin
        self.reason_user = reason_user
        self.event_timestamp = event_timestamp
    }
}

public struct TokenClaimsChangeEvent: Codable, Sendable {
    /// REQUIRED: claims that changed with their new values
    public let claims: [String: AnyCodable]
    public let initiating_entity: String?
    public let reason_admin: [String: String]?
    public let reason_user: [String: String]?
    public let event_timestamp: Int64?

    public init(
        claims: [String: AnyCodable],
        initiating_entity: String? = nil,
        reason_admin: [String: String]? = nil,
        reason_user: [String: String]? = nil,
        event_timestamp: Int64? = nil
    ) {
        self.claims = claims
        self.initiating_entity = initiating_entity
        self.reason_admin = reason_admin
        self.reason_user = reason_user
        self.event_timestamp = event_timestamp
    }
}

public struct CredentialChangeEvent: Codable, Sendable {
    /// REQUIRED: e.g. "password", "pin", "x509", "fido2-platform", ...
    public let credential_type: String

    /// REQUIRED: "create", "revoke", "update", or "delete"
    public let change_type: String

    public let friendly_name: String?
    public let x509_issuer: String?
    public let x509_serial: String?
    public let fido2_aaguid: String?
    public let initiating_entity: String?
    public let reason_admin: [String: String]?
    public let reason_user: [String: String]?
    public let event_timestamp: Int64?

    public init(
        credential_type: String,
        change_type: String,
        friendly_name: String? = nil,
        x509_issuer: String? = nil,
        x509_serial: String? = nil,
        fido2_aaguid: String? = nil,
        initiating_entity: String? = nil,
        reason_admin: [String: String]? = nil,
        reason_user: [String: String]? = nil,
        event_timestamp: Int64? = nil
    ) {
        self.credential_type = credential_type
        self.change_type = change_type
        self.friendly_name = friendly_name
        self.x509_issuer = x509_issuer
        self.x509_serial = x509_serial
        self.fido2_aaguid = fido2_aaguid
        self.initiating_entity = initiating_entity
        self.reason_admin = reason_admin
        self.reason_user = reason_user
        self.event_timestamp = event_timestamp
    }
}

public struct AssuranceLevelChangeEvent: Codable, Sendable {
    /// REQUIRED: the namespace of the levels, e.g. "nist-aal"
    public let namespace: String

    /// REQUIRED: the new assurance level
    public let current_level: String

    public let previous_level: String?

    /// "increase" or "decrease"
    public let change_direction: String?

    public let initiating_entity: String?
    public let reason_admin: [String: String]?
    public let reason_user: [String: String]?
    public let event_timestamp: Int64?

    public init(
        namespace: String,
        current_level: String,
        previous_level: String? = nil,
        change_direction: String? = nil,
        initiating_entity: String? = nil,
        reason_admin: [String: String]? = nil,
        reason_user: [String: String]? = nil,
        event_timestamp: Int64? = nil
    ) {
        self.namespace = namespace
        self.current_level = current_level
        self.previous_level = previous_level
        self.change_direction = change_direction
        self.initiating_entity = initiating_entity
        self.reason_admin = reason_admin
        self.reason_user = reason_user
        self.event_timestamp = event_timestamp
    }
}

public struct DeviceComplianceChangeEvent: Codable, Sendable {
    /// REQUIRED: "compliant" or "not-compliant"
    public let previous_status: String

    /// REQUIRED: "compliant" or "not-compliant"
    public let current_status: String

    public let initiating_entity: String?
    public let reason_admin: [String: String]?
    public let reason_user: [String: String]?
    public let event_timestamp: Int64?

    public init(
        previous_status: String,
        current_status: String,
        initiating_entity: String? = nil,
        reason_admin: [String: String]? = nil,
        reason_user: [String: String]? = nil,
        event_timestamp: Int64? = nil
    ) {
        self.previous_status = previous_status
        self.current_status = current_status
        self.initiating_entity = initiating_entity
        self.reason_admin = reason_admin
        self.reason_user = reason_user
        self.event_timestamp = event_timestamp
    }
}

public struct SessionEstablishedEvent: Codable, Sendable {
    /// IP addresses observed for the session
    public let ips: [String]?

    /// Fingerprint of the user agent
    public let fp_ua: String?

    /// Authentication context class reference
    public let acr: String?

    /// Authentication methods references
    public let amr: [String]?

    /// Transmitter's external session identifier
    public let ext_id: String?

    public let initiating_entity: String?
    public let reason_admin: [String: String]?
    public let reason_user: [String: String]?
    public let event_timestamp: Int64?

    public init(
        ips: [String]? = nil,
        fp_ua: String? = nil,
        acr: String? = nil,
        amr: [String]? = nil,
        ext_id: String? = nil,
        initiating_entity: String? = nil,
        reason_admin: [String: String]? = nil,
        reason_user: [String: String]? = nil,
        event_timestamp: Int64? = nil
    ) {
        self.ips = ips
        self.fp_ua = fp_ua
        self.acr = acr
        self.amr = amr
        self.ext_id = ext_id
        self.initiating_entity = initiating_entity
        self.reason_admin = reason_admin
        self.reason_user = reason_user
        self.event_timestamp = event_timestamp
    }
}

public struct SessionPresentedEvent: Codable, Sendable {
    public let ips: [String]?
    public let fp_ua: String?
    public let ext_id: String?
    public let initiating_entity: String?
    public let reason_admin: [String: String]?
    public let reason_user: [String: String]?
    public let event_timestamp: Int64?

    public init(
        ips: [String]? = nil,
        fp_ua: String? = nil,
        ext_id: String? = nil,
        initiating_entity: String? = nil,
        reason_admin: [String: String]? = nil,
        reason_user: [String: String]? = nil,
        event_timestamp: Int64? = nil
    ) {
        self.ips = ips
        self.fp_ua = fp_ua
        self.ext_id = ext_id
        self.initiating_entity = initiating_entity
        self.reason_admin = reason_admin
        self.reason_user = reason_user
        self.event_timestamp = event_timestamp
    }
}

public struct RiskLevelChangeEvent: Codable, Sendable {
    /// REQUIRED: "USER" or "SESSION"
    public let principal: String

    /// REQUIRED: "LOW", "MEDIUM", or "HIGH"
    public let current_level: String

    public let previous_level: String?
    public let risk_reason: String?
    public let initiating_entity: String?
    public let reason_admin: [String: String]?
    public let reason_user: [String: String]?
    public let event_timestamp: Int64?

    public init(
        principal: String,
        current_level: String,
        previous_level: String? = nil,
        risk_reason: String? = nil,
        initiating_entity: String? = nil,
        reason_admin: [String: String]? = nil,
        reason_user: [String: String]? = nil,
        event_timestamp: Int64? = nil
    ) {
        self.principal = principal
        self.current_level = current_level
        self.previous_level = previous_level
        self.risk_reason = risk_reason
        self.initiating_entity = initiating_entity
        self.reason_admin = reason_admin
        self.reason_user = reason_user
        self.event_timestamp = event_timestamp
    }
}

// MARK: - RISC Event Types (RISC 1.0)

public struct AccountPurgedEvent: Codable, Sendable {
    public init() {}
}

public struct AccountDisabledEvent: Codable, Sendable {
    /// "hijacking" or "bulk-account"
    public let reason: String?

    public init(reason: String? = nil) {
        self.reason = reason
    }
}

public struct AccountEnabledEvent: Codable, Sendable {
    public init() {}
}

public struct AccountCredentialChangeRequiredEvent: Codable, Sendable {
    public init() {}
}

public struct CredentialCompromiseEvent: Codable, Sendable {
    /// REQUIRED: the type of credential that was compromised
    public let credential_type: String

    public let event_timestamp: Int64?
    public let reason_admin: String?
    public let reason_user: String?

    public init(
        credential_type: String,
        event_timestamp: Int64? = nil,
        reason_admin: String? = nil,
        reason_user: String? = nil
    ) {
        self.credential_type = credential_type
        self.event_timestamp = event_timestamp
        self.reason_admin = reason_admin
        self.reason_user = reason_user
    }
}

public struct IdentifierChangedEvent: Codable, Sendable {
    /// The new value of the identifier, when it's shared with the receiver
    public let new_value: String?

    public init(new_value: String? = nil) {
        self.new_value = new_value
    }
}

public struct IdentifierRecycledEvent: Codable, Sendable {
    public init() {}
}

public struct OptInEvent: Codable, Sendable {
    public init() {}
}

public struct OptOutInitiatedEvent: Codable, Sendable {
    public init() {}
}

public struct OptOutCancelledEvent: Codable, Sendable {
    public init() {}
}

public struct OptOutEffectiveEvent: Codable, Sendable {
    public init() {}
}

public struct RecoveryActivatedEvent: Codable, Sendable {
    public init() {}
}

public struct RecoveryInformationChangedEvent: Codable, Sendable {
    public init() {}
}
