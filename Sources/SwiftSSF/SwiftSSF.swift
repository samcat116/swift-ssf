/// SwiftSSF - A cross-platform Swift framework for OpenID Shared Signals Framework (SSF) receivers
///
/// This framework enables Swift applications to act as receivers in the SSF ecosystem,
/// supporting both CAEP and RISC event types with push and poll delivery methods.

// MARK: - Framework Information

/// SwiftSSF framework version
public let swiftSSFVersion = "1.0.0"

/// Supported SSF specification version (SSF 1.0 Final)
public let supportedSSFVersion = "1_0"

/// Event types this framework has typed models for
/// (see CAEPEventTypes, RISCEventTypes, and SSFEventTypes)
public let supportedEventTypes: [String] =
    SSFEventTypes.all + CAEPEventTypes.all + RISCEventTypes.all

/// Supported delivery methods
public let supportedDeliveryMethods = [
    "urn:ietf:rfc:8935", // Push delivery
    "urn:ietf:rfc:8936", // Poll delivery
]
