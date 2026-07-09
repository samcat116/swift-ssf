import Foundation

/// Security Event Token (SET) - A JWT that contains security event information
public struct SecurityEventToken: Codable, Sendable {
    /// JWT header
    public let header: JWTHeader
    
    /// JWT payload containing the security event
    public let payload: SecurityEventPayload
    
    /// Raw JWT token string
    public let rawToken: String
    
    public init(header: JWTHeader, payload: SecurityEventPayload, rawToken: String) {
        self.header = header
        self.payload = payload
        self.rawToken = rawToken
    }
}

/// JWT Header for Security Event Tokens
public struct JWTHeader: Codable, Sendable {
    /// Algorithm used for signing
    public let alg: String

    /// Token type ("secevent+jwt" for SETs, per RFC 8417)
    public let typ: String?

    /// Key ID used for signing
    public let kid: String?

    public init(alg: String, typ: String? = "secevent+jwt", kid: String? = nil) {
        self.alg = alg
        self.typ = typ
        self.kid = kid
    }
}

/// Security Event Token payload
public struct SecurityEventPayload: Codable, Sendable {
    /// Issuer - who created this token
    public let iss: URL
    
    /// JWT ID - unique identifier for this token
    public let jti: String
    
    /// Issued at timestamp
    public let iat: Int64
    
    /// Audience - who this token is intended for
    public let aud: [String]?
    
    /// Subject identifier
    public let sub_id: SubjectIdentifier?
    
    /// The security events contained in this token
    public let events: [String: [String: AnyCodable]]
    
    /// Time when the event occurred
    public let toe: Int64?
    
    /// Transaction identifier
    public let txn: String?
    
    public init(
        iss: URL,
        jti: String,
        iat: Int64,
        aud: [String]? = nil,
        sub_id: SubjectIdentifier? = nil,
        events: [String: [String: AnyCodable]],
        toe: Int64? = nil,
        txn: String? = nil
    ) {
        self.iss = iss
        self.jti = jti
        self.iat = iat
        self.aud = aud
        self.sub_id = sub_id
        self.events = events
        self.toe = toe
        self.txn = txn
    }

    private enum CodingKeys: String, CodingKey {
        case iss, jti, iat, aud, sub_id, events, toe, txn
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        self.iss = try container.decode(URL.self, forKey: .iss)
        self.jti = try container.decode(String.self, forKey: .jti)
        self.iat = try container.decode(Int64.self, forKey: .iat)

        // RFC 7519 allows "aud" to be a single string or an array of strings
        if let singleAudience = try? container.decode(String.self, forKey: .aud) {
            self.aud = [singleAudience]
        } else {
            self.aud = try container.decodeIfPresent([String].self, forKey: .aud)
        }

        self.sub_id = try container.decodeIfPresent(SubjectIdentifier.self, forKey: .sub_id)
        self.events = try container.decode([String: [String: AnyCodable]].self, forKey: .events)
        self.toe = try container.decodeIfPresent(Int64.self, forKey: .toe)
        self.txn = try container.decodeIfPresent(String.self, forKey: .txn)
    }
}

/// A Subject Identifier (RFC 9493), including SSF complex subjects.
///
/// Every subject is a JSON object with a "format" member; the remaining
/// members depend on the format. SSF's "complex" format nests further
/// subject identifiers under member names like "user" and "session".
public struct SubjectIdentifier: Codable, Sendable {
    /// The subject identifier format ("email", "iss_sub", "complex", ...)
    public let format: String

    /// All members other than "format"
    public let members: [String: AnyCodable]

    public init(format: String, members: [String: AnyCodable] = [:]) {
        self.format = format
        self.members = members
    }

    /// A string-valued member, e.g. `subject.string("email")`
    public func string(_ member: String) -> String? {
        members[member]?.value as? String
    }

    /// A nested subject identifier member of a complex subject,
    /// e.g. `subject.subject("user")`
    public func subject(_ member: String) -> SubjectIdentifier? {
        guard let dictionary = members[member]?.value as? [String: AnyCodable],
              let format = dictionary["format"]?.value as? String else {
            return nil
        }
        var nested = dictionary
        nested.removeValue(forKey: "format")
        return SubjectIdentifier(format: format, members: nested)
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: AnyCodingKey.self)

        guard let formatKey = AnyCodingKey(stringValue: "format") else {
            throw DecodingError.dataCorrupted(.init(codingPath: decoder.codingPath, debugDescription: "Failed to create coding keys"))
        }

        self.format = try container.decode(String.self, forKey: formatKey)

        var members: [String: AnyCodable] = [:]
        for key in container.allKeys where key.stringValue != "format" {
            members[key.stringValue] = try container.decode(AnyCodable.self, forKey: key)
        }
        self.members = members
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: AnyCodingKey.self)
        try container.encode(format, forKey: AnyCodingKey(stringValue: "format")!)

        for (key, value) in members {
            try container.encode(value, forKey: AnyCodingKey(stringValue: key)!)
        }
    }
}

// MARK: - RFC 9493 format constructors

extension SubjectIdentifier {
    public static func account(uri: String) -> SubjectIdentifier {
        SubjectIdentifier(format: "account", members: ["uri": AnyCodable(uri)])
    }

    public static func email(_ email: String) -> SubjectIdentifier {
        SubjectIdentifier(format: "email", members: ["email": AnyCodable(email)])
    }

    public static func phoneNumber(_ phoneNumber: String) -> SubjectIdentifier {
        SubjectIdentifier(format: "phone_number", members: ["phone_number": AnyCodable(phoneNumber)])
    }

    public static func issSub(iss: String, sub: String) -> SubjectIdentifier {
        SubjectIdentifier(format: "iss_sub", members: ["iss": AnyCodable(iss), "sub": AnyCodable(sub)])
    }

    public static func opaque(id: String) -> SubjectIdentifier {
        SubjectIdentifier(format: "opaque", members: ["id": AnyCodable(id)])
    }

    public static func uri(_ uri: String) -> SubjectIdentifier {
        SubjectIdentifier(format: "uri", members: ["uri": AnyCodable(uri)])
    }

    public static func did(url: String) -> SubjectIdentifier {
        SubjectIdentifier(format: "did", members: ["url": AnyCodable(url)])
    }

    public static func jwtID(iss: String, jti: String) -> SubjectIdentifier {
        SubjectIdentifier(format: "jwt_id", members: ["iss": AnyCodable(iss), "jti": AnyCodable(jti)])
    }

    public static func samlAssertionID(issuer: String, assertionID: String) -> SubjectIdentifier {
        SubjectIdentifier(format: "saml_assertion_id", members: [
            "issuer": AnyCodable(issuer),
            "assertion_id": AnyCodable(assertionID),
        ])
    }

    public static func aliases(_ identifiers: [SubjectIdentifier]) -> SubjectIdentifier {
        SubjectIdentifier(format: "aliases", members: [
            "identifiers": AnyCodable(identifiers.map { AnyCodable($0.asAnyCodableDictionary()) })
        ])
    }

    /// SSF complex subject: each member is itself a subject identifier
    public static func complex(
        user: SubjectIdentifier? = nil,
        device: SubjectIdentifier? = nil,
        session: SubjectIdentifier? = nil,
        application: SubjectIdentifier? = nil,
        tenant: SubjectIdentifier? = nil,
        orgUnit: SubjectIdentifier? = nil,
        group: SubjectIdentifier? = nil
    ) -> SubjectIdentifier {
        var members: [String: AnyCodable] = [:]
        if let user = user { members["user"] = AnyCodable(user.asAnyCodableDictionary()) }
        if let device = device { members["device"] = AnyCodable(device.asAnyCodableDictionary()) }
        if let session = session { members["session"] = AnyCodable(session.asAnyCodableDictionary()) }
        if let application = application { members["application"] = AnyCodable(application.asAnyCodableDictionary()) }
        if let tenant = tenant { members["tenant"] = AnyCodable(tenant.asAnyCodableDictionary()) }
        if let orgUnit = orgUnit { members["org_unit"] = AnyCodable(orgUnit.asAnyCodableDictionary()) }
        if let group = group { members["group"] = AnyCodable(group.asAnyCodableDictionary()) }
        return SubjectIdentifier(format: "complex", members: members)
    }

    private func asAnyCodableDictionary() -> [String: AnyCodable] {
        var dictionary = members
        dictionary["format"] = AnyCodable(format)
        return dictionary
    }
}

/// A type-erased codable value. Only ever holds immutable JSON-plist values
/// (Bool/Int/Double/String and nested arrays/dictionaries of AnyCodable),
/// so cross-actor sharing is safe despite the `Any` storage.
public struct AnyCodable: Codable, @unchecked Sendable {
    public let value: Any
    
    public init<T: Codable>(_ value: T) {
        self.value = value
    }
    
    public init(from decoder: Decoder) throws {
        let container = try decoder.singleValueContainer()
        
        if let bool = try? container.decode(Bool.self) {
            value = bool
        } else if let int = try? container.decode(Int.self) {
            value = int
        } else if let double = try? container.decode(Double.self) {
            value = double
        } else if let string = try? container.decode(String.self) {
            value = string
        } else if let array = try? container.decode([AnyCodable].self) {
            value = array
        } else if let dictionary = try? container.decode([String: AnyCodable].self) {
            value = dictionary
        } else {
            throw DecodingError.dataCorruptedError(in: container, debugDescription: "Unsupported type")
        }
    }
    
    public func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        
        if let bool = value as? Bool {
            try container.encode(bool)
        } else if let int = value as? Int {
            try container.encode(int)
        } else if let double = value as? Double {
            try container.encode(double)
        } else if let string = value as? String {
            try container.encode(string)
        } else if let array = value as? [AnyCodable] {
            try container.encode(array)
        } else if let dictionary = value as? [String: AnyCodable] {
            try container.encode(dictionary)
        } else {
            throw EncodingError.invalidValue(value, EncodingError.Context(codingPath: container.codingPath, debugDescription: "Unsupported type"))
        }
    }
}

/// A coding key that can be created from any string
public struct AnyCodingKey: CodingKey, Sendable {
    public let stringValue: String
    public let intValue: Int?
    
    public init?(stringValue: String) {
        self.stringValue = stringValue
        self.intValue = nil
    }
    
    public init?(intValue: Int) {
        self.stringValue = String(intValue)
        self.intValue = intValue
    }
}