import Foundation
import Crypto
import _CryptoExtras
import Logging

/// A public key that can verify SET signatures
public enum JWTVerificationKey: Sendable {
    /// ECDSA using P-256 and SHA-256 (JWS "ES256")
    case es256(P256.Signing.PublicKey)

    /// RSASSA-PKCS1-v1_5 using SHA-256 (JWS "RS256")
    case rs256(_RSA.Signing.PublicKey)
}

/// How a SET's `aud` claim is checked against the receiver's expected audiences.
public enum AudienceValidation: Sendable {
    /// Accept when the SET's `aud` shares at least one value with the
    /// expected audiences. Suits receivers known by several identifiers.
    /// (Default.)
    case anyOverlap

    /// Require the SET to be addressed to exactly one audience, and that
    /// audience to be one the receiver answers to. Rejects tokens that also
    /// name other receivers.
    case strict
}

/// JWT processor for parsing and validating Security Event Tokens
public actor JWTProcessor {
    private let logger = Logger(label: "SwiftSSF.JWTProcessor")
    private let jsonDecoder: JSONDecoder
    private let jsonEncoder: JSONEncoder

    public init() {
        self.jsonDecoder = JSONDecoder()
        self.jsonEncoder = JSONEncoder()

        // Configure date decoding strategy
        jsonDecoder.dateDecodingStrategy = .secondsSince1970
        jsonEncoder.dateEncodingStrategy = .secondsSince1970
    }

    /// Parse a JWT string into its components without validation
    public func parseJWT(_ token: String) throws -> (header: JWTHeader, payload: [String: Any]) {
        let parts = token.split(separator: ".").map(String.init)
        guard parts.count == 3 else {
            throw SSFError.invalidJWT("JWT must have exactly 3 parts separated by dots")
        }

        // Decode header
        guard let headerData = Data(base64URLEncoded: parts[0]) else {
            throw SSFError.invalidJWT("Invalid base64url encoding in header")
        }

        let header = try jsonDecoder.decode(JWTHeader.self, from: headerData)

        // Decode payload as generic JSON
        guard let payloadData = Data(base64URLEncoded: parts[1]) else {
            throw SSFError.invalidJWT("Invalid base64url encoding in payload")
        }

        guard let payload = try JSONSerialization.jsonObject(with: payloadData) as? [String: Any] else {
            throw SSFError.invalidJWT("Payload is not a valid JSON object")
        }

        return (header: header, payload: payload)
    }

    /// Parse and validate a Security Event Token.
    ///
    /// Passing `key: nil` explicitly disables signature verification and MUST
    /// only be done for tokens whose authenticity is established elsewhere
    /// (e.g. in tests). There is no default value on purpose.
    public func parseSecurityEventToken(
        _ token: String,
        expectedIssuer: URL? = nil,
        expectedAudience: [String]? = nil,
        audienceValidation: AudienceValidation = .anyOverlap,
        key: JWTVerificationKey?
    ) throws -> SecurityEventToken {
        let (header, payloadDict) = try parseJWT(token)

        // RFC 8417 §2.3: reject tokens that don't identify themselves as SETs,
        // so ordinary access/ID tokens can't be replayed into the event pipeline.
        try validateTokenType(header)

        if let key = key {
            try verifySignature(token: token, header: header, key: key)
        } else {
            logger.warning("Signature verification explicitly disabled for this SET")
        }

        // Parse payload as SecurityEventPayload
        let payloadData = try JSONSerialization.data(withJSONObject: payloadDict)
        let payload = try jsonDecoder.decode(SecurityEventPayload.self, from: payloadData)

        // Validate issuer if expected
        if let expectedIssuer = expectedIssuer {
            guard Self.issuerMatches(payload.iss, expected: expectedIssuer) else {
                throw SSFError.invalidIssuer(expected: expectedIssuer.absoluteString, actual: payload.iss.absoluteString)
            }
        }

        // Validate audience if expected
        if let expectedAudience = expectedAudience {
            try Self.validateAudience(payload.aud, expected: expectedAudience, mode: audienceValidation)
        }

        // RFC 8417 discourages "exp" in SETs, but if a transmitter includes it,
        // honor it rather than accept a token it considers expired.
        if let expDict = payloadDict["exp"] as? NSNumber {
            let exp = expDict.int64Value
            let now = Int64(Date().timeIntervalSince1970)
            if exp < now {
                throw SSFError.tokenExpired
            }
        }

        return SecurityEventToken(header: header, payload: payload, rawToken: token)
    }

    /// Validate that the JWT "typ" header marks this token as a SET
    private func validateTokenType(_ header: JWTHeader) throws {
        guard let typ = header.typ else {
            throw SSFError.invalidJWT("Missing typ header; SETs must use typ \"secevent+jwt\"")
        }

        // RFC 8417 registers "application/secevent+jwt"; the "application/"
        // prefix may be omitted, and media types compare case-insensitively.
        let normalized = typ.lowercased()
        guard normalized == "secevent+jwt" || normalized == "application/secevent+jwt" else {
            throw SSFError.invalidJWT("Unexpected typ header \"\(typ)\"; SETs must use typ \"secevent+jwt\"")
        }
    }

    /// Compare a SET's issuer against the expected issuer.
    ///
    /// OIDC-style issuer matching is a verbatim string comparison, but the
    /// original code compared `URL` values, so `https://tr.example.com` and
    /// `https://tr.example.com/` — and case differences in scheme/host —
    /// failed even though they identify the same issuer. Try the exact
    /// comparison first, then fall back to a normalized comparison
    /// (lowercase scheme/host, default port stripped, trailing slash removed).
    static func issuerMatches(_ actual: URL, expected: URL) -> Bool {
        if actual.absoluteString == expected.absoluteString {
            return true
        }
        guard let normalizedActual = normalizedIssuer(actual),
              let normalizedExpected = normalizedIssuer(expected) else {
            return false
        }
        return normalizedActual == normalizedExpected
    }

    /// Canonicalize an issuer URL for equivalence comparison. Returns `nil`
    /// if the URL can't be decomposed.
    private static func normalizedIssuer(_ url: URL) -> String? {
        guard let components = URLComponents(url: url, resolvingAgainstBaseURL: false) else {
            return nil
        }

        let scheme = components.scheme?.lowercased() ?? ""
        let host = components.host?.lowercased() ?? ""

        var portPart = ""
        if let port = components.port {
            let isDefaultPort = (scheme == "https" && port == 443) || (scheme == "http" && port == 80)
            if !isDefaultPort {
                portPart = ":\(port)"
            }
        }

        var path = components.path
        while path.count > 1 && path.hasSuffix("/") {
            path.removeLast()
        }
        if path == "/" {
            path = ""
        }

        return "\(scheme)://\(host)\(portPart)\(path)"
    }

    /// Check a SET's `aud` against the configured expectation.
    ///
    /// A SET with no `aud` can't satisfy a configured expectation, so it's
    /// rejected here; a missing `aud` is only accepted when no expectation is
    /// configured (in which case this method isn't called).
    static func validateAudience(_ actual: [String]?, expected: [String], mode: AudienceValidation) throws {
        guard let actual = actual, !actual.isEmpty else {
            throw SSFError.invalidAudience(expected: expected, actual: actual)
        }

        let expectedSet = Set(expected)
        let actualSet = Set(actual)

        switch mode {
        case .anyOverlap:
            guard !expectedSet.isDisjoint(with: actualSet) else {
                throw SSFError.invalidAudience(expected: expected, actual: actual)
            }
        case .strict:
            // Exactly one audience, and it must be one we answer to.
            guard actualSet.count == 1, expectedSet.isSuperset(of: actualSet) else {
                throw SSFError.invalidAudience(expected: expected, actual: actual)
            }
        }
    }

    /// Verify the JWS signature over the token
    private func verifySignature(token: String, header: JWTHeader, key: JWTVerificationKey) throws {
        let parts = token.split(separator: ".").map(String.init)
        guard parts.count == 3 else {
            throw SSFError.invalidJWT("Invalid JWT format")
        }

        // Create signing input (header.payload)
        let signingInput = Data("\(parts[0]).\(parts[1])".utf8)

        // Decode signature
        guard let signatureData = Data(base64URLEncoded: parts[2]) else {
            throw SSFError.invalidJWT("Invalid signature encoding")
        }

        switch key {
        case .es256(let publicKey):
            guard header.alg == "ES256" else {
                throw SSFError.unsupportedAlgorithm(header.alg)
            }
            let signature = try P256.Signing.ECDSASignature(rawRepresentation: signatureData)
            guard publicKey.isValidSignature(signature, for: signingInput) else {
                throw SSFError.signatureVerificationFailed
            }

        case .rs256(let publicKey):
            guard header.alg == "RS256" else {
                throw SSFError.unsupportedAlgorithm(header.alg)
            }
            let signature = _RSA.Signing.RSASignature(rawRepresentation: signatureData)
            guard publicKey.isValidSignature(
                signature,
                for: SHA256.hash(data: signingInput),
                padding: .insecurePKCS1v1_5
            ) else {
                throw SSFError.signatureVerificationFailed
            }
        }
    }

    /// Create a Security Event Token (for testing purposes)
    public func createSecurityEventToken(
        issuer: URL,
        audience: [String],
        events: [String: [String: AnyCodable]],
        subject: SubjectIdentifier? = nil,
        privateKey: P256.Signing.PrivateKey
    ) throws -> SecurityEventToken {
        let header = JWTHeader(alg: "ES256", typ: "secevent+jwt")
        let jti = UUID().uuidString
        let iat = Int64(Date().timeIntervalSince1970)

        let payload = SecurityEventPayload(
            iss: issuer,
            jti: jti,
            iat: iat,
            aud: audience,
            sub_id: subject,
            events: events
        )

        let token = try createJWT(header: header, payload: payload, privateKey: privateKey)
        return SecurityEventToken(header: header, payload: payload, rawToken: token)
    }

    /// Create a signed JWT
    private func createJWT(
        header: JWTHeader,
        payload: SecurityEventPayload,
        privateKey: P256.Signing.PrivateKey
    ) throws -> String {
        // Encode header
        let headerData = try jsonEncoder.encode(header)
        let headerB64 = headerData.base64URLEncodedString()

        // Encode payload
        let payloadData = try jsonEncoder.encode(payload)
        let payloadB64 = payloadData.base64URLEncodedString()

        // Create signing input
        let signingInput = "\(headerB64).\(payloadB64)"
        let signingData = Data(signingInput.utf8)

        // Sign
        let signature = try privateKey.signature(for: signingData)
        let signatureB64 = signature.rawRepresentation.base64URLEncodedString()

        return "\(signingInput).\(signatureB64)"
    }
}

// MARK: - Base64URL Extension

extension Data {
    /// Initialize from base64url encoded string
    init?(base64URLEncoded string: String) {
        var base64 = string
            .replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")

        // Add padding if needed
        let remainder = base64.count % 4
        if remainder > 0 {
            base64 += String(repeating: "=", count: 4 - remainder)
        }

        self.init(base64Encoded: base64)
    }

    /// Encode as base64url string
    func base64URLEncodedString() -> String {
        return base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }
}
