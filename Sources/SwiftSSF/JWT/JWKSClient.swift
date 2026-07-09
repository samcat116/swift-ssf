import Foundation
import AsyncHTTPClient
import Crypto
import _CryptoExtras
import NIOFoundationCompat
import Logging

/// Client for fetching and managing JSON Web Key Sets (JWKS)
public actor JWKSClient {
    private let httpClient: HTTPClient
    private let logger = Logger(label: "SwiftSSF.JWKSClient")
    private var keyCache: [String: JWKSet] = [:]
    private let cacheTimeout: TimeInterval = 3600 // 1 hour

    public init(httpClient: HTTPClient) {
        self.httpClient = httpClient
    }

    /// Fetch JWKS from a URL
    public func fetchJWKS(from url: URL, forceRefresh: Bool = false) async throws -> JWKSet {
        let cacheKey = url.absoluteString

        if !forceRefresh, let cached = keyCache[cacheKey],
           Date().timeIntervalSince(cached.fetchedAt) < cacheTimeout {
            logger.debug("Using cached JWKS for \(url)")
            return cached
        }

        logger.info("Fetching JWKS from \(url)")

        let request = HTTPClientRequest(url: url.absoluteString)
        let response = try await httpClient.execute(request, timeout: .seconds(30))

        guard response.status == .ok else {
            throw SSFError.httpError(statusCode: Int(response.status.code), message: "Failed to fetch JWKS")
        }

        let body = try await response.body.collect(upTo: 1024 * 1024) // 1MB limit
        let jwks = try JSONDecoder().decode(JWKSet.self, from: Data(buffer: body))

        // Cache the result
        let cachedJWKS = JWKSet(keys: jwks.keys, fetchedAt: Date())
        keyCache[cacheKey] = cachedJWKS

        logger.debug("Successfully fetched and cached JWKS with \(jwks.keys.count) keys")
        return cachedJWKS
    }

    /// Resolve the verification key for a SET, refetching the JWKS once if the
    /// key ID is unknown (transmitter key rotation).
    public func verificationKey(forKeyID keyID: String?, jwksURI: URL) async throws -> JWTVerificationKey {
        let jwks = try await fetchJWKS(from: jwksURI)
        if let key = try? findKey(in: jwks, keyID: keyID) {
            return key
        }

        let fresh = try await fetchJWKS(from: jwksURI, forceRefresh: true)
        return try findKey(in: fresh, keyID: keyID)
    }

    /// Get a verification key for a specific key ID from an already-fetched JWKS
    public func getPublicKey(jwks: JWKSet, keyId: String) throws -> JWTVerificationKey {
        return try findKey(in: jwks, keyID: keyId)
    }

    private func findKey(in jwks: JWKSet, keyID: String?) throws -> JWTVerificationKey {
        let signingKeys = jwks.keys.filter { $0.use == nil || $0.use == "sig" }

        if let keyID = keyID {
            guard let jwk = signingKeys.first(where: { $0.kid == keyID }) else {
                throw SSFError.verificationKeyUnavailable("JWKS contains no signing key with kid \"\(keyID)\"")
            }
            return try jwk.toVerificationKey()
        }

        // No kid in the SET header: only unambiguous if exactly one usable key exists
        let usable = signingKeys.compactMap { try? $0.toVerificationKey() }
        guard usable.count == 1 else {
            throw SSFError.verificationKeyUnavailable(
                "SET has no kid header and the JWKS has \(usable.count) usable signing keys")
        }
        return usable[0]
    }

    /// Clear the key cache
    public func clearCache() {
        keyCache.removeAll()
    }
}

/// JSON Web Key Set
public struct JWKSet: Codable, Sendable {
    public let keys: [JWK]
    public let fetchedAt: Date

    public init(keys: [JWK], fetchedAt: Date = Date()) {
        self.keys = keys
        self.fetchedAt = fetchedAt
    }

    enum CodingKeys: String, CodingKey {
        case keys
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        self.keys = try container.decode([JWK].self, forKey: .keys)
        self.fetchedAt = Date()
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(keys, forKey: .keys)
    }
}

/// JSON Web Key
public struct JWK: Codable, Sendable {
    /// Key type (e.g., "EC", "RSA")
    public let kty: String

    /// Algorithm (e.g., "ES256")
    public let alg: String?

    /// Key usage (e.g., "sig")
    public let use: String?

    /// Key ID
    public let kid: String?

    /// Curve for EC keys
    public let crv: String?

    /// X coordinate for EC keys (base64url encoded)
    public let x: String?

    /// Y coordinate for EC keys (base64url encoded)
    public let y: String?

    /// RSA modulus (base64url encoded)
    public let n: String?

    /// RSA exponent (base64url encoded)
    public let e: String?

    public init(
        kty: String,
        alg: String? = nil,
        use: String? = nil,
        kid: String? = nil,
        crv: String? = nil,
        x: String? = nil,
        y: String? = nil,
        n: String? = nil,
        e: String? = nil
    ) {
        self.kty = kty
        self.alg = alg
        self.use = use
        self.kid = kid
        self.crv = crv
        self.x = x
        self.y = y
        self.n = n
        self.e = e
    }

    /// Convert JWK to a verification key
    public func toVerificationKey() throws -> JWTVerificationKey {
        switch kty {
        case "EC":
            guard crv == "P-256" else {
                throw SSFError.verificationKeyUnavailable("Unsupported EC curve \(crv ?? "nil"); only P-256 is supported")
            }
            guard let xString = x, let yString = y,
                  let xData = Data(base64URLEncoded: xString),
                  let yData = Data(base64URLEncoded: yString) else {
                throw SSFError.verificationKeyUnavailable("EC JWK is missing x/y coordinates")
            }

            // Create uncompressed point representation (0x04 + x + y)
            var keyData = Data([0x04])
            keyData.append(xData)
            keyData.append(yData)

            return .es256(try P256.Signing.PublicKey(x963Representation: keyData))

        case "RSA":
            guard let nString = n, let eString = e,
                  let nData = Data(base64URLEncoded: nString),
                  let eData = Data(base64URLEncoded: eString) else {
                throw SSFError.verificationKeyUnavailable("RSA JWK is missing n/e parameters")
            }

            return .rs256(try _RSA.Signing.PublicKey(n: nData, e: eData))

        default:
            throw SSFError.verificationKeyUnavailable("Unsupported JWK key type \(kty)")
        }
    }
}
