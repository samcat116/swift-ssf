import XCTest
@testable import SwiftSSF
import Foundation
import Crypto
import _CryptoExtras

final class JWTProcessorTests: XCTestCase {
    
    func testJWTParsingWithoutValidation() async throws {
        let processor = JWTProcessor()
        
        // Create a simple JWT for testing (header.payload.signature)
        let header = """
        {"alg":"ES256","typ":"JWT","kid":"test-key"}
        """
        let payload = """
        {"iss":"https://example.com","jti":"test-123","iat":1234567890,"aud":["test"],"events":{}}
        """
        
        let headerB64 = Data(header.utf8).base64URLEncodedString()
        let payloadB64 = Data(payload.utf8).base64URLEncodedString()
        let signatureB64 = "fake-signature"
        
        let jwt = "\(headerB64).\(payloadB64).\(signatureB64)"
        
        let (parsedHeader, parsedPayload) = try await processor.parseJWT(jwt)
        
        XCTAssertEqual(parsedHeader.alg, "ES256")
        XCTAssertEqual(parsedHeader.typ, "JWT")
        XCTAssertEqual(parsedHeader.kid, "test-key")
        
        XCTAssertEqual(parsedPayload["iss"] as? String, "https://example.com")
        XCTAssertEqual(parsedPayload["jti"] as? String, "test-123")
        XCTAssertEqual(parsedPayload["iat"] as? Int, 1234567890)
    }
    
    func testInvalidJWTFormat() async throws {
        let processor = JWTProcessor()
        
        // Test invalid JWT with wrong number of parts
        do {
            _ = try await processor.parseJWT("invalid.jwt")
            XCTFail("Should have thrown an error for invalid JWT format")
        } catch SSFError.invalidJWT(let message) {
            XCTAssertTrue(message.contains("exactly 3 parts"))
        }
    }
    
    func testCreateSecurityEventToken() async throws {
        let processor = JWTProcessor()
        let privateKey = P256.Signing.PrivateKey()
        
        let issuer = URL(string: "https://transmitter.example.com")!
        let audience = ["test-receiver"]
        let events: [String: [String: AnyCodable]] = [:]
        
        let token = try await processor.createSecurityEventToken(
            issuer: issuer,
            audience: audience,
            events: events,
            privateKey: privateKey
        )
        
        XCTAssertEqual(token.header.alg, "ES256")
        XCTAssertEqual(token.payload.iss, issuer)
        XCTAssertEqual(token.payload.aud, audience)
        XCTAssertNotNil(token.payload.jti)
    }
    
    func testSecurityEventTokenValidation() async throws {
        let processor = JWTProcessor()
        let privateKey = P256.Signing.PrivateKey()
        let publicKey = privateKey.publicKey
        
        let issuer = URL(string: "https://transmitter.example.com")!
        let audience = ["test-receiver"]
        let events: [String: [String: AnyCodable]] = [:]
        
        // Create a token
        let token = try await processor.createSecurityEventToken(
            issuer: issuer,
            audience: audience,
            events: events,
            privateKey: privateKey
        )
        
        // Validate the token
        let validatedToken = try await processor.parseSecurityEventToken(
            token.rawToken,
            expectedIssuer: issuer,
            expectedAudience: audience,
            key: .es256(publicKey)
        )
        
        XCTAssertEqual(validatedToken.payload.iss, issuer)
        XCTAssertEqual(validatedToken.payload.aud, audience)
    }
    
    func testSignatureVerificationFailure() async throws {
        let processor = JWTProcessor()
        let privateKey = P256.Signing.PrivateKey()
        let wrongPublicKey = P256.Signing.PrivateKey().publicKey // Different key
        
        let issuer = URL(string: "https://transmitter.example.com")!
        let audience = ["test-receiver"]
        let events: [String: [String: AnyCodable]] = [:]
        
        // Create a token with one key
        let token = try await processor.createSecurityEventToken(
            issuer: issuer,
            audience: audience,
            events: events,
            privateKey: privateKey
        )
        
        // Try to validate with wrong key
        do {
            _ = try await processor.parseSecurityEventToken(
                token.rawToken,
                expectedIssuer: issuer,
                expectedAudience: audience,
                key: .es256(wrongPublicKey)
            )
            XCTFail("Should have thrown signature verification error")
        } catch SSFError.signatureVerificationFailed {
            // Expected error
        }
    }
    
    func testIssuerValidation() async throws {
        let processor = JWTProcessor()
        let privateKey = P256.Signing.PrivateKey()
        
        let issuer = URL(string: "https://transmitter.example.com")!
        let wrongIssuer = URL(string: "https://wrong.example.com")!
        let audience = ["test-receiver"]
        let events: [String: [String: AnyCodable]] = [:]
        
        // Create a token
        let token = try await processor.createSecurityEventToken(
            issuer: issuer,
            audience: audience,
            events: events,
            privateKey: privateKey
        )
        
        // Try to validate with wrong issuer
        do {
            _ = try await processor.parseSecurityEventToken(
                token.rawToken,
                expectedIssuer: wrongIssuer,
                expectedAudience: audience,
                key: .es256(privateKey.publicKey)
            )
            XCTFail("Should have thrown invalid issuer error")
        } catch SSFError.invalidIssuer {
            // Expected error
        }
    }
    
    func testAudienceValidation() async throws {
        let processor = JWTProcessor()
        let privateKey = P256.Signing.PrivateKey()
        
        let issuer = URL(string: "https://transmitter.example.com")!
        let audience = ["test-receiver"]
        let wrongAudience = ["wrong-receiver"]
        let events: [String: [String: AnyCodable]] = [:]
        
        // Create a token
        let token = try await processor.createSecurityEventToken(
            issuer: issuer,
            audience: audience,
            events: events,
            privateKey: privateKey
        )
        
        // Try to validate with wrong audience
        do {
            _ = try await processor.parseSecurityEventToken(
                token.rawToken,
                expectedIssuer: issuer,
                expectedAudience: wrongAudience,
                key: .es256(privateKey.publicKey)
            )
            XCTFail("Should have thrown invalid audience error")
        } catch SSFError.invalidAudience {
            // Expected error
        }
    }

    // MARK: - SET type header validation

    func testRejectsTokenWithoutSETType() async throws {
        let processor = JWTProcessor()
        let privateKey = P256.Signing.PrivateKey()

        // An otherwise-valid token whose typ is "JWT" must be rejected:
        // it could be an access/ID token replayed into the event pipeline.
        let token = try Self.makeES256Token(
            header: #"{"alg":"ES256","typ":"JWT"}"#,
            payload: #"{"iss":"https://t.example.com","jti":"j1","iat":1700000000,"events":{}}"#,
            privateKey: privateKey
        )

        do {
            _ = try await processor.parseSecurityEventToken(token, key: .es256(privateKey.publicKey))
            XCTFail("Should have rejected typ JWT")
        } catch SSFError.invalidJWT(let message) {
            XCTAssertTrue(message.contains("typ"))
        }
    }

    func testAcceptsApplicationPrefixedSETType() async throws {
        let processor = JWTProcessor()
        let privateKey = P256.Signing.PrivateKey()

        let token = try Self.makeES256Token(
            header: #"{"alg":"ES256","typ":"application/secevent+jwt"}"#,
            payload: #"{"iss":"https://t.example.com","jti":"j1","iat":1700000000,"events":{}}"#,
            privateKey: privateKey
        )

        let parsed = try await processor.parseSecurityEventToken(token, key: .es256(privateKey.publicKey))
        XCTAssertEqual(parsed.payload.jti, "j1")
    }

    // MARK: - RS256

    func testRS256Verification() async throws {
        let processor = JWTProcessor()
        let privateKey = try _RSA.Signing.PrivateKey(keySize: .bits2048)

        let token = try Self.makeRS256Token(
            payload: #"{"iss":"https://t.example.com","jti":"rs-1","iat":1700000000,"aud":["r1"],"events":{}}"#,
            privateKey: privateKey
        )

        let parsed = try await processor.parseSecurityEventToken(
            token,
            expectedAudience: ["r1"],
            key: .rs256(privateKey.publicKey)
        )
        XCTAssertEqual(parsed.payload.jti, "rs-1")

        // Wrong RSA key must fail
        let otherKey = try _RSA.Signing.PrivateKey(keySize: .bits2048)
        do {
            _ = try await processor.parseSecurityEventToken(token, key: .rs256(otherKey.publicKey))
            XCTFail("Should have failed with wrong RSA key")
        } catch SSFError.signatureVerificationFailed {
            // Expected
        }
    }

    func testAlgorithmKeyMismatchRejected() async throws {
        let processor = JWTProcessor()
        let ecKey = P256.Signing.PrivateKey()

        // ES256-signed token verified against an RSA key must be rejected,
        // not silently accepted (algorithm confusion).
        let token = try Self.makeES256Token(
            header: #"{"alg":"ES256","typ":"secevent+jwt"}"#,
            payload: #"{"iss":"https://t.example.com","jti":"j1","iat":1700000000,"events":{}}"#,
            privateKey: ecKey
        )

        let rsaKey = try _RSA.Signing.PrivateKey(keySize: .bits2048)
        do {
            _ = try await processor.parseSecurityEventToken(token, key: .rs256(rsaKey.publicKey))
            XCTFail("Should have rejected alg/key mismatch")
        } catch SSFError.unsupportedAlgorithm(let alg) {
            XCTAssertEqual(alg, "ES256")
        }
    }

    // MARK: - Audience forms

    func testAudienceAsSingleString() async throws {
        let processor = JWTProcessor()
        let privateKey = P256.Signing.PrivateKey()

        // RFC 7519 allows "aud" to be a bare string
        let token = try Self.makeES256Token(
            header: #"{"alg":"ES256","typ":"secevent+jwt"}"#,
            payload: #"{"iss":"https://t.example.com","jti":"j1","iat":1700000000,"aud":"receiver-1","events":{}}"#,
            privateKey: privateKey
        )

        let parsed = try await processor.parseSecurityEventToken(
            token,
            expectedAudience: ["receiver-1"],
            key: .es256(privateKey.publicKey)
        )
        XCTAssertEqual(parsed.payload.aud, ["receiver-1"])
    }

    // MARK: - Test helpers

    static func makeES256Token(header: String, payload: String, privateKey: P256.Signing.PrivateKey) throws -> String {
        let signingInput = "\(Data(header.utf8).base64URLEncodedString()).\(Data(payload.utf8).base64URLEncodedString())"
        let signature = try privateKey.signature(for: Data(signingInput.utf8))
        return "\(signingInput).\(signature.rawRepresentation.base64URLEncodedString())"
    }

    static func makeRS256Token(payload: String, privateKey: _RSA.Signing.PrivateKey) throws -> String {
        let header = #"{"alg":"RS256","typ":"secevent+jwt"}"#
        let signingInput = "\(Data(header.utf8).base64URLEncodedString()).\(Data(payload.utf8).base64URLEncodedString())"
        let signature = try privateKey.signature(
            for: SHA256.hash(data: Data(signingInput.utf8)),
            padding: .insecurePKCS1v1_5
        )
        return "\(signingInput).\(signature.rawRepresentation.base64URLEncodedString())"
    }
}

// MARK: - JWK conversion tests

final class JWKSClientTests: XCTestCase {

    func testECJWKConversion() throws {
        let privateKey = P256.Signing.PrivateKey()
        let x963 = privateKey.publicKey.x963Representation
        // x963 = 0x04 || x (32 bytes) || y (32 bytes)
        let x = x963.subdata(in: 1..<33)
        let y = x963.subdata(in: 33..<65)

        let jwk = JWK(
            kty: "EC",
            use: "sig",
            kid: "ec-key",
            crv: "P-256",
            x: x.base64URLEncodedString(),
            y: y.base64URLEncodedString()
        )

        guard case .es256(let key) = try jwk.toVerificationKey() else {
            return XCTFail("Expected ES256 key")
        }
        XCTAssertEqual(key.x963Representation, x963)
    }

    func testRSAJWKConversion() throws {
        let privateKey = try _RSA.Signing.PrivateKey(keySize: .bits2048)
        let publicKey = privateKey.publicKey

        let primitives = try publicKey.getKeyPrimitives()
        let jwk = JWK(
            kty: "RSA",
            use: "sig",
            kid: "rsa-key",
            n: Data(primitives.modulus).base64URLEncodedString(),
            e: Data(primitives.publicExponent).base64URLEncodedString()
        )

        guard case .rs256 = try jwk.toVerificationKey() else {
            return XCTFail("Expected RS256 key")
        }
    }

    func testUnsupportedKeyTypeThrows() throws {
        let jwk = JWK(kty: "OKP", kid: "ed-key", crv: "Ed25519")
        XCTAssertThrowsError(try jwk.toVerificationKey())
    }
}

// MARK: - Base64URL Extension Tests

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