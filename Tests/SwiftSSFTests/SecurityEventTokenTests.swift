import XCTest
@testable import SwiftSSF
import Foundation

final class SecurityEventTokenTests: XCTestCase {

    func testSecurityEventTokenCreation() throws {
        let issuer = URL(string: "https://transmitter.example.com")!
        let events: [String: [String: AnyCodable]] = [:]

        let payload = SecurityEventPayload(
            iss: issuer,
            jti: "test-jti-123",
            iat: Int64(Date().timeIntervalSince1970),
            aud: ["test-audience"],
            sub_id: .email("user@example.com"),
            events: events
        )

        let header = JWTHeader(alg: "ES256", typ: "secevent+jwt", kid: "test-key-id")
        let token = SecurityEventToken(
            header: header,
            payload: payload,
            rawToken: "test.jwt.token"
        )

        XCTAssertEqual(token.header.alg, "ES256")
        XCTAssertEqual(token.payload.iss, issuer)
        XCTAssertEqual(token.payload.jti, "test-jti-123")
        XCTAssertEqual(token.rawToken, "test.jwt.token")
    }

    // MARK: - Subject identifiers (RFC 9493)

    func testEmailSubjectIdentifierRoundTrip() throws {
        let subject = SubjectIdentifier.email("user@example.com")

        let data = try JSONEncoder().encode(subject)
        let json = try JSONSerialization.jsonObject(with: data) as? [String: Any]
        XCTAssertEqual(json?["format"] as? String, "email")
        XCTAssertEqual(json?["email"] as? String, "user@example.com")

        let decoded = try JSONDecoder().decode(SubjectIdentifier.self, from: data)
        XCTAssertEqual(decoded.format, "email")
        XCTAssertEqual(decoded.string("email"), "user@example.com")
    }

    func testIssSubSubjectIdentifier() throws {
        let subject = SubjectIdentifier.issSub(iss: "https://idp.example.com", sub: "user-42")

        let data = try JSONEncoder().encode(subject)
        let decoded = try JSONDecoder().decode(SubjectIdentifier.self, from: data)
        XCTAssertEqual(decoded.format, "iss_sub")
        XCTAssertEqual(decoded.string("iss"), "https://idp.example.com")
        XCTAssertEqual(decoded.string("sub"), "user-42")
    }

    func testComplexSubjectDecoding() throws {
        // CAEP transmitters commonly identify both the session and the user
        let json = """
        {
            "format": "complex",
            "session": {"format": "opaque", "id": "session-123"},
            "user": {"format": "email", "email": "user@example.com"}
        }
        """

        let subject = try JSONDecoder().decode(SubjectIdentifier.self, from: Data(json.utf8))
        XCTAssertEqual(subject.format, "complex")

        let user = subject.subject("user")
        XCTAssertEqual(user?.format, "email")
        XCTAssertEqual(user?.string("email"), "user@example.com")

        let session = subject.subject("session")
        XCTAssertEqual(session?.format, "opaque")
        XCTAssertEqual(session?.string("id"), "session-123")
    }

    func testComplexSubjectConstructionRoundTrip() throws {
        let subject = SubjectIdentifier.complex(
            user: .email("user@example.com"),
            session: .opaque(id: "session-123")
        )

        let data = try JSONEncoder().encode(subject)
        let decoded = try JSONDecoder().decode(SubjectIdentifier.self, from: data)

        XCTAssertEqual(decoded.format, "complex")
        XCTAssertEqual(decoded.subject("user")?.string("email"), "user@example.com")
        XCTAssertEqual(decoded.subject("session")?.string("id"), "session-123")
    }

    // MARK: - Typed event access

    func testTypedEventDecoding() throws {
        let json = """
        {
            "iss": "https://transmitter.example.com",
            "jti": "jti-1",
            "iat": 1700000000,
            "aud": "receiver",
            "sub_id": {"format": "email", "email": "user@example.com"},
            "events": {
                "https://schemas.openid.net/secevent/caep/event-type/credential-change": {
                    "credential_type": "fido2-roaming",
                    "change_type": "create",
                    "fido2_aaguid": "accced6a-63f5-490a-9eea-e59bc1896cfc",
                    "friendly_name": "Jane's USB authenticator",
                    "event_timestamp": 1615304991
                }
            }
        }
        """

        let payload = try JSONDecoder().decode(SecurityEventPayload.self, from: Data(json.utf8))
        XCTAssertEqual(payload.eventTypes, [CAEPEventTypes.credentialChange])

        let event = try payload.event(CAEPEventTypes.credentialChange, as: CredentialChangeEvent.self)
        XCTAssertEqual(event?.credential_type, "fido2-roaming")
        XCTAssertEqual(event?.change_type, "create")
        XCTAssertEqual(event?.event_timestamp, 1615304991)

        // Absent event types return nil rather than throwing
        XCTAssertNil(try payload.event(CAEPEventTypes.sessionRevoked, as: SessionRevokedEvent.self))
    }

    func testVerificationEventDecoding() throws {
        let json = """
        {
            "iss": "https://transmitter.example.com",
            "jti": "jti-2",
            "iat": 1700000000,
            "events": {
                "https://schemas.openid.net/secevent/ssf/event-type/verification": {
                    "state": "correlate-me"
                }
            }
        }
        """

        let payload = try JSONDecoder().decode(SecurityEventPayload.self, from: Data(json.utf8))
        let event = try payload.event(SSFEventTypes.verification, as: VerificationEvent.self)
        XCTAssertEqual(event?.state, "correlate-me")
    }

    // MARK: - AnyCodable

    func testAnyCodableEncoding() throws {
        let stringValue = AnyCodable("test")
        let intValue = AnyCodable(42)
        let boolValue = AnyCodable(true)

        let encoder = JSONEncoder()
        let decoder = JSONDecoder()

        // Test string
        let stringData = try encoder.encode(stringValue)
        let decodedString = try decoder.decode(AnyCodable.self, from: stringData)
        XCTAssertEqual(decodedString.value as? String, "test")

        // Test int
        let intData = try encoder.encode(intValue)
        let decodedInt = try decoder.decode(AnyCodable.self, from: intData)
        XCTAssertEqual(decodedInt.value as? Int, 42)

        // Test bool
        let boolData = try encoder.encode(boolValue)
        let decodedBool = try decoder.decode(AnyCodable.self, from: boolData)
        XCTAssertEqual(decodedBool.value as? Bool, true)
    }
}
