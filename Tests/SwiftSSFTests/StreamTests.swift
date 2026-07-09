import XCTest
@testable import SwiftSSF
import Foundation

final class StreamTests: XCTestCase {

    // MARK: - Stream Configuration (SSF 1.0 §8.1.1)

    func testStreamConfigurationDecodingSpecExample() throws {
        // Mirrors the shape of the spec's stream configuration example
        let json = """
        {
            "stream_id": "f67e39a0a4d34d56b3aa1bc4cff0069f",
            "iss": "https://tr.example.com",
            "aud": ["https://rp.example.com"],
            "events_supported": [
                "https://schemas.openid.net/secevent/caep/event-type/session-revoked"
            ],
            "events_requested": [
                "https://schemas.openid.net/secevent/caep/event-type/session-revoked"
            ],
            "events_delivered": [
                "https://schemas.openid.net/secevent/caep/event-type/session-revoked"
            ],
            "delivery": {
                "method": "urn:ietf:rfc:8936",
                "endpoint_url": "https://tr.example.com/poll/f67e39a0"
            },
            "min_verification_interval": 60,
            "inactivity_timeout": 86400
        }
        """

        let stream = try JSONDecoder().decode(StreamConfiguration.self, from: Data(json.utf8))

        XCTAssertEqual(stream.stream_id, "f67e39a0a4d34d56b3aa1bc4cff0069f")
        XCTAssertEqual(stream.iss, URL(string: "https://tr.example.com"))
        XCTAssertEqual(stream.aud, ["https://rp.example.com"])
        XCTAssertEqual(stream.events_delivered?.count, 1)
        XCTAssertEqual(stream.delivery?.method, .poll)
        XCTAssertEqual(stream.delivery?.endpoint_url, URL(string: "https://tr.example.com/poll/f67e39a0"))
        XCTAssertEqual(stream.min_verification_interval, 60)
        XCTAssertEqual(stream.inactivity_timeout, 86400)
    }

    func testStreamConfigurationDecodesStringAudience() throws {
        // The spec allows "aud" to be a single string
        let json = """
        {
            "stream_id": "s1",
            "iss": "https://tr.example.com",
            "aud": "https://rp.example.com"
        }
        """

        let stream = try JSONDecoder().decode(StreamConfiguration.self, from: Data(json.utf8))
        XCTAssertEqual(stream.aud, ["https://rp.example.com"])
    }

    func testDeliveryMethodSerialization() throws {
        XCTAssertEqual(DeliveryMethod.push.rawValue, "urn:ietf:rfc:8935")
        XCTAssertEqual(DeliveryMethod.poll.rawValue, "urn:ietf:rfc:8936")

        let encoder = JSONEncoder()
        let decoder = JSONDecoder()

        for method in DeliveryMethod.allCases {
            let decoded = try decoder.decode(DeliveryMethod.self, from: try encoder.encode(method))
            XCTAssertEqual(decoded, method)
        }
    }

    // MARK: - Stream Status (SSF 1.0 §8.1.2)

    func testStreamStatusValues() throws {
        // The spec defines exactly these three states (no "configuring")
        XCTAssertEqual(
            Set(StreamStatus.allCases.map(\.rawValue)),
            Set(["enabled", "paused", "disabled"])
        )
    }

    func testStreamStatusResponseCoding() throws {
        let json = """
        {"stream_id": "s1", "status": "paused", "reason": "Investigating anomalous activity"}
        """
        let status = try JSONDecoder().decode(StreamStatusResponse.self, from: Data(json.utf8))
        XCTAssertEqual(status.stream_id, "s1")
        XCTAssertEqual(status.status, .paused)
        XCTAssertEqual(status.reason, "Investigating anomalous activity")
    }

    // MARK: - Requests

    func testCreateStreamRequestOmitsTransmitterSuppliedFields() throws {
        // Receivers only send events_requested, delivery, and description;
        // aud/iss/stream_id are transmitter-supplied
        let request = CreateStreamRequest(
            events_requested: ["https://schemas.openid.net/secevent/caep/event-type/session-revoked"],
            delivery: DeliveryConfiguration(method: .poll),
            description: "Poll stream"
        )

        let encoded = try JSONSerialization.jsonObject(with: JSONEncoder().encode(request)) as? [String: Any]
        XCTAssertNil(encoded?["aud"])
        XCTAssertNil(encoded?["stream_id"])
        XCTAssertNotNil(encoded?["events_requested"])

        // Poll delivery requests must not invent an endpoint_url; the
        // transmitter supplies it in the response
        let delivery = encoded?["delivery"] as? [String: Any]
        XCTAssertEqual(delivery?["method"] as? String, "urn:ietf:rfc:8936")
        XCTAssertNil(delivery?["endpoint_url"])
    }

    func testUpdateStreamRequestCarriesStreamID() throws {
        let request = UpdateStreamRequest(
            stream_id: "s1",
            events_requested: ["https://schemas.openid.net/secevent/caep/event-type/credential-change"]
        )

        let encoded = try JSONSerialization.jsonObject(with: JSONEncoder().encode(request)) as? [String: Any]
        XCTAssertEqual(encoded?["stream_id"] as? String, "s1")
    }

    func testSubjectRequestsCarryStreamIDAndVerified() throws {
        let subject = SubjectIdentifier.email("user@example.com")

        let add = AddSubjectRequest(stream_id: "s1", subject: subject, verified: true)
        let addEncoded = try JSONSerialization.jsonObject(with: JSONEncoder().encode(add)) as? [String: Any]
        XCTAssertEqual(addEncoded?["stream_id"] as? String, "s1")
        XCTAssertEqual(addEncoded?["verified"] as? Bool, true)

        let remove = RemoveSubjectRequest(stream_id: "s1", subject: subject)
        let removeEncoded = try JSONSerialization.jsonObject(with: JSONEncoder().encode(remove)) as? [String: Any]
        XCTAssertEqual(removeEncoded?["stream_id"] as? String, "s1")
    }

    func testVerificationRequestCoding() throws {
        let request = VerificationRequest(stream_id: "s1", state: "correlate-me")
        let encoded = try JSONSerialization.jsonObject(with: JSONEncoder().encode(request)) as? [String: Any]
        XCTAssertEqual(encoded?["stream_id"] as? String, "s1")
        XCTAssertEqual(encoded?["state"] as? String, "correlate-me")
    }

    // MARK: - Poll wire format (RFC 8936)

    func testPollResponseDecoding() throws {
        // "sets" is an object keyed by jti; the flag is camelCase moreAvailable
        let json = """
        {
            "sets": {
                "jti-1": "eyJhbGciOi...",
                "jti-2": "eyJhbGciOi..."
            },
            "moreAvailable": true
        }
        """

        let response = try JSONDecoder().decode(PollResponse.self, from: Data(json.utf8))
        XCTAssertEqual(response.sets.count, 2)
        XCTAssertNotNil(response.sets["jti-1"])
        XCTAssertEqual(response.moreAvailable, true)
    }

    func testPollRequestEncoding() throws {
        let request = PollRequest(
            maxEvents: 10,
            returnImmediately: true,
            ack: ["jti-1"],
            setErrs: ["jti-2": SETErrorStatus(err: "invalid_key", description: "bad signature")]
        )

        let encoded = try JSONSerialization.jsonObject(with: JSONEncoder().encode(request)) as? [String: Any]
        XCTAssertEqual(encoded?["maxEvents"] as? Int, 10)
        XCTAssertEqual(encoded?["returnImmediately"] as? Bool, true)
        XCTAssertEqual(encoded?["ack"] as? [String], ["jti-1"])

        let errs = encoded?["setErrs"] as? [String: Any]
        let err = errs?["jti-2"] as? [String: Any]
        XCTAssertEqual(err?["err"] as? String, "invalid_key")
    }

    // MARK: - Discovery (SSF 1.0 §7.1.1)

    func testWellKnownURLForRootIssuer() throws {
        let url = try SSFHTTPClient.wellKnownConfigurationURL(for: URL(string: "https://tr.example.com")!)
        XCTAssertEqual(url.absoluteString, "https://tr.example.com/.well-known/ssf-configuration")
    }

    func testWellKnownURLInsertsBetweenHostAndPath() throws {
        // Per spec, the well-known path goes between host and path components
        let url = try SSFHTTPClient.wellKnownConfigurationURL(for: URL(string: "https://tr.example.com/tenant/a")!)
        XCTAssertEqual(url.absoluteString, "https://tr.example.com/.well-known/ssf-configuration/tenant/a")
    }

    func testTransmitterConfigurationDecoding() throws {
        let json = """
        {
            "issuer": "https://tr.example.com",
            "spec_version": "1_0",
            "jwks_uri": "https://tr.example.com/jwks.json",
            "delivery_methods_supported": ["urn:ietf:rfc:8935", "urn:ietf:rfc:8936"],
            "configuration_endpoint": "https://tr.example.com/ssf/mgmt/stream",
            "status_endpoint": "https://tr.example.com/ssf/mgmt/status",
            "add_subject_endpoint": "https://tr.example.com/ssf/mgmt/subject:add",
            "remove_subject_endpoint": "https://tr.example.com/ssf/mgmt/subject:remove",
            "verification_endpoint": "https://tr.example.com/ssf/mgmt/verification",
            "critical_subject_members": ["user"],
            "authorization_schemes": [{"spec_urn": "urn:ietf:rfc:6749"}],
            "default_subjects": "ALL"
        }
        """

        let config = try JSONDecoder().decode(TransmitterConfiguration.self, from: Data(json.utf8))
        XCTAssertEqual(config.spec_version, "1_0")
        XCTAssertEqual(config.default_subjects, "ALL")
        XCTAssertEqual(config.critical_subject_members, ["user"])
        XCTAssertEqual(config.authorization_schemes?.first?.spec_urn, "urn:ietf:rfc:6749")
    }
}
