#![forbid(unsafe_code)]

//! Identify by saml: a SAML 2.0 assertion's subject and issuer, read and not
//! verified.
//!
//! An identity provider asserts who a subject is and signs the assertion;
//! the subject then carries it to the service. Who the assertion says the
//! subject is — the `NameID` — and who says so — the `Issuer` — are in the
//! clear, and this identifier reads them: the `NameID` is the claim, the
//! issuer and the `NameID` format ride beside it as evidence, and the
//! assertion itself rides as proof for `authenticate/saml` to check the
//! signature and conditions against the `IdP` metadata. Nothing here checks
//! them; an assertion signed by nobody is presented exactly as one signed
//! by the right `IdP`. An `EncryptedAssertion` is recognised and refused: the
//! names are not readable and saying so is different from seeing nothing.
//!
//! The mechanism travels on both layers (ADR-0050 section 3). On the
//! transport layer the HTTP POST binding (SAML Bindings 3.5) carries the
//! response as standard base64 in the `SAMLResponse` form field, which the
//! HTTP transport promotes onto the arrival; on the message layer the
//! content is the XML itself — a SOAP-borne assertion, a WS-Security SAML
//! token — and the first section is scanned for an `Assertion`.
//!
//! What this reads and writes:
//!
//! ```text
//! http.form.samlresponse   the SAMLResponse field, base64   the property, by default
//! saml.issuer              the Issuer text                  evidence
//! saml.name-id-format      the NameID Format attribute      evidence, where present
//! principal.user           the NameID, or the UPN attribute evidence, where it is one
//! saml.assertion           the assertion, base64            proof
//! ```
//!
//! Principal evidence (ADR-0054): where the `NameID`'s format is
//! `emailAddress`, `WindowsDomainQualifiedName` or unspecified and its text is
//! a user principal name, or else where the assertion carries the UPN
//! attribute [`identify::saml::UPN_ATTRIBUTE`] and that is one, it is written as
//! `principal.user` in the capability's canonical form. The claim stays the
//! `NameID`; a persistent or transient identifier is never read as a name.
//!
//! On the transport layer the proof is the base64 exactly as it was posted;
//! on the message layer it is the `Assertion` element, encoded here, so the
//! second gate reads one shape. Only a pushed arrival carries a passed claim.

pub mod assertion;
use identify::evidence;
use identify::saml;
use identify::{IdentifyError, MessageIdentifier, Presented, StreamArrival, TransportIdentifier};
use message::Message;
use xcore::{Arriving, Mechanism};

pub use assertion::Assertion;

/// The property read by default: the posted `SAMLResponse` form field.
pub const SAML_RESPONSE: &str = "http.form.samlresponse";
/// The evidence name carrying the issuer.
pub const ISSUER: &str = "saml.issuer";
/// The evidence name carrying the `NameID` format.
pub const NAME_ID_FORMAT: &str = "saml.name-id-format";
/// Reads an assertion's subject, from a posted response or from the content.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Saml {
    property: String,
}

impl Saml {
    /// The response in the `SAMLResponse` form field the transport promoted.
    #[must_use]
    pub fn posted() -> Self {
        Self::in_property(SAML_RESPONSE)
    }

    /// The base64 response or assertion in a named property.
    #[must_use]
    pub fn in_property(property: impl Into<String>) -> Self {
        Self {
            property: property.into(),
        }
    }

    fn present(
        &self,
        assertion: &Assertion,
        xml: &str,
        proof: String,
    ) -> Result<Presented, IdentifyError> {
        let mut claim = Presented::passed(TransportIdentifier::mechanism(self), &assertion.name_id)
            .with_evidence(ISSUER, &assertion.issuer);
        if let Some(format) = &assertion.format {
            claim = claim.with_evidence(NAME_ID_FORMAT, format);
        }
        let upn = assertion.attribute_value(xml, saml::is_upn_attribute)?;
        let name = saml::user_principal(
            &assertion.name_id,
            assertion.format.as_deref(),
            upn.as_deref(),
        );
        if let Some(name) = name {
            claim = claim.with_evidence(evidence::PRINCIPAL_USER, name.to_string());
        }
        Ok(claim.with_proof(evidence::SAML_ASSERTION, proof))
    }
}

impl TransportIdentifier for Saml {
    fn mechanism(&self) -> Mechanism {
        xcore::mechanism::saml()
    }

    fn identify(&self, arrival: &StreamArrival<'_>) -> Result<Option<Presented>, IdentifyError> {
        if arrival.arriving() != Arriving::Pushed {
            return Ok(None);
        }
        let Some(posted) = arrival.property(&self.property) else {
            return Ok(None);
        };

        let bytes = saml::decode(posted)?;
        let xml = String::from_utf8(bytes)
            .map_err(|_| IdentifyError::new("the SAML response is not UTF-8 XML"))?;

        let Some(assertion) = Assertion::scan(&xml)? else {
            return Err(IdentifyError::new("the SAML response carries no Assertion"));
        };
        self.present(&assertion, &xml, posted.to_string()).map(Some)
    }
}

impl MessageIdentifier for Saml {
    fn mechanism(&self) -> Mechanism {
        TransportIdentifier::mechanism(self)
    }

    fn identify(&self, message: &Message) -> Result<Option<Presented>, IdentifyError> {
        let Some(section) = message.sections().first() else {
            return Ok(None);
        };
        let Ok(xml) = core::str::from_utf8(section.stream.bytes()) else {
            return Ok(None);
        };
        if !xml.contains("Assertion") {
            return Ok(None);
        }

        let Some(assertion) = Assertion::scan(xml)? else {
            return Ok(None);
        };
        let proof = codec::base64::encode(&xml.as_bytes()[assertion.span.0..assertion.span.1]);
        self.present(&assertion, xml, proof).map(Some)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use context::MessageContext;
    use message::{MessageSection, MessageTreatment};
    use stream::Stream;
    use xcore::{Established, Layer, MessageId, SectionId, StreamId};

    const RESPONSE: &str = concat!(
        r#"<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol""#,
        r#" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">"#,
        "<saml:Issuer>https://idp.example</saml:Issuer>",
        r#"<saml:Assertion ID="a1">"#,
        "<saml:Issuer>https://idp.example</saml:Issuer>",
        "<saml:Subject>",
        r#"<saml:NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:persistent">"#,
        "partner-x</saml:NameID>",
        "</saml:Subject>",
        "</saml:Assertion>",
        "</samlp:Response>"
    );

    fn stream() -> Stream {
        Stream::new(StreamId::new(1), b"".to_vec(), None)
    }

    fn posted(text: &str) -> Vec<(String, String)> {
        vec![(
            SAML_RESPONSE.to_string(),
            codec::base64::encode(text.as_bytes()),
        )]
    }

    fn message(bytes: &[u8]) -> Message {
        Message::received(
            MessageId::new(1),
            vec![MessageSection {
                section_id: SectionId::new(2),
                name: None,
                stream: Stream::new(StreamId::new(3), bytes.to_vec(), None),
                contract: None,
            }],
            MessageContext::new(),
            MessageTreatment::default(),
        )
    }

    #[test]
    fn a_posted_response_is_presented_by_its_name_id_with_the_issuer_beside() {
        let stream = stream();
        let properties = posted(RESPONSE);
        let arrival = StreamArrival::new(&stream, Arriving::Pushed, "https://x/acs", &properties);

        let claim = TransportIdentifier::identify(&Saml::posted(), &arrival)
            .expect("read")
            .expect("a claim");

        assert_eq!(claim.value, "partner-x");
        assert_eq!(claim.established, Established::Passed);
        assert_eq!(claim.layer(), Layer::Transport);
        assert_eq!(claim.mechanism.name(), "saml");
        assert_eq!(
            claim.evidence,
            vec![
                (ISSUER.to_string(), "https://idp.example".to_string()),
                (
                    NAME_ID_FORMAT.to_string(),
                    "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent".to_string()
                ),
            ]
        );
        assert_eq!(
            claim.proof(evidence::SAML_ASSERTION),
            Some(properties[0].1.as_str())
        );
    }

    /// An assertion with this `NameID` element and these attribute statements.
    fn presented(name_id: &str, statements: &str) -> Presented {
        let xml = format!(
            "<saml:Assertion><saml:Issuer>https://idp.example</saml:Issuer>\
             <saml:Subject>{name_id}</saml:Subject>{statements}</saml:Assertion>"
        );
        let stream = stream();
        let properties = posted(&xml);
        let arrival = StreamArrival::new(&stream, Arriving::Pushed, "https://x/acs", &properties);

        TransportIdentifier::identify(&Saml::posted(), &arrival)
            .expect("read")
            .expect("a claim")
    }

    fn upn_statement(text: &str) -> String {
        format!(
            "<saml:AttributeStatement><saml:Attribute Name=\"{}\">\
             <saml:AttributeValue>{text}</saml:AttributeValue></saml:Attribute>\
             </saml:AttributeStatement>",
            saml::UPN_ATTRIBUTE
        )
    }

    fn principals(claim: &Presented) -> Vec<(&str, &str)> {
        claim
            .evidence
            .iter()
            .filter(|(name, _)| name.starts_with("principal."))
            .map(|(name, value)| (name.as_str(), value.as_str()))
            .collect()
    }

    #[test]
    fn a_name_id_that_is_a_principal_name_is_written_in_canonical_form() {
        let claim = presented(
            "<saml:NameID Format=\"urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress\">\
             Jane@Partner-X.Example</saml:NameID>",
            "",
        );
        assert_eq!(claim.value, "Jane@Partner-X.Example", "the value stands");
        assert_eq!(
            principals(&claim),
            [(evidence::PRINCIPAL_USER, "Jane@partner-x.example")]
        );

        let claim = presented("<saml:NameID>PARTNERX\\jane</saml:NameID>", "");
        assert_eq!(
            principals(&claim),
            [(evidence::PRINCIPAL_USER, "jane@partnerx")]
        );
    }

    #[test]
    fn the_upn_attribute_names_the_user_where_the_name_id_does_not() {
        let claim = presented(
            "<saml:NameID Format=\"urn:oasis:names:tc:SAML:2.0:nameid-format:persistent\">\
             opaque@Idp.Example</saml:NameID>",
            &upn_statement("Jane@Partner-X.Example"),
        );

        assert_eq!(claim.value, "opaque@Idp.Example");
        assert_eq!(
            principals(&claim),
            [(evidence::PRINCIPAL_USER, "Jane@partner-x.example")]
        );
    }

    #[test]
    fn text_that_is_not_a_principal_name_gains_no_principal_evidence() {
        let persistent = presented(
            "<saml:NameID Format=\"urn:oasis:names:tc:SAML:2.0:nameid-format:persistent\">\
             opaque@idp.example</saml:NameID>",
            "",
        );
        let bare = presented("<saml:NameID>jane</saml:NameID>", &upn_statement("jane"));

        assert!(principals(&persistent).is_empty(), "a persistent id");
        assert!(principals(&bare).is_empty(), "a bare user");
    }

    #[test]
    fn an_arrival_without_a_posted_response_presents_nothing() {
        let stream = stream();
        let arrival = StreamArrival::new(&stream, Arriving::Pushed, "https://x/acs", &[]);

        assert!(
            TransportIdentifier::identify(&Saml::posted(), &arrival)
                .expect("read")
                .is_none()
        );
    }

    #[test]
    fn a_response_that_is_not_base64_is_an_error_naming_why() {
        let stream = stream();
        let properties = [(SAML_RESPONSE.to_string(), "<not base64>".to_string())];
        let arrival = StreamArrival::new(&stream, Arriving::Pushed, "https://x/acs", &properties);

        let failure =
            TransportIdentifier::identify(&Saml::posted(), &arrival).expect_err("not base64");

        assert!(failure.message.contains("not base64"), "{failure}");
    }

    #[test]
    fn a_response_without_an_assertion_is_an_error_and_not_an_absence() {
        let stream = stream();
        let properties = posted("<samlp:Response><samlp:Status/></samlp:Response>");
        let arrival = StreamArrival::new(&stream, Arriving::Pushed, "https://x/acs", &properties);

        let failure =
            TransportIdentifier::identify(&Saml::posted(), &arrival).expect_err("no assertion");

        assert!(failure.message.contains("no Assertion"), "{failure}");
    }

    #[test]
    fn an_assertion_in_the_content_is_read_on_the_message_layer_and_encoded_as_proof() {
        let claim = MessageIdentifier::identify(&Saml::posted(), &message(RESPONSE.as_bytes()))
            .expect("read")
            .expect("a claim");

        assert_eq!(claim.value, "partner-x");
        assert_eq!(
            claim.layer(),
            Layer::Transport,
            "the mechanism decides the layer"
        );
        let proof = claim.proof(evidence::SAML_ASSERTION).expect("proof");
        let decoded =
            String::from_utf8(codec::base64::decode(proof).expect("base64")).expect("text");
        assert!(decoded.starts_with("<saml:Assertion"));
        assert!(decoded.ends_with("</saml:Assertion>"));
    }

    #[test]
    fn content_without_an_assertion_presents_nothing() {
        assert!(
            MessageIdentifier::identify(&Saml::posted(), &message(b"<Order/>"))
                .expect("read")
                .is_none()
        );
        assert!(
            MessageIdentifier::identify(&Saml::posted(), &message(&[0xff, 0xfe]))
                .expect("read")
                .is_none()
        );
    }

    #[test]
    fn a_scheduled_pickup_presents_nothing_because_nobody_posted_anything() {
        let stream = stream();
        let properties = posted(RESPONSE);
        let arrival =
            StreamArrival::new(&stream, Arriving::Scheduled, "https://idp/out", &properties);

        assert!(
            TransportIdentifier::identify(&Saml::posted(), &arrival)
                .expect("read")
                .is_none()
        );
    }
}
