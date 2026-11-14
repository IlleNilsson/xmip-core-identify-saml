//! The two names a SAML 2.0 assertion carries in the clear, read in one
//! pass through the estate's one XML reader.
//!
//! An assertion is `<saml:Assertion>` with an `<saml:Issuer>` and, under
//! `<saml:Subject>`, a `<saml:NameID>`. The document is read a piece at a
//! time by `codec::xml::Reader` — the reader under the tree the second gate
//! reads the verified assertion with — so both gates read one text the same
//! way: entities, line ends and an attribute's white space as XML reads
//! them. No tree is built: what is read is kept as it passes, and reading
//! stops where the assertion ends. The assertion is the first element named
//! `Assertion` whatever its prefix; an `EncryptedAssertion` is recognized
//! and refused rather than mistaken for one. Until 2026-11-13 this file
//! scanned the text itself.
//!
//! **Where the schema puts them, and nowhere else.** The `Issuer`, `Subject`
//! and `AttributeStatement` read are the assertion's own children, the
//! `NameID` the `Subject`'s, an `Attribute` the statement's and its value
//! the attribute's — the same children the second gate reads from the
//! verified assertion. A `Subject` planted inside the assertion's
//! `Signature`, or anywhere deeper, is not the one read here, so the claim
//! this presents is the one the signature covers. It does not validate the
//! document, and it does not need to: one that fails the second gate's
//! signature check is refused there whatever this read.

use codec::xml::{Event, Malformed, Reader, Tag};
use identify::IdentifyError;

/// What the first gate reads out of an assertion.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Assertion {
    /// The `Issuer` text.
    pub issuer: String,
    /// The `NameID` text: the subject.
    pub name_id: String,
    /// The `NameID`'s `Format` attribute, where it has one.
    pub format: Option<String>,
    /// Where the `Assertion` element starts and ends in the document.
    pub span: (usize, usize),
    /// Each `Attribute` of the assertion's own attribute statements: its
    /// `Name` and its first `AttributeValue`, in order.
    pub attributes: Vec<(String, Option<String>)>,
}

impl Assertion {
    /// Find the assertion in `xml` and read its names.
    ///
    /// `None` where the document has no `Assertion` element at all.
    ///
    /// # Errors
    ///
    /// Where the document is not XML, the assertion is encrypted, or it
    /// names no issuer or no subject.
    pub fn scan(xml: &str) -> Result<Option<Self>, IdentifyError> {
        let mut reader = Reader::document(xml);
        let mut encrypted = false;
        let (start, tag) = loop {
            // Until the assertion, only the elements matter.
            let Some(piece) = reader.read_tag().map_err(not_xml)? else {
                return if encrypted {
                    Err(IdentifyError::new(
                        "the SAML assertion is encrypted and this gate cannot read it",
                    ))
                } else {
                    Ok(None)
                };
            };
            if let Event::Start(tag) = piece.event {
                match tag.local() {
                    "Assertion" => break (piece.span, tag),
                    "EncryptedAssertion" => encrypted = true,
                    _ => {}
                }
            }
        };
        let mut read = Reading::default();
        let end = if tag.empty() {
            start.end
        } else {
            loop {
                let piece = reader
                    .read()
                    .map_err(not_xml)?
                    .ok_or_else(|| IdentifyError::new("the SAML assertion is not closed"))?;
                match piece.event {
                    Event::End(_) if read.open.is_empty() => break piece.span.end,
                    other => read.take(other)?,
                }
            }
        };
        let no_subject = || IdentifyError::new("the SAML assertion names no subject: no NameID");
        Ok(Some(Self {
            issuer: read
                .issuer
                .ok_or_else(|| IdentifyError::new("the SAML assertion names no Issuer"))?,
            name_id: read.name_id.ok_or_else(no_subject)?,
            format: read.format,
            span: (start.start, end),
            attributes: read.attributes,
        }))
    }

    /// The first `AttributeValue` of the first `Attribute` whose `Name`
    /// `named` accepts, among the assertion's own attribute statements.
    #[must_use]
    pub fn attribute_value(&self, named: impl Fn(&str) -> bool) -> Option<&str> {
        self.attributes
            .iter()
            .find(|(name, _)| named(name))
            .and_then(|(_, value)| value.as_deref())
    }
}

fn not_xml(refused: Malformed) -> IdentifyError {
    IdentifyError::new(format!("the SAML is not XML: {refused}"))
}

/// What an element open inside the assertion is to this reading.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Role {
    Issuer,
    Subject,
    NameId,
    Statement,
    Attribute,
    Value,
    Other,
}

/// The first `Issuer` was met.
const ISSUER: u8 = 1;
/// The first `Subject` was met.
const SUBJECT: u8 = 2;
/// The first `Subject`'s first `NameID` was met.
const NAME_ID: u8 = 4;

/// The assertion's names, kept as its pieces pass.
#[derive(Default)]
struct Reading {
    /// The elements open inside the assertion, by what each is.
    open: Vec<Role>,
    /// Which of the first `Issuer`, the first `Subject` and its first
    /// `NameID` were met ([`ISSUER`], [`SUBJECT`], [`NAME_ID`]).
    met: u8,
    issuer: Option<String>,
    name_id: Option<String>,
    format: Option<String>,
    attributes: Vec<(String, Option<String>)>,
    /// Whether the open `Attribute` has had its first value.
    valued: bool,
    /// The text of the element whose text is kept, so far.
    text: String,
}

impl Reading {
    fn take(&mut self, event: Event<'_>) -> Result<(), IdentifyError> {
        match event {
            Event::Start(tag) => {
                let role = self.role(&tag)?;
                self.open.push(role);
                if self.keeping() {
                    self.text.clear();
                }
                if tag.empty() {
                    self.close();
                }
            }
            Event::End(_) => self.close(),
            Event::Text(text) if self.keeping() => {
                self.text.push_str(&codec::xml::line_ends(text));
            }
            Event::CData(data) if self.keeping() => self.text.push_str(data),
            Event::Reference(name) if self.keeping() => {
                self.text.push(codec::xml::entity(name)?);
            }
            _ => {}
        }
        Ok(())
    }

    fn keeping(&self) -> bool {
        matches!(
            self.open.last(),
            Some(Role::Issuer | Role::NameId | Role::Value)
        )
    }

    /// What the element `tag` opens is, where it stands.
    fn role(&mut self, tag: &Tag<'_>) -> Result<Role, IdentifyError> {
        Ok(match (self.open.last(), tag.local()) {
            (None, "Issuer") if self.met & ISSUER == 0 => {
                self.met |= ISSUER;
                Role::Issuer
            }
            (None, "Subject") if self.met & SUBJECT == 0 => {
                self.met |= SUBJECT;
                Role::Subject
            }
            (None, "AttributeStatement") => Role::Statement,
            (Some(Role::Subject), "NameID") if self.met & NAME_ID == 0 => {
                self.met |= NAME_ID;
                self.format = attribute(tag, "Format")?;
                Role::NameId
            }
            (Some(Role::Statement), "Attribute") => match attribute(tag, "Name")? {
                Some(name) => {
                    self.attributes.push((name, None));
                    self.valued = false;
                    Role::Attribute
                }
                None => Role::Other,
            },
            (Some(Role::Attribute), "AttributeValue") if !self.valued => {
                self.valued = true;
                Role::Value
            }
            _ => Role::Other,
        })
    }

    fn close(&mut self) {
        let kept = || {
            let text = self.text.trim();
            (!text.is_empty()).then(|| text.to_string())
        };
        match self.open.last() {
            Some(Role::Issuer) => self.issuer = kept(),
            Some(Role::NameId) => self.name_id = kept(),
            Some(Role::Value) => {
                let value = kept();
                if let Some((_, slot)) = self.attributes.last_mut() {
                    *slot = value;
                }
            }
            _ => {}
        }
        self.open.pop();
    }
}

/// The value of the attribute `name` in no namespace on `tag`, as XML
/// reads it.
fn attribute(tag: &Tag<'_>, name: &str) -> Result<Option<String>, IdentifyError> {
    for written in tag.attributes() {
        let written = written.map_err(not_xml)?;
        if written.name == name {
            return Ok(Some(
                codec::xml::attribute_value(written.value)?.into_owned(),
            ));
        }
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;

    const RESPONSE: &str = r#"<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
    xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="r1">
  <saml:Issuer>https://idp.example/metadata</saml:Issuer>
  <saml:Assertion ID="a1" Version="2.0">
    <saml:Issuer>https://idp.example/metadata</saml:Issuer>
    <saml:Subject>
      <saml:NameID
        Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">
        jane&amp;co@party-x.example
      </saml:NameID>
      <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"/>
    </saml:Subject>
  </saml:Assertion>
</samlp:Response>"#;

    #[test]
    fn the_issuer_and_name_id_are_read_whatever_the_prefix_and_unescaped() {
        let assertion = Assertion::scan(RESPONSE)
            .expect("read")
            .expect("an assertion");

        assert_eq!(assertion.issuer, "https://idp.example/metadata");
        assert_eq!(assertion.name_id, "jane&co@party-x.example");
        assert_eq!(
            assertion.format.as_deref(),
            Some("urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress")
        );
        assert!(RESPONSE[assertion.span.0..assertion.span.1].starts_with("<saml:Assertion"));
        assert!(RESPONSE[assertion.span.0..assertion.span.1].ends_with("</saml:Assertion>"));
    }

    #[test]
    fn a_subject_planted_in_the_signature_is_not_the_one_read() {
        // The signature wrapping attack's first half: a Subject inside the
        // unsigned Signature comes first in the text, and is not the
        // assertion's own.
        let xml = concat!(
            "<saml:Assertion xmlns:saml=\"urn:s\" xmlns:ds=\"urn:d\" ID=\"a1\">",
            "<saml:Issuer>idp</saml:Issuer>",
            "<ds:Signature><ds:Object><saml:Subject><saml:NameID>admin</saml:NameID>",
            "</saml:Subject></ds:Object></ds:Signature>",
            "<saml:Subject><saml:NameID>party-x</saml:NameID></saml:Subject>",
            "</saml:Assertion>",
        );

        let assertion = Assertion::scan(xml).expect("read").expect("an assertion");

        assert_eq!(assertion.name_id, "party-x");
        assert!(xml[assertion.span.0..assertion.span.1].ends_with("</saml:Assertion>"));
    }

    #[test]
    fn an_unprefixed_assertion_reads_the_same() {
        let xml =
            "<Assertion><Issuer>idp</Issuer><Subject><NameID>u</NameID></Subject></Assertion>";

        let assertion = Assertion::scan(xml).expect("read").expect("an assertion");

        assert_eq!(assertion.issuer, "idp");
        assert_eq!(assertion.name_id, "u");
        assert_eq!(assertion.format, None);
    }

    #[test]
    fn an_attribute_is_read_by_its_name_and_not_by_the_one_beside_it() {
        let xml = concat!(
            "<saml:Assertion xmlns:saml=\"urn:s\"><saml:Issuer>idp</saml:Issuer>",
            "<saml:Subject><saml:NameID>u</saml:NameID></saml:Subject>",
            "<saml:AttributeStatement>",
            r#"<saml:Attribute Name="urn:empty" NameFormat="urn:x"></saml:Attribute>"#,
            r#"<saml:Attribute NameFormat="urn:x" Name="urn:role">"#,
            "<saml:AttributeValue>buyer</saml:AttributeValue></saml:Attribute>",
            "</saml:AttributeStatement></saml:Assertion>",
        );
        let assertion = Assertion::scan(xml).expect("read").expect("an assertion");

        assert_eq!(
            assertion.attribute_value(|name| name == "urn:role"),
            Some("buyer")
        );
        assert_eq!(assertion.attribute_value(|name| name == "urn:empty"), None);
        assert_eq!(assertion.attribute_value(|name| name == "urn:absent"), None);
    }

    #[test]
    fn a_document_without_an_assertion_has_nothing_to_read() {
        assert_eq!(
            Assertion::scan("<order><Assertions/></order>").expect("read"),
            None
        );
    }

    #[test]
    fn an_encrypted_assertion_is_recognized_and_refused_by_name() {
        let xml = "<samlp:Response xmlns:samlp=\"urn:p\" xmlns:saml=\"urn:s\">\
                   <saml:EncryptedAssertion>x</saml:EncryptedAssertion></samlp:Response>";

        let failure = Assertion::scan(xml).expect_err("encrypted");

        assert!(failure.message.contains("encrypted"), "{failure}");
    }

    #[test]
    fn an_assertion_without_a_name_id_is_an_error_naming_the_element() {
        let xml = "<saml:Assertion xmlns:saml=\"urn:s\"><saml:Issuer>idp</saml:Issuer>\
                   <saml:Subject/></saml:Assertion>";

        let failure = Assertion::scan(xml).expect_err("no NameID");

        assert!(failure.message.contains("NameID"), "{failure}");
    }

    #[test]
    fn text_that_is_not_xml_is_refused_saying_so() {
        let failure = Assertion::scan("<Assertion><Issuer>").expect_err("not XML");

        assert!(failure.message.contains("not XML"), "{failure}");
    }
}
