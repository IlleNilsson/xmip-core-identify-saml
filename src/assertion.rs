//! The two names a SAML 2.0 assertion carries in the clear, read with a scan
//! and not a parser.
//!
//! An assertion is `<saml:Assertion>` with an `<saml:Issuer>` and, under
//! `<saml:Subject>`, a `<saml:NameID>`. The scan finds elements by local name
//! whatever the prefix, skips an `EncryptedAssertion` rather than mistaking
//! it for one, and reads element text with the five predefined entities
//! unescaped. It does not validate the document, and it does not need to: a
//! document that passes the second gate's signature check is well-formed, and
//! one that fails it is refused there whatever this read.

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
}

impl Assertion {
    /// Find the assertion in `xml` and read its names.
    ///
    /// `None` where the document has no `Assertion` element at all.
    ///
    /// # Errors
    ///
    /// Where the assertion is encrypted, unterminated, or names no issuer or
    /// no subject.
    pub fn scan(xml: &str) -> Result<Option<Self>, IdentifyError> {
        let Some((start, name_end)) = find_element(xml, "Assertion", 0) else {
            return if find_element(xml, "EncryptedAssertion", 0).is_some() {
                Err(IdentifyError::new(
                    "the SAML assertion is encrypted and this gate cannot read it",
                ))
            } else {
                Ok(None)
            };
        };
        let qualified = &xml[start + 1..name_end];
        let closing = format!("</{qualified}>");
        let Some(end) = xml[name_end..]
            .find(&closing)
            .map(|at| name_end + at + closing.len())
        else {
            return Err(IdentifyError::new(
                "the SAML assertion is not closed: no </Assertion>",
            ));
        };
        let body = &xml[start..end];

        let issuer = text_of(body, "Issuer")
            .ok_or_else(|| IdentifyError::new("the SAML assertion names no Issuer"))?;
        let (name_id, format) = name_id(body)
            .ok_or_else(|| IdentifyError::new("the SAML assertion names no subject: no NameID"))?;

        Ok(Some(Self {
            issuer,
            name_id,
            format,
            span: (start, end),
        }))
    }
}

/// The `NameID` text and its `Format`, from the first `NameID` in the body,
/// which is the Subject's: a `SubjectConfirmation` may carry another and it
/// comes after.
fn name_id(body: &str) -> Option<(String, Option<String>)> {
    let (_, name_end) = find_element(body, "NameID", 0)?;
    let tag_end = body[name_end..].find('>')? + name_end;
    let attributes = &body[name_end..tag_end];
    let format = attribute(attributes, "Format").as_deref().map(unescape);
    let text = element_text(body, name_end)?;
    Some((text, format))
}

fn text_of(body: &str, local_name: &str) -> Option<String> {
    let (_, name_end) = find_element(body, local_name, 0)?;
    element_text(body, name_end)
}

/// The text between the start tag's `>` and the next `<`, trimmed and
/// unescaped. An empty element (`<x/>`) has none.
fn element_text(body: &str, name_end: usize) -> Option<String> {
    let tag_end = body[name_end..].find('>')? + name_end;
    if body[..tag_end].ends_with('/') {
        return None;
    }
    let content = &body[tag_end + 1..];
    let text = &content[..content.find('<')?];
    let text = text.trim();
    (!text.is_empty()).then(|| unescape(text))
}

/// The start of the first element whose local name is `local_name`, at or
/// after `from`: the index of its `<` and the index just past its qualified
/// name.
fn find_element(xml: &str, local_name: &str, from: usize) -> Option<(usize, usize)> {
    let bytes = xml.as_bytes();
    let mut at = from;
    while let Some(offset) = xml[at..].find('<') {
        let start = at + offset;
        let name_start = start + 1;
        let name_end = name_start
            + bytes[name_start..]
                .iter()
                .position(|byte| byte.is_ascii_whitespace() || *byte == b'>' || *byte == b'/')
                .unwrap_or(bytes.len() - name_start);
        let qualified = &xml[name_start..name_end];
        let local = qualified.rsplit(':').next().unwrap_or(qualified);
        if local == local_name && !qualified.starts_with(['?', '!']) {
            return Some((start, name_end));
        }
        at = name_end.max(start + 1);
    }
    None
}

/// One attribute's value from the text between an element's name and `>`.
fn attribute(attributes: &str, name: &str) -> Option<String> {
    let mut rest = attributes;
    while let Some(at) = rest.find(name) {
        let after = rest[at + name.len()..].trim_start();
        let preceded_by_space = at == 0 || rest.as_bytes()[at - 1].is_ascii_whitespace();
        if preceded_by_space && let Some(value) = after.strip_prefix('=') {
            let value = value.trim_start();
            let quote = value.chars().next()?;
            if quote == '"' || quote == '\'' {
                let inner = &value[1..];
                return inner.find(quote).map(|end| inner[..end].to_string());
            }
        }
        rest = &rest[at + name.len()..];
    }
    None
}

fn unescape(text: &str) -> String {
    text.replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&apos;", "'")
        .replace("&amp;", "&")
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
        jane&amp;co@partner-x.example
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
        assert_eq!(assertion.name_id, "jane&co@partner-x.example");
        assert_eq!(
            assertion.format.as_deref(),
            Some("urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress")
        );
        assert!(RESPONSE[assertion.span.0..assertion.span.1].starts_with("<saml:Assertion"));
        assert!(RESPONSE[assertion.span.0..assertion.span.1].ends_with("</saml:Assertion>"));
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
    fn a_document_without_an_assertion_has_nothing_to_read() {
        assert_eq!(
            Assertion::scan("<order><Assertions/></order>").expect("read"),
            None
        );
    }

    #[test]
    fn an_encrypted_assertion_is_recognised_and_refused_by_name() {
        let xml =
            "<samlp:Response><saml:EncryptedAssertion>x</saml:EncryptedAssertion></samlp:Response>";

        let failure = Assertion::scan(xml).expect_err("encrypted");

        assert!(failure.message.contains("encrypted"), "{failure}");
    }

    #[test]
    fn an_assertion_without_a_name_id_is_an_error_naming_the_element() {
        let xml = "<saml:Assertion><saml:Issuer>idp</saml:Issuer><saml:Subject/></saml:Assertion>";

        let failure = Assertion::scan(xml).expect_err("no NameID");

        assert!(failure.message.contains("NameID"), "{failure}");
    }
}
