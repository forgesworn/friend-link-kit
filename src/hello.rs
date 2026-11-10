use serde::{Deserialize, Serialize};

use crate::link::{parse_hex32, relays_ok};
use crate::{InviteError, Result, ATTESTATION_MAX_BYTES, HELLO_MAX_BYTES, MAX_RELAYS};

const NAME_MAX_CHARS: usize = 32;

/// Characters that draw nothing or reorder text: controls, bidi controls,
/// zero-width and joiner characters, line and paragraph separators, the
/// invisible operators, and the byte-order mark. Matches the other sanitisers
/// in the workspace.
fn is_stripped(c: char) -> bool {
    c.is_control()
        || matches!(
            c,
            '\u{061C}'
                | '\u{200B}'..='\u{200F}'
                | '\u{2028}'..='\u{202E}'
                | '\u{2060}'..='\u{2069}'
                | '\u{FEFF}'
        )
}

/// Remove control, zero-width and bidi characters and trim. The result must be
/// 1-32 characters with at least one that is not whitespace, else it is empty
/// (the caller shows its own placeholder).
pub fn sanitise_name(raw: &str) -> String {
    let cleaned: String = raw.chars().filter(|c| !is_stripped(*c)).collect();
    let t = cleaned.trim();
    if (1..=NAME_MAX_CHARS).contains(&t.chars().count()) {
        t.to_string()
    } else {
        String::new()
    }
}

#[derive(Serialize)]
struct WireOut<'a> {
    v: u8,
    kind: &'a str,
    link: String,
    name: String,
    relays: &'a [String],
    attestation: &'a str,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireIn {
    v: u8,
    kind: String,
    link: String,
    name: String,
    relays: Vec<String>,
    attestation: String,
}

fn to_json(
    kind: &str,
    link: &[u8; 32],
    name: &str,
    relays: &[String],
    attestation: &str,
) -> Result<String> {
    if !relays_ok(relays, 0) || relays.len() > MAX_RELAYS {
        return Err(InviteError::BadRelays);
    }
    if attestation.len() > ATTESTATION_MAX_BYTES {
        return Err(InviteError::TooLarge("attestation"));
    }
    let json = serde_json::to_string(&WireOut {
        v: 1,
        kind,
        link: hex::encode(link),
        name: sanitise_name(name),
        relays,
        attestation,
    })
    .map_err(|_| InviteError::Malformed("hello JSON"))?;
    if json.len() > HELLO_MAX_BYTES {
        return Err(InviteError::TooLarge("hello"));
    }
    Ok(json)
}

type Parsed = ([u8; 32], String, Vec<String>, String);

fn from_json(kind: &str, s: &str) -> Result<Parsed> {
    if s.len() > HELLO_MAX_BYTES {
        return Err(InviteError::TooLarge("hello"));
    }
    let w: WireIn = serde_json::from_str(s).map_err(|_| InviteError::Malformed("hello JSON"))?;
    if w.v != 1 {
        return Err(InviteError::BadVersion);
    }
    if w.kind != kind {
        return Err(InviteError::WrongKind("hello payload"));
    }
    let link = parse_hex32(&w.link, "link")?;
    if !relays_ok(&w.relays, 0) {
        return Err(InviteError::BadRelays);
    }
    if w.attestation.len() > ATTESTATION_MAX_BYTES {
        return Err(InviteError::TooLarge("attestation"));
    }
    Ok((link, sanitise_name(&w.name), w.relays, w.attestation))
}

macro_rules! payload {
    ($(#[$doc:meta])* $name:ident, $kind:literal) => {
        $(#[$doc])*
        #[derive(Debug, Clone, PartialEq, Eq)]
        pub struct $name {
            /// SHA-256 of the link's canonical JSON.
            pub link: [u8; 32],
            /// A display name, already sanitised, or empty.
            pub name: String,
            /// The sender's inbox relays (0-3).
            pub relays: Vec<String>,
            /// The sender's attestation JSON (at most 2048 bytes).
            pub attestation: String,
        }

        impl $name {
            /// Build one, sanitising the name and checking relays and size.
            pub fn new(
                link: [u8; 32],
                name: &str,
                relays: Vec<String>,
                attestation: String,
            ) -> Result<Self> {
                to_json($kind, &link, name, &relays, &attestation)?;
                Ok(Self { link, name: sanitise_name(name), relays, attestation })
            }

            /// The wire JSON `{v:1, kind, link, name, relays, attestation}`.
            pub fn to_json(&self) -> Result<String> {
                to_json($kind, &self.link, &self.name, &self.relays, &self.attestation)
            }

            /// Parse and check wire JSON. The name comes back sanitised.
            pub fn from_json(s: &str) -> Result<Self> {
                let (link, name, relays, attestation) = from_json($kind, s)?;
                Ok(Self { link, name, relays, attestation })
            }
        }
    };
}

payload!(
    /// What the link user sends: `kind` is `"friend-hello"`.
    Hello,
    "friend-hello"
);
payload!(
    /// The link owner's answer, `kind` `"friend-reply"`. Only a payload type
    /// here: the caller sends it inside an ordinary NIP-59 gift wrap.
    Reply,
    "friend-reply"
);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names() {
        assert_eq!(sanitise_name("  Sam  "), "Sam");
        assert_eq!(sanitise_name("Sa\u{0}m\n"), "Sam");
        assert_eq!(sanitise_name("\u{202E}Sam\u{2066}"), "Sam");
        assert_eq!(sanitise_name(""), "");
        assert_eq!(sanitise_name(" \u{202E} "), "");
        assert_eq!(sanitise_name(&"a".repeat(32)), "a".repeat(32));
        assert_eq!(sanitise_name(&"a".repeat(33)), "");
        assert_eq!(sanitise_name(&"é".repeat(32)), "é".repeat(32));
        assert_eq!(sanitise_name("\u{200B}"), "");
        assert_eq!(sanitise_name("\u{FEFF}\u{200D}"), "");
        assert_eq!(sanitise_name("Mum\u{2028}Dad"), "MumDad");
        assert_eq!(sanitise_name("Sa\u{200B}m\u{2060}"), "Sam");
        assert_eq!(sanitise_name("\u{2029}"), "");
    }
}
