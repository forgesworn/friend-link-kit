use std::fmt;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use nostr::{Keys, PublicKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::mailbox::derive_mailbox;
use crate::{InviteError, Result, KIT_MAILBOX_SALT, LINK_TTL_MAX, MAX_RELAYS};

/// A link's JSON is at most this many bytes once decoded.
const LINK_JSON_MAX: usize = 4096;
/// A relay URL is at most this many characters.
const RELAY_MAX_CHARS: usize = 256;
const MARKER: &str = "friend#";
/// A link lasts at least this long: a zero TTL would make one that is dead on arrival.
const MIN_TTL: u64 = 60;
/// A reader's clock may be this far behind the maker's: a 30-day link still opens.
const CLOCK_SKEW: u64 = 300;

/// A friend link: a recipient runtime key, a secret that derives the mailbox,
/// the recipient's inbox relays, and an expiry (unix seconds).
#[derive(Clone, PartialEq, Eq)]
pub struct FriendLink {
    pub to: PublicKey,
    pub secret: [u8; 32],
    pub relays: Vec<String>,
    pub exp: u64,
}

// The secret is the whole point of the link: never print it.
impl fmt::Debug for FriendLink {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FriendLink")
            .field("to", &self.to)
            .field("secret", &"<hidden>")
            .field("relays", &self.relays)
            .field("exp", &self.exp)
            .finish()
    }
}

/// Fixed field order: this is both the wire form and what the link hash covers.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct LinkWire {
    v: u8,
    to: String,
    secret: String,
    relays: Vec<String>,
    exp: u64,
}

/// A relay we are willing to dial or share: `wss://`, a host, at most 256
/// characters, no whitespace or control characters, no credentials.
pub(crate) fn relay_ok(url: &str) -> bool {
    let Some(rest) = url.strip_prefix("wss://") else {
        return false;
    };
    if url.chars().count() > RELAY_MAX_CHARS
        || url.chars().any(|c| c.is_whitespace() || c.is_control())
    {
        return false;
    }
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    !authority.is_empty() && !authority.contains('@') && !authority.starts_with(':')
}

/// `min..=MAX_RELAYS` relays, each acceptable.
pub(crate) fn relays_ok(relays: &[String], min: usize) -> bool {
    (min..=MAX_RELAYS).contains(&relays.len()) && relays.iter().all(|r| relay_ok(r))
}

/// Pick a secret: draw until `ok` accepts one. Never reduces an out-of-range
/// value. Bounded so a broken source cannot loop forever.
pub(crate) fn pick_secret(
    mut next: impl FnMut() -> Result<[u8; 32]>,
    ok: impl Fn(&[u8; 32]) -> bool,
) -> Result<[u8; 32]> {
    for _ in 0..64 {
        let s = next()?;
        if ok(&s) {
            return Ok(s);
        }
    }
    Err(InviteError::InvalidMailboxKey)
}

fn random_32() -> Result<[u8; 32]> {
    let mut b = [0u8; 32];
    getrandom::fill(&mut b).map_err(|_| InviteError::Random)?;
    Ok(b)
}

fn hex32(s: &str, what: &'static str) -> Result<[u8; 32]> {
    let mut out = [0u8; 32];
    if s.len() != 64 {
        return Err(InviteError::BadHex(what));
    }
    hex::decode_to_slice(s, &mut out).map_err(|_| InviteError::BadHex(what))?;
    Ok(out)
}

impl FriendLink {
    /// Make a link to `to` with a random secret. The secret is redrawn if the
    /// mailbox it gives for `app_id` would be invalid. Relays must be 1-3
    /// acceptable `wss://` URLs; `ttl_secs` is capped at [`LINK_TTL_MAX`].
    pub fn new(
        to: PublicKey,
        relays: Vec<String>,
        app_id: &str,
        now: u64,
        ttl_secs: u64,
    ) -> Result<Self> {
        if !relays_ok(&relays, 1) {
            return Err(InviteError::BadRelays);
        }
        let secret = pick_secret(random_32, |s| {
            derive_mailbox(s, KIT_MAILBOX_SALT, app_id).is_ok()
        })?;
        Ok(Self {
            to,
            secret,
            relays,
            exp: now.saturating_add(ttl_secs.clamp(MIN_TTL, LINK_TTL_MAX)),
        })
    }

    fn wire(&self) -> LinkWire {
        LinkWire {
            v: 1,
            to: self.to.to_hex(),
            secret: hex::encode(self.secret),
            relays: self.relays.clone(),
            exp: self.exp,
        }
    }

    /// The canonical JSON: `{"v":1,"to":..,"secret":..,"relays":[..],"exp":..}`.
    pub(crate) fn canonical_json(&self) -> String {
        // Plain strings and integers: serialising cannot fail.
        serde_json::to_string(&self.wire()).unwrap_or_default()
    }

    /// `<prefix>#<base64url-nopad(canonical JSON)>`. The prefix is the scheme and
    /// host, such as `x://friend`, so that it ends in `friend#`.
    pub fn encode(&self, prefix: &str) -> String {
        format!("{prefix}#{}", URL_SAFE_NO_PAD.encode(self.canonical_json()))
    }

    /// SHA-256 of the canonical JSON; what a hello's `link` field holds.
    pub fn hash(&self) -> [u8; 32] {
        Sha256::digest(self.canonical_json().as_bytes()).into()
    }

    /// The mailbox keys for this link and app id.
    pub fn mailbox(&self, app_id: &str) -> Result<Keys> {
        derive_mailbox(&self.secret, KIT_MAILBOX_SALT, app_id)
    }

    /// Find `friend#<payload>` anywhere in pasted text (any scheme or host may
    /// precede it) and check it: version 1, good hex, good relays, not expired,
    /// not more than 30 days ahead. Tries each occurrence; returns the first
    /// that is valid, otherwise the first occurrence's error.
    pub fn find_in(text: &str, now: u64) -> Result<Self> {
        let mut first_err = None;
        for (at, _) in text.match_indices(MARKER) {
            let start = at + MARKER.len();
            let payload: String = text[start..]
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_')
                .take(LINK_JSON_MAX * 2)
                .collect();
            match Self::parse_payload(&payload, now) {
                Ok(l) => return Ok(l),
                Err(e) => {
                    first_err.get_or_insert(e);
                }
            }
        }
        Err(first_err.unwrap_or(InviteError::NotFound))
    }

    fn parse_payload(payload: &str, now: u64) -> Result<Self> {
        if payload.len() > LINK_JSON_MAX * 4 / 3 + 4 {
            return Err(InviteError::TooLarge("link"));
        }
        let json = URL_SAFE_NO_PAD
            .decode(payload)
            .map_err(|_| InviteError::Malformed("link encoding"))?;
        if json.len() > LINK_JSON_MAX {
            return Err(InviteError::TooLarge("link"));
        }
        let w: LinkWire =
            serde_json::from_slice(&json).map_err(|_| InviteError::Malformed("link JSON"))?;
        if w.v != 1 {
            return Err(InviteError::BadVersion);
        }
        if w.to.len() != 64 {
            return Err(InviteError::BadHex("to"));
        }
        let to = PublicKey::from_hex(&w.to).map_err(|_| InviteError::BadHex("to"))?;
        // The hex form alone does not prove the point is on the curve.
        if to.xonly().is_err() {
            return Err(InviteError::BadHex("to"));
        }
        let secret = hex32(&w.secret, "secret")?;
        if !relays_ok(&w.relays, 1) {
            return Err(InviteError::BadRelays);
        }
        if w.exp <= now {
            return Err(InviteError::Expired);
        }
        if w.exp > now.saturating_add(LINK_TTL_MAX + CLOCK_SKEW) {
            return Err(InviteError::ExpiryTooFar);
        }
        Ok(Self {
            to,
            secret,
            relays: w.relays,
            exp: w.exp,
        })
    }
}

/// Parse a 32-byte lowercase-or-uppercase hex field (used for a hello's `link`).
pub(crate) fn parse_hex32(s: &str, what: &'static str) -> Result<[u8; 32]> {
    hex32(s, what)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn relay_rules() {
        assert!(relay_ok("wss://relay.example"));
        assert!(relay_ok("wss://relay.example:7777/path?x=1"));
        assert!(!relay_ok("ws://relay.example"));
        assert!(!relay_ok("https://relay.example"));
        assert!(!relay_ok("wss://"));
        assert!(!relay_ok("wss://user:pw@relay.example"));
        assert!(!relay_ok("wss://user@relay.example"));
        assert!(!relay_ok("wss://relay .example"));
        assert!(!relay_ok("wss://relay.example\n"));
        assert!(!relay_ok(&format!("wss://{}", "a".repeat(251))));
        assert!(relay_ok(&format!("wss://{}", "a".repeat(250))));
        assert!(!relays_ok(&[], 1));
        assert!(relays_ok(&[], 0));
        let r = "wss://r.example".to_string();
        assert!(relays_ok(&[r.clone(), r.clone(), r.clone()], 1));
        assert!(!relays_ok(&[r.clone(), r.clone(), r.clone(), r], 1));
    }

    #[test]
    fn secret_is_redrawn_until_valid() {
        let mut calls = 0u8;
        let got = pick_secret(
            || {
                calls += 1;
                Ok([calls; 32])
            },
            |s| s[0] >= 3,
        )
        .unwrap();
        assert_eq!(got, [3u8; 32]);
        assert_eq!(calls, 3);
    }

    #[test]
    fn secret_redraw_is_bounded() {
        let r = pick_secret(|| Ok([1u8; 32]), |_| false);
        assert_eq!(r, Err(InviteError::InvalidMailboxKey));
    }

    #[test]
    fn source_failure_propagates() {
        let r = pick_secret(|| Err(InviteError::Random), |_| true);
        assert_eq!(r, Err(InviteError::Random));
    }
}
