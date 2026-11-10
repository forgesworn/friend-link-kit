use std::fmt;

/// Why a link, hello or packet was refused. Plain data, no secrets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InviteError {
    /// No `friend#<payload>` in the text.
    NotFound,
    /// The structure or encoding is wrong; the text says which part.
    Malformed(&'static str),
    /// `v` is not 1.
    BadVersion,
    /// A hex field is not the right length or not valid hex.
    BadHex(&'static str),
    /// A relay list is outside 1-3 (or 0-3 in a hello), or a URL is not an
    /// acceptable `wss://` address.
    BadRelays,
    /// The link's `exp` has passed.
    Expired,
    /// The link's `exp` is more than 30 days ahead.
    ExpiryTooFar,
    /// A size bound was exceeded; the text says which layer.
    TooLarge(&'static str),
    /// The secret derives a zero or out-of-range mailbox key.
    InvalidMailboxKey,
    /// The random source failed.
    Random,
    /// A signature does not verify.
    BadSignature(&'static str),
    /// The wrong event kind.
    WrongKind(&'static str),
    /// The tags are not exactly the allowed ones.
    BadTags(&'static str),
    /// The key we were given is not the link's recipient key.
    WrongRecipient,
    /// NIP-44 encryption or decryption failed.
    Crypto(&'static str),
    /// The hello's `link` is not this link's hash.
    LinkMismatch,
    /// The attestation does not bind the seal's signer.
    NotBound,
}

impl fmt::Display for InviteError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotFound => f.write_str("no friend link found"),
            Self::Malformed(w) => write!(f, "malformed: {w}"),
            Self::BadVersion => f.write_str("unsupported version"),
            Self::BadHex(w) => write!(f, "bad hex in {w}"),
            Self::BadRelays => f.write_str("bad relay list"),
            Self::Expired => f.write_str("link expired"),
            Self::ExpiryTooFar => f.write_str("link expiry too far ahead"),
            Self::TooLarge(w) => write!(f, "{w} too large"),
            Self::InvalidMailboxKey => f.write_str("secret gives an invalid mailbox key"),
            Self::Random => f.write_str("random source failed"),
            Self::BadSignature(w) => write!(f, "bad signature on {w}"),
            Self::WrongKind(w) => write!(f, "wrong kind for {w}"),
            Self::BadTags(w) => write!(f, "unexpected tags on {w}"),
            Self::WrongRecipient => f.write_str("not the link's recipient key"),
            Self::Crypto(w) => write!(f, "cannot decrypt {w}"),
            Self::LinkMismatch => f.write_str("hello is for a different link"),
            Self::NotBound => f.write_str("attestation does not bind the sender"),
        }
    }
}

impl std::error::Error for InviteError {}
