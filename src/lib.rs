//! Friend links and their two-layer encrypted hello packet, for decentralised
//! games. Pure: this crate never touches the network, the clock or storage. The
//! caller passes in the time, the keys and the attestation verifier, and
//! publishes or subscribes to the events itself.
//!
//! A friend link lets someone who has never played with you reach you, even
//! while you are offline. It carries a recipient runtime key, a random secret
//! and 1-3 inbox relays. The secret derives a *mailbox* key (HKDF-SHA256 with
//! the kit's own salt and the app id as `info`). The sender posts a hello to
//! that mailbox as a kind 1059 event with one `p` tag, which relays see as the
//! same shape as any other gift wrap.
//!
//! # Threat handled
//!
//! Anyone who holds the link can derive the mailbox key, so the outer layer
//! hides nothing from them. The **inner layer** is what keeps the hello private:
//! the signed seal is NIP-44 encrypted to the link's recipient key `to`, so only
//! the recipient can see who the sender is and read their attestation. Without
//! it every link holder could read the sender's attestation and learn which
//! persona plays. The sender signs the seal with a *runtime* key, never a
//! persona, and the recipient requires an attestation that binds exactly that
//! key (the caller supplies the verifier). Timestamps are randomised up to two
//! days into the past, and both outer and inner event keys are fresh ephemerals.
//!
//! The construction follows `contact-invite-v1` from forgesworn/signet-contacts
//! (the mailbox key, the two-layer packet, the size bounds and the randomised
//! timestamps), with the kit's own salt [`KIT_MAILBOX_SALT`]. The app id is a
//! parameter everywhere; no game is named here.
//!
//! Size bounds: a hello is at most [`HELLO_MAX_BYTES`], the packet at most
//! [`PACKET_MAX_CHARS`], the outer ciphertext at most [`OUTER_MAX_CHARS`].
//! Hostile input returns an [`InviteError`]; nothing here panics on it.

mod error;
mod hello;
mod link;
mod mailbox;
mod packet;

pub use error::InviteError;
pub use hello::{sanitise_name, Hello, Reply};
pub use link::FriendLink;
pub use mailbox::derive_mailbox;
pub use packet::{open_hello, seal_hello, OpenedHello};

/// The kit's HKDF salt for mailbox keys.
pub const KIT_MAILBOX_SALT: &str = "decented-play:mailbox:v1";

/// A hello (the seal's content) is at most this many bytes.
pub const HELLO_MAX_BYTES: usize = 8192;
/// The packet JSON, and its ciphertext field, are at most this many characters.
pub const PACKET_MAX_CHARS: usize = 20000;
/// The outer event's encrypted content is at most this many characters.
pub const OUTER_MAX_CHARS: usize = 32000;

/// A link lasts 7 days unless the caller asks otherwise.
pub const LINK_TTL_DEFAULT: u64 = 7 * 24 * 60 * 60;
/// No link may be valid for more than 30 days.
pub const LINK_TTL_MAX: u64 = 30 * 24 * 60 * 60;
/// A link and a hello carry at most this many relays.
pub const MAX_RELAYS: usize = 3;
/// Seal and wrap timestamps are set back by up to this many seconds (2 days).
pub const BACKDATE_MAX_SECS: u64 = 2 * 24 * 60 * 60;
/// The attestation JSON in a hello or reply is at most this many bytes.
pub const ATTESTATION_MAX_BYTES: usize = 2048;

pub type Result<T> = std::result::Result<T, InviteError>;
