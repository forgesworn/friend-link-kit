use nostr::nips::nip44;
use nostr::util::JsonUtil;
use nostr::{Event, EventBuilder, Keys, Kind, PublicKey, Tag, Timestamp};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{
    FriendLink, Hello, InviteError, Result, BACKDATE_MAX_SECS, HELLO_MAX_BYTES, OUTER_MAX_CHARS,
    PACKET_MAX_CHARS,
};

#[derive(Serialize)]
struct PacketOut<'a> {
    v: u8,
    key: String,
    ciphertext: &'a str,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PacketIn {
    v: u8,
    key: String,
    ciphertext: String,
}

/// What `open_hello` hands back.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenedHello {
    /// The runtime key that signed the seal, bound by the attestation.
    pub sender: PublicKey,
    pub hello: Hello,
    /// SHA-256 of the seal's content, for deduplication.
    pub id: [u8; 32],
}

/// `now` minus a random 0..=2 days.
fn backdated(now: u64) -> Result<Timestamp> {
    let mut b = [0u8; 8];
    getrandom::fill(&mut b).map_err(|_| InviteError::Random)?;
    let off = u64::from_le_bytes(b) % (BACKDATE_MAX_SECS + 1);
    Ok(Timestamp::from(now.saturating_sub(off)))
}

/// Build the kind 1059 event for a hello to `link`'s mailbox. See the crate
/// docs for the layers. `sender` is the sender's runtime key. The caller
/// publishes the result to `link.relays`.
pub fn seal_hello(
    sender: &Keys,
    link: &FriendLink,
    hello: &Hello,
    app_id: &str,
    now: u64,
) -> Result<Event> {
    if link.exp <= now {
        return Err(InviteError::Expired);
    }
    if hello.link != link.hash() {
        return Err(InviteError::LinkMismatch);
    }
    let mailbox = link.mailbox(app_id)?;
    let content = hello.to_json()?;

    // Layer 1: the seal, signed by the sender's runtime key.
    let seal = EventBuilder::new(Kind::Seal, content)
        .custom_created_at(backdated(now)?)
        .sign_with_keys(sender)
        .map_err(|_| InviteError::BadSignature("seal"))?;

    // Layer 2: a fresh key encrypts the whole seal to the link's recipient.
    let seal_json = seal
        .try_as_json()
        .map_err(|_| InviteError::Malformed("seal"))?;
    let eph_inner = Keys::generate();
    let ciphertext = nip44::encrypt(
        eph_inner.secret_key(),
        &link.to,
        seal_json,
        nip44::Version::V2,
    )
    .map_err(|_| InviteError::Crypto("seal"))?;
    if ciphertext.len() > PACKET_MAX_CHARS {
        return Err(InviteError::TooLarge("packet"));
    }
    let packet = serde_json::to_string(&PacketOut {
        v: 1,
        key: eph_inner.public_key().to_hex(),
        ciphertext: &ciphertext,
    })
    .map_err(|_| InviteError::Malformed("packet"))?;
    if packet.len() > PACKET_MAX_CHARS {
        return Err(InviteError::TooLarge("packet"));
    }

    // Layer 3: another fresh key encrypts the packet to the mailbox and signs
    // the wrap, whose only tag is the mailbox `p`.
    let eph_outer = Keys::generate();
    let outer = nip44::encrypt(
        eph_outer.secret_key(),
        &mailbox.public_key(),
        packet,
        nip44::Version::V2,
    )
    .map_err(|_| InviteError::Crypto("packet"))?;
    if outer.len() > OUTER_MAX_CHARS {
        return Err(InviteError::TooLarge("outer"));
    }
    EventBuilder::new(Kind::GiftWrap, outer)
        .tag(Tag::public_key(mailbox.public_key()))
        .custom_created_at(backdated(now)?)
        .sign_with_keys(&eph_outer)
        .map_err(|_| InviteError::BadSignature("wrap"))
}

/// Open a hello from `link`'s mailbox.
///
/// `mailbox` is the link's mailbox key (anyone with the link has it), `me` is
/// the link's recipient runtime key (`link.to`). `now` is unix seconds: a link
/// that has lapsed opens nothing ([`InviteError::Expired`]).
///
/// `verify(attestation_json, seal_signer)` must return `true` only when the
/// attestation is **fully verified**: its signature, the persona that signed
/// it, the app id and role, and that `now` is inside its validity window; and
/// it binds exactly `seal_signer`. Never answer from an unverified extractor
/// (such as reading the attestation's `p` tag): anyone holding the link could
/// then forge a hello as any persona.
///
/// Checks, in order: recipient and expiry; outer kind, size, signature, tags;
/// both decryptions; the seal's kind, signature, tags and size; the hello's
/// `link` field; and `verify`. The link names no app, so `verify`'s app id and
/// the app-specific mailbox are what tie a hello to one game.
pub fn open_hello(
    mailbox: &Keys,
    me: &Keys,
    link: &FriendLink,
    ev: &Event,
    now: u64,
    verify: impl Fn(&str, &PublicKey) -> bool,
) -> Result<OpenedHello> {
    if me.public_key() != link.to {
        return Err(InviteError::WrongRecipient);
    }
    if link.exp <= now {
        return Err(InviteError::Expired);
    }
    if ev.kind != Kind::GiftWrap {
        return Err(InviteError::WrongKind("outer"));
    }
    if ev.content.len() > OUTER_MAX_CHARS {
        return Err(InviteError::TooLarge("outer"));
    }
    ev.verify()
        .map_err(|_| InviteError::BadSignature("outer"))?;
    let mut tags = ev.tags.iter();
    match (tags.next(), tags.next()) {
        (Some(t), None) => {
            let s = t.as_slice();
            if s.len() != 2 || s[0] != "p" || s[1] != mailbox.public_key().to_hex() {
                return Err(InviteError::BadTags("outer"));
            }
        }
        _ => return Err(InviteError::BadTags("outer")),
    }

    let packet_json = nip44::decrypt(mailbox.secret_key(), &ev.pubkey, &ev.content)
        .map_err(|_| InviteError::Crypto("outer"))?;
    if packet_json.len() > PACKET_MAX_CHARS {
        return Err(InviteError::TooLarge("packet"));
    }
    let packet: PacketIn =
        serde_json::from_str(&packet_json).map_err(|_| InviteError::Malformed("packet"))?;
    if packet.v != 1 {
        return Err(InviteError::BadVersion);
    }
    if packet.ciphertext.len() > PACKET_MAX_CHARS {
        return Err(InviteError::TooLarge("packet"));
    }
    let key = PublicKey::from_hex(&packet.key).map_err(|_| InviteError::BadHex("packet key"))?;

    let seal_json = nip44::decrypt(me.secret_key(), &key, &packet.ciphertext)
        .map_err(|_| InviteError::Crypto("packet"))?;
    let seal = Event::from_json(&seal_json).map_err(|_| InviteError::Malformed("seal"))?;
    if seal.kind != Kind::Seal {
        return Err(InviteError::WrongKind("seal"));
    }
    if !seal.tags.is_empty() {
        return Err(InviteError::BadTags("seal"));
    }
    if seal.content.len() > HELLO_MAX_BYTES {
        return Err(InviteError::TooLarge("hello"));
    }
    seal.verify()
        .map_err(|_| InviteError::BadSignature("seal"))?;

    let hello = Hello::from_json(&seal.content)?;
    if hello.link != link.hash() {
        return Err(InviteError::LinkMismatch);
    }
    if !verify(&hello.attestation, &seal.pubkey) {
        return Err(InviteError::NotBound);
    }
    Ok(OpenedHello {
        sender: seal.pubkey,
        hello,
        id: Sha256::digest(seal.content.as_bytes()).into(),
    })
}
