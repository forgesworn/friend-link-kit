//! Public-API tests for decented-invite. Fixtures may name the game's scheme.

use decented_invite::*;
use nostr::nips::nip44;
use nostr::util::JsonUtil;
use nostr::{Event, EventBuilder, Keys, Kind, PublicKey, Tag, Timestamp};
use sha2::{Digest, Sha256};

const APP: &str = "test-app";
const NOW: u64 = 1_800_000_000;
const DAY: u64 = 86_400;

fn relay() -> Vec<String> {
    vec!["wss://relay.example".into()]
}

struct World {
    a: Keys, // link owner
    b: Keys, // link user
    link: FriendLink,
    mailbox: Keys,
    hello: Hello,
}

fn att_for(k: &Keys) -> String {
    format!("att:{}", k.public_key().to_hex())
}

/// The test attestation `att:<hex>` binds the key `<hex>`.
fn verify(att: &str, signer: &PublicKey) -> bool {
    att.strip_prefix("att:")
        .and_then(|h| PublicKey::from_hex(h).ok())
        .is_some_and(|k| k == *signer)
}

fn world() -> World {
    let a = Keys::generate();
    let b = Keys::generate();
    let link = FriendLink::new(a.public_key(), relay(), APP, NOW, LINK_TTL_DEFAULT).unwrap();
    let mailbox = link.mailbox(APP).unwrap();
    let hello = Hello::new(
        link.hash(),
        "  Sam\u{202E} ",
        vec!["wss://b.example".into()],
        att_for(&b),
    )
    .unwrap();
    World {
        a,
        b,
        link,
        mailbox,
        hello,
    }
}

fn open(w: &World, ev: &Event) -> Result<OpenedHello> {
    open_hello(&w.mailbox, &w.a, &w.link, ev, NOW, verify)
}

// ---- hand-built layers, for hostile input ----

fn seal_ev(sender: &Keys, content: &str, tags: Vec<Tag>) -> Event {
    EventBuilder::new(Kind::Seal, content)
        .tags(tags)
        .custom_created_at(Timestamp::from(NOW - 10))
        .sign_with_keys(sender)
        .unwrap()
}

fn packet_for(w: &World, seal_json: &str) -> String {
    let eph = Keys::generate();
    let ct = nip44::encrypt(
        eph.secret_key(),
        &w.a.public_key(),
        seal_json,
        nip44::Version::V2,
    )
    .unwrap();
    format!(
        r#"{{"v":1,"key":"{}","ciphertext":"{}"}}"#,
        eph.public_key().to_hex(),
        ct
    )
}

fn wrap_for(w: &World, packet: &str, tags: Vec<Tag>) -> Event {
    let eph = Keys::generate();
    let ct = nip44::encrypt(
        eph.secret_key(),
        &w.mailbox.public_key(),
        packet,
        nip44::Version::V2,
    )
    .unwrap();
    EventBuilder::new(Kind::GiftWrap, ct)
        .tags(tags)
        .custom_created_at(Timestamp::from(NOW - 10))
        .sign_with_keys(&eph)
        .unwrap()
}

fn p_tag(w: &World) -> Vec<Tag> {
    vec![Tag::public_key(w.mailbox.public_key())]
}

/// Peel the real event into (outer packet JSON, seal event).
fn peel(w: &World, ev: &Event) -> (String, Event) {
    let packet = nip44::decrypt(w.mailbox.secret_key(), &ev.pubkey, &ev.content).unwrap();
    let v: serde_json::Value = serde_json::from_str(&packet).unwrap();
    let key = PublicKey::from_hex(v["key"].as_str().unwrap()).unwrap();
    let seal = nip44::decrypt(w.a.secret_key(), &key, v["ciphertext"].as_str().unwrap()).unwrap();
    (packet, Event::from_json(seal).unwrap())
}

fn good_hello_json(w: &World) -> String {
    w.hello.to_json().unwrap()
}

// ---- round trip and privacy ----

#[test]
fn round_trip() {
    let w = world();
    let ev = seal_hello(&w.b, &w.link, &w.hello, APP, NOW).unwrap();
    assert_eq!(ev.kind, Kind::GiftWrap);
    assert_eq!(ev.tags.len(), 1);
    assert_eq!(
        ev.tags.iter().next().unwrap().as_slice(),
        ["p", &w.mailbox.public_key().to_hex()]
    );
    assert_ne!(
        ev.pubkey,
        w.b.public_key(),
        "wrap is signed by an ephemeral key"
    );
    let got = open(&w, &ev).unwrap();
    assert_eq!(got.sender, w.b.public_key());
    assert_eq!(got.hello.name, "Sam");
    assert_eq!(got.hello.relays, vec!["wss://b.example".to_string()]);
    assert_eq!(got.hello.link, w.link.hash());
    assert_eq!(got.hello.attestation, att_for(&w.b));
    let (_, seal) = peel(&w, &ev);
    assert_eq!(
        got.id,
        <[u8; 32]>::from(Sha256::digest(seal.content.as_bytes()))
    );
    assert!(seal.tags.is_empty());
    assert_eq!(seal.kind, Kind::Seal);
    assert_ne!(seal.pubkey, ev.pubkey);
}

#[test]
fn two_hellos_have_different_ids_and_events() {
    let w = world();
    let e1 = seal_hello(&w.b, &w.link, &w.hello, APP, NOW).unwrap();
    let e2 = seal_hello(&w.b, &w.link, &w.hello, APP, NOW).unwrap();
    assert_ne!(e1.id, e2.id);
    assert_ne!(e1.pubkey, e2.pubkey);
}

#[test]
fn link_holder_without_recipient_key_cannot_read_the_hello() {
    let w = world();
    let ev = seal_hello(&w.b, &w.link, &w.hello, APP, NOW).unwrap();
    // The link holder derives the mailbox and opens the outer layer...
    let packet = nip44::decrypt(w.mailbox.secret_key(), &ev.pubkey, &ev.content).unwrap();
    let v: serde_json::Value = serde_json::from_str(&packet).unwrap();
    let key = PublicKey::from_hex(v["key"].as_str().unwrap()).unwrap();
    let ct = v["ciphertext"].as_str().unwrap();
    // ...but the inner layer is closed to the mailbox key and to anyone else.
    assert!(nip44::decrypt(w.mailbox.secret_key(), &key, ct).is_err());
    assert!(nip44::decrypt(Keys::generate().secret_key(), &key, ct).is_err());
    assert!(!packet.contains(&w.b.public_key().to_hex()));
    assert!(!packet.contains("att:"));
    // open_hello without the recipient key refuses.
    let stranger = Keys::generate();
    assert_eq!(
        open_hello(&w.mailbox, &stranger, &w.link, &ev, NOW, verify).unwrap_err(),
        InviteError::WrongRecipient
    );
    let mut forged = w.link.clone();
    forged.to = stranger.public_key();
    assert_eq!(
        open_hello(&w.mailbox, &stranger, &forged, &ev, NOW, verify).unwrap_err(),
        InviteError::Crypto("packet")
    );
}

#[test]
fn timestamps_within_two_days() {
    let w = world();
    let mut seen_early = false;
    for _ in 0..60 {
        let ev = seal_hello(&w.b, &w.link, &w.hello, APP, NOW).unwrap();
        let (_, seal) = peel(&w, &ev);
        for t in [ev.created_at.as_secs(), seal.created_at.as_secs()] {
            assert!((NOW - 2 * DAY..=NOW).contains(&t), "{t}");
            seen_early |= t < NOW - DAY;
        }
    }
    assert!(seen_early, "timestamps are spread, not constant");
}

#[test]
fn seal_refuses_bad_inputs() {
    let w = world();
    // Expired link.
    assert_eq!(
        seal_hello(&w.b, &w.link, &w.hello, APP, w.link.exp).unwrap_err(),
        InviteError::Expired
    );
    // Hello for a different link.
    let other = FriendLink::new(w.a.public_key(), relay(), APP, NOW, 100).unwrap();
    let h = Hello::new(other.hash(), "x", vec![], att_for(&w.b)).unwrap();
    assert_eq!(
        seal_hello(&w.b, &w.link, &h, APP, NOW).unwrap_err(),
        InviteError::LinkMismatch
    );
}

// ---- rejection on open ----

#[test]
fn wrong_sealer_vs_attestation_rejected() {
    let w = world();
    // B seals, but the attestation binds somebody else.
    let h = Hello::new(w.link.hash(), "Sam", vec![], att_for(&Keys::generate())).unwrap();
    let ev = seal_hello(&w.b, &w.link, &h, APP, NOW).unwrap();
    assert_eq!(open(&w, &ev).unwrap_err(), InviteError::NotBound);
    // A verifier that rejects the attestation.
    let ev = seal_hello(&w.b, &w.link, &w.hello, APP, NOW).unwrap();
    assert_eq!(
        open_hello(&w.mailbox, &w.a, &w.link, &ev, NOW, |_, _| false).unwrap_err(),
        InviteError::NotBound
    );
}

#[test]
fn wrong_link_hash_rejected() {
    let w = world();
    let mut h = w.hello.clone();
    h.link = [9u8; 32];
    let seal = seal_ev(&w.b, &h.to_json().unwrap(), vec![]);
    let ev = wrap_for(&w, &packet_for(&w, &seal.as_json()), p_tag(&w));
    assert_eq!(open(&w, &ev).unwrap_err(), InviteError::LinkMismatch);
}

#[test]
fn tampered_outer_rejected() {
    let w = world();
    let ev = seal_hello(&w.b, &w.link, &w.hello, APP, NOW).unwrap();
    let mut bad = ev.clone();
    let mut c: Vec<char> = bad.content.chars().collect();
    let i = c.len() / 2;
    c[i] = if c[i] == 'A' { 'B' } else { 'A' };
    bad.content = c.into_iter().collect();
    assert_eq!(
        open(&w, &bad).unwrap_err(),
        InviteError::BadSignature("outer")
    );
    // A different created_at also breaks the id/signature.
    let mut bad = ev.clone();
    bad.created_at = Timestamp::from(NOW);
    assert!(open(&w, &bad).is_err());
    // Properly signed, but the content is not a valid ciphertext.
    let eph = Keys::generate();
    let junk = EventBuilder::new(Kind::GiftWrap, "not a ciphertext")
        .tags(p_tag(&w))
        .sign_with_keys(&eph)
        .unwrap();
    assert_eq!(open(&w, &junk).unwrap_err(), InviteError::Crypto("outer"));
}

#[test]
fn tampered_packet_rejected() {
    let w = world();
    let ev = seal_hello(&w.b, &w.link, &w.hello, APP, NOW).unwrap();
    let (packet, _) = peel(&w, &ev);
    let mut v: serde_json::Value = serde_json::from_str(&packet).unwrap();
    let ct = v["ciphertext"].as_str().unwrap().to_string();
    let mut c: Vec<char> = ct.chars().collect();
    let i = c.len() / 2;
    c[i] = if c[i] == 'A' { 'B' } else { 'A' };
    v["ciphertext"] = c.into_iter().collect::<String>().into();
    let bad = wrap_for(&w, &v.to_string(), p_tag(&w));
    assert_eq!(open(&w, &bad).unwrap_err(), InviteError::Crypto("packet"));
    // Wrong version, unknown field, junk.
    let mut v2: serde_json::Value = serde_json::from_str(&packet).unwrap();
    v2["v"] = 2.into();
    assert_eq!(
        open(&w, &wrap_for(&w, &v2.to_string(), p_tag(&w))).unwrap_err(),
        InviteError::BadVersion
    );
    let mut v3: serde_json::Value = serde_json::from_str(&packet).unwrap();
    v3["extra"] = 1.into();
    assert!(open(&w, &wrap_for(&w, &v3.to_string(), p_tag(&w))).is_err());
    assert!(open(&w, &wrap_for(&w, "{nope", p_tag(&w))).is_err());
}

#[test]
fn tampered_seal_rejected() {
    let w = world();
    let ev = seal_hello(&w.b, &w.link, &w.hello, APP, NOW).unwrap();
    let (_, mut seal) = peel(&w, &ev);
    // Change the content but keep the signature.
    seal.content = seal.content.replace("Sam", "Eve");
    let bad = wrap_for(&w, &packet_for(&w, &seal.as_json()), p_tag(&w));
    assert_eq!(
        open(&w, &bad).unwrap_err(),
        InviteError::BadSignature("seal")
    );
    // Wrong kind for the seal.
    let not_seal = EventBuilder::new(Kind::TextNote, good_hello_json(&w))
        .sign_with_keys(&w.b)
        .unwrap();
    let bad = wrap_for(&w, &packet_for(&w, &not_seal.as_json()), p_tag(&w));
    assert_eq!(open(&w, &bad).unwrap_err(), InviteError::WrongKind("seal"));
    // Bad hello JSON inside a valid seal.
    for content in ["{}", "nope", r#"{"v":2,"kind":"friend-hello"}"#] {
        let s = seal_ev(&w.b, content, vec![]);
        let bad = wrap_for(&w, &packet_for(&w, &s.as_json()), p_tag(&w));
        assert!(open(&w, &bad).is_err(), "{content}");
    }
    // A reply is not a hello.
    let r = Reply::new(w.link.hash(), "x", vec![], att_for(&w.b)).unwrap();
    let s = seal_ev(&w.b, &r.to_json().unwrap(), vec![]);
    let bad = wrap_for(&w, &packet_for(&w, &s.as_json()), p_tag(&w));
    assert_eq!(
        open(&w, &bad).unwrap_err(),
        InviteError::WrongKind("hello payload")
    );
}

#[test]
fn oversize_each_layer_rejected() {
    let w = world();
    // Outer.
    let eph = Keys::generate();
    let big = EventBuilder::new(Kind::GiftWrap, "a".repeat(OUTER_MAX_CHARS + 1))
        .tags(p_tag(&w))
        .sign_with_keys(&eph)
        .unwrap();
    assert_eq!(open(&w, &big).unwrap_err(), InviteError::TooLarge("outer"));
    // Packet.
    let packet = format!(
        r#"{{"v":1,"key":"{}","ciphertext":"{}"}}"#,
        eph.public_key().to_hex(),
        "a".repeat(PACKET_MAX_CHARS)
    );
    assert!(packet.len() > PACKET_MAX_CHARS);
    assert_eq!(
        open(&w, &wrap_for(&w, &packet, p_tag(&w))).unwrap_err(),
        InviteError::TooLarge("packet")
    );
    // Hello (seal content).
    let seal = seal_ev(&w.b, &"x".repeat(HELLO_MAX_BYTES + 1), vec![]);
    let bad = wrap_for(&w, &packet_for(&w, &seal.as_json()), p_tag(&w));
    assert_eq!(open(&w, &bad).unwrap_err(), InviteError::TooLarge("hello"));
    // At the limit a hello of exactly 8192 bytes is not refused for size.
    let at_limit = format!(
        "{}{}",
        good_hello_json(&w),
        " ".repeat(HELLO_MAX_BYTES - good_hello_json(&w).len())
    );
    assert_eq!(at_limit.len(), HELLO_MAX_BYTES);
    let seal = seal_ev(&w.b, &at_limit, vec![]);
    let ok = wrap_for(&w, &packet_for(&w, &seal.as_json()), p_tag(&w));
    assert!(open(&w, &ok).is_ok());
    // Attestation over 2048 bytes.
    assert_eq!(
        Hello::new(
            w.link.hash(),
            "x",
            vec![],
            "a".repeat(ATTESTATION_MAX_BYTES + 1)
        )
        .unwrap_err(),
        InviteError::TooLarge("attestation")
    );
    assert!(Hello::new(
        w.link.hash(),
        "x",
        vec![],
        "a".repeat(ATTESTATION_MAX_BYTES)
    )
    .is_ok());
    // A maximal legitimate hello still fits every layer.
    let h = Hello::new(
        w.link.hash(),
        &"n".repeat(32),
        vec![format!("wss://{}", "r".repeat(250)); 3],
        format!("\"{}\"", "\"".repeat(ATTESTATION_MAX_BYTES - 2)),
    );
    let h = h.unwrap();
    let ev = seal_hello(&w.b, &w.link, &h, APP, NOW).unwrap();
    assert!(ev.content.len() <= OUTER_MAX_CHARS);
}

#[test]
fn extra_or_wrong_tags_rejected() {
    let w = world();
    let seal = seal_ev(&w.b, &good_hello_json(&w), vec![]);
    let packet = packet_for(&w, &seal.as_json());
    // Sanity: the hand-built path is accepted.
    assert!(open(&w, &wrap_for(&w, &packet, p_tag(&w))).is_ok());
    // Extra tag on the outer.
    let mut tags = p_tag(&w);
    tags.push(Tag::parse(["x", "y"]).unwrap());
    assert_eq!(
        open(&w, &wrap_for(&w, &packet, tags)).unwrap_err(),
        InviteError::BadTags("outer")
    );
    // Extra field on the p tag.
    let t = Tag::parse(["p", &w.mailbox.public_key().to_hex(), "wss://r"]).unwrap();
    assert_eq!(
        open(&w, &wrap_for(&w, &packet, vec![t])).unwrap_err(),
        InviteError::BadTags("outer")
    );
    // No tags, and a p tag to someone else.
    assert_eq!(
        open(&w, &wrap_for(&w, &packet, vec![])).unwrap_err(),
        InviteError::BadTags("outer")
    );
    let other = Tag::public_key(Keys::generate().public_key());
    assert_eq!(
        open(&w, &wrap_for(&w, &packet, vec![other])).unwrap_err(),
        InviteError::BadTags("outer")
    );
    // Wrong outer kind.
    let eph = Keys::generate();
    let ct = nip44::encrypt(
        eph.secret_key(),
        &w.mailbox.public_key(),
        &packet,
        nip44::Version::V2,
    )
    .unwrap();
    let k1 = EventBuilder::new(Kind::TextNote, ct)
        .tags(p_tag(&w))
        .sign_with_keys(&eph)
        .unwrap();
    assert_eq!(open(&w, &k1).unwrap_err(), InviteError::WrongKind("outer"));
    // Extra tag on the seal.
    let seal = seal_ev(
        &w.b,
        &good_hello_json(&w),
        vec![Tag::parse(["x", "y"]).unwrap()],
    );
    let bad = wrap_for(&w, &packet_for(&w, &seal.as_json()), p_tag(&w));
    assert_eq!(open(&w, &bad).unwrap_err(), InviteError::BadTags("seal"));
}

// ---- links ----

fn link_json(v: u64, to: &str, secret: &str, relays: &str, exp: u64) -> String {
    format!(r#"{{"v":{v},"to":"{to}","secret":"{secret}","relays":{relays},"exp":{exp}}}"#)
}

fn b64(s: &str) -> String {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(s)
}

#[test]
fn find_in_works_on_text_and_bare_links() {
    let w = world();
    let enc = w.link.encode("twangthang://friend");
    assert!(enc.starts_with("twangthang://friend#"));
    let line = format!("Play Twang Thang with me: {enc}");
    assert_eq!(FriendLink::find_in(&line, NOW).unwrap(), w.link);
    assert_eq!(FriendLink::find_in(&enc, NOW).unwrap(), w.link);
    assert_eq!(
        FriendLink::find_in(&w.link.encode("friend"), NOW).unwrap(),
        w.link
    );
    let web = w.link.encode("https://example.org/friend");
    assert_eq!(
        FriendLink::find_in(&format!("hi!\n{web} thanks"), NOW).unwrap(),
        w.link
    );
    assert_eq!(
        FriendLink::find_in("no link here", NOW).unwrap_err(),
        InviteError::NotFound
    );
    assert_eq!(
        FriendLink::find_in("x://friend#", NOW).unwrap_err(),
        InviteError::Malformed("link JSON")
    );
    // A bad earlier occurrence does not hide a good later one.
    let both = format!("friend#AAAA then {enc}");
    assert_eq!(FriendLink::find_in(&both, NOW).unwrap(), w.link);
    // The payload is base64url(canonical JSON) with a fixed field order.
    let payload = enc.split('#').nth(1).unwrap();
    use base64::Engine;
    let json = String::from_utf8(
        base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(payload)
            .unwrap(),
    )
    .unwrap();
    assert!(json.starts_with(&format!(
        r#"{{"v":1,"to":"{}","secret":"{}","relays":["#,
        w.a.public_key().to_hex(),
        hex::encode(w.link.secret)
    )));
    assert!(json.ends_with(&format!(r#""exp":{}}}"#, w.link.exp)));
    assert_eq!(
        w.link.hash(),
        <[u8; 32]>::from(Sha256::digest(json.as_bytes()))
    );
}

#[test]
fn find_in_rejects_bad_links() {
    let w = world();
    let to = w.a.public_key().to_hex();
    let sec = "11".repeat(32);
    let rel = r#"["wss://r.example"]"#;
    let exp = NOW + DAY;
    let ok = link_json(1, &to, &sec, rel, exp);
    let find = |j: &str| FriendLink::find_in(&format!("x://friend#{}", b64(j)), NOW);
    assert!(find(&ok).is_ok());
    assert_eq!(
        find(&link_json(2, &to, &sec, rel, exp)).unwrap_err(),
        InviteError::BadVersion
    );
    assert_eq!(
        find(&link_json(1, &to, &"zz".repeat(32), rel, exp)).unwrap_err(),
        InviteError::BadHex("secret")
    );
    assert_eq!(
        find(&link_json(1, &to, &"11".repeat(31), rel, exp)).unwrap_err(),
        InviteError::BadHex("secret")
    );
    assert_eq!(
        find(&link_json(1, "ab", &sec, rel, exp)).unwrap_err(),
        InviteError::BadHex("to")
    );
    assert_eq!(
        find(&link_json(1, &"00".repeat(32), &sec, rel, exp)).unwrap_err(),
        InviteError::BadHex("to")
    );
    for bad in [
        "[]",
        r#"["ws://r.example"]"#,
        r#"["wss://u:p@r.example"]"#,
        r#"["wss://r .example"]"#,
        r#"["wss://a","wss://b","wss://c","wss://d"]"#,
        r#"[7]"#,
    ] {
        assert!(find(&link_json(1, &to, &sec, bad, exp)).is_err(), "{bad}");
    }
    assert_eq!(
        find(&link_json(1, &to, &sec, rel, NOW)).unwrap_err(),
        InviteError::Expired
    );
    assert_eq!(
        find(&link_json(1, &to, &sec, rel, 5)).unwrap_err(),
        InviteError::Expired
    );
    assert!(find(&link_json(1, &to, &sec, rel, NOW + LINK_TTL_MAX)).is_ok());
    assert!(
        find(&link_json(1, &to, &sec, rel, NOW + LINK_TTL_MAX + 300)).is_ok(),
        "a reader's clock may run 5 minutes behind"
    );
    assert_eq!(
        find(&link_json(1, &to, &sec, rel, NOW + LINK_TTL_MAX + 301)).unwrap_err(),
        InviteError::ExpiryTooFar
    );
    assert_eq!(
        find(&link_json(1, &to, &sec, rel, u64::MAX)).unwrap_err(),
        InviteError::ExpiryTooFar
    );
    assert!(find(&ok.replace('}', r#","extra":1}"#)).is_err());
    assert!(find("not json").is_err());
    // A huge payload is refused, not parsed.
    let huge = format!("x://friend#{}", "A".repeat(100_000));
    assert!(FriendLink::find_in(&huge, NOW).is_err());
}

#[test]
fn ttl_is_capped_and_expiry_is_enforced() {
    let a = Keys::generate().public_key();
    let l = FriendLink::new(a, relay(), APP, NOW, LINK_TTL_DEFAULT).unwrap();
    assert_eq!(l.exp, NOW + 7 * DAY);
    let l = FriendLink::new(a, relay(), APP, NOW, 365 * DAY).unwrap();
    assert_eq!(l.exp, NOW + 30 * DAY);
    let l = FriendLink::new(a, relay(), APP, NOW, u64::MAX).unwrap();
    assert_eq!(l.exp, NOW + 30 * DAY);
    assert!(FriendLink::find_in(&l.encode("x://friend"), NOW).is_ok());
    assert!(FriendLink::find_in(&l.encode("x://friend"), l.exp - 1).is_ok());
    assert_eq!(
        FriendLink::find_in(&l.encode("x://friend"), l.exp).unwrap_err(),
        InviteError::Expired
    );
    // Relays are validated on creation.
    assert_eq!(
        FriendLink::new(a, vec![], APP, NOW, 10).unwrap_err(),
        InviteError::BadRelays
    );
    assert_eq!(
        FriendLink::new(a, vec!["ws://x".into()], APP, NOW, 10).unwrap_err(),
        InviteError::BadRelays
    );
    assert_eq!(
        FriendLink::new(a, vec!["wss://u:p@x".into()], APP, NOW, 10).unwrap_err(),
        InviteError::BadRelays
    );
    assert_eq!(
        FriendLink::new(a, relay(), APP, NOW, 0).unwrap().exp,
        NOW + 60,
        "never dead on arrival"
    );
    let four = vec!["wss://a".to_string(); 4];
    assert_eq!(
        FriendLink::new(a, four, APP, NOW, 10).unwrap_err(),
        InviteError::BadRelays
    );
}

#[test]
fn links_are_random_and_hash_depends_on_fields() {
    let a = Keys::generate().public_key();
    let l1 = FriendLink::new(a, relay(), APP, NOW, 100).unwrap();
    let l2 = FriendLink::new(a, relay(), APP, NOW, 100).unwrap();
    assert_ne!(l1.secret, l2.secret);
    assert_ne!(l1.hash(), l2.hash());
    let mut l3 = l1.clone();
    l3.exp += 1;
    assert_ne!(l1.hash(), l3.hash());
    assert!(!format!("{l1:?}").contains(&hex::encode(l1.secret)));
}

#[test]
fn mailbox_depends_on_app_id() {
    let w = world();
    assert_ne!(
        w.link.mailbox("app-a").unwrap().public_key(),
        w.link.mailbox("app-b").unwrap().public_key()
    );
}

// ---- derivation vectors ----

fn vector(s: &str) -> serde_json::Value {
    serde_json::from_str(s).unwrap()
}

fn hex32(v: &serde_json::Value) -> [u8; 32] {
    let mut out = [0u8; 32];
    hex::decode_to_slice(v.as_str().unwrap(), &mut out).unwrap();
    out
}

#[test]
fn signet_hkdf_vector() {
    // From forgesworn/signet-contacts (MIT); see vectors/NOTICE.
    let v = vector(include_str!("../vectors/signet-mailbox-v1.json"));
    assert_eq!(v["salt"], "signet-contacts:mailbox:v1");
    let k = derive_mailbox(
        &hex32(&v["inviteSecret"]),
        v["salt"].as_str().unwrap(),
        v["info"].as_str().unwrap(),
    )
    .unwrap();
    assert_eq!(
        k.secret_key().to_secret_hex(),
        v["mailboxPrivateKey"].as_str().unwrap()
    );
}

#[test]
fn kit_hkdf_vector() {
    let v = vector(include_str!("../vectors/kit-mailbox-v1.json"));
    assert_eq!(v["salt"], KIT_MAILBOX_SALT);
    let secret = hex32(&v["secret"]);
    let k = derive_mailbox(&secret, KIT_MAILBOX_SALT, v["info"].as_str().unwrap()).unwrap();
    assert_eq!(
        k.secret_key().to_secret_hex(),
        v["mailboxPrivateKey"].as_str().unwrap()
    );
    // Domain separation: another app id or the other salt gives another key.
    let other_app = derive_mailbox(&secret, KIT_MAILBOX_SALT, "other-app").unwrap();
    let other_salt = derive_mailbox(&secret, "signet-contacts:mailbox:v1", "test-app").unwrap();
    assert_ne!(k.public_key(), other_app.public_key());
    assert_ne!(k.public_key(), other_salt.public_key());
}

// ---- reply payload ----

#[test]
fn reply_payload_round_trips() {
    let w = world();
    let r = Reply::new(
        w.link.hash(),
        "Ann",
        vec!["wss://a.example".into()],
        att_for(&w.a),
    )
    .unwrap();
    let json = r.to_json().unwrap();
    assert!(json.starts_with(r#"{"v":1,"kind":"friend-reply","link":""#));
    assert_eq!(Reply::from_json(&json).unwrap(), r);
    assert!(Hello::from_json(&json).is_err());
    let hello_json = w.hello.to_json().unwrap();
    assert!(hello_json.starts_with(r#"{"v":1,"kind":"friend-hello","link":""#));
    assert!(Reply::from_json(&hello_json).is_err());
    // A name that needs sanitising comes back clean; an over-long one empty.
    let raw = hello_json.replace("Sam", &"z".repeat(40));
    assert_eq!(Hello::from_json(&raw).unwrap().name, "");
    // Relays in a hello are checked.
    let bad = hello_json.replace("wss://b.example", "http://b.example");
    assert_eq!(Hello::from_json(&bad).unwrap_err(), InviteError::BadRelays);
}

#[test]
fn a_lapsed_link_opens_nothing_and_a_verifier_that_says_no_refuses() {
    let w = world();
    let ev = seal_hello(&w.b, &w.link, &w.hello, APP, NOW).unwrap();
    assert_eq!(
        open_hello(&w.mailbox, &w.a, &w.link, &ev, w.link.exp, verify).unwrap_err(),
        InviteError::Expired
    );
    // The verifier is handed the seal signer, not a key the caller chose.
    let signer = w.b.public_key();
    let opened = open_hello(&w.mailbox, &w.a, &w.link, &ev, NOW, |_, k| *k == signer).unwrap();
    assert_eq!(opened.sender, signer);
}
