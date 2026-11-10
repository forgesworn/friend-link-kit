# friend-link-kit

The Rust crate `decented-invite`: friend links for decentralised games, and the
two-layer encrypted hello packet that goes with them.

A friend link lets someone who has never played with you reach you, even while
you are offline. It carries a recipient runtime key, a random secret and one to
three inbox relays. The secret derives a mailbox key (HKDF-SHA256 with the
kit's salt and the app id as `info`). The sender posts a hello to that mailbox
as a kind 1059 gift-wrap event with one `p` tag. The hello itself is a signed
seal, NIP-44 encrypted to the link's recipient key, so holding the link is not
enough to read who wrote to you or to see their attestation. Timestamps are
randomised up to two days into the past, and the event keys are fresh and
single-use.

The crate is pure. It does no networking, reads no clock and touches no
storage: the caller passes in the time, the keys and the attestation verifier,
and publishes or subscribes to the events itself. The app id is a parameter
everywhere, so no game is named in the code. Hostile input returns an
`InviteError`; nothing panics on it.

The public items are `FriendLink`, `Hello`, `Reply`, `seal_hello`,
`open_hello`, `derive_mailbox`, `sanitise_name` and the size and lifetime
constants documented in `src/lib.rs`.

## Depending on it

Pin a git revision in `Cargo.toml`:

```toml
decented-invite = { git = "https://github.com/forgesworn/friend-link-kit", rev = "<full commit hash>" }
```

## Tests

```
cargo test
```

The tests in `tests/invite.rs` use the public API only and include the
conformance vectors below.

## Vectors

`vectors/signet-mailbox-v1.json` reproduces two values from
`vectors/contact-invite-v1.json` in
[forgesworn/signet-contacts](https://github.com/forgesworn/signet-contacts),
used under its MIT licence; the licence text is in `vectors/NOTICE`.
`vectors/kit-mailbox-v1.json` was made for this crate, with this crate's own
salt, and computed independently of the Rust code (HKDF-SHA256 in Python).

## Licence

MIT. See `LICENSE`.
