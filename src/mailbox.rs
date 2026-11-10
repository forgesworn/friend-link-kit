use hkdf::Hkdf;
use nostr::{Keys, SecretKey};
use sha2::Sha256;

use crate::{InviteError, Result};

/// The secp256k1 group order n, big-endian.
const CURVE_ORDER: [u8; 32] = [
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE,
    0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B, 0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x41,
];

/// True when `k` is a valid secp256k1 secret scalar: nonzero and below the
/// group order. Never reduce an out-of-range value; make another secret.
pub(crate) fn scalar_ok(k: &[u8; 32]) -> bool {
    k.iter().any(|b| *b != 0) && k.as_slice() < CURVE_ORDER.as_slice()
}

/// The mailbox key for a link secret: HKDF-SHA256 with IKM = `secret`, the given
/// `salt` and `info`, 32 bytes. Errors when the result is zero or at least the
/// curve order.
pub fn derive_mailbox(secret: &[u8; 32], salt: &str, info: &str) -> Result<Keys> {
    let hk = Hkdf::<Sha256>::new(Some(salt.as_bytes()), secret);
    let mut okm = [0u8; 32];
    hk.expand(info.as_bytes(), &mut okm)
        .map_err(|_| InviteError::InvalidMailboxKey)?;
    if !scalar_ok(&okm) {
        return Err(InviteError::InvalidMailboxKey);
    }
    let sk = SecretKey::from_slice(&okm).map_err(|_| InviteError::InvalidMailboxKey)?;
    Ok(Keys::new(sk))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn n_plus(delta: i8) -> [u8; 32] {
        let mut k = CURVE_ORDER;
        k[31] = k[31].wrapping_add(delta as u8);
        k
    }

    #[test]
    fn scalar_range() {
        assert!(!scalar_ok(&[0u8; 32]));
        let mut one = [0u8; 32];
        one[31] = 1;
        assert!(scalar_ok(&one));
        assert!(scalar_ok(&n_plus(-1)), "n-1 is the largest valid scalar");
        assert!(!scalar_ok(&n_plus(0)), "n is out of range");
        assert!(!scalar_ok(&n_plus(1)));
        assert!(!scalar_ok(&[0xFF; 32]));
        // The nostr library agrees at the edges.
        assert!(SecretKey::from_slice(&n_plus(-1)).is_ok());
        assert!(SecretKey::from_slice(&n_plus(0)).is_err());
        assert!(SecretKey::from_slice(&[0u8; 32]).is_err());
    }
}
