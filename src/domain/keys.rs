use super::{KeyError, PrivateKey, PublicKey};
use base64::{engine::general_purpose::STANDARD, Engine};
use std::fmt;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};
use zeroize::Zeroize;

pub struct WireGuardKeyPair {
    pub private_key: PrivateKey,
    pub public_key: PublicKey,
}

impl fmt::Debug for WireGuardKeyPair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WireGuardKeyPair")
            .field("private_key", &"[REDACTED]")
            .field("public_key", &self.public_key)
            .finish()
    }
}

pub fn generate_keypair() -> Result<WireGuardKeyPair, KeyError> {
    let secret = StaticSecret::random();
    let public = X25519PublicKey::from(&secret);
    let mut private_bytes = secret.to_bytes();
    let private_key = PrivateKey::new(STANDARD.encode(private_bytes))?;
    private_bytes.zeroize();
    let public_key = PublicKey::new(STANDARD.encode(public.as_bytes()))?;
    Ok(WireGuardKeyPair {
        private_key,
        public_key,
    })
}

pub fn derive_public_key(private_key: &PrivateKey) -> Result<PublicKey, KeyError> {
    let mut private_bytes: [u8; 32] = STANDARD
        .decode(private_key.expose_secret())
        .map_err(|_| KeyError)?
        .try_into()
        .map_err(|_| KeyError)?;
    let secret = StaticSecret::from(private_bytes);
    private_bytes.zeroize();
    let public = X25519PublicKey::from(&secret);
    PublicKey::new(STANDARD.encode(public.as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{engine::general_purpose::STANDARD, Engine};

    #[test]
    fn derives_wireguard_public_key_from_known_private_key() {
        let private_bytes = STANDARD
            .decode("6LTHiAM4vgKEgi5vm30f/EBIEWFDmySkTc9EWCcIqEs=")
            .unwrap();
        let private: [u8; 32] = private_bytes.try_into().unwrap();
        let secret = StaticSecret::from(private);
        let public = X25519PublicKey::from(&secret);
        assert_eq!(
            STANDARD.encode(public.as_bytes()),
            "JKossUAjywXuJ2YVcaeD6PaHs+afPmIthDuqEVlspwA="
        );
    }

    #[test]
    fn generated_keypair_has_valid_distinct_keys_and_redacted_debug() {
        let pair = generate_keypair().unwrap();
        assert_ne!(pair.private_key.expose_secret(), pair.public_key.expose());
        assert!(PrivateKey::new(pair.private_key.expose_secret().to_owned()).is_ok());
        let debug = format!("{pair:?}");
        assert!(!debug.contains(pair.private_key.expose_secret()));
        assert!(debug.contains(pair.public_key.expose()));
    }
}
