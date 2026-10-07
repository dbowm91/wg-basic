use base64::{engine::general_purpose::STANDARD, Engine};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;
use zeroize::Zeroize;

#[derive(Clone, Eq, PartialEq)]
pub struct PublicKey(String);

impl PublicKey {
    pub fn new(value: String) -> Result<Self, KeyError> {
        validate_key(&value).map(|()| Self(value))
    }
    pub fn expose(&self) -> &str {
        &self.0
    }
}
impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("PublicKey").field(&self.0).finish()
    }
}
impl Serialize for PublicKey {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0)
    }
}
impl<'de> Deserialize<'de> for PublicKey {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Self::new(String::deserialize(deserializer)?).map_err(serde::de::Error::custom)
    }
}

pub struct PrivateKey(String);
impl PrivateKey {
    pub fn new(value: String) -> Result<Self, KeyError> {
        validate_key(&value).map(|()| Self(value))
    }
}
impl Drop for PrivateKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}
impl fmt::Debug for PrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PrivateKey([REDACTED])")
    }
}
impl fmt::Display for PrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[REDACTED]")
    }
}
impl Serialize for PrivateKey {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0)
    }
}
impl<'de> Deserialize<'de> for PrivateKey {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Self::new(String::deserialize(deserializer)?).map_err(serde::de::Error::custom)
    }
}

pub struct PresharedKey(String);
impl PresharedKey {
    pub fn new(value: String) -> Result<Self, KeyError> {
        validate_key(&value).map(|()| Self(value))
    }
}
impl Drop for PresharedKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}
impl fmt::Debug for PresharedKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PresharedKey([REDACTED])")
    }
}
impl fmt::Display for PresharedKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[REDACTED]")
    }
}
impl Serialize for PresharedKey {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0)
    }
}
impl<'de> Deserialize<'de> for PresharedKey {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Self::new(String::deserialize(deserializer)?).map_err(serde::de::Error::custom)
    }
}

fn validate_key(value: &str) -> Result<(), KeyError> {
    if !STANDARD.decode(value).is_ok_and(|key| key.len() == 32) {
        return Err(KeyError);
    }
    Ok(())
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[error("WireGuard key must be a 44-character base64 value")]
pub struct KeyError;

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn private_and_preshared_formatting_is_redacted() {
        let marker = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".to_owned();
        let private = PrivateKey::new(marker.clone()).unwrap();
        let preshared = PresharedKey::new(marker.clone()).unwrap();
        assert!(!format!("{private:?} {private}").contains(&marker));
        assert!(!format!("{preshared:?} {preshared}").contains(&marker));
        assert!(format!("{private:?}").contains("REDACTED"));
    }
}
