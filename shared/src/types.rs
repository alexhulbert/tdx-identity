//! Shared types between the registry and the identity service

use core::fmt;

use ed25519_dalek::{PUBLIC_KEY_LENGTH, SIGNATURE_LENGTH};
use serde::{Deserialize, Serialize};

/// The data that the registry stores for each instance
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct RegisterRequest {
    #[serde(with = "hex_serde")]
    pub instance_pubkey: [u8; PUBLIC_KEY_LENGTH],
    #[serde(with = "hex_serde")]
    pub ppid: Vec<u8>,
    #[serde(with = "base64_serde")]
    pub attestation_quote: Vec<u8>,
    pub operator: Option<IdentityInfo>,
    pub owner: Option<IdentityInfo>,
}

/// Allows for more descriptive error messages in generic validation functions
pub enum UserType {
    Operator,
    Owner,
    Instance,
}

impl fmt::Display for UserType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Operator => "operator",
            Self::Owner => "owner",
            Self::Instance => "instance",
        };
        write!(f, "{}", s)
    }
}

/// Identifying information for either the owner or operator
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct IdentityInfo {
    #[serde(with = "hex_serde")]
    pub pubkey: [u8; PUBLIC_KEY_LENGTH],
    #[serde(with = "hex_serde")]
    pub instance_signature: [u8; SIGNATURE_LENGTH],
    #[serde(with = "hex_serde")]
    pub identity_signature: [u8; SIGNATURE_LENGTH],
}

/// Serde serialization and deserialization for base64-encoded data
pub mod base64_serde {
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &Vec<u8>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let encoded = STANDARD.encode(bytes);
        serializer.serialize_str(&encoded)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        STANDARD.decode(&s).map_err(serde::de::Error::custom)
    }
}

/// Serde serialization and deserialization for hex-encoded data
pub mod hex_serde {
    use hex;
    use serde::{Deserialize, Deserializer, Serializer};

    pub trait HexSerializable: Sized {
        fn try_from_hex_vec(vec: Vec<u8>) -> Result<Self, String>;
    }

    impl HexSerializable for Vec<u8> {
        fn try_from_hex_vec(vec: Vec<u8>) -> Result<Self, String> {
            Ok(vec)
        }
    }

    impl<const N: usize> HexSerializable for [u8; N] {
        fn try_from_hex_vec(vec: Vec<u8>) -> Result<Self, String> {
            let len = vec.len();
            vec.try_into()
                .map_err(|_| format!("Expected {} bytes, got {}", N, len))
        }
    }

    pub fn serialize<S, T>(bytes: &T, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
        T: AsRef<[u8]>,
    {
        serializer.serialize_str(&hex::encode(bytes))
    }

    pub fn deserialize<'de, D, T>(deserializer: D) -> Result<T, D::Error>
    where
        D: Deserializer<'de>,
        T: HexSerializable,
    {
        let s = String::deserialize(deserializer)?;
        let vec = hex::decode(&s).map_err(serde::de::Error::custom)?;
        T::try_from_hex_vec(vec).map_err(serde::de::Error::custom)
    }
}
