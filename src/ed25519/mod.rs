use curve25519_dalek::edwards::{CompressedEdwardsY, EdwardsPoint};
use curve25519_dalek::scalar::Scalar;
use sha2::{Digest, Sha512};

/// Ed25519 key pair
#[derive(Copy, Clone)]
pub struct KeyPair {
    pub secret_key: ExpandedSecretKey,
    pub public_key: PublicKey,
}

impl KeyPair {
    /// Signs a serialized TL representation of data
    #[inline(always)]
    #[cfg(feature = "tl-proto")]
    pub fn sign_tl<T: tl_proto::TlWrite>(&self, data: T) -> [u8; 64] {
        self.secret_key.sign_tl(data, &self.public_key)
    }

    /// Signs raw bytes
    #[inline(always)]
    pub fn sign_raw(&self, data: &[u8]) -> [u8; 64] {
        self.secret_key.sign_raw(data, &self.public_key)
    }

    /// Computes shared secret using x25519
    #[inline(always)]
    pub fn compute_shared_secret(&self, other_public_key: &PublicKey) -> [u8; 32] {
        self.secret_key.compute_shared_secret(other_public_key)
    }
}

#[cfg(feature = "rand8")]
impl rand8::distributions::Distribution<KeyPair> for rand8::distributions::Standard {
    #[inline]
    fn sample<R: rand8::Rng + ?Sized>(&self, rng: &mut R) -> KeyPair {
        let secret_key = rng.r#gen::<SecretKey>();

        KeyPair {
            secret_key: ExpandedSecretKey::from(&secret_key),
            public_key: PublicKey::from(&secret_key),
        }
    }
}

#[cfg(feature = "rand9")]
impl rand9::distr::Distribution<KeyPair> for rand9::distr::StandardUniform {
    fn sample<R: rand9::Rng + ?Sized>(&self, rng: &mut R) -> KeyPair {
        let secret_key = rng.random::<SecretKey>();

        KeyPair {
            secret_key: ExpandedSecretKey::from(&secret_key),
            public_key: PublicKey::from(&secret_key),
        }
    }
}

impl From<ExpandedSecretKey> for KeyPair {
    fn from(secret_key: ExpandedSecretKey) -> Self {
        let public_key = PublicKey::from(&secret_key);
        Self {
            secret_key,
            public_key,
        }
    }
}

impl From<&'_ SecretKey> for KeyPair {
    fn from(secret_key: &SecretKey) -> Self {
        let secret_key = secret_key.expand();
        let public_key = PublicKey::from(&secret_key);
        Self {
            secret_key,
            public_key,
        }
    }
}

/// Ed25519 public key
#[derive(Copy, Clone)]
pub struct PublicKey {
    compressed: CompressedEdwardsY,
    neg_point: EdwardsPoint,
}

impl PublicKey {
    /// Tries to create public key from
    #[inline(always)]
    pub fn from_bytes(bytes: [u8; 32]) -> Option<Self> {
        let compressed = CompressedEdwardsY(bytes);
        let point = compressed.decompress()?;
        Some(PublicKey {
            compressed,
            neg_point: -point,
        })
    }

    #[inline(always)]
    #[cfg(feature = "tl-proto")]
    pub fn from_tl(tl: crate::tl::PublicKey<'_>) -> Option<Self> {
        match tl {
            crate::tl::PublicKey::Ed25519 { key } => Self::from_bytes(*key),
            _ => None,
        }
    }

    #[inline(always)]
    #[cfg(feature = "tl-proto")]
    pub fn as_tl(&'_ self) -> crate::tl::PublicKey<'_> {
        crate::tl::PublicKey::Ed25519 {
            key: self.compressed.as_bytes(),
        }
    }

    #[inline(always)]
    pub fn to_bytes(&self) -> [u8; 32] {
        self.compressed.to_bytes()
    }

    #[inline(always)]
    pub fn as_bytes(&'_ self) -> &'_ [u8; 32] {
        self.compressed.as_bytes()
    }

    /// Verifies message signature using its TL representation
    ///
    /// NOTE: `[u8]` is representation differently in TL. Use [PublicKey::verify_raw] if
    /// you need to verify raw bytes signature
    #[cfg(feature = "tl-proto")]
    pub fn verify_tl<T: tl_proto::TlWrite>(&self, message: T, signature: &[u8; 64]) -> bool {
        let target_r = CompressedEdwardsY(signature[..32].try_into().unwrap());
        let s = match check_scalar(signature[32..].try_into().unwrap()) {
            Some(s) => s,
            None => return false,
        };

        let mut h = Sha512::new();
        h.update(target_r.as_bytes());
        h.update(self.compressed.as_bytes());
        tl_proto::HashWrapper(message).update_hasher(&mut h);

        let k = Scalar::from_bytes_mod_order_wide(&h.finalize().into());
        let r = EdwardsPoint::vartime_double_scalar_mul_basepoint(&k, &self.neg_point, &s);

        r.compress() == target_r
    }

    /// Verifies message signature as it is
    pub fn verify_raw(&self, message: &[u8], signature: &[u8; 64]) -> bool {
        let target_r = CompressedEdwardsY(signature[..32].try_into().unwrap());
        let s = match check_scalar(signature[32..].try_into().unwrap()) {
            Some(s) => s,
            None => return false,
        };

        let mut h = Sha512::new();
        h.update(target_r.as_bytes());
        h.update(self.compressed.as_bytes());
        h.update(message);

        let k = Scalar::from_bytes_mod_order_wide(&h.finalize().into());
        let r = EdwardsPoint::vartime_double_scalar_mul_basepoint(&k, &self.neg_point, &s);

        r.compress() == target_r
    }

    #[inline(always)]
    fn from_scalar(bits: [u8; 32]) -> PublicKey {
        let point = EdwardsPoint::mul_base_clamped(bits);
        let compressed = point.compress();
        Self {
            compressed,
            neg_point: -point,
        }
    }
}

impl From<&'_ SecretKey> for PublicKey {
    fn from(secret_key: &SecretKey) -> Self {
        let mut h = Sha512::new();
        h.update(secret_key.0.as_slice());
        let hash: [u8; 64] = h.finalize().into();
        Self::from_scalar(hash[..32].try_into().unwrap())
    }
}

impl From<&'_ ExpandedSecretKey> for PublicKey {
    fn from(expanded_secret_key: &ExpandedSecretKey) -> Self {
        Self::from_scalar(expanded_secret_key.key_bytes)
    }
}

impl AsRef<[u8; 32]> for PublicKey {
    fn as_ref(&self) -> &[u8; 32] {
        self.as_bytes()
    }
}

impl PartialEq for PublicKey {
    #[inline(always)]
    fn eq(&self, other: &Self) -> bool {
        self.compressed.eq(&other.compressed)
    }
}

impl Eq for PublicKey {}

impl std::fmt::Display for PublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let mut output = [0u8; 64];
        hex::encode_to_slice(self.compressed.as_bytes(), &mut output).ok();

        // SAFETY: output is guaranteed to contain only [0-9a-f]
        let output = unsafe { std::str::from_utf8_unchecked(&output) };
        f.write_str(output)
    }
}

impl std::fmt::Debug for PublicKey {
    #[inline]
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        std::fmt::Display::fmt(self, f)
    }
}

#[cfg(feature = "serde")]
impl serde::Serialize for PublicKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        if serializer.is_human_readable() {
            serializer.collect_str(self)
        } else {
            self.as_bytes().serialize(serializer)
        }
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for PublicKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::{Error, Visitor};

        struct BytesVisitor;

        impl Visitor<'_> for BytesVisitor {
            type Value = [u8; 32];

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("hex-encoded public key")
            }

            fn visit_str<E: Error>(self, value: &str) -> Result<Self::Value, E> {
                let mut result = [0; 32];
                match hex::decode_to_slice(value, &mut result) {
                    Ok(()) => Ok(result),
                    Err(_) => Err(Error::invalid_value(
                        serde::de::Unexpected::Str(value),
                        &self,
                    )),
                }
            }
        }

        let bytes = if deserializer.is_human_readable() {
            deserializer.deserialize_str(BytesVisitor)
        } else {
            <[u8; 32]>::deserialize(deserializer)
        }?;

        Self::from_bytes(bytes).ok_or_else(|| Error::custom("invalid public key"))
    }
}

#[derive(Copy, Clone)]
pub struct ExpandedSecretKey {
    key: Scalar,
    key_bytes: [u8; 32],
    nonce: [u8; 32],
}

impl ExpandedSecretKey {
    #[inline(always)]
    pub fn nonce(&'_ self) -> &'_ [u8; 32] {
        &self.nonce
    }

    #[cfg(feature = "tl-proto")]
    pub fn sign_tl<T: tl_proto::TlWrite>(&self, message: T, public_key: &PublicKey) -> [u8; 64] {
        #![allow(non_snake_case)]

        let message = tl_proto::HashWrapper(message);

        let mut h = Sha512::new();
        h.update(self.nonce.as_slice());
        message.update_hasher(&mut h);

        let r = Scalar::from_bytes_mod_order_wide(&h.finalize().into());
        let R = EdwardsPoint::mul_base(&r).compress();

        h = Sha512::new();
        h.update(R.as_bytes());
        h.update(public_key.as_bytes());
        message.update_hasher(&mut h);

        let k = Scalar::from_bytes_mod_order_wide(&h.finalize().into());
        let s = (k * self.key) + r;

        let mut result = [0u8; 64];
        result[..32].copy_from_slice(R.as_bytes().as_slice());
        result[32..].copy_from_slice(s.as_bytes().as_slice());
        result
    }

    pub fn sign_raw(&self, message: &[u8], public_key: &PublicKey) -> [u8; 64] {
        #![allow(non_snake_case)]

        let mut h = Sha512::new();
        h.update(self.nonce.as_slice());
        h.update(message);

        let r = Scalar::from_bytes_mod_order_wide(&h.finalize().into());
        let R = EdwardsPoint::mul_base(&r).compress();

        h = Sha512::new();
        h.update(R.as_bytes());
        h.update(public_key.as_bytes());
        h.update(message);

        let k = Scalar::from_bytes_mod_order_wide(&h.finalize().into());
        let s = (k * self.key) + r;

        let mut result = [0u8; 64];
        result[..32].copy_from_slice(R.as_bytes().as_slice());
        result[32..].copy_from_slice(s.as_bytes().as_slice());
        result
    }

    #[inline(always)]
    pub fn compute_shared_secret(&self, other_public_key: &PublicKey) -> [u8; 32] {
        let point = (-other_public_key.neg_point).to_montgomery();
        (point * self.key).to_bytes()
    }
}

impl From<&'_ SecretKey> for ExpandedSecretKey {
    fn from(secret_key: &SecretKey) -> Self {
        let mut h = Sha512::new();
        h.update(secret_key.0.as_slice());
        let hash: [u8; 64] = h.finalize().into();

        let lower: [u8; 32] = hash[..32].try_into().unwrap();
        let nonce: [u8; 32] = hash[32..].try_into().unwrap();

        let key_bytes = curve25519_dalek::scalar::clamp_integer(lower);

        Self {
            key: Scalar::from_bytes_mod_order(key_bytes),
            key_bytes,
            nonce,
        }
    }
}

#[derive(Copy, Clone)]
pub struct SecretKey([u8; 32]);

impl SecretKey {
    #[inline(always)]
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    #[inline(always)]
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0
    }

    #[inline(always)]
    pub fn as_bytes(&'_ self) -> &'_ [u8; 32] {
        &self.0
    }

    #[inline(always)]
    pub fn expand(&self) -> ExpandedSecretKey {
        ExpandedSecretKey::from(self)
    }
}

#[cfg(feature = "rand8")]
impl rand8::distributions::Distribution<SecretKey> for rand8::distributions::Standard {
    #[inline]
    fn sample<R: rand8::Rng + ?Sized>(&self, rng: &mut R) -> SecretKey {
        SecretKey(rng.r#gen())
    }
}

#[cfg(feature = "rand9")]
impl rand9::distr::Distribution<SecretKey> for rand9::distr::StandardUniform {
    #[inline]
    fn sample<R: rand9::Rng + ?Sized>(&self, rng: &mut R) -> SecretKey {
        SecretKey(rng.random())
    }
}

#[inline(always)]
fn check_scalar(bytes: [u8; 32]) -> Option<Scalar> {
    Scalar::from_canonical_bytes(bytes).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn correct_signature() {
        let secret = SecretKey::from_bytes([
            99, 87, 207, 105, 199, 108, 51, 89, 172, 108, 232, 48, 240, 147, 49, 155, 145, 60, 66,
            55, 98, 149, 119, 0, 251, 19, 132, 69, 151, 132, 184, 53,
        ]);

        let pubkey = PublicKey::from(&secret);
        assert_eq!(
            pubkey.to_bytes(),
            [
                75, 54, 96, 93, 16, 21, 8, 159, 230, 42, 68, 148, 54, 18, 251, 196, 205, 254, 252,
                114, 76, 87, 204, 218, 132, 26, 196, 181, 191, 188, 115, 123
            ]
        );
        println!("{pubkey:?}");

        let data = b"hello world";

        let extended = ExpandedSecretKey::from(&secret);
        let signature = extended.sign_tl(data, &pubkey);
        assert_eq!(
            signature,
            [
                76, 51, 131, 27, 77, 188, 20, 26, 229, 121, 93, 100, 10, 166, 183, 121, 12, 48, 17,
                239, 115, 184, 50, 162, 103, 228, 3, 136, 213, 165, 246, 113, 220, 84, 255, 136,
                251, 141, 229, 52, 236, 249, 135, 182, 242, 198, 171, 1, 194, 148, 164, 8, 131,
                253, 205, 112, 112, 145, 6, 225, 71, 78, 138, 1
            ]
        );

        assert!(pubkey.verify_tl(data, &signature))
    }

    #[test]
    fn verify_with_different_key() {
        let first = rand9::random::<SecretKey>();
        let first_pubkey = PublicKey::from(&first);

        let second = rand9::random::<SecretKey>();
        let second_pubkey = PublicKey::from(&second);

        let data = b"hello world";

        let extended = ExpandedSecretKey::from(&first);
        let signature = extended.sign_tl(data, &first_pubkey);

        assert!(!second_pubkey.verify_tl(data, &signature))
    }

    #[test]
    fn correct_shared_secret() {
        let first = ExpandedSecretKey::from(&SecretKey::from_bytes([
            215, 30, 117, 171, 183, 9, 171, 48, 212, 45, 10, 198, 14, 66, 109, 80, 163, 180, 194,
            66, 82, 184, 13, 48, 240, 102, 40, 110, 156, 5, 13, 143,
        ]));
        let first_pubkey = PublicKey::from(&first);

        let second = ExpandedSecretKey::from(&SecretKey::from_bytes([
            181, 115, 13, 55, 26, 150, 138, 43, 66, 28, 162, 50, 0, 133, 120, 24, 20, 142, 183, 60,
            159, 53, 200, 97, 14, 123, 63, 249, 222, 211, 186, 99,
        ]));
        let second_pubkey = PublicKey::from(&second);

        let first_shared_key = first.compute_shared_secret(&second_pubkey);
        let second_shared_key = second.compute_shared_secret(&first_pubkey);

        assert_eq!(
            first_shared_key,
            [
                30, 243, 238, 65, 216, 53, 237, 172, 6, 120, 204, 220, 34, 163, 18, 28, 181, 245,
                215, 233, 98, 0, 87, 11, 85, 6, 41, 130, 140, 95, 66, 72
            ]
        );
        assert_eq!(first_shared_key, second_shared_key);
    }

    #[test]
    fn same_shared_secret() {
        let first = ExpandedSecretKey::from(&rand9::random::<SecretKey>());
        let first_pubkey = PublicKey::from(&first);

        let second = ExpandedSecretKey::from(&rand9::random::<SecretKey>());
        let second_pubkey = PublicKey::from(&second);

        let first_shared_key = first.compute_shared_secret(&second_pubkey);
        let second_shared_key = second.compute_shared_secret(&first_pubkey);

        assert_eq!(first_shared_key, second_shared_key);
    }

    #[test]
    fn shared_secret_on_self() {
        let secret = rand9::random::<SecretKey>();
        let pubkey = PublicKey::from(&secret);

        let shared = ExpandedSecretKey::from(&secret).compute_shared_secret(&pubkey);
        assert_ne!(secret.as_bytes(), &shared);
    }
}
