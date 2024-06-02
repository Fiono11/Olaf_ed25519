//! Implementation of the Olaf protocol (<https://eprint.iacr.org/2023/899>), which is composed of the Distributed
//! Key Generation (DKG) protocol SimplPedPoP and the Threshold Signing protocol FROST.

/// Implementation of the FROST protocol.
pub mod frost;

/// Implementation of the SimplPedPoP protocol.
pub mod simplpedpop;

extern crate alloc;

use curve25519_dalek::{
    constants::ED25519_BASEPOINT_POINT, edwards::CompressedEdwardsY, EdwardsPoint, Scalar,
};
use ed25519::Signature;
use ed25519_dalek::{
    hazmat::ExpandedSecretKey, SecretKey, SignatureError, Signer, Verifier, VerifyingKey,
    KEYPAIR_LENGTH, PUBLIC_KEY_LENGTH, SECRET_KEY_LENGTH,
};
use merlin::Transcript;
use rand_core::CryptoRngCore;
use sha2::{digest::consts::U64, Digest, Sha512};

pub(crate) const MINIMUM_THRESHOLD: u16 = 2;
pub(crate) const GENERATOR: EdwardsPoint = ED25519_BASEPOINT_POINT;
pub(crate) const SCALAR_LENGTH: usize = 32;
pub(crate) const COMPRESSED_EDWARDS_LENGTH: usize = 32;

/// The threshold public key generated in the SimplPedPoP protocol, used to validate the threshold signatures of the FROST protocol.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct ThresholdPublicKey(pub VerifyingKey);

/// The verifying share of a participant generated in the SimplPedPoP protocol, used to verify its signatures shares in the FROST protocol.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct VerifyingShare(pub VerifyingKey);

/// The signing keypair of a participant generated in the SimplPedPoP protocol, used to produce its signatures shares in the FROST protocol.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SigningKeypair {
    pub secret_key: SecretKey,
    pub verifying_key: VerifyingKey,
}

impl SigningKeypair {
    /// Serializes `SigningKeypair` to bytes.
    pub fn to_bytes(&self) -> [u8; KEYPAIR_LENGTH] {
        let mut bytes = [0; KEYPAIR_LENGTH];

        bytes[..SECRET_KEY_LENGTH].copy_from_slice(&self.secret_key);
        bytes[PUBLIC_KEY_LENGTH..].copy_from_slice(self.verifying_key.as_bytes());

        bytes
    }

    /// Deserializes a `SigningKeypair` from bytes.
    pub fn from_bytes(bytes: &[u8; KEYPAIR_LENGTH]) -> Result<SigningKeypair, SignatureError> {
        let mut secret_key = [0; SECRET_KEY_LENGTH];
        secret_key.copy_from_slice(&bytes[..SECRET_KEY_LENGTH]);

        let mut verifying_key_bytes = [0; PUBLIC_KEY_LENGTH];
        verifying_key_bytes.copy_from_slice(&bytes[PUBLIC_KEY_LENGTH..]);

        let verifying_key = VerifyingKey::from_bytes(&verifying_key_bytes)?;

        let signing_keypair = SigningKeypair {
            secret_key,
            verifying_key,
        };

        Ok(signing_keypair)
    }

    pub fn generate<R: CryptoRngCore + ?Sized>(csprng: &mut R) -> SigningKeypair {
        let mut secret = SecretKey::default();
        csprng.fill_bytes(&mut secret);
        Self::from_secret_key(&secret)
    }

    pub fn from_secret_key(secret_key: &SecretKey) -> Self {
        let verifying_key = VerifyingKey::from(&ExpandedSecretKey::from(secret_key));
        Self {
            secret_key: *secret_key,
            verifying_key,
        }
    }
}

impl Signer<Signature> for SigningKeypair {
    /// Sign a message with this signing key's secret key.
    fn try_sign(&self, message: &[u8]) -> Result<Signature, SignatureError> {
        let expanded: ExpandedSecretKey = (&self.secret_key).into();
        Ok(raw_sign::<Sha512>(&expanded, message, &self.verifying_key))
    }
}

pub(crate) fn raw_sign<CtxDigest>(
    expanded_secret_key: &ExpandedSecretKey,
    message: &[u8],
    verifying_key: &VerifyingKey,
) -> Signature
where
    CtxDigest: Digest<OutputSize = U64>,
{
    let mut h = CtxDigest::new();

    h.update(expanded_secret_key.hash_prefix);
    h.update(message);

    let r = Scalar::from_hash(h);
    let R: CompressedEdwardsY = EdwardsPoint::mul_base(&r).compress();

    h = CtxDigest::new();
    h.update(R.as_bytes());
    h.update(verifying_key.as_bytes());
    h.update(message);

    let k = Scalar::from_hash(h);
    let s: Scalar = (k * expanded_secret_key.scalar) + r;

    Signature::from_components(R.0, s.to_bytes())
}

/// The identifier of a participant, which is the same in the SimplPedPoP protocol and in the FROST protocol.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Identifier(pub(crate) Scalar);

impl Identifier {
    pub(crate) fn generate(recipients_hash: &[u8; 16], index: u16) -> Identifier {
        let mut pos = Transcript::new(b"Identifier");
        pos.append_message(b"RecipientsHash", recipients_hash);
        pos.append_message(b"i", &index.to_le_bytes()[..]);

        let mut buf = [0; 64];
        pos.challenge_bytes(b"identifier", &mut buf);

        Identifier(Scalar::from_bytes_mod_order_wide(&buf))
    }
}

pub(crate) fn scalar_from_canonical_bytes(bytes: [u8; 32]) -> Option<Scalar> {
    let key = Scalar::from_canonical_bytes(bytes);

    // Note: this is a `CtOption` so we have to do this to extract the value.
    if bool::from(key.is_none()) {
        return None;
    }

    Some(key.unwrap())
}

#[cfg(test)]
pub(crate) mod test_utils {
    use super::MINIMUM_THRESHOLD;
    use crate::{
        simplpedpop::Parameters, SigningKeypair, VerifyingKey, GENERATOR, PUBLIC_KEY_LENGTH,
        SECRET_KEY_LENGTH,
    };
    use curve25519_dalek::Scalar;
    use ed25519::signature::Keypair;
    use rand::{thread_rng, Rng, RngCore};

    const MAXIMUM_PARTICIPANTS: u16 = 10;
    const MINIMUM_PARTICIPANTS: u16 = 2;

    pub(crate) fn generate_parameters() -> Parameters {
        let mut rng = thread_rng();
        let participants = rng.gen_range(MINIMUM_PARTICIPANTS..=MAXIMUM_PARTICIPANTS);
        let threshold = rng.gen_range(MINIMUM_THRESHOLD..=participants);

        Parameters {
            participants,
            threshold,
        }
    }

    #[test]
    fn test_signing_keypair_serialization() {
        let mut rng = thread_rng();

        let mut secret_key = [0; SECRET_KEY_LENGTH];
        thread_rng().fill_bytes(&mut secret_key);

        let mut point = Scalar::random(&mut rng) * GENERATOR;

        let verifying_key = VerifyingKey::from_bytes(&point.compress().0).unwrap();

        let keypair = SigningKeypair {
            secret_key,
            verifying_key,
        };

        let bytes = keypair.to_bytes();
        let deserialized_keypair = SigningKeypair::from_bytes(&bytes).unwrap();

        assert_eq!(keypair, deserialized_keypair);
    }
}
