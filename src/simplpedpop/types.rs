//! SimplPedPoP types.

use alloc::vec::Vec;
use core::iter;
use curve25519_dalek::{edwards::CompressedEdwardsY, traits::Identity, EdwardsPoint, Scalar};
use ed25519::Signature;
use ed25519_dalek::{VerifyingKey, PUBLIC_KEY_LENGTH, SIGNATURE_LENGTH};
use merlin::Transcript;
use rand_core::{CryptoRng, RngCore};
use zeroize::Zeroize;

use crate::{
    scalar_from_canonical_bytes, Identifier, ThresholdPublicKey, VerifyingShare, GENERATOR,
    MINIMUM_THRESHOLD,
};

use super::errors::{SPPError, SPPResult};

pub(super) const COMPRESSED_EDWARDS_LENGTH: usize = 32;
pub(super) const VEC_LENGTH: usize = 2;
pub(super) const ENCRYPTION_NONCE_LENGTH: usize = 12;
pub(super) const RECIPIENTS_HASH_LENGTH: usize = 16;
pub(super) const SCALAR_LENGTH: usize = 32;
pub(super) const U16_LENGTH: usize = 2;

/// The parameters of a given execution of the SimplPedPoP protocol.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Parameters {
    pub(crate) participants: u16,
    pub(crate) threshold: u16,
}

impl Parameters {
    /// Create new parameters.
    pub fn generate(participants: u16, threshold: u16) -> Parameters {
        Parameters {
            participants,
            threshold,
        }
    }

    pub(super) fn validate(&self) -> Result<(), SPPError> {
        if self.threshold < MINIMUM_THRESHOLD {
            return Err(SPPError::InsufficientThreshold);
        }

        if self.participants < MINIMUM_THRESHOLD {
            return Err(SPPError::InvalidNumberOfParticipants);
        }

        if self.threshold > self.participants {
            return Err(SPPError::ExcessiveThreshold);
        }

        Ok(())
    }

    pub(super) fn commit(&self, t: &mut Transcript) {
        t.append_message(b"threshold", &self.threshold.to_le_bytes());
        t.append_message(b"participants", &self.participants.to_le_bytes());
    }

    /// Serializes `Parameters` into a byte array.
    pub fn to_bytes(&self) -> [u8; U16_LENGTH * 2] {
        let mut bytes = [0u8; U16_LENGTH * 2];
        bytes[0..U16_LENGTH].copy_from_slice(&self.participants.to_le_bytes());
        bytes[U16_LENGTH..U16_LENGTH * 2].copy_from_slice(&self.threshold.to_le_bytes());
        bytes
    }

    /// Constructs `Parameters` from a byte array.
    pub fn from_bytes(bytes: &[u8]) -> SPPResult<Parameters> {
        if bytes.len() != U16_LENGTH * 2 {
            return Err(SPPError::InvalidParameters);
        }

        let participants = u16::from_le_bytes([bytes[0], bytes[1]]);
        let threshold = u16::from_le_bytes([bytes[2], bytes[3]]);

        Ok(Parameters {
            participants,
            threshold,
        })
    }
}

#[derive(Zeroize)]
pub(super) struct SecretShare(pub(super) Scalar);

impl Drop for SecretShare {
    fn drop(&mut self) {
        self.zeroize()
    }
}

impl SecretShare {
    pub(super) fn encrypt(
        &self,
        transcript: &mut Transcript,
        i: usize,
        recipient: &VerifyingKey,
        encryption_nonce: &[u8],
        key_exchange: &EdwardsPoint,
    ) -> EncryptedSecretShare {
        // We tweak by i too since encrypton_nonce is not truly a nonce.
        transcript.append_message(b"i", &i.to_le_bytes());

        transcript.append_message(b"recipient", &recipient.to_bytes());
        transcript.append_message(b"kex", &key_exchange.compress().to_bytes());

        // Afaik redundant for merlin, but attacks get better.
        transcript.append_message(b"nonce", encryption_nonce);

        let mut buf = [0; 64];
        transcript.challenge_bytes(b"encryption scalar", &mut buf);
        let scalar = Scalar::from_bytes_mod_order_wide(&buf);

        // As this is encryption, we require similar security properties
        // as from witness_bytes here, but without randomness, and
        // challenge_scalar is imeplemented close enough.
        EncryptedSecretShare(self.0 + scalar)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EncryptedSecretShare(pub(super) Scalar);

impl EncryptedSecretShare {
    pub(super) fn decrypt(
        &self,
        transcript: &mut Transcript,
        i: usize,
        recipient: &VerifyingKey,
        encryption_nonce: &[u8],
        key_exchange: &EdwardsPoint,
    ) -> SecretShare {
        transcript.append_message(b"i", &i.to_le_bytes());

        transcript.append_message(b"recipient", &recipient.to_bytes());
        transcript.append_message(b"kex", &key_exchange.compress().to_bytes());

        transcript.append_message(b"nonce", encryption_nonce);

        let mut buf = [0; 64];
        transcript.challenge_bytes(b"encryption scalar", &mut buf);
        let scalar = Scalar::from_bytes_mod_order_wide(&buf);

        SecretShare(self.0 - scalar)
    }
}

/// The secret polynomial of a participant chosen at randoma nd used to generate the secret shares of all the participants (including itself).
#[derive(Zeroize)]
pub(crate) struct SecretPolynomial {
    pub(super) coefficients: Vec<Scalar>,
}

impl Drop for SecretPolynomial {
    fn drop(&mut self) {
        self.zeroize()
    }
}

impl SecretPolynomial {
    pub(super) fn generate<R: RngCore + CryptoRng>(degree: usize, rng: &mut R) -> Self {
        let mut coefficients = Vec::with_capacity(degree + 1);

        let mut first = Scalar::random(rng);
        while first == Scalar::ZERO {
            first = Scalar::random(rng);
        }

        coefficients.push(first);
        coefficients.extend(iter::repeat_with(|| Scalar::random(rng)).take(degree));

        SecretPolynomial { coefficients }
    }

    pub(super) fn evaluate(&self, x: &Scalar) -> Scalar {
        let mut value = *self
            .coefficients
            .last()
            .expect("coefficients must have at least one element");

        // Process all coefficients except the last one, using Horner's method
        for coeff in self.coefficients.iter().rev().skip(1) {
            value = value * x + coeff;
        }

        value
    }
}

/// The polynomial commitment of a participant, used to verify the secret shares without revealing the polynomial.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct PolynomialCommitment {
    pub(super) coefficients_commitments: Vec<EdwardsPoint>,
}

impl PolynomialCommitment {
    pub(super) fn commit(secret_polynomial: &SecretPolynomial) -> Self {
        let coefficients_commitments = secret_polynomial
            .coefficients
            .iter()
            .map(|coefficient| GENERATOR * coefficient)
            .collect();

        Self {
            coefficients_commitments,
        }
    }

    pub(super) fn evaluate(&self, identifier: &Scalar) -> EdwardsPoint {
        let i = identifier;

        let (_, result) = self.coefficients_commitments.iter().fold(
            (Scalar::ONE, EdwardsPoint::identity()),
            |(i_to_the_k, sum_so_far), comm_k| (i * i_to_the_k, sum_so_far + comm_k * i_to_the_k),
        );

        result
    }

    pub(super) fn sum_polynomial_commitments(
        polynomials_commitments: &[&PolynomialCommitment],
    ) -> PolynomialCommitment {
        let max_length = polynomials_commitments
            .iter()
            .map(|c| c.coefficients_commitments.len())
            .max()
            .unwrap_or(0);

        let mut total_commitment = vec![EdwardsPoint::identity(); max_length];

        for polynomial_commitment in polynomials_commitments {
            for (i, coeff_commitment) in polynomial_commitment
                .coefficients_commitments
                .iter()
                .enumerate()
            {
                total_commitment[i] += coeff_commitment;
            }
        }

        PolynomialCommitment {
            coefficients_commitments: total_commitment,
        }
    }
}

/// AllMessage packs together messages for all participants.
///
/// We'd save bandwidth by having separate messages for each
/// participant, but typical thresholds lie between 1/2 and 2/3,
/// so this doubles or tripples bandwidth usage.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct AllMessage {
    pub(super) content: MessageContent,
    pub(super) signature: ed25519::Signature,
}

impl AllMessage {
    /// Creates a new message.
    pub fn new(content: MessageContent, signature: Signature) -> Self {
        Self { content, signature }
    }
    /// Serialize AllMessage
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();

        bytes.extend(self.content.to_bytes());
        bytes.extend(self.signature.to_bytes());

        bytes
    }

    /// Deserialize AllMessage from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<AllMessage, SPPError> {
        let mut cursor = 0;

        let content = MessageContent::from_bytes(&bytes[cursor..])?;
        cursor += content.to_bytes().len();

        let mut signature_bytes = [0; SIGNATURE_LENGTH];
        signature_bytes.copy_from_slice(&bytes[cursor..cursor + SIGNATURE_LENGTH]);

        let signature = Signature::from_bytes(&signature_bytes);

        Ok(AllMessage { content, signature })
    }
}

/// The contents of the message destined to all participants.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct MessageContent {
    pub(super) sender: VerifyingKey,
    pub(super) encryption_nonce: [u8; ENCRYPTION_NONCE_LENGTH],
    pub(super) parameters: Parameters,
    pub(super) recipients_hash: [u8; RECIPIENTS_HASH_LENGTH],
    pub(super) polynomial_commitment: PolynomialCommitment,
    pub(super) encrypted_secret_shares: Vec<EncryptedSecretShare>,
    pub(super) ephemeral_key: VerifyingKey,
}

impl MessageContent {
    /// Creates the content of the message.
    pub fn new(
        sender: VerifyingKey,
        encryption_nonce: [u8; ENCRYPTION_NONCE_LENGTH],
        parameters: Parameters,
        recipients_hash: [u8; RECIPIENTS_HASH_LENGTH],
        polynomial_commitment: PolynomialCommitment,
        encrypted_secret_shares: Vec<EncryptedSecretShare>,
        ephemeral_key: VerifyingKey,
    ) -> Self {
        Self {
            sender,
            encryption_nonce,
            parameters,
            recipients_hash,
            polynomial_commitment,
            encrypted_secret_shares,
            ephemeral_key,
        }
    }
    /// Serialize MessageContent
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();

        bytes.extend(self.sender.to_bytes());
        bytes.extend(&self.encryption_nonce);
        bytes.extend(self.parameters.to_bytes());
        bytes.extend(&self.recipients_hash);

        for point in &self.polynomial_commitment.coefficients_commitments {
            bytes.extend(point.compress().to_bytes());
        }

        for ciphertext in &self.encrypted_secret_shares {
            bytes.extend(ciphertext.0.as_bytes());
        }

        bytes.extend(&self.ephemeral_key.to_bytes());

        bytes
    }

    /// Deserialize MessageContent from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<MessageContent, SPPError> {
        let mut cursor = 0;

        let mut public_key_bytes = [0; PUBLIC_KEY_LENGTH];
        public_key_bytes.copy_from_slice(&bytes[cursor..cursor + PUBLIC_KEY_LENGTH]);

        let sender =
            VerifyingKey::from_bytes(&public_key_bytes).map_err(SPPError::InvalidPublicKey)?;
        cursor += PUBLIC_KEY_LENGTH;

        let encryption_nonce: [u8; ENCRYPTION_NONCE_LENGTH] = bytes
            [cursor..cursor + ENCRYPTION_NONCE_LENGTH]
            .try_into()
            .map_err(SPPError::DeserializationError)?;
        cursor += ENCRYPTION_NONCE_LENGTH;

        let parameters = Parameters::from_bytes(&bytes[cursor..cursor + U16_LENGTH * 2])?;
        cursor += U16_LENGTH * 2;

        let participants = parameters.participants;

        let recipients_hash: [u8; RECIPIENTS_HASH_LENGTH] = bytes
            [cursor..cursor + RECIPIENTS_HASH_LENGTH]
            .try_into()
            .map_err(SPPError::DeserializationError)?;
        cursor += RECIPIENTS_HASH_LENGTH;

        let mut coefficients_commitments = Vec::with_capacity(participants as usize);

        for _ in 0..parameters.threshold {
            let point =
                CompressedEdwardsY::from_slice(&bytes[cursor..cursor + COMPRESSED_EDWARDS_LENGTH])
                    .map_err(SPPError::DeserializationError)?;

            coefficients_commitments.push(
                point
                    .decompress()
                    .ok_or(SPPError::InvalidCoefficientCommitment)?,
            );

            cursor += COMPRESSED_EDWARDS_LENGTH;
        }

        let polynomial_commitment = PolynomialCommitment {
            coefficients_commitments,
        };

        let mut encrypted_secret_shares = Vec::new();

        for _ in 0..participants {
            let mut scalar_bytes = [0; SCALAR_LENGTH];
            scalar_bytes.copy_from_slice(&bytes[cursor..cursor + SCALAR_LENGTH]);
            let scalar = scalar_from_canonical_bytes(scalar_bytes)
                .ok_or(SPPError::ErrorDeserializingEncryptedShare)?;
            encrypted_secret_shares.push(EncryptedSecretShare(scalar));
            cursor += SCALAR_LENGTH;
        }

        let mut ephemeral_key_bytes = [0; PUBLIC_KEY_LENGTH];
        ephemeral_key_bytes.copy_from_slice(&bytes[cursor..cursor + PUBLIC_KEY_LENGTH]);

        let ephemeral_key =
            VerifyingKey::from_bytes(&ephemeral_key_bytes).map_err(SPPError::InvalidPublicKey)?;

        Ok(MessageContent {
            sender,
            encryption_nonce,
            parameters,
            recipients_hash,
            polynomial_commitment,
            encrypted_secret_shares,
            ephemeral_key,
        })
    }
}

/// The signed output of the SimplPedPoP protocol.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct SPPOutputMessage {
    pub(super) sender: VerifyingKey,
    /// The output of the SimplPedPoP protocol.
    pub spp_output: SPPOutput,
    pub(super) signature: Signature,
}

impl SPPOutputMessage {
    /// Creates a signed SimplPedPoP output.
    pub fn new(sender: VerifyingKey, content: SPPOutput, signature: Signature) -> Self {
        Self {
            sender,
            spp_output: content,
            signature,
        }
    }

    /// Serializes the SPPOutput into bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();

        let pk_bytes = self.sender.to_bytes();
        bytes.extend(pk_bytes);

        let content_bytes = self.spp_output.to_bytes();
        bytes.extend(content_bytes);

        let signature_bytes = self.signature.to_bytes();
        bytes.extend(signature_bytes);

        bytes
    }

    /// Deserializes the SPPOutput from bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, SPPError> {
        let mut cursor = 0;

        let mut pk_bytes = [0; PUBLIC_KEY_LENGTH];
        pk_bytes.copy_from_slice(&bytes[..PUBLIC_KEY_LENGTH]);

        let sender = VerifyingKey::from_bytes(&pk_bytes).map_err(SPPError::InvalidPublicKey)?;
        cursor += PUBLIC_KEY_LENGTH;

        let content_bytes = &bytes[cursor..bytes.len() - SIGNATURE_LENGTH];
        let spp_output = SPPOutput::from_bytes(content_bytes)?;

        cursor = bytes.len() - SIGNATURE_LENGTH;

        let mut sig_bytes = [0; SIGNATURE_LENGTH];
        sig_bytes.copy_from_slice(&bytes[cursor..cursor + SIGNATURE_LENGTH]);

        let signature = Signature::from_bytes(&sig_bytes);

        Ok(SPPOutputMessage {
            sender,
            spp_output,
            signature,
        })
    }
}

/// The content of the signed output of the SimplPedPoP protocol.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SPPOutput {
    pub(crate) parameters: Parameters,
    /// The threshold public key.
    pub threshold_public_key: ThresholdPublicKey,
    pub(crate) verifying_keys: Vec<(Identifier, VerifyingShare)>,
}

impl SPPOutput {
    /// Creates the content of the SimplPedPoP output.
    pub fn new(
        parameters: &Parameters,
        group_public_key: ThresholdPublicKey,
        verifying_keys: Vec<(Identifier, VerifyingShare)>,
    ) -> Self {
        let parameters = Parameters::generate(parameters.participants, parameters.threshold);

        Self {
            parameters,
            threshold_public_key: group_public_key,
            verifying_keys,
        }
    }
    /// Serializes the SPPOutputContent into bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();

        bytes.extend(self.parameters.to_bytes());

        bytes.extend(self.threshold_public_key.0.to_bytes());

        let key_count = self.verifying_keys.len() as u16;
        bytes.extend(key_count.to_le_bytes());

        for (id, key) in &self.verifying_keys {
            bytes.extend(id.0.to_bytes());
            bytes.extend(key.0.to_bytes());
        }

        bytes
    }

    /// Deserializes the SPPOutputContent from bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, SPPError> {
        let mut cursor = 0;

        let parameters = Parameters::from_bytes(&bytes[cursor..cursor + U16_LENGTH * 2])?;
        cursor += U16_LENGTH * 2;

        let mut public_key_bytes = [0; PUBLIC_KEY_LENGTH];
        public_key_bytes.copy_from_slice(&bytes[cursor..cursor + PUBLIC_KEY_LENGTH]);
        cursor += PUBLIC_KEY_LENGTH;

        let group_public_key = ThresholdPublicKey(
            VerifyingKey::from_bytes(&public_key_bytes).map_err(SPPError::InvalidPublicKey)?,
        );

        cursor += VEC_LENGTH;

        let mut verifying_keys = Vec::new();

        while cursor < bytes.len() {
            let mut identifier_bytes = [0; SCALAR_LENGTH];
            identifier_bytes.copy_from_slice(&bytes[cursor..cursor + SCALAR_LENGTH]);

            let identifier =
                scalar_from_canonical_bytes(identifier_bytes).ok_or(SPPError::InvalidIdentifier)?;
            cursor += SCALAR_LENGTH;

            let mut vk_bytes = [0; PUBLIC_KEY_LENGTH];
            vk_bytes.copy_from_slice(&bytes[cursor..cursor + PUBLIC_KEY_LENGTH]);
            cursor += PUBLIC_KEY_LENGTH;

            let key = VerifyingKey::from_bytes(&vk_bytes).map_err(SPPError::InvalidPublicKey)?;
            verifying_keys.push((Identifier(identifier), VerifyingShare(key)));
        }

        Ok(SPPOutput {
            parameters,
            threshold_public_key: group_public_key,
            verifying_keys,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{test_utils::generate_parameters, SigningKeypair};
    use merlin::Transcript;
    use rand_core::OsRng;

    #[test]
    fn test_serialize_deserialize_all_message() {
        let parameters = generate_parameters();
        let participants = parameters.participants as usize;
        let threshold = parameters.threshold as usize;

        let mut keypairs: Vec<SigningKeypair> = (0..participants)
            .map(|_| SigningKeypair::generate(&mut OsRng))
            .collect();

        let public_keys: Vec<VerifyingKey> = keypairs.iter().map(|kp| kp.verifying_key).collect();

        let message: AllMessage = keypairs[0]
            .simplpedpop_contribute_all(threshold as u16, public_keys.clone())
            .unwrap();

        let bytes = message.to_bytes();

        let deserialized_message = AllMessage::from_bytes(&bytes).expect("Failed to deserialize");

        assert_eq!(message, deserialized_message);
    }

    #[test]
    fn test_spp_output_serialization() {
        let parameters = generate_parameters();
        let participants = parameters.participants as usize;
        let threshold = parameters.threshold as usize;

        let mut keypairs: Vec<SigningKeypair> = (0..participants)
            .map(|_| SigningKeypair::generate(&mut OsRng))
            .collect();

        let public_keys: Vec<VerifyingKey> = keypairs.iter().map(|kp| kp.verifying_key).collect();

        let mut all_messages = Vec::new();

        for i in 0..participants {
            let message: AllMessage = keypairs[i]
                .simplpedpop_contribute_all(threshold as u16, public_keys.clone())
                .unwrap();
            all_messages.push(message);
        }

        let spp_output = keypairs[0]
            .simplpedpop_recipient_all(&all_messages)
            .unwrap();

        let bytes = spp_output.0.to_bytes();

        let deserialized_spp_output_message =
            SPPOutputMessage::from_bytes(&bytes).expect("Deserialization failed");

        assert_eq!(deserialized_spp_output_message, spp_output.0);
    }

    #[test]
    fn test_encryption_and_decryption() {
        let mut rng = OsRng;

        // Generate a random secret
        let secret_scalar = Scalar::random(&mut rng);
        let secret_share = SecretShare(secret_scalar);

        // Generate a random recipient verifying key
        let recipient_point = Scalar::random(&mut rng) * GENERATOR;
        let recipient_key = VerifyingKey::from(recipient_point);

        // Generate a random key exchange point
        let key_exchange = Scalar::random(&mut rng) * GENERATOR;

        // Generate a random nonce
        let mut encryption_nonce = [0u8; ENCRYPTION_NONCE_LENGTH];
        rng.fill_bytes(&mut encryption_nonce);

        // Create a transcript
        let mut transcript = Transcript::new(b"Test Transcript");

        // Encrypt the secret share
        let encrypted_share = secret_share.encrypt(
            &mut transcript,
            1,
            &recipient_key,
            &encryption_nonce,
            &key_exchange,
        );

        let mut transcript = Transcript::new(b"Test Transcript");

        // Decrypt the secret share
        let decrypted_share = encrypted_share.decrypt(
            &mut transcript,
            1,
            &recipient_key,
            &encryption_nonce,
            &key_exchange,
        );

        assert_eq!(decrypted_share.0, secret_share.0);
    }

    #[test]
    fn test_generate_polynomial_commitment_valid() {
        let degree = 3;

        let polynomial = SecretPolynomial::generate(degree, &mut OsRng);

        let polynomial_commitment = PolynomialCommitment::commit(&polynomial);

        assert_eq!(polynomial.coefficients.len(), degree as usize + 1);

        assert_eq!(
            polynomial_commitment.coefficients_commitments.len(),
            degree as usize + 1
        );
    }

    #[test]
    fn test_evaluate_polynomial() {
        let coefficients: Vec<Scalar> =
            vec![Scalar::from(3u64), Scalar::from(2u64), Scalar::from(1u64)]; // Polynomial x^2 + 2x + 3

        let polynomial = SecretPolynomial { coefficients };

        let value = Scalar::from(5u64); // x = 5

        let result = polynomial.evaluate(&value);

        assert_eq!(result, Scalar::from(38u64)); // 5^2 + 2*5 + 3
    }

    #[test]
    fn test_sum_secret_polynomial_commitments() {
        let polynomial_commitment1 = PolynomialCommitment {
            coefficients_commitments: vec![
                GENERATOR * Scalar::from(1u64), // Constant
                GENERATOR * Scalar::from(2u64), // Linear
                GENERATOR * Scalar::from(3u64), // Quadratic
            ],
        };

        let polynomial_commitment2 = PolynomialCommitment {
            coefficients_commitments: vec![
                GENERATOR * Scalar::from(4u64), // Constant
                GENERATOR * Scalar::from(5u64), // Linear
                GENERATOR * Scalar::from(6u64), // Quadratic
            ],
        };

        let summed_polynomial_commitments = PolynomialCommitment::sum_polynomial_commitments(&[
            &polynomial_commitment1,
            &polynomial_commitment2,
        ]);

        let expected_coefficients_commitments = vec![
            GENERATOR * Scalar::from(5u64), // 1 + 4 = 5
            GENERATOR * Scalar::from(7u64), // 2 + 5 = 7
            GENERATOR * Scalar::from(9u64), // 3 + 6 = 9
        ];

        assert_eq!(
            summed_polynomial_commitments.coefficients_commitments,
            expected_coefficients_commitments,
            "Coefficient commitments do not match"
        );
    }

    #[test]
    fn test_evaluate_polynomial_commitment() {
        // f(x) = 3 + 2x + x^2
        let constant_coefficient_commitment = Scalar::from(3u64) * GENERATOR;
        let linear_commitment = Scalar::from(2u64) * GENERATOR;
        let quadratic_commitment = Scalar::from(1u64) * GENERATOR;

        // Note the order and inclusion of the constant term
        let coefficients_commitments = vec![
            constant_coefficient_commitment,
            linear_commitment,
            quadratic_commitment,
        ];

        let polynomial_commitment = PolynomialCommitment {
            coefficients_commitments,
        };

        let value = Scalar::from(2u64);

        // f(2) = 11
        let expected = Scalar::from(11u64) * GENERATOR;

        let result = polynomial_commitment.evaluate(&value);

        assert_eq!(
            result, expected,
            "The evaluated commitment does not match the expected result"
        );
    }
}
