mod errors;
mod types;

pub use self::types::{AllMessage, Parameters, SPPOutput};
use crate::{Identifier, SigningKeypair, ThresholdPublicKey, VerifyingShare, GENERATOR};
use curve25519_dalek::{edwards::CompressedEdwardsY, traits::Identity, EdwardsPoint, Scalar};
use ed25519::signature::{SignerMut, Verifier};
use ed25519_dalek::{hazmat::ExpandedSecretKey, SigningKey, VerifyingKey};
pub use errors::*;
use merlin::Transcript;
use rand::{thread_rng, RngCore};
use rand_core::OsRng;
use types::{
    MessageContent, PolynomialCommitment, SPPOutputMessage, SecretPolynomial, SecretShare,
    ENCRYPTION_NONCE_LENGTH, RECIPIENTS_HASH_LENGTH,
};

impl SigningKeypair {
    /// First round of the SimplPedPoP protocol.
    pub fn simplpedpop_contribute_all(
        &mut self,
        threshold: u16,
        recipients: Vec<VerifyingKey>,
    ) -> SPPResult<AllMessage> {
        let parameters = Parameters::generate(recipients.len() as u16, threshold);
        parameters.validate()?;

        let mut rng = thread_rng();

        // We do not recipients.sort() because the protocol is simpler
        // if we require that all contributions provide the list in
        // exactly the same order.
        //
        // Instead we create a kind of session id by hashing the list
        // provided, but we provide only hash to recipients, not the
        // full recipients list.
        let mut recipients_transcript = Transcript::new(b"RecipientsHash");
        parameters.commit(&mut recipients_transcript);

        for recipient in &recipients {
            recipients_transcript.append_message(b"recipient", recipient.as_bytes());
        }

        let mut recipients_hash = [0u8; RECIPIENTS_HASH_LENGTH];
        recipients_transcript.challenge_bytes(b"finalize", &mut recipients_hash);

        let secret_polynomial =
            SecretPolynomial::generate(parameters.threshold as usize - 1, &mut rng);

        let mut encrypted_secret_shares = Vec::new();

        let polynomial_commitment = PolynomialCommitment::commit(&secret_polynomial);

        let mut encryption_transcript = Transcript::new(b"Encryption");
        parameters.commit(&mut encryption_transcript);
        encryption_transcript.append_message(b"contributor", self.verifying_key.as_bytes());

        let mut encryption_nonce = [0u8; ENCRYPTION_NONCE_LENGTH];
        rng.fill_bytes(&mut encryption_nonce);
        encryption_transcript.append_message(b"nonce", &encryption_nonce);

        let secret = *secret_polynomial
            .coefficients
            .first()
            .expect("This never fails because the minimum threshold is 2");

        let mut nonce: [u8; 32] = [0u8; 32];
        rng.fill_bytes(&mut nonce);

        let ephemeral_key = SigningKey::generate(&mut rng);

        for i in 0..parameters.participants {
            let mut transcript = encryption_transcript.clone();

            let identifier = Identifier::generate(&recipients_hash, i);

            let polynomial_evaluation = secret_polynomial.evaluate(&identifier.0);

            let secret_share = SecretShare(polynomial_evaluation);

            let recipient: VerifyingKey = recipients[i as usize];

            //let key_exchange = ephemeral_key.to_scalar() * recipient.point;

            let key_exchange = ephemeral_key.to_scalar()
                * CompressedEdwardsY::from_slice(recipient.as_bytes())
                    .unwrap()
                    .decompress()
                    .unwrap();

            let encrypted_secret_share = secret_share.encrypt(
                &mut transcript,
                i as usize,
                &recipient,
                &encryption_nonce,
                &key_exchange,
            );

            encrypted_secret_shares.push(encrypted_secret_share);
        }

        let message_content = MessageContent::new(
            self.verifying_key,
            encryption_nonce,
            parameters,
            recipients_hash,
            polynomial_commitment,
            encrypted_secret_shares,
            ephemeral_key.verifying_key(),
        );

        let signature = self.sign(&message_content.to_bytes());

        Ok(AllMessage::new(message_content, signature))
    }

    /// Second round of the SimplPedPoP protocol.
    pub fn simplpedpop_recipient_all(
        &mut self,
        messages: &[AllMessage],
    ) -> SPPResult<(SPPOutputMessage, SigningKeypair)> {
        let first_message = &messages[0];
        let parameters = &first_message.content.parameters;
        let threshold = parameters.threshold as usize;
        let participants = parameters.participants as usize;

        first_message.content.parameters.validate()?;

        if messages.len() < participants {
            return Err(SPPError::InvalidNumberOfMessages);
        }

        let mut secret_shares = Vec::with_capacity(participants);
        let mut verifying_keys = Vec::with_capacity(participants);
        let mut senders = Vec::with_capacity(participants);
        let mut signatures = Vec::with_capacity(participants);
        let mut signatures_messages = Vec::with_capacity(participants);
        let mut group_point = EdwardsPoint::identity();
        let mut total_secret_share = Scalar::ZERO;
        let mut total_polynomial_commitment = PolynomialCommitment {
            coefficients_commitments: vec![],
        };
        let mut identifiers = Vec::new();

        for (j, message) in messages.iter().enumerate() {
            if &message.content.parameters != parameters {
                return Err(SPPError::DifferentParameters);
            }
            if message.content.recipients_hash != first_message.content.recipients_hash {
                return Err(SPPError::DifferentRecipientsHash);
            }

            let content = &message.content;
            let polynomial_commitment = &content.polynomial_commitment;
            let encrypted_secret_shares = &content.encrypted_secret_shares;

            let secret_commitment: EdwardsPoint = *polynomial_commitment
                .coefficients_commitments
                .first()
                .expect("This never fails because the minimum threshold is 2");

            senders.push(content.sender);
            signatures.push(message.signature);

            let mut encryption_transcript = Transcript::new(b"Encryption");
            parameters.commit(&mut encryption_transcript);
            encryption_transcript.append_message(b"contributor", content.sender.as_bytes());
            encryption_transcript.append_message(b"nonce", &content.encryption_nonce);

            if polynomial_commitment.coefficients_commitments.len() != threshold {
                return Err(SPPError::IncorrectNumberOfCoefficientCommitments);
            }

            if encrypted_secret_shares.len() != participants {
                return Err(SPPError::IncorrectNumberOfEncryptedShares);
            }

            signatures_messages.push(content.to_bytes());

            total_polynomial_commitment = PolynomialCommitment::sum_polynomial_commitments(&[
                &total_polynomial_commitment,
                &polynomial_commitment,
            ]);

            //let key_exchange: EdwardsPoint = self.to_scalar() * message.content.ephemeral_key.point;

            let scalar = ExpandedSecretKey::from(&self.secret_key).scalar;

            let key_exchange: EdwardsPoint = scalar
                * CompressedEdwardsY::from_slice(message.content.ephemeral_key.as_bytes())
                    .unwrap()
                    .decompress()
                    .unwrap();

            //assert!(self.to_scalar() * GENERATOR == self.verifying_key.point);

            //encryption_transcript.append_message(b"recipient", self.verifying_key.as_bytes());
            //encryption_transcript
            //.append_message(b"key exchange", &key_exchange.compress().as_bytes()[..]);

            let mut secret_share_found = false;

            for (i, encrypted_secret_share) in encrypted_secret_shares.iter().enumerate() {
                let mut transcript = encryption_transcript.clone();

                //encryption_transcript.append_message(b"i", &i.to_le_bytes());

                //let mut key_bytes = [0; CHACHA20POLY1305_KEY_LENGTH];
                //encryption_transcript.challenge_bytes(b"key", &mut key_bytes);

                if identifiers.len() != participants {
                    let identifier =
                        Identifier::generate(&first_message.content.recipients_hash, i as u16);
                    identifiers.push(identifier);
                }

                if !secret_share_found {
                    let secret_share = encrypted_secret_share.decrypt(
                        &mut transcript,
                        i,
                        &self.verifying_key,
                        &content.encryption_nonce,
                        &key_exchange,
                    );
                    if secret_share.0 * GENERATOR
                        == polynomial_commitment.evaluate(&identifiers[i].0)
                    {
                        secret_shares.push(secret_share);
                        secret_share_found = true;
                    }
                }
            }

            total_secret_share += secret_shares.get(j).ok_or(SPPError::InvalidSecretShare)?.0;
            group_point += secret_commitment;

            message
                .content
                .sender
                .verify(
                    &message.content.to_bytes(),
                    &ed25519_dalek::Signature::from_bytes(&message.signature.to_bytes()),
                )
                .map_err(SPPError::InvalidSignature)?;

            //if j == messages.len() - 1 && secret_shares.get(j).is_some() {
            //break;
            //}
        }

        for id in &identifiers {
            let evaluation = total_polynomial_commitment.evaluate(&id.0);
            verifying_keys.push((*id, VerifyingShare(VerifyingKey::from(evaluation))));
        }

        let spp_output = SPPOutput::new(
            parameters,
            ThresholdPublicKey(VerifyingKey::from(group_point)),
            verifying_keys,
        );

        let signature = self.sign(&spp_output.to_bytes());
        let spp_output = SPPOutputMessage::new(self.verifying_key, spp_output, signature);

        let mut nonce: [u8; 32] = [0u8; 32];
        OsRng.fill_bytes(&mut nonce);

        let signing_keypair = SigningKeypair {
            secret_key: *total_secret_share.as_bytes(),
            verifying_key: VerifyingKey::from(total_secret_share * GENERATOR),
        };

        Ok((spp_output, signing_keypair))
    }
}

#[cfg(test)]
mod tests {
    use crate::test_utils::generate_parameters;
    use crate::GENERATOR;
    use crate::{simplpedpop::types::AllMessage, SigningKeypair};
    use alloc::vec::Vec;
    use curve25519_dalek::{edwards::CompressedEdwardsY, Scalar};
    use ed25519_dalek::{SigningKey, VerifyingKey};
    use rand::Rng;
    use rand_core::OsRng;

    const PROTOCOL_RUNS: usize = 1;

    #[test]
    fn test_simplpedpop_protocol() {
        for _ in 0..PROTOCOL_RUNS {
            let parameters = generate_parameters();
            let participants = parameters.participants as usize;
            let threshold = parameters.threshold as usize;

            let mut keypairs: Vec<SigningKeypair> = (0..participants)
                .map(|_| SigningKeypair::generate(&mut OsRng))
                .collect();

            let mut recipients_keypairs: Vec<SigningKeypair> = (0..participants)
                .map(|_| SigningKeypair::generate(&mut OsRng))
                .collect();

            let public_keys: Vec<VerifyingKey> = recipients_keypairs
                .iter()
                .map(|kp| kp.verifying_key)
                .collect();

            let mut all_messages = Vec::new();
            for i in 0..participants {
                let message: AllMessage = keypairs[i]
                    .simplpedpop_contribute_all(threshold as u16, public_keys.clone())
                    .unwrap();
                all_messages.push(message);
            }

            let mut spp_outputs = Vec::new();

            for kp in recipients_keypairs.iter_mut() {
                let spp_output = kp.simplpedpop_recipient_all(&all_messages).unwrap();
                spp_outputs.push(spp_output);
            }

            // Verify that all SPP outputs are equal for group_public_key and verifying_keys
            assert!(
                spp_outputs
                    .windows(2)
                    .all(|w| w[0].0.spp_output.threshold_public_key.0
                        == w[1].0.spp_output.threshold_public_key.0
                        && w[0].0.spp_output.verifying_keys.len()
                            == w[1].0.spp_output.verifying_keys.len()
                        && w[0]
                            .0
                            .spp_output
                            .verifying_keys
                            .iter()
                            .zip(w[1].0.spp_output.verifying_keys.iter())
                            .all(|((a, b), (c, d))| a.0 == c.0 && b.0 == d.0)),
                "All SPP outputs should have identical group public keys and verifying keys."
            );

            // Verify that all verifying_shares are valid
            for i in 0..participants {
                for j in 0..participants {
                    assert_eq!(
                        CompressedEdwardsY::from_slice(
                            spp_outputs[i].0.spp_output.verifying_keys[j]
                                .1
                                 .0
                                .as_bytes()
                        )
                        .unwrap(),
                        (Scalar::from_canonical_bytes(spp_outputs[j].1.secret_key).unwrap()
                            * GENERATOR)
                            .compress(),
                        "Verification of total secret shares failed!"
                    );
                }
            }
        }
    }
}
