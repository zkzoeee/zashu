pub mod error;
pub mod field;
pub mod pedersen;
pub mod poseidon;
pub mod reserves;
pub mod spec;
pub mod stealth;
pub mod token;
pub mod types;

pub use error::{Result, ZashuError};
pub use field::{Fp, Fq, PallasAffine, PallasPoint};
pub use pedersen::ValueCommitment;
pub use types::{
    MintState, Note, NoteCommitment, NoteOutputRecord, Nullifier, PredicateId, ReserveUtxo,
    ReservesAttestation, SolvencyBundle,
};

#[cfg(test)]
mod tests {
    use ff::Field;
    use group::Group;
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    use crate::field::Fq;
    use crate::pedersen::ValueCommitment;
    use crate::reserves::{
        compute_reserves_challenge, sign_taproot_reserve_utxo, verify_reserves_attestation,
        MockUtxoProvider,
    };
    use crate::stealth::{create_stealth_output, decrypt_stealth_memo, StealthAddress, StealthKeypair, StealthMemoPayload};
    use crate::token::{ZashuToken, ZashuTokenNote};
    use crate::types::{MintState, Note, ReservesAttestation};

    #[test]
    fn pedersen_homomorphic_balance() {
        let mut rng = StdRng::seed_from_u64(42);
        let r1 = Fq::random(&mut rng);
        let r2 = Fq::random(&mut rng);
        let r_out1 = Fq::random(&mut rng);
        let r_out2 = r1 + r2 - r_out1;

        let in1 = ValueCommitment::commit(100, r1);
        let in2 = ValueCommitment::commit(37, r2);
        let out1 = ValueCommitment::commit(80, r_out1);
        let out2 = ValueCommitment::commit(57, r_out2);

        assert!(ValueCommitment::verify_balance(&[in1, in2], &[out1, out2]).unwrap());
        let bad_out = ValueCommitment::commit(58, r_out2);
        assert!(!ValueCommitment::verify_balance(&[in1, in2], &[out1, bad_out]).unwrap());
    }

    #[test]
    fn note_commitment_and_nullifier_deterministic() {
        let note = Note {
            value: 137,
            owner_pk: [1u8; 32],
            predicate_id: 0,
            predicate_params_hash: [0u8; 32],
            rho: [2u8; 32],
            r: [3u8; 32],
        };
        assert_eq!(note.commitment(), note.commitment());
        assert_eq!(note.nullifier(), note.nullifier());
        let mut other = note.clone();
        other.rho = [4u8; 32];
        assert_ne!(note.nullifier(), other.nullifier());
        // The nullifier does not depend on who owns or spends the note.
        let mut reowned = note.clone();
        reowned.owner_pk = [7u8; 32];
        assert_eq!(note.nullifier(), reowned.nullifier());
    }

    #[test]
    fn token_cbor_roundtrip() {
        let tok = ZashuToken {
            mint: "https://mint.example.com".into(),
            epoch: 7,
            notes: vec![ZashuTokenNote {
                v: 137,
                spend_sk: [4u8; 32],
                predicate_id: 0,
                predicate_params_hash: [0u8; 32],
                rho: [5u8; 32],
                r: [6u8; 32],
                leaf_index: 12,
                witness_bytes: vec![1, 2, 3, 4],
            }],
        };
        let encoded = tok.encode().unwrap();
        assert!(encoded.starts_with("zashuA"));
        let decoded = ZashuToken::decode(&encoded).unwrap();
        assert_eq!(tok, decoded);
    }

    #[test]
    fn stealth_address_and_memo_roundtrip() {
        let mut rng = StdRng::seed_from_u64(99);
        let bob = StealthKeypair::random(&mut rng);
        let addr_str = bob.address.encode();
        assert!(addr_str.starts_with("zsp1"));
        let parsed = StealthAddress::decode(&addr_str).unwrap();

        let payload = StealthMemoPayload {
            value: 137,
            predicate_id: 0,
            predicate_params_hash: [0u8; 32],
            rho: [7u8; 32],
            r: [8u8; 32],
            leaf_index: 5,
        };
        let (one_time_pk, memo) = create_stealth_output(&parsed, &payload, &mut rng).unwrap();
        let (dec_payload, one_time_sk) = decrypt_stealth_memo(&bob, &memo).unwrap();
        assert_eq!(dec_payload, payload);

        // Verify one_time_sk * G == one_time_pk
        let sk_fq = crate::field::bytes_to_fq(&one_time_sk).unwrap();
        let derived_pk = crate::field::PallasPoint::generator() * sk_fq;
        use crate::stealth::PointBytesExt;
        assert_eq!(derived_pk.to_affine_bytes(), one_time_pk);
    }

    #[test]
    fn reserves_attestation_solvent_and_fractional_fail() {
        let sk = bitcoin::secp256k1::SecretKey::from_slice(&[0x11u8; 32]).unwrap();
        let mint_id = [0xAAu8; 32];
        let mut state = MintState::genesis([0u8; 32], [0u8; 32]);
        state.epoch = 1;
        state.total_liabilities = 10_000;

        let challenge = compute_reserves_challenge(&mint_id, &state);
        let utxo = sign_taproot_reserve_utxo(&sk, "txid1", 0, 15_000, &challenge);

        let mut provider = MockUtxoProvider::new();
        provider.insert("txid1", 0, 15_000, &utxo.script_pubkey);

        let att = ReservesAttestation {
            challenge,
            utxos: vec![utxo.clone()],
        };
        let verified = verify_reserves_attestation(&mint_id, &state, &att, &provider).unwrap();
        assert_eq!(verified, 15_000);

        // Fractional reserve check
        state.total_liabilities = 20_000;
        let bad_challenge = compute_reserves_challenge(&mint_id, &state);
        let bad_utxo = sign_taproot_reserve_utxo(&sk, "txid1", 0, 15_000, &bad_challenge);
        let bad_att = ReservesAttestation {
            challenge: bad_challenge,
            utxos: vec![bad_utxo],
        };
        assert!(verify_reserves_attestation(&mint_id, &state, &bad_att, &provider).is_err());
    }
}
