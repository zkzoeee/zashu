pub mod error;
pub mod mode_a;
pub mod mode_b;
pub mod pcd;
pub mod poseidon_chip;
pub mod predicates;
#[cfg(feature = "ragu")]
pub(crate) mod ragu_app;
#[cfg(feature = "ragu")]
pub mod ragu_gadgets;
pub mod range_check;
pub mod spec;

pub use error::{CircuitError, Result};
pub use pcd::{
    FoldedProof, PcdEngine, PcdProver, PcdVerifier, StateTransition, SubcircuitId, DEFAULT_K,
};

#[cfg(test)]
mod tests {
    use ff::Field;
    use group::Group;
    use proptest::prelude::*;
    use rand::rngs::StdRng;
    use rand::SeedableRng;
    use zashu_acc::NoteAccumulator;
    use zashu_core::field::{bytes_to_fq, fq_to_bytes, hash_bytes_to_fq, Fq, PallasPoint};
    use zashu_core::poseidon::{hash_event_melt, hash_event_mint};
    use zashu_core::stealth::PointBytesExt;
    use zashu_core::types::{MintState, Note, PredicateId};

    use crate::mode_a::{
        fold_mode_a_batch_with, prove_melt_step, prove_mint_step, prove_swap_step, verify_fold_batch,
        verify_mode_a_step,
    };
    use crate::mode_b::{
        balance_blinding, prove_zk_melt, prove_zk_mint, prove_zk_swap, verify_zk_melt,
        verify_zk_mint, verify_zk_swap, InputNoteWitness, OutputNoteWitness,
    };
    use crate::predicates::{
        compute_htlc_params, compute_multisig_params, compute_p2pk_params, compute_timelock_params,
        htlc_hashlock, verify_predicate, HtlcAction, PredicateWitness,
    };

    fn keypair(seed: u8) -> ([u8; 32], [u8; 32]) {
        let sk = hash_bytes_to_fq(b"test-sk", &[seed]);
        let pk = (PallasPoint::generator() * sk).to_affine_bytes();
        (fq_to_bytes(&sk), pk)
    }

    #[test]
    fn mode_a_mint_swap_melt_and_fold_e2e() {
        let s0 = MintState::genesis([0u8; 32], [0u8; 32]);
        let mut s1 = s0.clone();
        s1.epoch = 1;
        s1.total_liabilities = 1000;
        s1.event_log_hash = hash_event_mint(&s0.event_log_hash, &[1u8; 32], 1000);
        let p1 = prove_mint_step(&s0, &s1, 1000).unwrap();
        verify_mode_a_step(&p1).unwrap();

        let mut s2 = s1.clone();
        s2.nullifier_acc_root = [2u8; 32];
        let p2 = prove_swap_step(&s1, &s2, 500, 500, &[]).unwrap();
        verify_mode_a_step(&p2).unwrap();

        let mut s3 = s2.clone();
        s3.total_liabilities = 700;
        s3.event_log_hash = hash_event_melt(&s2.event_log_hash, &[3u8; 32], 300);
        let p3 = prove_melt_step(&s2, &s3, 300).unwrap();
        verify_mode_a_step(&p3).unwrap();

        // These states are made up (no real accumulators behind the roots),
        // so fold them with the backend that does not bind root changes.
        let folded =
            fold_mode_a_batch_with(crate::mode_a::FoldBackend::Halo2, &s0, &s3, &[p1, p2, p3]).unwrap();
        verify_fold_batch(&folded, &s0.state_hash(), &s3).unwrap();

        // Tamper check
        let mut bad_s3 = s3.clone();
        bad_s3.total_liabilities = 600;
        assert!(verify_fold_batch(&folded, &s0.state_hash(), &bad_s3).is_err());

        // Underflow check
        assert!(prove_melt_step(&s2, &s3, 9999).is_err());
    }

    #[test]
    fn mode_b_mint_swap_melt_and_predicates() {
        let mut rng = StdRng::seed_from_u64(7);
        let (sk_a, pk_a) = keypair(1);
        let (sk_b, pk_b) = keypair(2);

        let note1 = Note {
            value: 137,
            owner_pk: pk_a,
            predicate_id: PredicateId::StandardSpend as u8,
            predicate_params_hash: [0u8; 32],
            rho: [11u8; 32],
            r: [12u8; 32],
        };
        let b1 = Fq::random(&mut rng);
        let (cm1, cv1, p_mint) = prove_zk_mint(&note1, b1, 137).unwrap();
        verify_zk_mint(&p_mint, 137, &cm1, &cv1).unwrap();

        let mut acc = NoteAccumulator::new(16);
        let idx1 = acc.insert(cm1.0).unwrap();
        let root1 = acc.root();
        let w1 = acc.witness(idx1).unwrap();

        // Swap 137 -> 100 (PrivateHTLC) + 37 (Standard)
        let preimage = [0x42u8; 32];
        let hl = htlc_hashlock(&preimage);
        let htlc_params = compute_htlc_params(&hl, &pk_b, &pk_a, 10);

        let out_htlc = Note {
            value: 100,
            owner_pk: pk_b,
            predicate_id: PredicateId::PrivateHTLC as u8,
            predicate_params_hash: htlc_params,
            rho: [21u8; 32],
            r: [22u8; 32],
        };
        let out_change = Note {
            value: 37,
            owner_pk: pk_a,
            predicate_id: PredicateId::StandardSpend as u8,
            predicate_params_hash: [0u8; 32],
            rho: [31u8; 32],
            r: [32u8; 32],
        };
        let b_out1 = Fq::random(&mut rng);
        let b_out2 = balance_blinding(&[b1], &[b_out1]);

        let (nfs, cms, out_cvs, p_swap) = prove_zk_swap(
            &root1,
            &[InputNoteWitness {
                note: &note1,
                blind: b1,
                witness: &w1,
                predicate: &PredicateWitness::StandardSpend { sk: sk_a },
            }],
            &[
                OutputNoteWitness {
                    note: &out_htlc,
                    blind: b_out1,
                },
                OutputNoteWitness {
                    note: &out_change,
                    blind: b_out2,
                },
            ],
        )
        .unwrap();

        verify_zk_swap(&p_swap, &root1, &nfs, &cms, &[cv1], &out_cvs).unwrap();

        // Claim HTLC note at epoch 5, melt 80 with 20 shielded change
        let idx_htlc = acc.insert(cms[0].0).unwrap();
        let root2 = acc.root();
        let w_htlc = acc.witness(idx_htlc).unwrap();

        // Predicate isolation test: cannot spend HTLC with StandardSpend
        assert!(verify_predicate(&out_htlc, &PredicateWitness::StandardSpend { sk: sk_b }).is_err());

        let melt_change = Note {
            value: 20,
            owner_pk: pk_b,
            predicate_id: 0,
            predicate_params_hash: [0u8; 32],
            rho: [41u8; 32],
            r: [42u8; 32],
        };
        let b_ch = Fq::random(&mut rng);
        let (melt_nfs, melt_ch, p_melt) = prove_zk_melt(
            &root2,
            &[InputNoteWitness {
                note: &out_htlc,
                blind: b_out1,
                witness: &w_htlc,
                predicate: &PredicateWitness::PrivateHTLC {
                    hashlock: hl,
                    pk_receiver: pk_b,
                    pk_refund: pk_a,
                    expiry_epoch: 10,
                    current_epoch: 5,
                    action: HtlcAction::Claim {
                        preimage,
                        sk_receiver: sk_b,
                    },
                },
            }],
            80,
            Some((&melt_change, b_ch)),
        )
        .unwrap();

        verify_zk_melt(
            &p_melt,
            &root2,
            80,
            melt_ch.as_ref().map(|(c, _)| c),
            &melt_nfs,
        )
        .unwrap();
    }

    #[test]
    fn predicates_p2pk_multisig_timelock() {
        let (sk1, pk1) = keypair(10);
        let (sk2, pk2) = keypair(11);
        let (_sk3, pk3) = keypair(12);

        let n_p2pk = Note {
            value: 50,
            owner_pk: pk1,
            predicate_id: PredicateId::P2PK as u8,
            predicate_params_hash: compute_p2pk_params(&pk2),
            rho: [1u8; 32],
            r: [2u8; 32],
        };
        assert!(verify_predicate(
            &n_p2pk,
            &PredicateWitness::P2PK {
                target_sk: sk2,
                target_pk: pk2
            }
        )
        .is_ok());

        let pks = vec![pk1, pk2, pk3];
        let n_ms = Note {
            value: 50,
            owner_pk: pk1,
            predicate_id: PredicateId::Multisig as u8,
            predicate_params_hash: compute_multisig_params(2, &pks),
            rho: [3u8; 32],
            r: [4u8; 32],
        };
        assert!(verify_predicate(
            &n_ms,
            &PredicateWitness::Multisig {
                threshold: 2,
                pubkeys: pks.clone(),
                signer_indices: vec![0, 1],
                signer_sks: vec![sk1, sk2],
            }
        )
        .is_ok());
        assert!(verify_predicate(
            &n_ms,
            &PredicateWitness::Multisig {
                threshold: 2,
                pubkeys: pks,
                signer_indices: vec![0],
                signer_sks: vec![sk1],
            }
        )
        .is_err());

        let n_tl = Note {
            value: 50,
            owner_pk: pk1,
            predicate_id: PredicateId::Timelock as u8,
            predicate_params_hash: compute_timelock_params(100, &pk1),
            rho: [5u8; 32],
            r: [6u8; 32],
        };
        assert!(verify_predicate(
            &n_tl,
            &PredicateWitness::Timelock {
                lock_epoch: 100,
                current_epoch: 99,
                sk: sk1,
            }
        )
        .is_err());
        assert!(verify_predicate(
            &n_tl,
            &PredicateWitness::Timelock {
                lock_epoch: 100,
                current_epoch: 100,
                sk: sk1,
            }
        )
        .is_ok());
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(8))]
        #[test]
        fn prop_conservation_and_overflow_immunity(a in 1u64..1_000_000_000u64, b in 1u64..1_000_000_000u64) {
            let s0 = MintState::genesis([0u8; 32], [0u8; 32]);
            let mut s1 = s0.clone();
            s1.total_liabilities = a;
            let p1 = prove_mint_step(&s0, &s1, a).unwrap();
            prop_assert!(verify_mode_a_step(&p1).is_ok());

            // Mismatched liabilities must fail
            let mut bad_s1 = s1.clone();
            bad_s1.total_liabilities = a + b;
            prop_assert!(prove_mint_step(&s0, &bad_s1, a).is_err());
            let _ = bytes_to_fq(&sk_dummy());
        }
    }

    fn sk_dummy() -> [u8; 32] {
        fq_to_bytes(&Fq::ONE)
    }

    #[test]
    fn in_circuit_poseidon_merkle_inclusion() {
        let mut acc = NoteAccumulator::new(8);
        let cm1 = zashu_core::field::fp_to_bytes(&zashu_core::field::Fp::from(111u64));
        let cm2 = zashu_core::field::fp_to_bytes(&zashu_core::field::Fp::from(222u64));
        let idx1 = acc.insert(cm1).unwrap();
        let _idx2 = acc.insert(cm2).unwrap();
        let root = acc.root();
        let w1 = acc.witness(idx1).unwrap();

        let proof = crate::mode_b::prove_merkle_inclusion(&cm1, &root, &w1).unwrap();
        crate::mode_b::verify_merkle_inclusion(&proof, &cm1, &root).unwrap();

        // Tampered leaf must fail
        assert!(crate::mode_b::verify_merkle_inclusion(&proof, &cm2, &root).is_err());
    }

    #[test]
    fn proof_wire_encoding_is_compact_and_reads_the_old_form() {
        let s0 = MintState::genesis([0u8; 32], [0u8; 32]);
        let mut s1 = s0.clone();
        s1.epoch = 1;
        s1.total_liabilities = 5;
        s1.event_log_hash = hash_event_mint(&s0.event_log_hash, &[1u8; 32], 5);
        let mut proof = prove_mint_step(&s0, &s1, 5).unwrap();
        proof.transition = None;

        // New form: strings, and far smaller than a JSON array of numbers.
        let json = serde_json::to_string(&proof).unwrap();
        assert!(json.contains("\"ipa_proof\":\""));
        assert!(json.len() < proof.ipa_proof.len() * 2, "{} vs {}", json.len(), proof.ipa_proof.len());
        assert_eq!(serde_json::from_str::<crate::FoldedProof>(&json).unwrap(), proof);
        assert_eq!(crate::FoldedProof::from_base64(&proof.to_base64().unwrap()).unwrap(), proof);

        // Old form: byte arrays as arrays of numbers.
        let old = serde_json::json!({
            "subcircuit": "MintStep",
            "k": proof.k,
            "public_inputs": proof.public_inputs.iter().map(|b| b.to_vec()).collect::<Vec<_>>(),
            "ipa_proof": proof.ipa_proof,
            "folded_children": proof.folded_children,
        });
        assert_eq!(serde_json::from_value::<crate::FoldedProof>(old).unwrap(), proof);
    }
}
