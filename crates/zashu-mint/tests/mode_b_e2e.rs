use bitcoin::secp256k1::{Keypair, Secp256k1, SecretKey, XOnlyPublicKey};
use bitcoin::ScriptBuf;
use ff::Field;
use group::Group;
use rand::rngs::StdRng;
use rand::SeedableRng;
use zashu_acc::NoteAccumulator;
use zashu_auditor::verify_solvency_bundle;
use zashu_circuits::mode_b::{
    balance_blinding, prove_zk_melt, prove_zk_mint, prove_zk_shield, prove_zk_swap,
    prove_zk_unshield, InputNoteWitness, OutputNoteWitness,
};
use zashu_circuits::predicates::{
    compute_htlc_params, htlc_hashlock, HtlcAction, PredicateWitness,
};
use zashu_core::field::{fq_to_bytes, hash_bytes_to_fq, Fq, PallasPoint};
use zashu_core::reserves::MockUtxoProvider;
use zashu_core::stealth::{
    create_stealth_output, decrypt_stealth_memo, PointBytesExt, StealthKeypair, StealthMemoPayload,
};
use zashu_core::types::{Note, PredicateId};
use zashu_mint::{
    MintReserveKey, ZashuMint, ZkMeltRequest, ZkMintRequest, ZkShieldRequest, ZkSwapRequest,
    ZkUnshieldRequest,
};

fn keypair(seed: u8) -> ([u8; 32], [u8; 32]) {
    let sk = hash_bytes_to_fq(b"e2e-sk", &[seed]);
    let pk = (PallasPoint::generator() * sk).to_affine_bytes();
    (fq_to_bytes(&sk), pk)
}

fn setup_mint(seed: u8) -> (ZashuMint, MockUtxoProvider) {
    let secp = Secp256k1::new();
    let mint_sk = SecretKey::from_slice(&[seed; 32]).unwrap();
    let res_sk = SecretKey::from_slice(&[seed + 1; 32]).unwrap();
    let kp = Keypair::from_secret_key(&secp, &res_sk);
    let (xonly, _) = XOnlyPublicKey::from_keypair(&kp);
    let spk = ScriptBuf::new_p2tr(&secp, xonly, None);

    let txid = format!("{:02x}", seed).repeat(32);
    let mut provider = MockUtxoProvider::new();
    provider.insert(&txid, 0, 1_000_000, hex::encode(spk.as_bytes()));

    let mint = ZashuMint::new(
        mint_sk,
        vec![MintReserveKey {
            secret_key: res_sk,
            txid,
            vout: 0,
            value_sats: 1_000_000,
        }],
        64,
    );
    (mint, provider)
}

#[test]
fn mode_b_lifecycle_interop_stealth_and_cross_mint_swap() {
    let mut rng = StdRng::seed_from_u64(2026);
    let (mut mint_a, provider_a) = setup_mint(0x11);
    let (mut mint_b, provider_b) = setup_mint(0x21);

    let (sk_alice, pk_alice) = keypair(1);
    let (_sk_bob, pk_bob) = keypair(2);

    // 1. Arbitrary amount lifecycle: Mint 137 sats in 1 note -> split 100 + 37 -> melt 37
    let n137 = Note {
        value: 137,
        owner_pk: pk_alice,
        predicate_id: 0,
        predicate_params_hash: [0u8; 32],
        rho: [1u8; 32],
        r: [2u8; 32],
    };
    let b137 = Fq::random(&mut rng);
    let (cm137, cv137, p_mint) = prove_zk_mint(&n137, b137, 137).unwrap();
    let mint_res = mint_a
        .zk_mint(ZkMintRequest {
            quote_id: "q1".into(),
            amount: 137,
            cm: cm137,
            cv: cv137,
            proof: p_mint.to_base64().unwrap(),
        })
        .unwrap();

    // Split 137 -> 100 + 37
    let n100 = Note {
        value: 100,
        owner_pk: pk_alice,
        predicate_id: 0,
        predicate_params_hash: [0u8; 32],
        rho: [3u8; 32],
        r: [4u8; 32],
    };
    let n37 = Note {
        value: 37,
        owner_pk: pk_alice,
        predicate_id: 0,
        predicate_params_hash: [0u8; 32],
        rho: [5u8; 32],
        r: [6u8; 32],
    };
    let b100 = Fq::random(&mut rng);
    let b37 = balance_blinding(&[b137], &[b100]);
    let (nfs, cms, out_cvs, p_swap) = prove_zk_swap(
        &mint_res.state.note_acc_root,
        &[InputNoteWitness {
            note: &n137,
            blind: b137,
            witness: &mint_res.witness,
            predicate: &PredicateWitness::StandardSpend { sk: sk_alice },
        }],
        &[
            OutputNoteWitness {
                note: &n100,
                blind: b100,
            },
            OutputNoteWitness {
                note: &n37,
                blind: b37,
            },
        ],
    )
    .unwrap();

    let swap_res = mint_a
        .zk_swap(ZkSwapRequest {
            anchor_root: mint_res.state.note_acc_root,
            nullifiers: nfs,
            output_commitments: cms,
            output_value_commitments: out_cvs,
            proof: p_swap.to_base64().unwrap(),
        })
        .unwrap();

    // Double-spend rejection
    assert!(mint_a
        .zk_swap(ZkSwapRequest {
            anchor_root: mint_res.state.note_acc_root,
            nullifiers: vec![n137.nullifier()],
            output_commitments: vec![],
            output_value_commitments: vec![],
            proof: p_swap.to_base64().unwrap(),
        })
        .is_err());

    // Melt 37 sats
    let (m_nfs, _, p_melt) = prove_zk_melt(
        &swap_res.state.note_acc_root,
        &[InputNoteWitness {
            note: &n37,
            blind: b37,
            witness: &swap_res.witnesses[1],
            predicate: &PredicateWitness::StandardSpend { sk: sk_alice },
        }],
        37,
        None,
    )
    .unwrap();
    mint_a
        .zk_melt(ZkMeltRequest {
            quote_id: "melt1".into(),
            amount: 37,
            anchor_root: swap_res.state.note_acc_root,
            nullifiers: m_nfs,
            change_cm: None,
            change_cv: None,
            proof: p_melt.to_base64().unwrap(),
        })
        .unwrap();

    // 2. Intra-mint Cashu interop: legacy BDHKE (128+8+1 = 137) -> shield -> unshield
    let legacy = mint_a.mint_legacy_bdhke(&[128, 8, 1]).unwrap();
    let n_shielded = Note {
        value: 137,
        owner_pk: pk_alice,
        predicate_id: 0,
        predicate_params_hash: [0u8; 32],
        rho: [7u8; 32],
        r: [8u8; 32],
    };
    let b_sh = Fq::random(&mut rng);
    let (cm_sh, cv_sh, p_sh) = prove_zk_shield(&n_shielded, b_sh, 137).unwrap();
    let sh_res = mint_a
        .zk_shield(ZkShieldRequest {
            bdhke_proofs: legacy,
            cm: cm_sh,
            cv: cv_sh,
            proof: p_sh.to_base64().unwrap(),
        })
        .unwrap();

    let (un_nfs, _, p_un) = prove_zk_unshield(
        &sh_res.state.note_acc_root,
        &[InputNoteWitness {
            note: &n_shielded,
            blind: b_sh,
            witness: &sh_res.witness,
            predicate: &PredicateWitness::StandardSpend { sk: sk_alice },
        }],
        137,
        None,
    )
    .unwrap();
    let un_res = mint_a
        .zk_unshield(ZkUnshieldRequest {
            anchor_root: sh_res.state.note_acc_root,
            nullifiers: un_nfs,
            unshield_amount: 137,
            change_cm: None,
            change_cv: None,
            proof: p_un.to_base64().unwrap(),
        })
        .unwrap();
    assert_eq!(un_res.bdhke_proofs.iter().map(|p| p.amount).sum::<u64>(), 137);

    // 3. Offline stealth receive + oblivious sync
    let bob_stealth = StealthKeypair::random(&mut rng);
    let mut bob_acc = NoteAccumulator::new(64);
    let sync_before = mint_a.sync_from_epoch(0);
    for (_, cm) in &sync_before.new_commitments {
        bob_acc.insert(cm.0).unwrap();
    }

    let memo_payload = StealthMemoPayload {
        value: 100,
        predicate_id: 0,
        predicate_params_hash: [0u8; 32],
        rho: [9u8; 32],
        r: [10u8; 32],
        leaf_index: 0,
    };
    let (one_time_pk, enc_memo) =
        create_stealth_output(&bob_stealth.address, &memo_payload, &mut rng).unwrap();
    let n_stealth = Note {
        value: 100,
        owner_pk: one_time_pk,
        predicate_id: 0,
        predicate_params_hash: [0u8; 32],
        rho: [9u8; 32],
        r: [10u8; 32],
    };
    // Alice swaps n100 (at swap_res.witnesses[0]) to Bob's stealth key; update Alice's witness to latest root first
    let alice_acc = bob_acc.clone();
    let w100_latest = alice_acc.witness(swap_res.leaf_indices[0]).unwrap();
    let b_st = b100;
    let (st_nfs, st_cms, st_cvs, p_st) = prove_zk_swap(
        &alice_acc.root(),
        &[InputNoteWitness {
            note: &n100,
            blind: b100,
            witness: &w100_latest,
            predicate: &PredicateWitness::StandardSpend { sk: sk_alice },
        }],
        &[OutputNoteWitness {
            note: &n_stealth,
            blind: b_st,
        }],
    )
    .unwrap();
    let st_res = mint_a
        .zk_swap(ZkSwapRequest {
            anchor_root: alice_acc.root(),
            nullifiers: st_nfs,
            output_commitments: st_cms,
            output_value_commitments: st_cvs,
            proof: p_st.to_base64().unwrap(),
        })
        .unwrap();

    // Bob comes online, syncs deltas, decrypts memo, and spends stealth note
    let sync_delta = mint_a.sync_from_epoch(sync_before.to_epoch);
    for (_, cm) in &sync_delta.new_commitments {
        bob_acc.insert(cm.0).unwrap();
    }
    let (dec_payload, bob_one_time_sk) = decrypt_stealth_memo(&bob_stealth, &enc_memo).unwrap();
    assert_eq!(dec_payload.value, 100);
    let w_bob_st = bob_acc.witness(st_res.leaf_indices[0]).unwrap();
    let (_b_nfs, _, _) = prove_zk_melt(
        &bob_acc.root(),
        &[InputNoteWitness {
            note: &n_stealth,
            blind: b_st,
            witness: &w_bob_st,
            predicate: &PredicateWitness::StandardSpend { sk: bob_one_time_sk },
        }],
        100,
        None,
    )
    .unwrap();

    // 4. Private cross-mint atomic swap (Mint A <-> Mint B via PrivateHTLC 0x04)
    let preimage = [0x77u8; 32];
    let hl = htlc_hashlock(&preimage);
    let htlc_params = compute_htlc_params(&hl, &pk_alice, &pk_bob, 50);
    let n_b_htlc = Note {
        value: 200,
        owner_pk: pk_alice,
        predicate_id: PredicateId::PrivateHTLC as u8,
        predicate_params_hash: htlc_params,
        rho: [12u8; 32],
        r: [13u8; 32],
    };
    let b_htlc = Fq::random(&mut rng);
    let (cm_bh, cv_bh, p_bh) = prove_zk_mint(&n_b_htlc, b_htlc, 200).unwrap();
    let bh_res = mint_b
        .zk_mint(ZkMintRequest {
            quote_id: "htlc_b".into(),
            amount: 200,
            cm: cm_bh,
            cv: cv_bh,
            proof: p_bh.to_base64().unwrap(),
        })
        .unwrap();

    // Alice claims on Mint B using preimage
    let (claim_nfs, _, p_claim) = prove_zk_melt(
        &bh_res.state.note_acc_root,
        &[InputNoteWitness {
            note: &n_b_htlc,
            blind: b_htlc,
            witness: &bh_res.witness,
            predicate: &PredicateWitness::PrivateHTLC {
                hashlock: hl,
                pk_receiver: pk_alice,
                pk_refund: pk_bob,
                expiry_epoch: 50,
                current_epoch: 1,
                action: HtlcAction::Claim {
                    preimage,
                    sk_receiver: sk_alice,
                },
            },
        }],
        200,
        None,
    )
    .unwrap();
    mint_b
        .zk_melt(ZkMeltRequest {
            quote_id: "claim_b".into(),
            amount: 200,
            anchor_root: bh_res.state.note_acc_root,
            nullifiers: claim_nfs,
            change_cm: None,
            change_cv: None,
            proof: p_claim.to_base64().unwrap(),
        })
        .unwrap();

    // Verify unified Mode A + Mode B solvency bundles on both mints!
    let sol_a = mint_a.solvency_bundle().unwrap();
    let sol_b = mint_b.solvency_bundle().unwrap();
    let report_a = verify_solvency_bundle(&sol_a, &provider_a).unwrap();
    assert!(report_a.solvent);
    assert!(verify_solvency_bundle(&sol_b, &provider_b).unwrap().solvent);
    // On the default backend the solvency proof attests every step and every
    // event-log and root change this whole lifecycle made.
    let default_backend =
        std::env::var("ZASHU_PCD_BACKEND").is_err() && std::env::var("ZASHU_FOLD_BACKEND").is_err();
    if cfg!(feature = "ragu") && default_backend {
        assert!(report_a.steps_proven && report_a.roots_bound, "{}", report_a.fold_proof);
    }
}
