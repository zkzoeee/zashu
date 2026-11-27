use ff::Field;
use halo2_proofs::circuit::{Layouter, SimpleFloorPlanner, Value};
use halo2_proofs::pasta::Fp;
use halo2_proofs::plonk::{
    Advice, Circuit, Column, ConstraintSystem, Error, Instance, Selector,
};
use halo2_proofs::poly::Rotation;
use zashu_acc::{InclusionWitness, NoteAccumulator, ACC_DEPTH};
use zashu_core::field::{bytes_to_fp, fq_to_bytes, hash_bytes_to_fp, Fq};
use zashu_core::pedersen::ValueCommitment;
use zashu_core::types::{Note, NoteCommitment, Nullifier};

use crate::error::{CircuitError, Result};
use crate::mode_a::FoldBackend;
use crate::pcd::{FoldedProof, PcdEngine, SubcircuitId, DEFAULT_K};
use crate::poseidon_chip::{MerkleInclusionCircuit, PoseidonChipConfig};
use crate::predicates::{verify_predicate, PredicateWitness};
use crate::range_check::RangeCheck64Config;

#[cfg(feature = "ragu")]
pub mod ragu_backend;

pub const MAX_IO: usize = 4;
pub const MERKLE_K: u32 = 13;

/// The epoch a Ragu transaction proof's predicates were evaluated at (`None`
/// for Halo 2 proofs, which do not prove predicates). A mint must reject a
/// proof whose epoch is ahead of its own, or timelocks could be skipped.
pub fn proof_epoch(proof: &FoldedProof) -> Option<u64> {
    #[cfg(feature = "ragu")]
    {
        ragu_backend::proof_epoch(proof)
    }
    #[cfg(not(feature = "ragu"))]
    {
        let _ = proof;
        None
    }
}

/// Gate in front of the Halo 2 verifiers: a Ragu proof cannot be checked by
/// them, and a mint running the Ragu backend does not accept Halo 2 proofs.
fn require_halo2(proof: &FoldedProof) -> Result<()> {
    if proof.subcircuit == SubcircuitId::RaguTx {
        return Err(CircuitError::VerificationFailed(
            "Ragu transaction proof, but the Ragu backend is not compiled in".into(),
        ));
    }
    if FoldBackend::ragu_selected()? {
        return Err(CircuitError::VerificationFailed(
            "this mint only accepts Ragu transaction proofs".into(),
        ));
    }
    Ok(())
}

/// The epoch a transaction's predicates are evaluated at: the latest
/// `current_epoch` any of its predicate witnesses names.
#[cfg(feature = "ragu")]
fn tx_epoch(inputs: &[InputNoteWitness<'_>]) -> u64 {
    inputs
        .iter()
        .map(|i| match i.predicate {
            PredicateWitness::Timelock { current_epoch, .. }
            | PredicateWitness::PrivateHTLC { current_epoch, .. } => *current_epoch,
            _ => 0,
        })
        .max()
        .unwrap_or(0)
}

#[cfg(feature = "ragu")]
fn ragu_inputs<'a>(inputs: &'a [InputNoteWitness<'a>]) -> Vec<ragu_backend::SpendInput<'a>> {
    inputs
        .iter()
        .map(|i| ragu_backend::SpendInput { note: i.note, witness: i.witness, predicate: i.predicate })
        .collect()
}

fn bytes_fp(b: &[u8; 32]) -> Fp {
    bytes_to_fp(b).unwrap_or_else(|_| hash_bytes_to_fp(b"zashu-b-fp", b))
}

#[derive(Debug, Clone)]
pub struct ModeBConfig {
    pub vals: [Column<Advice>; MAX_IO],
    pub out_vals: [Column<Advice>; MAX_IO],
    pub sum_col: Column<Advice>,
    pub pub_val: Column<Advice>,
    pub instance: Column<Instance>,
    pub q_balance: Selector,
    pub q_mint: Selector,
    pub q_melt: Selector,
    pub range: RangeCheck64Config,
    pub poseidon: PoseidonChipConfig,
}

impl ModeBConfig {
    pub fn configure(meta: &mut ConstraintSystem<Fp>) -> Self {
        let vals = [
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
        ];
        let out_vals = [
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
        ];
        let sum_col = meta.advice_column();
        let pub_val = meta.advice_column();
        let bits = [
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
        ];
        let acc = meta.advice_column();
        let p_state = [
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
        ];
        let p_rc = [
            meta.fixed_column(),
            meta.fixed_column(),
            meta.fixed_column(),
        ];
        let p_bit = meta.advice_column();
        let constant = meta.fixed_column();
        let instance = meta.instance_column();

        for c in vals
            .iter()
            .chain(out_vals.iter())
            .chain(bits.iter())
            .chain(p_state.iter())
        {
            meta.enable_equality(*c);
        }
        meta.enable_equality(sum_col);
        meta.enable_equality(pub_val);
        meta.enable_equality(acc);
        meta.enable_equality(p_bit);
        meta.enable_constant(constant);
        meta.enable_equality(instance);

        let q_balance = meta.selector();
        let q_mint = meta.selector();
        let q_melt = meta.selector();

        meta.create_gate("zk_swap_balance", |meta| {
            let q = meta.query_selector(q_balance);
            let sum_in = vals
                .iter()
                .map(|c| meta.query_advice(*c, Rotation::cur()))
                .reduce(|a, b| a + b)
                .unwrap();
            let sum_out = out_vals
                .iter()
                .map(|c| meta.query_advice(*c, Rotation::cur()))
                .reduce(|a, b| a + b)
                .unwrap();
            vec![q * (sum_in - sum_out)]
        });

        meta.create_gate("zk_mint_eq", |meta| {
            let q = meta.query_selector(q_mint);
            let v = meta.query_advice(vals[0], Rotation::cur());
            let pv = meta.query_advice(pub_val, Rotation::cur());
            vec![q * (v - pv)]
        });

        meta.create_gate("zk_melt_balance", |meta| {
            let q = meta.query_selector(q_melt);
            let sum_in = vals
                .iter()
                .map(|c| meta.query_advice(*c, Rotation::cur()))
                .reduce(|a, b| a + b)
                .unwrap();
            let pv = meta.query_advice(pub_val, Rotation::cur());
            let ch = meta.query_advice(out_vals[0], Rotation::cur());
            vec![q * (sum_in - (pv + ch))]
        });

        let range = RangeCheck64Config::configure(meta, bits, acc);
        let poseidon = PoseidonChipConfig::configure(meta, p_state, p_rc, p_bit);

        Self {
            vals,
            out_vals,
            sum_col,
            pub_val,
            instance,
            q_balance,
            q_mint,
            q_melt,
            range,
            poseidon,
        }
    }
}

/// `ZkMintCircuit`: proves `v == public_mint_amount`, `0 <= v < 2^64`, bound to `(cm, cv, amount)`.
#[derive(Debug, Clone, Default)]
pub struct ZkMintCircuit {
    pub value: Value<u64>,
    pub public_amount: Value<u64>,
    pub cm_fp: Value<Fp>,
    pub cv_fp: Value<Fp>,
}

impl Circuit<Fp> for ZkMintCircuit {
    type Config = ModeBConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<Fp>) -> Self::Config {
        ModeBConfig::configure(meta)
    }

    fn synthesize(&self, cfg: Self::Config, mut layouter: impl Layouter<Fp>) -> std::result::Result<(), Error> {
        let v_rc = cfg.range.constrain_u64(layouter.namespace(|| "rc_v"), "mint_v", self.value, None)?;
        let (pv_c, cm_c, cv_c) = layouter.assign_region(
            || "zk_mint",
            |mut region| {
                cfg.q_mint.enable(&mut region, 0)?;
                let v_c = region.assign_advice(|| "v", cfg.vals[0], 0, || self.value.map(Fp::from))?;
                region.constrain_equal(v_c.cell(), v_rc.cell())?;
                let pv_c = region.assign_advice(|| "pv", cfg.pub_val, 0, || self.public_amount.map(Fp::from))?;
                let cm_c = region.assign_advice(|| "cm", cfg.sum_col, 0, || self.cm_fp)?;
                let cv_c = region.assign_advice(|| "cv", cfg.out_vals[0], 0, || self.cv_fp)?;
                Ok((pv_c, cm_c, cv_c))
            },
        )?;
        layouter.constrain_instance(pv_c.cell(), cfg.instance, 0)?;
        layouter.constrain_instance(cm_c.cell(), cfg.instance, 1)?;
        layouter.constrain_instance(cv_c.cell(), cfg.instance, 2)?;
        Ok(())
    }
}

/// Unified `ZkSwapCircuit` (`k = 13`):
/// Proves in a single Halo 2 proof:
/// 1. In-circuit 24-level Poseidon Merkle inclusion of private `primary_in_cm` in public `anchor_root_fp`.
/// 2. 64-bit unsigned range checks on all `k <= 4` inputs and `m <= 4` outputs.
/// 3. Value conservation `sum(in) == sum(out)`.
/// Public instances: `[anchor_root_fp, nf_0..3, cm_out_0..3]`.
#[derive(Debug, Clone)]
pub struct ZkSwapCircuit {
    pub in_values: [Value<u64>; MAX_IO],
    pub out_values: [Value<u64>; MAX_IO],
    pub anchor_root_fp: Value<Fp>,
    pub nfs: [Value<Fp>; MAX_IO],
    pub cms: [Value<Fp>; MAX_IO],
    pub primary_in_cm: Value<Fp>,
    pub primary_siblings: [Value<Fp>; ACC_DEPTH],
    pub primary_leaf_index: Value<u64>,
}

impl Default for ZkSwapCircuit {
    fn default() -> Self {
        Self {
            in_values: [Value::unknown(); MAX_IO],
            out_values: [Value::unknown(); MAX_IO],
            anchor_root_fp: Value::unknown(),
            nfs: [Value::unknown(); MAX_IO],
            cms: [Value::unknown(); MAX_IO],
            primary_in_cm: Value::unknown(),
            primary_siblings: [Value::unknown(); ACC_DEPTH],
            primary_leaf_index: Value::unknown(),
        }
    }
}

impl Circuit<Fp> for ZkSwapCircuit {
    type Config = ModeBConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<Fp>) -> Self::Config {
        ModeBConfig::configure(meta)
    }

    fn synthesize(&self, cfg: Self::Config, mut layouter: impl Layouter<Fp>) -> std::result::Result<(), Error> {
        let mut in_rcs = Vec::with_capacity(MAX_IO);
        let mut out_rcs = Vec::with_capacity(MAX_IO);
        for i in 0..MAX_IO {
            in_rcs.push(cfg.range.constrain_u64(
                layouter.namespace(|| format!("rc_in_{i}")),
                &format!("in_{i}"),
                self.in_values[i],
                None,
            )?);
            out_rcs.push(cfg.range.constrain_u64(
                layouter.namespace(|| format!("rc_out_{i}")),
                &format!("out_{i}"),
                self.out_values[i],
                None,
            )?);
        }

        let (anc_c, prim_cm_c, nf_cs, cm_cs) = layouter.assign_region(
            || "zk_swap",
            |mut region| {
                cfg.q_balance.enable(&mut region, 0)?;
                for i in 0..MAX_IO {
                    let ic = region.assign_advice(
                        || format!("in_{i}"),
                        cfg.vals[i],
                        0,
                        || self.in_values[i].map(Fp::from),
                    )?;
                    region.constrain_equal(ic.cell(), in_rcs[i].cell())?;

                    let oc = region.assign_advice(
                        || format!("out_{i}"),
                        cfg.out_vals[i],
                        0,
                        || self.out_values[i].map(Fp::from),
                    )?;
                    region.constrain_equal(oc.cell(), out_rcs[i].cell())?;
                }

                let anc_c = region.assign_advice(|| "anchor", cfg.pub_val, 0, || self.anchor_root_fp)?;
                let prim_cm_c = region.assign_advice(|| "prim_in_cm", cfg.sum_col, 0, || self.primary_in_cm)?;
                let mut nf_cs = Vec::with_capacity(MAX_IO);
                let mut cm_cs = Vec::with_capacity(MAX_IO);
                for i in 0..MAX_IO {
                    nf_cs.push(region.assign_advice(|| format!("nf_{i}"), cfg.vals[i], 1, || self.nfs[i])?);
                    cm_cs.push(region.assign_advice(|| format!("cm_{i}"), cfg.out_vals[i], 1, || self.cms[i])?);
                }
                Ok((anc_c, prim_cm_c, nf_cs, cm_cs))
            },
        )?;

        // In-circuit 24-level Poseidon Merkle inclusion of primary input note
        cfg.poseidon.verify_merkle_inclusion(
            layouter.namespace(|| "zk_swap_merkle"),
            prim_cm_c,
            &self.primary_siblings,
            self.primary_leaf_index,
            &anc_c,
        )?;

        layouter.constrain_instance(anc_c.cell(), cfg.instance, 0)?;
        for i in 0..MAX_IO {
            layouter.constrain_instance(nf_cs[i].cell(), cfg.instance, 1 + i)?;
            layouter.constrain_instance(cm_cs[i].cell(), cfg.instance, 1 + MAX_IO + i)?;
        }
        Ok(())
    }
}

/// Unified `ZkMeltCircuit` (`k = 13`):
/// Proves in-circuit 24-level Poseidon Merkle inclusion + `sum(in) == public_melt_amount + change_val` + 64-bit range checks.
/// Public instances: `[anchor_root_fp, public_melt_amount, change_cm_fp, nf_0..3]`.
#[derive(Debug, Clone)]
pub struct ZkMeltCircuit {
    pub in_values: [Value<u64>; MAX_IO],
    pub public_melt_amount: Value<u64>,
    pub change_value: Value<u64>,
    pub anchor_root_fp: Value<Fp>,
    pub change_cm_fp: Value<Fp>,
    pub nfs: [Value<Fp>; MAX_IO],
    pub primary_in_cm: Value<Fp>,
    pub primary_siblings: [Value<Fp>; ACC_DEPTH],
    pub primary_leaf_index: Value<u64>,
}

impl Default for ZkMeltCircuit {
    fn default() -> Self {
        Self {
            in_values: [Value::unknown(); MAX_IO],
            public_melt_amount: Value::unknown(),
            change_value: Value::unknown(),
            anchor_root_fp: Value::unknown(),
            change_cm_fp: Value::unknown(),
            nfs: [Value::unknown(); MAX_IO],
            primary_in_cm: Value::unknown(),
            primary_siblings: [Value::unknown(); ACC_DEPTH],
            primary_leaf_index: Value::unknown(),
        }
    }
}

impl Circuit<Fp> for ZkMeltCircuit {
    type Config = ModeBConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<Fp>) -> Self::Config {
        ModeBConfig::configure(meta)
    }

    fn synthesize(&self, cfg: Self::Config, mut layouter: impl Layouter<Fp>) -> std::result::Result<(), Error> {
        let mut in_rcs = Vec::with_capacity(MAX_IO);
        for i in 0..MAX_IO {
            in_rcs.push(cfg.range.constrain_u64(
                layouter.namespace(|| format!("rc_melt_in_{i}")),
                &format!("melt_in_{i}"),
                self.in_values[i],
                None,
            )?);
        }
        let ch_rc = cfg.range.constrain_u64(
            layouter.namespace(|| "rc_melt_ch"),
            "melt_ch",
            self.change_value,
            None,
        )?;
        let pm_rc = cfg.range.constrain_u64(
            layouter.namespace(|| "rc_melt_pub"),
            "melt_pub",
            self.public_melt_amount,
            None,
        )?;

        let (anc_c, prim_cm_c, pv_c, ch_cm_c, nf_cs) = layouter.assign_region(
            || "zk_melt",
            |mut region| {
                cfg.q_melt.enable(&mut region, 0)?;
                for i in 0..MAX_IO {
                    let ic = region.assign_advice(
                        || format!("in_{i}"),
                        cfg.vals[i],
                        0,
                        || self.in_values[i].map(Fp::from),
                    )?;
                    region.constrain_equal(ic.cell(), in_rcs[i].cell())?;
                }
                let ch_c = region.assign_advice(|| "ch", cfg.out_vals[0], 0, || self.change_value.map(Fp::from))?;
                region.constrain_equal(ch_c.cell(), ch_rc.cell())?;
                let pv_c = region.assign_advice(|| "pv", cfg.pub_val, 0, || self.public_melt_amount.map(Fp::from))?;
                region.constrain_equal(pv_c.cell(), pm_rc.cell())?;

                let anc_c = region.assign_advice(|| "anchor", cfg.pub_val, 1, || self.anchor_root_fp)?;
                let ch_cm_c = region.assign_advice(|| "ch_cm", cfg.sum_col, 1, || self.change_cm_fp)?;
                let prim_cm_c = region.assign_advice(|| "prim_in_cm", cfg.out_vals[1], 1, || self.primary_in_cm)?;
                let mut nf_cs = Vec::with_capacity(MAX_IO);
                for i in 0..MAX_IO {
                    nf_cs.push(region.assign_advice(|| format!("nf_{i}"), cfg.vals[i], 1, || self.nfs[i])?);
                }
                Ok((anc_c, prim_cm_c, pv_c, ch_cm_c, nf_cs))
            },
        )?;

        cfg.poseidon.verify_merkle_inclusion(
            layouter.namespace(|| "zk_melt_merkle"),
            prim_cm_c,
            &self.primary_siblings,
            self.primary_leaf_index,
            &anc_c,
        )?;

        layouter.constrain_instance(anc_c.cell(), cfg.instance, 0)?;
        layouter.constrain_instance(pv_c.cell(), cfg.instance, 1)?;
        layouter.constrain_instance(ch_cm_c.cell(), cfg.instance, 2)?;
        for i in 0..MAX_IO {
            layouter.constrain_instance(nf_cs[i].cell(), cfg.instance, 3 + i)?;
        }
        Ok(())
    }
}

pub struct InputNoteWitness<'a> {
    pub note: &'a Note,
    pub blind: Fq,
    pub witness: &'a InclusionWitness,
    pub predicate: &'a PredicateWitness,
}

pub struct OutputNoteWitness<'a> {
    pub note: &'a Note,
    pub blind: Fq,
}

pub fn prove_zk_mint(note: &Note, blind: Fq, public_amount: u64) -> Result<(NoteCommitment, ValueCommitment, FoldedProof)> {
    if note.value != public_amount {
        return Err(CircuitError::ValueBounds);
    }
    let cm = note.commitment();
    let cv = ValueCommitment::commit(note.value, blind);
    #[cfg(feature = "ragu")]
    if FoldBackend::ragu_selected()? {
        let proof = ragu_backend::prove_tx(&[0u8; 32], 0, &[], &[note])?;
        return Ok((cm, cv, proof));
    }
    #[cfg(not(feature = "ragu"))]
    FoldBackend::ragu_selected()?;
    let cm_fp = bytes_fp(&cm.0);
    let cv_fp = bytes_fp(&cv.bytes);

    let circuit = ZkMintCircuit {
        value: Value::known(note.value),
        public_amount: Value::known(public_amount),
        cm_fp: Value::known(cm_fp),
        cv_fp: Value::known(cv_fp),
    };
    let instances = [Fp::from(public_amount), cm_fp, cv_fp];
    let proof = PcdEngine::global().prove(
        SubcircuitId::ZkMint,
        DEFAULT_K,
        &ZkMintCircuit::default(),
        circuit,
        &instances,
        1,
    )?;
    Ok((cm, cv, proof))
}

pub fn prove_zk_shield(note: &Note, blind: Fq, bdhke_sum: u64) -> Result<(NoteCommitment, ValueCommitment, FoldedProof)> {
    let (cm, cv, mut proof) = prove_zk_mint(note, blind, bdhke_sum)?;
    if proof.subcircuit == SubcircuitId::ZkMint {
        proof.subcircuit = SubcircuitId::ZkShield;
    }
    Ok((cm, cv, proof))
}

pub fn verify_zk_mint(proof: &FoldedProof, public_amount: u64, cm: &NoteCommitment, cv: &ValueCommitment) -> Result<()> {
    #[cfg(feature = "ragu")]
    if proof.subcircuit == SubcircuitId::RaguTx {
        return ragu_backend::verify_tx(proof, None, &[], &[*cm], ragu_backend::Balance::In(public_amount));
    }
    require_halo2(proof)?;
    let expected = [
        zashu_core::field::fp_to_bytes(&Fp::from(public_amount)),
        zashu_core::field::fp_to_bytes(&bytes_fp(&cm.0)),
        zashu_core::field::fp_to_bytes(&bytes_fp(&cv.bytes)),
    ];
    if proof.public_inputs != expected {
        return Err(CircuitError::VerificationFailed("zk_mint public input mismatch".into()));
    }
    PcdEngine::global().verify(SubcircuitId::ZkMint, &ZkMintCircuit::default(), proof)
}

pub fn verify_zk_shield(proof: &FoldedProof, bdhke_sum: u64, cm: &NoteCommitment, cv: &ValueCommitment) -> Result<()> {
    if proof.subcircuit == SubcircuitId::RaguTx {
        return verify_zk_mint(proof, bdhke_sum, cm, cv);
    }
    let mut inner = proof.clone();
    inner.subcircuit = SubcircuitId::ZkMint;
    verify_zk_mint(&inner, bdhke_sum, cm, cv)
}

fn siblings_to_values(w: &InclusionWitness) -> Result<[Value<Fp>; ACC_DEPTH]> {
    if w.siblings.len() != ACC_DEPTH {
        return Err(CircuitError::InvalidWitness("invalid sibling length".into()));
    }
    let mut out = [Value::unknown(); ACC_DEPTH];
    for (i, s) in w.siblings.iter().enumerate() {
        out[i] = Value::known(bytes_fp(s));
    }
    Ok(out)
}

pub fn prove_zk_swap(
    anchor_root: &[u8; 32],
    inputs: &[InputNoteWitness<'_>],
    outputs: &[OutputNoteWitness<'_>],
) -> Result<(Vec<Nullifier>, Vec<NoteCommitment>, Vec<ValueCommitment>, FoldedProof)> {
    if inputs.is_empty() || inputs.len() > MAX_IO || outputs.is_empty() || outputs.len() > MAX_IO {
        return Err(CircuitError::InvalidWitness("inputs/outputs must be 1..=4".into()));
    }

    let mut in_vals = [0u64; MAX_IO];
    let mut out_vals = [0u64; MAX_IO];
    let mut in_cvs = Vec::with_capacity(inputs.len());
    let mut out_cvs = Vec::with_capacity(outputs.len());
    let mut nfs = Vec::with_capacity(inputs.len());
    let mut cms = Vec::with_capacity(outputs.len());
    let mut nf_fps = [Fp::ZERO; MAX_IO];
    let mut cm_fps = [Fp::ZERO; MAX_IO];

    let mut sum_in: u128 = 0;
    let mut primary_cm_fp = Fp::ZERO;
    for (i, inp) in inputs.iter().enumerate() {
        let cm = inp.note.commitment();
        if i == 0 {
            primary_cm_fp = bytes_fp(&cm.0);
        }
        if !NoteAccumulator::verify_inclusion(anchor_root, &cm.0, inp.witness) {
            return Err(CircuitError::InvalidWitness("input note not in anchor_root".into()));
        }
        verify_predicate(inp.note, inp.predicate)?;
        let nf = inp.note.nullifier();
        nfs.push(nf);
        nf_fps[i] = bytes_fp(&nf.0);
        in_vals[i] = inp.note.value;
        sum_in += inp.note.value as u128;
        in_cvs.push(ValueCommitment::commit(inp.note.value, inp.blind));
    }

    let mut sum_out: u128 = 0;
    for (i, outp) in outputs.iter().enumerate() {
        let cm = outp.note.commitment();
        cms.push(cm);
        cm_fps[i] = bytes_fp(&cm.0);
        out_vals[i] = outp.note.value;
        sum_out += outp.note.value as u128;
        out_cvs.push(ValueCommitment::commit(outp.note.value, outp.blind));
    }

    if sum_in != sum_out || !ValueCommitment::verify_balance(&in_cvs, &out_cvs)? {
        return Err(CircuitError::ValueBounds);
    }

    #[cfg(feature = "ragu")]
    if FoldBackend::ragu_selected()? {
        let out_notes: Vec<&Note> = outputs.iter().map(|o| o.note).collect();
        let proof = ragu_backend::prove_tx(anchor_root, tx_epoch(inputs), &ragu_inputs(inputs), &out_notes)?;
        return Ok((nfs, cms, out_cvs, proof));
    }
    #[cfg(not(feature = "ragu"))]
    FoldBackend::ragu_selected()?;

    let anc_fp = bytes_fp(anchor_root);
    let circuit = ZkSwapCircuit {
        in_values: in_vals.map(Value::known),
        out_values: out_vals.map(Value::known),
        anchor_root_fp: Value::known(anc_fp),
        nfs: nf_fps.map(Value::known),
        cms: cm_fps.map(Value::known),
        primary_in_cm: Value::known(primary_cm_fp),
        primary_siblings: siblings_to_values(inputs[0].witness)?,
        primary_leaf_index: Value::known(inputs[0].witness.leaf_index),
    };

    let mut instances = Vec::with_capacity(1 + 2 * MAX_IO);
    instances.push(anc_fp);
    instances.extend_from_slice(&nf_fps);
    instances.extend_from_slice(&cm_fps);

    let proof = PcdEngine::global().prove(
        SubcircuitId::ZkSwap,
        MERKLE_K,
        &ZkSwapCircuit::default(),
        circuit,
        &instances,
        1,
    )?;

    Ok((nfs, cms, out_cvs, proof))
}

pub fn verify_zk_swap(
    proof: &FoldedProof,
    anchor_root: &[u8; 32],
    nullifiers: &[Nullifier],
    out_cms: &[NoteCommitment],
    in_cvs: &[ValueCommitment],
    out_cvs: &[ValueCommitment],
) -> Result<()> {
    if !in_cvs.is_empty() && !ValueCommitment::verify_balance(in_cvs, out_cvs)? {
        return Err(CircuitError::VerificationFailed("pedersen balance mismatch".into()));
    }
    #[cfg(feature = "ragu")]
    if proof.subcircuit == SubcircuitId::RaguTx {
        return ragu_backend::verify_tx(proof, Some(anchor_root), nullifiers, out_cms, ragu_backend::Balance::Zero);
    }
    require_halo2(proof)?;
    let mut expected = vec![zashu_core::field::fp_to_bytes(&bytes_fp(anchor_root))];
    for i in 0..MAX_IO {
        let fp = nullifiers.get(i).map(|n| bytes_fp(&n.0)).unwrap_or(Fp::ZERO);
        expected.push(zashu_core::field::fp_to_bytes(&fp));
    }
    for i in 0..MAX_IO {
        let fp = out_cms.get(i).map(|c| bytes_fp(&c.0)).unwrap_or(Fp::ZERO);
        expected.push(zashu_core::field::fp_to_bytes(&fp));
    }
    if proof.public_inputs != expected {
        return Err(CircuitError::VerificationFailed("zk_swap public input mismatch".into()));
    }
    PcdEngine::global().verify(SubcircuitId::ZkSwap, &ZkSwapCircuit::default(), proof)
}

pub fn prove_zk_melt(
    anchor_root: &[u8; 32],
    inputs: &[InputNoteWitness<'_>],
    public_melt_amount: u64,
    change_note: Option<(&Note, Fq)>,
) -> Result<(Vec<Nullifier>, Option<(NoteCommitment, ValueCommitment)>, FoldedProof)> {
    if inputs.is_empty() || inputs.len() > MAX_IO {
        return Err(CircuitError::InvalidWitness("inputs must be 1..=4".into()));
    }
    let mut in_vals = [0u64; MAX_IO];
    let mut nfs = Vec::with_capacity(inputs.len());
    let mut nf_fps = [Fp::ZERO; MAX_IO];
    let mut sum_in: u128 = 0;
    let mut primary_cm_fp = Fp::ZERO;

    for (i, inp) in inputs.iter().enumerate() {
        let cm = inp.note.commitment();
        if i == 0 {
            primary_cm_fp = bytes_fp(&cm.0);
        }
        if !NoteAccumulator::verify_inclusion(anchor_root, &cm.0, inp.witness) {
            return Err(CircuitError::InvalidWitness("melt input note not in anchor_root".into()));
        }
        verify_predicate(inp.note, inp.predicate)?;
        let nf = inp.note.nullifier();
        nfs.push(nf);
        nf_fps[i] = bytes_fp(&nf.0);
        in_vals[i] = inp.note.value;
        sum_in += inp.note.value as u128;
    }

    let (ch_val, ch_out, ch_cm_fp) = match change_note {
        Some((n, b)) => {
            let cm = n.commitment();
            let cv = ValueCommitment::commit(n.value, b);
            let fp = bytes_fp(&cm.0);
            (n.value, Some((cm, cv)), fp)
        }
        None => (0u64, None, Fp::ZERO),
    };

    if sum_in != (public_melt_amount as u128 + ch_val as u128) {
        return Err(CircuitError::ValueBounds);
    }

    #[cfg(feature = "ragu")]
    if FoldBackend::ragu_selected()? {
        let change: Vec<&Note> = change_note.iter().map(|(n, _)| *n).collect();
        let proof = ragu_backend::prove_tx(anchor_root, tx_epoch(inputs), &ragu_inputs(inputs), &change)?;
        return Ok((nfs, ch_out, proof));
    }
    #[cfg(not(feature = "ragu"))]
    FoldBackend::ragu_selected()?;

    let anc_fp = bytes_fp(anchor_root);
    let circuit = ZkMeltCircuit {
        in_values: in_vals.map(Value::known),
        public_melt_amount: Value::known(public_melt_amount),
        change_value: Value::known(ch_val),
        anchor_root_fp: Value::known(anc_fp),
        change_cm_fp: Value::known(ch_cm_fp),
        nfs: nf_fps.map(Value::known),
        primary_in_cm: Value::known(primary_cm_fp),
        primary_siblings: siblings_to_values(inputs[0].witness)?,
        primary_leaf_index: Value::known(inputs[0].witness.leaf_index),
    };

    let mut instances = Vec::with_capacity(3 + MAX_IO);
    instances.push(anc_fp);
    instances.push(Fp::from(public_melt_amount));
    instances.push(ch_cm_fp);
    instances.extend_from_slice(&nf_fps);

    let proof = PcdEngine::global().prove(
        SubcircuitId::ZkMelt,
        MERKLE_K,
        &ZkMeltCircuit::default(),
        circuit,
        &instances,
        1,
    )?;

    Ok((nfs, ch_out, proof))
}

pub fn prove_zk_unshield(
    anchor_root: &[u8; 32],
    inputs: &[InputNoteWitness<'_>],
    unshield_amount: u64,
    change_note: Option<(&Note, Fq)>,
) -> Result<(Vec<Nullifier>, Option<(NoteCommitment, ValueCommitment)>, FoldedProof)> {
    let (nfs, ch, mut proof) = prove_zk_melt(anchor_root, inputs, unshield_amount, change_note)?;
    if proof.subcircuit == SubcircuitId::ZkMelt {
        proof.subcircuit = SubcircuitId::ZkUnshield;
    }
    Ok((nfs, ch, proof))
}

pub fn verify_zk_melt(
    proof: &FoldedProof,
    anchor_root: &[u8; 32],
    public_melt_amount: u64,
    change_cm: Option<&NoteCommitment>,
    nullifiers: &[Nullifier],
) -> Result<()> {
    #[cfg(feature = "ragu")]
    if proof.subcircuit == SubcircuitId::RaguTx {
        let change: Vec<NoteCommitment> = change_cm.into_iter().copied().collect();
        return ragu_backend::verify_tx(
            proof,
            Some(anchor_root),
            nullifiers,
            &change,
            ragu_backend::Balance::Out(public_melt_amount),
        );
    }
    require_halo2(proof)?;
    let mut expected = vec![
        zashu_core::field::fp_to_bytes(&bytes_fp(anchor_root)),
        zashu_core::field::fp_to_bytes(&Fp::from(public_melt_amount)),
        zashu_core::field::fp_to_bytes(&change_cm.map(|c| bytes_fp(&c.0)).unwrap_or(Fp::ZERO)),
    ];
    for i in 0..MAX_IO {
        let fp = nullifiers.get(i).map(|n| bytes_fp(&n.0)).unwrap_or(Fp::ZERO);
        expected.push(zashu_core::field::fp_to_bytes(&fp));
    }
    if proof.public_inputs != expected {
        return Err(CircuitError::VerificationFailed("zk_melt public input mismatch".into()));
    }
    PcdEngine::global().verify(SubcircuitId::ZkMelt, &ZkMeltCircuit::default(), proof)
}

pub fn verify_zk_unshield(
    proof: &FoldedProof,
    anchor_root: &[u8; 32],
    unshield_amount: u64,
    change_cm: Option<&NoteCommitment>,
    nullifiers: &[Nullifier],
) -> Result<()> {
    if proof.subcircuit == SubcircuitId::RaguTx {
        return verify_zk_melt(proof, anchor_root, unshield_amount, change_cm, nullifiers);
    }
    let mut inner = proof.clone();
    inner.subcircuit = SubcircuitId::ZkMelt;
    verify_zk_melt(&inner, anchor_root, unshield_amount, change_cm, nullifiers)
}

pub fn balance_blinding(in_blinds: &[Fq], out_blinds_except_last: &[Fq]) -> Fq {
    let sum_in: Fq = in_blinds.iter().copied().sum();
    let sum_out: Fq = out_blinds_except_last.iter().copied().sum();
    sum_in - sum_out
}

/// Standalone Merkle inclusion proof helper (`k = 13`).
pub fn prove_merkle_inclusion(
    leaf: &[u8; 32],
    root: &[u8; 32],
    witness: &InclusionWitness,
) -> Result<FoldedProof> {
    let leaf_fp = bytes_fp(leaf);
    let root_fp = bytes_fp(root);
    let circuit = MerkleInclusionCircuit {
        leaf: Value::known(leaf_fp),
        root: Value::known(root_fp),
        siblings: siblings_to_values(witness)?,
        leaf_index: Value::known(witness.leaf_index),
    };
    PcdEngine::global().prove(
        SubcircuitId::MerkleInclusion,
        MERKLE_K,
        &MerkleInclusionCircuit::default(),
        circuit,
        &[leaf_fp, root_fp],
        1,
    )
}

pub fn verify_merkle_inclusion(
    proof: &FoldedProof,
    leaf: &[u8; 32],
    root: &[u8; 32],
) -> Result<()> {
    let expected = [
        zashu_core::field::fp_to_bytes(&bytes_fp(leaf)),
        zashu_core::field::fp_to_bytes(&bytes_fp(root)),
    ];
    if proof.public_inputs != expected {
        return Err(CircuitError::VerificationFailed("merkle inclusion public input mismatch".into()));
    }
    PcdEngine::global().verify(
        SubcircuitId::MerkleInclusion,
        &MerkleInclusionCircuit::default(),
        proof,
    )
}

const _: fn(&Fq) -> [u8; 32] = fq_to_bytes;
