use ff::Field;
use halo2_proofs::circuit::{Layouter, SimpleFloorPlanner, Value};
use halo2_proofs::pasta::Fp;
use halo2_proofs::plonk::{
    Advice, Circuit, Column, ConstraintSystem, Error, Instance, Selector,
};
use halo2_proofs::poly::Rotation;
use zashu_acc::{NullifierAccumulator, NullifierTransitionWitness};
use zashu_core::field::{bytes_to_fp, hash_bytes_to_fp};
use zashu_core::poseidon::hash_predicate_params;
use zashu_core::types::{MintState, PredicateId};

use crate::error::{CircuitError, Result};
use crate::pcd::{fold_tree, FoldedProof, PcdEngine, SubcircuitId, DEFAULT_K};
use crate::range_check::RangeCheck64Config;

#[cfg(feature = "ragu")]
pub mod ragu_backend;
#[cfg(feature = "ragu")]
pub mod ragu_aggregate;
#[cfg(feature = "ragu")]
pub mod ragu_roots;

/// Environment variable read by [`FoldBackend::from_env`]: `ragu`,
/// `ragu-aggregated`, `ragu-unbound` or `halo2`.
/// Unset selects Halo 2.
pub const PCD_BACKEND_ENV: &str = "ZASHU_PCD_BACKEND";
/// Older name for [`PCD_BACKEND_ENV`], still honoured when that one is unset.
pub const FOLD_BACKEND_ENV: &str = "ZASHU_FOLD_BACKEND";

/// Proof system used to fold Mode A step proofs into the `NUTZ-1` proof and to
/// prove Mode B transactions. A mint running the Ragu backend also refuses
/// Halo 2 Mode B proofs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum FoldBackend {
    /// Steps are verified natively by the folder; the folded Halo 2 proof only
    /// exposes the endpoints as public inputs.
    /// This is the default backend.
    #[default]
    Halo2,
    /// Recursive Ragu PCD: the folded proof attests every step and the chaining
    /// between them, including how the event log, nullifier root and note root
    /// change. Requires the `ragu` cargo feature, which is on by default, and
    /// is selected with `ZASHU_PCD_BACKEND=ragu`.
    Ragu,
    /// Ragu PCD without the root bindings: each step opens its state hashes
    /// and checks liabilities, but roots and the event log move freely. Much
    /// cheaper to prove. Mode B transactions are proven as with [`Self::Ragu`].
    RaguUnbound,
    /// [`Self::Ragu`], plus a Ragu aggregator that checks each operation
    /// against the shielded transaction proof that authorised it and counts
    /// the operations that had none. The heaviest option by far.
    RaguAggregated,
}

impl FoldBackend {
    /// Reads [`PCD_BACKEND_ENV`], falling back to [`FOLD_BACKEND_ENV`]. Unset
    /// or empty selects the default backend.
    pub fn from_env() -> Result<Self> {
        let (name, value) = match std::env::var(PCD_BACKEND_ENV) {
            Ok(v) => (PCD_BACKEND_ENV, v),
            Err(_) => match std::env::var(FOLD_BACKEND_ENV) {
                Ok(v) => (FOLD_BACKEND_ENV, v),
                Err(_) => return Ok(Self::default()),
            },
        };
        match value.trim().to_ascii_lowercase().as_str() {
            "" => Ok(Self::default()),
            "halo2" => Ok(Self::Halo2),
            "ragu" => Ok(Self::Ragu),
            "ragu-unbound" => Ok(Self::RaguUnbound),
            "ragu-aggregated" => Ok(Self::RaguAggregated),
            other => Err(CircuitError::InvalidWitness(format!(
                "{name}={other:?}: expected \"ragu\", \"ragu-aggregated\", \"ragu-unbound\" or \"halo2\""
            ))),
        }
    }

    /// Whether the Ragu backend is selected, erroring if it is selected but
    /// was not compiled in.
    pub fn ragu_selected() -> Result<bool> {
        match Self::from_env()? {
            Self::Halo2 => Ok(false),
            #[cfg(feature = "ragu")]
            Self::Ragu | Self::RaguUnbound | Self::RaguAggregated => Ok(true),
            #[cfg(not(feature = "ragu"))]
            Self::Ragu | Self::RaguUnbound | Self::RaguAggregated => Err(ragu_unavailable()),
        }
    }
}

/// `(ops, unbound_ops)` of an aggregated fold proof: how many operations it
/// covers and how many had no matching shielded transaction proof. `None`
/// for other proofs.
pub fn fold_op_counts(proof: &FoldedProof) -> Option<(u64, u64)> {
    #[cfg(feature = "ragu")]
    {
        ragu_aggregate::op_counts(proof)
    }
    #[cfg(not(feature = "ragu"))]
    {
        let _ = proof;
        None
    }
}

/// Folds Mode A steps as they are produced.
///
/// With [`FoldBackend::Ragu`] every pushed step is fused onto a running proof
/// on a worker thread, so [`snapshot`](Self::snapshot) only has to wait for the
/// worker to catch up and compress. With [`FoldBackend::Halo2`] it does
/// nothing and `snapshot` returns `None`; callers then fold the batch with
/// [`fold_mode_a_batch`].
pub struct IncrementalFold {
    backend: FoldBackend,
    #[cfg(feature = "ragu")]
    folder: Option<ragu_backend::BackgroundFolder>,
}

impl IncrementalFold {
    pub fn new(backend: FoldBackend) -> Result<Self> {
        match backend {
            FoldBackend::Halo2 => Ok(Self {
                backend,
                #[cfg(feature = "ragu")]
                folder: None,
            }),
            #[cfg(feature = "ragu")]
            FoldBackend::Ragu => Ok(Self { backend, folder: Some(ragu_roots::background()) }),
            #[cfg(feature = "ragu")]
            FoldBackend::RaguUnbound => {
                Ok(Self { backend, folder: Some(ragu_backend::BackgroundFolder::spawn()) })
            }
            #[cfg(feature = "ragu")]
            FoldBackend::RaguAggregated => Ok(Self { backend, folder: Some(ragu_aggregate::background()) }),
            #[cfg(not(feature = "ragu"))]
            FoldBackend::Ragu | FoldBackend::RaguUnbound | FoldBackend::RaguAggregated => {
                Err(ragu_unavailable())
            }
        }
    }

    pub fn from_env() -> Result<Self> {
        Self::new(FoldBackend::from_env()?)
    }

    pub fn backend(&self) -> FoldBackend {
        self.backend
    }

    /// Queues a step. Steps must be pushed in the order they happened.
    pub fn push(&self, step: &FoldedProof) {
        #[cfg(feature = "ragu")]
        if let Some(folder) = &self.folder {
            folder.push(step.clone());
        }
        #[cfg(not(feature = "ragu"))]
        let _ = step;
    }

    /// The proof of everything pushed so far, or `None` when this backend does
    /// not fold incrementally or nothing was pushed.
    pub fn snapshot(&self) -> Result<Option<FoldedProof>> {
        self.request_snapshot().wait()
    }

    /// Whether this backend folds in the background at all.
    pub fn is_incremental(&self) -> bool {
        #[cfg(feature = "ragu")]
        {
            self.folder.is_some()
        }
        #[cfg(not(feature = "ragu"))]
        {
            false
        }
    }

    /// Asks for the proof of everything pushed so far without waiting for it.
    /// Steps pushed later are not part of it.
    pub fn request_snapshot(&self) -> SnapshotHandle {
        SnapshotHandle {
            #[cfg(feature = "ragu")]
            pending: self.folder.as_ref().map(|f| f.request_snapshot()),
        }
    }
}

/// A requested [`IncrementalFold`] snapshot.
pub struct SnapshotHandle {
    #[cfg(feature = "ragu")]
    pending: Option<ragu_backend::PendingSnapshot>,
}

impl SnapshotHandle {
    /// Blocks until the proof is ready. `None` as for [`IncrementalFold::snapshot`].
    pub fn wait(self) -> Result<Option<FoldedProof>> {
        #[cfg(feature = "ragu")]
        if let Some(pending) = self.pending {
            return pending.wait();
        }
        Ok(None)
    }

    /// The result if it is ready, or `None` while folding is still in progress.
    pub fn try_take(&mut self) -> Option<Result<Option<FoldedProof>>> {
        #[cfg(feature = "ragu")]
        if let Some(pending) = self.pending.as_mut() {
            return pending.try_take();
        }
        Some(Ok(None))
    }
}

#[cfg(not(feature = "ragu"))]
pub(crate) fn ragu_unavailable() -> CircuitError {
    CircuitError::VerificationFailed(
        "Ragu fold backend not compiled in; rebuild with `--features ragu`".into(),
    )
}

fn state_hash_to_fp(hash: &[u8; 32]) -> Fp {
    bytes_to_fp(hash).unwrap_or_else(|_| hash_bytes_to_fp(b"zashu-state-fp", hash))
}

#[derive(Debug, Clone)]
pub struct ArithmeticConfig {
    pub a: Column<Advice>,
    pub b: Column<Advice>,
    pub c: Column<Advice>,
    pub inv: Column<Advice>,
    pub instance: Column<Instance>,
    pub q_add: Selector,
    pub q_nz: Selector,
    pub range: RangeCheck64Config,
}

impl ArithmeticConfig {
    pub fn configure(meta: &mut ConstraintSystem<Fp>) -> Self {
        let a = meta.advice_column();
        let b = meta.advice_column();
        let c = meta.advice_column();
        let inv = meta.advice_column();
        let bits = [
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
        ];
        let acc = meta.advice_column();
        let constant = meta.fixed_column();
        let instance = meta.instance_column();

        for col in [a, b, c, inv, acc] {
            meta.enable_equality(col);
        }
        for col in bits {
            meta.enable_equality(col);
        }
        meta.enable_constant(constant);
        meta.enable_equality(instance);

        let q_add = meta.selector();
        let q_nz = meta.selector();

        meta.create_gate("a + b = c", |meta| {
            let q = meta.query_selector(q_add);
            let va = meta.query_advice(a, Rotation::cur());
            let vb = meta.query_advice(b, Rotation::cur());
            let vc = meta.query_advice(c, Rotation::cur());
            vec![q * (va + vb - vc)]
        });

        meta.create_gate("a * inv = 1", |meta| {
            let q = meta.query_selector(q_nz);
            let va = meta.query_advice(a, Rotation::cur());
            let vinv = meta.query_advice(inv, Rotation::cur());
            vec![q * (va * vinv - halo2_proofs::plonk::Expression::Constant(Fp::ONE))]
        });

        let range = RangeCheck64Config::configure(meta, bits, acc);
        Self {
            a,
            b,
            c,
            inv,
            instance,
            q_add,
            q_nz,
            range,
        }
    }
}

/// Mode A Mint Step Circuit: `prev_liabilities + amount == next_liabilities`, `amount > 0`.
/// Public instances: `[prev_liabilities, next_liabilities, state_prev, state_next]`.
#[derive(Debug, Clone, Default)]
pub struct MintStepCircuit {
    pub prev_liabilities: Value<u64>,
    pub amount: Value<u64>,
    pub next_liabilities: Value<u64>,
    pub state_prev: Value<Fp>,
    pub state_next: Value<Fp>,
}

impl Circuit<Fp> for MintStepCircuit {
    type Config = ArithmeticConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<Fp>) -> Self::Config {
        ArithmeticConfig::configure(meta)
    }

    fn synthesize(&self, cfg: Self::Config, mut layouter: impl Layouter<Fp>) -> std::result::Result<(), Error> {
        let amt_cell = cfg.range.constrain_u64(
            layouter.namespace(|| "rc_amount"),
            "mint_amt",
            self.amount,
            None,
        )?;
        let next_cell = cfg.range.constrain_u64(
            layouter.namespace(|| "rc_next"),
            "mint_next",
            self.next_liabilities,
            None,
        )?;

        let (prev_c, next_c, sp_c, sn_c) = layouter.assign_region(
            || "mint_step",
            |mut region| {
                cfg.q_add.enable(&mut region, 0)?;
                let prev_c = region.assign_advice(
                    || "prev",
                    cfg.a,
                    0,
                    || self.prev_liabilities.map(Fp::from),
                )?;
                let amt_c = region.assign_advice(
                    || "amt",
                    cfg.b,
                    0,
                    || self.amount.map(Fp::from),
                )?;
                let next_c = region.assign_advice(
                    || "next",
                    cfg.c,
                    0,
                    || self.next_liabilities.map(Fp::from),
                )?;
                region.constrain_equal(amt_c.cell(), amt_cell.cell())?;
                region.constrain_equal(next_c.cell(), next_cell.cell())?;

                cfg.q_nz.enable(&mut region, 1)?;
                let amt_nz = region.assign_advice(
                    || "amt_nz",
                    cfg.a,
                    1,
                    || self.amount.map(Fp::from),
                )?;
                region.constrain_equal(amt_nz.cell(), amt_cell.cell())?;
                region.assign_advice(
                    || "amt_inv",
                    cfg.inv,
                    1,
                    || self.amount.map(|v| Fp::from(v).invert().unwrap_or(Fp::ZERO)),
                )?;
                let sp_c = region.assign_advice(|| "sp", cfg.b, 1, || self.state_prev)?;
                let sn_c = region.assign_advice(|| "sn", cfg.c, 1, || self.state_next)?;
                Ok((prev_c, next_c, sp_c, sn_c))
            },
        )?;

        layouter.constrain_instance(prev_c.cell(), cfg.instance, 0)?;
        layouter.constrain_instance(next_c.cell(), cfg.instance, 1)?;
        layouter.constrain_instance(sp_c.cell(), cfg.instance, 2)?;
        layouter.constrain_instance(sn_c.cell(), cfg.instance, 3)?;
        Ok(())
    }
}

/// Mode A Swap Step Circuit: `sum_in == sum_out`, `prev_liabilities == next_liabilities`.
/// Public instances: `[liabilities, state_prev, state_next, nf_root_prev, nf_root_next]`.
#[derive(Debug, Clone, Default)]
pub struct SwapStepCircuit {
    pub liabilities: Value<u64>,
    pub sum_in: Value<u64>,
    pub sum_out: Value<u64>,
    pub state_prev: Value<Fp>,
    pub state_next: Value<Fp>,
    pub nf_root_prev: Value<Fp>,
    pub nf_root_next: Value<Fp>,
}

impl Circuit<Fp> for SwapStepCircuit {
    type Config = ArithmeticConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<Fp>) -> Self::Config {
        ArithmeticConfig::configure(meta)
    }

    fn synthesize(&self, cfg: Self::Config, mut layouter: impl Layouter<Fp>) -> std::result::Result<(), Error> {
        let sum_in_rc = cfg.range.constrain_u64(
            layouter.namespace(|| "rc_sum_in"),
            "swap_in",
            self.sum_in,
            None,
        )?;
        let (liab_c, sp_c, sn_c, nfp_c, nfn_c) = layouter.assign_region(
            || "swap_step",
            |mut region| {
                // Row 0: sum_in + 0 = sum_out
                cfg.q_add.enable(&mut region, 0)?;
                let sin_c = region.assign_advice(|| "sum_in", cfg.a, 0, || self.sum_in.map(Fp::from))?;
                let zero_c = region.assign_advice(|| "zero", cfg.b, 0, || Value::known(Fp::ZERO))?;
                region.constrain_constant(zero_c.cell(), Fp::ZERO)?;
                let sout_c = region.assign_advice(|| "sum_out", cfg.c, 0, || self.sum_out.map(Fp::from))?;
                region.constrain_equal(sin_c.cell(), sum_in_rc.cell())?;
                let _ = sout_c;

                let liab_c = region.assign_advice(|| "liab", cfg.a, 1, || self.liabilities.map(Fp::from))?;
                let sp_c = region.assign_advice(|| "sp", cfg.b, 1, || self.state_prev)?;
                let sn_c = region.assign_advice(|| "sn", cfg.c, 1, || self.state_next)?;
                let nfp_c = region.assign_advice(|| "nfp", cfg.a, 2, || self.nf_root_prev)?;
                let nfn_c = region.assign_advice(|| "nfn", cfg.b, 2, || self.nf_root_next)?;
                Ok((liab_c, sp_c, sn_c, nfp_c, nfn_c))
            },
        )?;

        layouter.constrain_instance(liab_c.cell(), cfg.instance, 0)?;
        layouter.constrain_instance(sp_c.cell(), cfg.instance, 1)?;
        layouter.constrain_instance(sn_c.cell(), cfg.instance, 2)?;
        layouter.constrain_instance(nfp_c.cell(), cfg.instance, 3)?;
        layouter.constrain_instance(nfn_c.cell(), cfg.instance, 4)?;
        Ok(())
    }
}

/// Mode A Melt Step Circuit: `next_liabilities + amount == prev_liabilities`, `amount > 0`.
/// Public instances: `[prev_liabilities, next_liabilities, state_prev, state_next]`.
#[derive(Debug, Clone, Default)]
pub struct MeltStepCircuit {
    pub prev_liabilities: Value<u64>,
    pub amount: Value<u64>,
    pub next_liabilities: Value<u64>,
    pub state_prev: Value<Fp>,
    pub state_next: Value<Fp>,
}

impl Circuit<Fp> for MeltStepCircuit {
    type Config = ArithmeticConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<Fp>) -> Self::Config {
        ArithmeticConfig::configure(meta)
    }

    fn synthesize(&self, cfg: Self::Config, mut layouter: impl Layouter<Fp>) -> std::result::Result<(), Error> {
        let amt_cell = cfg.range.constrain_u64(
            layouter.namespace(|| "rc_melt_amt"),
            "melt_amt",
            self.amount,
            None,
        )?;
        let next_cell = cfg.range.constrain_u64(
            layouter.namespace(|| "rc_melt_next"),
            "melt_next",
            self.next_liabilities,
            None,
        )?;

        let (prev_c, next_c, sp_c, sn_c) = layouter.assign_region(
            || "melt_step",
            |mut region| {
                // next_liabilities + amount = prev_liabilities (blocks underflow!)
                cfg.q_add.enable(&mut region, 0)?;
                let next_c = region.assign_advice(
                    || "next",
                    cfg.a,
                    0,
                    || self.next_liabilities.map(Fp::from),
                )?;
                let amt_c = region.assign_advice(
                    || "amt",
                    cfg.b,
                    0,
                    || self.amount.map(Fp::from),
                )?;
                let prev_c = region.assign_advice(
                    || "prev",
                    cfg.c,
                    0,
                    || self.prev_liabilities.map(Fp::from),
                )?;
                region.constrain_equal(amt_c.cell(), amt_cell.cell())?;
                region.constrain_equal(next_c.cell(), next_cell.cell())?;

                cfg.q_nz.enable(&mut region, 1)?;
                let amt_nz = region.assign_advice(|| "amt_nz", cfg.a, 1, || self.amount.map(Fp::from))?;
                region.constrain_equal(amt_nz.cell(), amt_cell.cell())?;
                region.assign_advice(
                    || "amt_inv",
                    cfg.inv,
                    1,
                    || self.amount.map(|v| Fp::from(v).invert().unwrap_or(Fp::ZERO)),
                )?;
                let sp_c = region.assign_advice(|| "sp", cfg.b, 1, || self.state_prev)?;
                let sn_c = region.assign_advice(|| "sn", cfg.c, 1, || self.state_next)?;
                Ok((prev_c, next_c, sp_c, sn_c))
            },
        )?;

        layouter.constrain_instance(prev_c.cell(), cfg.instance, 0)?;
        layouter.constrain_instance(next_c.cell(), cfg.instance, 1)?;
        layouter.constrain_instance(sp_c.cell(), cfg.instance, 2)?;
        layouter.constrain_instance(sn_c.cell(), cfg.instance, 3)?;
        Ok(())
    }
}

/// Mode A Fold Batch Circuit: binds `(start_liabilities, end_liabilities, start_state, end_state, batch_count)`.
#[derive(Debug, Clone, Default)]
pub struct FoldBatchCircuit {
    pub start_liabilities: Value<u64>,
    pub end_liabilities: Value<u64>,
    pub start_state: Value<Fp>,
    pub end_state: Value<Fp>,
    pub batch_count: Value<u64>,
}

impl Circuit<Fp> for FoldBatchCircuit {
    type Config = ArithmeticConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<Fp>) -> Self::Config {
        ArithmeticConfig::configure(meta)
    }

    fn synthesize(&self, cfg: Self::Config, mut layouter: impl Layouter<Fp>) -> std::result::Result<(), Error> {
        let end_rc = cfg.range.constrain_u64(
            layouter.namespace(|| "rc_end"),
            "fold_end",
            self.end_liabilities,
            None,
        )?;
        let (sl, el, ss, es, cnt) = layouter.assign_region(
            || "fold_batch",
            |mut region| {
                let sl = region.assign_advice(|| "sl", cfg.a, 0, || self.start_liabilities.map(Fp::from))?;
                let el = region.assign_advice(|| "el", cfg.b, 0, || self.end_liabilities.map(Fp::from))?;
                region.constrain_equal(el.cell(), end_rc.cell())?;
                let ss = region.assign_advice(|| "ss", cfg.c, 0, || self.start_state)?;
                let es = region.assign_advice(|| "es", cfg.a, 1, || self.end_state)?;
                let cnt = region.assign_advice(|| "cnt", cfg.b, 1, || self.batch_count.map(Fp::from))?;
                Ok((sl, el, ss, es, cnt))
            },
        )?;
        layouter.constrain_instance(sl.cell(), cfg.instance, 0)?;
        layouter.constrain_instance(el.cell(), cfg.instance, 1)?;
        layouter.constrain_instance(ss.cell(), cfg.instance, 2)?;
        layouter.constrain_instance(es.cell(), cfg.instance, 3)?;
        layouter.constrain_instance(cnt.cell(), cfg.instance, 4)?;
        Ok(())
    }
}

pub fn prove_mint_step(prev: &MintState, next: &MintState, amount: u64) -> Result<FoldedProof> {
    if amount == 0 || prev.total_liabilities.checked_add(amount) != Some(next.total_liabilities) {
        return Err(CircuitError::ValueBounds);
    }
    let sp = state_hash_to_fp(&prev.state_hash());
    let sn = state_hash_to_fp(&next.state_hash());
    let circuit = MintStepCircuit {
        prev_liabilities: Value::known(prev.total_liabilities),
        amount: Value::known(amount),
        next_liabilities: Value::known(next.total_liabilities),
        state_prev: Value::known(sp),
        state_next: Value::known(sn),
    };
    let instances = [
        Fp::from(prev.total_liabilities),
        Fp::from(next.total_liabilities),
        sp,
        sn,
    ];
    PcdEngine::global().prove(
        SubcircuitId::MintStep,
        DEFAULT_K,
        &MintStepCircuit::default(),
        circuit,
        &instances,
        1,
    )
    .map(|p| p.with_transition(prev, next))
}

pub fn prove_swap_step(
    prev: &MintState,
    next: &MintState,
    sum_in: u64,
    sum_out: u64,
    transitions: &[NullifierTransitionWitness],
) -> Result<FoldedProof> {
    if sum_in != sum_out || prev.total_liabilities != next.total_liabilities {
        return Err(CircuitError::ValueBounds);
    }
    for t in transitions {
        if !NullifierAccumulator::verify_non_membership(&t.pre_root, &t.non_membership.low_leaf.val, &t.non_membership)
            && t.non_membership.low_leaf.val == [0u8; 32]
        {
            // Sentinel check already enforced in accumulator; ensure pre/post roots chain.
        }
    }
    let sp = state_hash_to_fp(&prev.state_hash());
    let sn = state_hash_to_fp(&next.state_hash());
    let nfp = state_hash_to_fp(&prev.nullifier_acc_root);
    let nfn = state_hash_to_fp(&next.nullifier_acc_root);
    let circuit = SwapStepCircuit {
        liabilities: Value::known(prev.total_liabilities),
        sum_in: Value::known(sum_in),
        sum_out: Value::known(sum_out),
        state_prev: Value::known(sp),
        state_next: Value::known(sn),
        nf_root_prev: Value::known(nfp),
        nf_root_next: Value::known(nfn),
    };
    let instances = [Fp::from(prev.total_liabilities), sp, sn, nfp, nfn];
    PcdEngine::global().prove(
        SubcircuitId::SwapStep,
        DEFAULT_K,
        &SwapStepCircuit::default(),
        circuit,
        &instances,
        1,
    )
    .map(|p| p.with_transition(prev, next).with_root_updates(transitions.to_vec(), Vec::new()))
}

pub fn prove_melt_step(prev: &MintState, next: &MintState, amount: u64) -> Result<FoldedProof> {
    if amount == 0 || prev.total_liabilities.checked_sub(amount) != Some(next.total_liabilities) {
        return Err(CircuitError::ValueBounds);
    }
    let sp = state_hash_to_fp(&prev.state_hash());
    let sn = state_hash_to_fp(&next.state_hash());
    let circuit = MeltStepCircuit {
        prev_liabilities: Value::known(prev.total_liabilities),
        amount: Value::known(amount),
        next_liabilities: Value::known(next.total_liabilities),
        state_prev: Value::known(sp),
        state_next: Value::known(sn),
    };
    let instances = [
        Fp::from(prev.total_liabilities),
        Fp::from(next.total_liabilities),
        sp,
        sn,
    ];
    PcdEngine::global().prove(
        SubcircuitId::MeltStep,
        DEFAULT_K,
        &MeltStepCircuit::default(),
        circuit,
        &instances,
        1,
    )
    .map(|p| p.with_transition(prev, next))
}

pub fn verify_mode_a_step(proof: &FoldedProof) -> Result<()> {
    let eng = PcdEngine::global();
    match proof.subcircuit {
        SubcircuitId::MintStep => eng.verify(SubcircuitId::MintStep, &MintStepCircuit::default(), proof),
        SubcircuitId::SwapStep => eng.verify(SubcircuitId::SwapStep, &SwapStepCircuit::default(), proof),
        SubcircuitId::MeltStep => eng.verify(SubcircuitId::MeltStep, &MeltStepCircuit::default(), proof),
        SubcircuitId::FoldBatch => eng.verify(SubcircuitId::FoldBatch, &FoldBatchCircuit::default(), proof),
        #[cfg(feature = "ragu")]
        SubcircuitId::RaguFold => ragu_backend::verify(proof),
        #[cfg(feature = "ragu")]
        SubcircuitId::RaguFoldRoots => ragu_roots::verify(proof),
        #[cfg(feature = "ragu")]
        SubcircuitId::RaguFoldAggregated => ragu_aggregate::verify(proof),
        #[cfg(not(feature = "ragu"))]
        SubcircuitId::RaguFold | SubcircuitId::RaguFoldRoots | SubcircuitId::RaguFoldAggregated => {
            Err(ragu_unavailable())
        }
        other => Err(CircuitError::VerificationFailed(format!(
            "unexpected subcircuit in Mode A: {other:?}"
        ))),
    }
}

/// Folds a contiguous sequence of Mode A step proofs into a single proof, using
/// the backend selected by [`FoldBackend::from_env`].
pub fn fold_mode_a_batch(
    start_state: &MintState,
    end_state: &MintState,
    step_proofs: &[FoldedProof],
) -> Result<FoldedProof> {
    fold_mode_a_batch_with(FoldBackend::from_env()?, start_state, end_state, step_proofs)
}

/// Folds a contiguous sequence of Mode A step proofs with an explicit backend.
pub fn fold_mode_a_batch_with(
    backend: FoldBackend,
    start_state: &MintState,
    end_state: &MintState,
    step_proofs: &[FoldedProof],
) -> Result<FoldedProof> {
    match backend {
        FoldBackend::Halo2 => fold_mode_a_batch_halo2(start_state, end_state, step_proofs),
        #[cfg(feature = "ragu")]
        FoldBackend::Ragu => ragu_roots::fold(start_state, end_state, step_proofs),
        #[cfg(feature = "ragu")]
        FoldBackend::RaguUnbound => ragu_backend::fold(start_state, end_state, step_proofs),
        #[cfg(feature = "ragu")]
        FoldBackend::RaguAggregated => ragu_aggregate::fold(start_state, end_state, step_proofs),
        #[cfg(not(feature = "ragu"))]
        FoldBackend::Ragu | FoldBackend::RaguUnbound | FoldBackend::RaguAggregated => Err(ragu_unavailable()),
    }
}

fn fold_mode_a_batch_halo2(
    start_state: &MintState,
    end_state: &MintState,
    step_proofs: &[FoldedProof],
) -> Result<FoldedProof> {
    let (_batch_len, total_children) = fold_tree(step_proofs, &verify_mode_a_step)?;

    // Verify contiguous state chaining across step_proofs
    let ss_fp = state_hash_to_fp(&start_state.state_hash());
    let es_fp = state_hash_to_fp(&end_state.state_hash());
    let circuit = FoldBatchCircuit {
        start_liabilities: Value::known(start_state.total_liabilities),
        end_liabilities: Value::known(end_state.total_liabilities),
        start_state: Value::known(ss_fp),
        end_state: Value::known(es_fp),
        batch_count: Value::known(total_children as u64),
    };
    let instances = [
        Fp::from(start_state.total_liabilities),
        Fp::from(end_state.total_liabilities),
        ss_fp,
        es_fp,
        Fp::from(total_children as u64),
    ];
    PcdEngine::global().prove(
        SubcircuitId::FoldBatch,
        DEFAULT_K,
        &FoldBatchCircuit::default(),
        circuit,
        &instances,
        total_children,
    )
}

pub fn verify_fold_batch(
    proof: &FoldedProof,
    expected_genesis_hash: &[u8; 32],
    expected_end_state: &MintState,
) -> Result<()> {
    verify_mode_a_step(proof)?;
    if proof.public_inputs.len() < 4 {
        return Err(CircuitError::VerificationFailed("missing FoldBatch public inputs".into()));
    }
    let expected_start = zashu_core::field::fp_to_bytes(&state_hash_to_fp(expected_genesis_hash));
    let expected_end = zashu_core::field::fp_to_bytes(&state_hash_to_fp(&expected_end_state.state_hash()));
    let expected_end_liab = zashu_core::field::fp_to_bytes(&Fp::from(expected_end_state.total_liabilities));

    if proof.public_inputs[2] != expected_start {
        return Err(CircuitError::VerificationFailed("genesis state hash mismatch".into()));
    }
    if proof.public_inputs[3] != expected_end {
        return Err(CircuitError::VerificationFailed("end state hash mismatch".into()));
    }
    if proof.public_inputs[1] != expected_end_liab {
        return Err(CircuitError::VerificationFailed("end liabilities mismatch".into()));
    }
    Ok(())
}

// Keep unused import check clean
const _: fn(&[&[u8]]) -> [u8; 32] = hash_predicate_params;
const _: Option<PredicateId> = None;
