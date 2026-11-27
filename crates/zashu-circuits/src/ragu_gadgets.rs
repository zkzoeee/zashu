//! Gadgets shared by the Ragu backends (`ragu` feature).
//!
//! The Poseidon here is bit-compatible with `zashu_core::poseidon`: the same
//! `P128Pow5T3` permutation over the Pallas base field with halo2's
//! `ConstantLength` domain separation, so hashes computed in a Ragu circuit
//! equal the ones the rest of zashu computes natively.

use ragu::drivers::emulator::Emulator;
use ragu::drivers::{Driver, DriverValue};
use ragu::maybe::Maybe;
use ragu::pasta::Fp;
use ragu::primitives::poseidon::{Sponge, SpongeState};
use ragu::primitives::vec::{ConstLen, FixedVec};
use ragu::primitives::Element;
use ragu::udon::field::Field;
use ragu::udon::poseidon::PoseidonFpT3;

use crate::error::{CircuitError, Result};

static POSEIDON_T3: PoseidonFpT3 = PoseidonFpT3;

/// Digest domain tags. A transaction's digest is a left-leaning hash chain
/// over tagged leaves, nullifiers first and then output commitments:
/// `leaf = Poseidon2(TAG_SPEND, nf)` or `Poseidon2(TAG_OUTPUT, cm)`,
/// `node = Poseidon3(TAG_NODE, left, right)`. The Mode A fold accumulates the
/// same digest over the nullifiers and notes an operation inserts.
pub const TAG_SPEND: u64 = 0x21;
pub const TAG_OUTPUT: u64 = 0x22;
pub const TAG_NODE: u64 = 0x23;

/// In-circuit `halo2_poseidon::Hash<_, P128Pow5T3, ConstantLength<L>, 3, 2>`
/// for `L = inputs.len()`.
///
/// halo2's sponge starts from `[0, 0, L << 64]`, absorbs two elements per
/// permutation, zero-pads the last block and outputs the first state element.
/// Ragu's sponge always starts from zero, so it is resumed from that state.
pub fn poseidon_hash<'dr, D: Driver<'dr, F = Fp>>(
    dr: &mut D,
    inputs: &[Element<'dr, D>],
) -> ragu::Result<Element<'dr, D>> {
    let two_32 = Fp::from(1u64 << 32);
    let capacity = Fp::from(inputs.len() as u64) * two_32 * two_32;
    let state = SpongeState::from_elements(FixedVec::new(vec![
        Element::zero(dr),
        Element::zero(dr),
        Element::constant(dr, capacity),
    ])?);
    let mut sponge = Sponge::resume(state, &POSEIDON_T3);
    for input in inputs {
        sponge.absorb(dr, input)?;
    }
    sponge.squeeze(dr)
}

/// [`poseidon_hash`] evaluated outside a circuit.
pub fn poseidon_hash_native(inputs: &[Fp]) -> Result<Fp> {
    let dr = &mut Emulator::execute();
    let elements: Vec<_> = inputs.iter().map(|v| Element::constant(dr, *v)).collect();
    let out = poseidon_hash(dr, &elements).map_err(|e| CircuitError::Plonk(format!("ragu poseidon: {e}")))?;
    Ok(*out.value().take())
}

/// zashu field bytes (canonical little-endian Pallas base field) -> Ragu `Fp`.
pub fn fp_from_bytes(bytes: &[u8; 32]) -> Result<Fp> {
    Fp::from_bytes(*bytes).ok_or_else(|| CircuitError::InvalidWitness("non-canonical field element".into()))
}

/// `pasta_curves` field element -> Ragu `Fp` (same field, different crates).
pub fn fp_from_pasta(f: &zashu_core::field::Fp) -> Fp {
    Fp::from_bytes(zashu_core::field::fp_to_bytes(f)).expect("canonical encoding of the same field")
}

/// Collects the values of a fixed-size gadget vector into header data.
pub fn values_of<'dr, D: Driver<'dr, F = Fp>, const N: usize>(
    out: &FixedVec<Element<'dr, D>, ConstLen<N>>,
) -> DriverValue<D, [Fp; N]> {
    let mut acc: DriverValue<D, Vec<Fp>> = D::just(|| Vec::with_capacity(N));
    for i in 0..N {
        let v = out[i].value().map(|v| *v);
        acc = acc.and_then(|mut xs| {
            v.map(|v| {
                xs.push(v);
                xs
            })
        });
    }
    acc.map(|xs| core::array::from_fn(|i| xs[i]))
}

#[cfg(test)]
mod tests {
    use zashu_core::field::fp_from_u64;
    use zashu_core::poseidon::{poseidon_2, poseidon_3, poseidon_4, poseidon_7};

    use super::*;

    #[test]
    fn ragu_poseidon_matches_zashu_core() {
        let xs: Vec<zashu_core::field::Fp> = (1..=7u64).map(|i| fp_from_u64(i * 0x9e37_79b9 + 11)).collect();
        let r = |n: usize| xs[..n].iter().map(fp_from_pasta).collect::<Vec<_>>();
        assert_eq!(poseidon_hash_native(&r(2)).unwrap(), fp_from_pasta(&poseidon_2(xs[0], xs[1])));
        assert_eq!(poseidon_hash_native(&r(3)).unwrap(), fp_from_pasta(&poseidon_3(xs[0], xs[1], xs[2])));
        assert_eq!(
            poseidon_hash_native(&r(4)).unwrap(),
            fp_from_pasta(&poseidon_4(xs[0], xs[1], xs[2], xs[3]))
        );
        let seven: [zashu_core::field::Fp; 7] = core::array::from_fn(|i| xs[i]);
        assert_eq!(poseidon_hash_native(&r(7)).unwrap(), fp_from_pasta(&poseidon_7(seven)));
    }
}
