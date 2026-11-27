//! Circuit helpers shared by the Ragu steps.

#[cfg(test)]
use ragu::drivers::emulator::Emulator;
use ragu::drivers::{Driver, DriverValue};
use ragu::header::Header;
use ragu::maybe::Maybe;
use ragu::pasta::{Fp, Pasta};
use ragu::primitives::allocator::Allocator;
use ragu::primitives::poseidon::{Sponge, SpongeState};
use ragu::primitives::vec::{ConstLen, FixedVec};
use ragu::primitives::{Boolean, Element};
use ragu::step::{Encoded, Step};
use ragu::udon::poseidon::PoseidonFpT3;

pub(super) use crate::ragu_gadgets::{fp_from_pasta as fp, values_of};

static POSEIDON_T3: PoseidonFpT3 = PoseidonFpT3;

pub(super) type V<'dr, D, const N: usize> = FixedVec<Element<'dr, D>, ConstLen<N>>;

pub(super) type StepOut<'dr, D, S, const HS: usize> = ragu::Result<(
    (
        Encoded<'dr, D, <S as Step<Pasta>>::Left, HS>,
        Encoded<'dr, D, <S as Step<Pasta>>::Right, HS>,
        Encoded<'dr, D, <S as Step<Pasta>>::Output, HS>,
    ),
    DriverValue<D, <<S as Step<Pasta>>::Output as Header<Fp>>::Data>,
    DriverValue<D, ()>,
)>;

macro_rules! header {
    ($(#[$doc:meta])* $name:ident, $suffix:expr, $n:expr) => {
        $(#[$doc])*
        pub(crate) struct $name;

        impl ragu::header::Header<ragu::pasta::Fp> for $name {
            const SUFFIX: ragu::header::Suffix = ragu::header::Suffix::new($suffix);
            type OnlinePolyCommit = (ragu::header::Padding, ragu::header::Padding);
            type Data = [ragu::pasta::Fp; $n];
            type Output = ragu::gadgets::Kind![ragu::pasta::Fp; ragu::primitives::vec::FixedVec<ragu::primitives::Element<'_, _>, ragu::primitives::vec::ConstLen<$n>>];

            fn encode<'dr, D: ragu::drivers::Driver<'dr, F = ragu::pasta::Fp>, A: ragu::primitives::allocator::Allocator<'dr, D>>(
                dr: &mut D,
                allocator: &mut A,
                witness: ragu::drivers::DriverValue<D, Self::Data>,
            ) -> ragu::Result<ragu::gadgets::Bound<'dr, D, Self::Output>> {
                use ragu::maybe::Maybe;
                ragu::primitives::vec::FixedVec::try_from_fn(|i| {
                    ragu::primitives::Element::alloc(dr, allocator, witness.as_ref().map(|w| w[i]))
                })
            }
        }
    };
}
pub(super) use header;

pub(super) fn constant<'dr, D: Driver<'dr, F = Fp>>(dr: &mut D, v: u64) -> Element<'dr, D> {
    Element::constant(dr, Fp::from(v))
}

pub(super) fn enforce_equal<'dr, D: Driver<'dr, F = Fp>>(
    dr: &mut D,
    a: &Element<'dr, D>,
    b: &Element<'dr, D>,
) -> ragu::Result<()> {
    a.sub(dr, b).enforce_zero(dr)
}

pub(super) fn enforce_true<'dr, D: Driver<'dr, F = Fp>>(dr: &mut D, b: &Boolean<'dr, D>) -> ragu::Result<()> {
    b.element().sub(dr, &Element::one()).enforce_zero(dr)
}

pub(super) fn or<'dr, D: Driver<'dr, F = Fp>>(
    dr: &mut D,
    a: &Boolean<'dr, D>,
    b: &Boolean<'dr, D>,
) -> ragu::Result<Boolean<'dr, D>> {
    let (na, nb) = (a.not(dr), b.not(dr));
    Ok(na.and(dr, &nb)?.not(dr))
}

/// A field element known to fit 64 bits.
pub(super) fn alloc_u64<'dr, D: Driver<'dr, F = Fp>>(
    dr: &mut D,
    allocator: &mut impl Allocator<'dr, D>,
    v: DriverValue<D, u64>,
) -> ragu::Result<Element<'dr, D>> {
    let e = Element::alloc(dr, allocator, v.map(Fp::from))?;
    enforce_u64(dr, allocator, &e)?;
    Ok(e)
}

pub(super) fn enforce_u64<'dr, D: Driver<'dr, F = Fp>>(
    dr: &mut D,
    allocator: &mut impl Allocator<'dr, D>,
    e: &Element<'dr, D>,
) -> ragu::Result<()> {
    e.enforce_le::<64>(dr, allocator, Fp::from(u64::MAX))
}

/// The capacity element of `H_tag`: `2^128 + tag`.
pub(super) fn capacity(tag: u64) -> Fp {
    let two_32 = Fp::from(1u64 << 32);
    two_32 * two_32 * two_32 * two_32 + Fp::from(tag)
}

/// `H_tag(inputs)` of `NUTZ-0`: the Poseidon sponge from `[0, 0, 2^128 + tag]`.
pub(super) fn sponge<'dr, D: Driver<'dr, F = Fp>>(
    dr: &mut D,
    tag: u64,
    inputs: &[Element<'dr, D>],
) -> ragu::Result<Element<'dr, D>> {
    let state = SpongeState::from_elements(FixedVec::new(vec![
        Element::zero(dr),
        Element::zero(dr),
        Element::constant(dr, capacity(tag)),
    ])?);
    let mut sponge = Sponge::resume(state, &POSEIDON_T3);
    for input in inputs {
        sponge.absorb(dr, input)?;
    }
    sponge.squeeze(dr)
}

/// [`sponge`] evaluated outside a circuit.
#[cfg(test)]
pub(super) fn sponge_native(tag: u64, inputs: &[Fp]) -> ragu::Result<Fp> {
    let dr = &mut Emulator::execute();
    let elements: Vec<_> = inputs.iter().map(|v| Element::constant(dr, *v)).collect();
    Ok(*sponge(dr, tag, &elements)?.value().take())
}

/// A tree node: `H_NODE(left, right)`, one permutation.
pub(super) fn node<'dr, D: Driver<'dr, F = Fp>>(
    dr: &mut D,
    left: &Element<'dr, D>,
    right: &Element<'dr, D>,
) -> ragu::Result<Element<'dr, D>> {
    sponge(dr, zashu_core::spec::hash::T_NODE, &[left.clone(), right.clone()])
}

#[cfg(test)]
mod tests {
    use zashu_core::spec::hash::{h, T_MULTISIG, T_NODE, T_NOTE, T_PK, T_STATE};
    use zashu_core::spec::vectors::random_fe;

    use super::*;

    #[test]
    fn ragu_sponge_matches_the_reference() {
        let xs: Vec<_> = (1..=6u64).map(random_fe).collect();
        for (tag, n) in [(T_PK, 1), (T_NODE, 2), (T_STATE, 5), (T_NOTE, 6), (T_MULTISIG, 6), (T_NODE, 3)] {
            let ragu_inputs: Vec<Fp> = xs[..n].iter().map(fp).collect();
            assert_eq!(sponge_native(tag, &ragu_inputs).unwrap(), fp(&h(tag, &xs[..n])), "tag {tag}, {n} inputs");
        }
    }
}
