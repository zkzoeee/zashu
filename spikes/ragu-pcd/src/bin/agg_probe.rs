//! Probe: what does Ragu's aggregator profile cost? A wallet application's
//! compressed proof is decompressed inside an aggregator application and
//! used as a child of the aggregator's own step.

use std::time::Instant;

use ragu::circuits::polynomials::{AggregatorRank, WalletRank};
use ragu::drivers::{Driver, DriverValue};
use ragu::gadgets::{Bound, Kind};
use ragu::header::{Header, Padding, Suffix};
use ragu::maybe::Maybe;
use ragu::pasta::{Fp, Pasta};
use ragu::pcd::profile::{Aggregator, Decompression, Profiled};
use ragu::primitives::allocator::{Allocator, Standard};
use ragu::primitives::Element;
use ragu::step::{Encoded, Index, Oracles, Step};
use ragu::{ApplicationBuilder, Cycle, Result};
use rand::rngs::StdRng;
use rand::SeedableRng;

const H: usize = 7;
type Agg = Profiled<Pasta, Aggregator<H>>;

struct Num;
impl Header<Fp> for Num {
    const SUFFIX: Suffix = Suffix::new(0);
    type OnlinePolyCommit = (Padding, Padding);
    type Data = Fp;
    type Output = Kind![Fp; Element<'_, _>];
    fn encode<'dr, D: Driver<'dr, F = Fp>, A: Allocator<'dr, D>>(
        dr: &mut D,
        allocator: &mut A,
        witness: DriverValue<D, Fp>,
    ) -> Result<Bound<'dr, D, Self::Output>> {
        Element::alloc(dr, allocator, witness)
    }
}

type Out<'dr, D, S, C, const HS: usize> = Result<(
    (
        Encoded<'dr, D, <S as Step<C>>::Left, HS>,
        Encoded<'dr, D, <S as Step<C>>::Right, HS>,
        Encoded<'dr, D, <S as Step<C>>::Output, HS>,
    ),
    DriverValue<D, Fp>,
    DriverValue<D, ()>,
)>;

struct Leaf;
impl<C: Cycle<CircuitField = Fp>> Step<C> for Leaf {
    const INDEX: Index = Index::new(0);
    type Witness<'source> = Fp;
    type Aux<'source> = ();
    type Left = ();
    type Right = ();
    type Output = Num;
    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>, const HS: usize>(
        &self,
        dr: &mut D,
        _: &mut Oracles<'_, 'dr, D, C, Self>,
        w: DriverValue<D, Fp>,
        _: DriverValue<D, ()>,
        _: DriverValue<D, ()>,
    ) -> Out<'dr, D, Self, C, HS>
    where
        Self: 'dr,
    {
        let x = Element::alloc(dr, &mut Standard::new(), w)?;
        let v = x.value().map(|v| *v);
        Ok(((Encoded::from_gadget(()), Encoded::from_gadget(()), Encoded::from_gadget(x)), v, D::unit()))
    }
}

struct Join;
impl<C: Cycle<CircuitField = Fp>> Step<C> for Join {
    const INDEX: Index = Index::new(1);
    type Witness<'source> = ();
    type Aux<'source> = ();
    type Left = Num;
    type Right = Num;
    type Output = Num;
    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>, const HS: usize>(
        &self,
        dr: &mut D,
        _: &mut Oracles<'_, 'dr, D, C, Self>,
        _: DriverValue<D, ()>,
        l: DriverValue<D, Fp>,
        r: DriverValue<D, Fp>,
    ) -> Out<'dr, D, Self, C, HS>
    where
        Self: 'dr,
    {
        let a = &mut Standard::new();
        let l = Encoded::new(dr, a, l)?;
        let r = Encoded::new(dr, a, r)?;
        let (lg, rg): (&Element<'dr, D>, &Element<'dr, D>) = (l.as_gadget(), r.as_gadget());
        let sum = lg.add(dr, rg);
        let v = sum.value().map(|v| *v);
        Ok(((l, r, Encoded::from_gadget(sum)), v, D::unit()))
    }
}

fn secs(t: Instant) -> f64 {
    t.elapsed().as_secs_f64()
}

fn main() -> Result<()> {
    let pasta = ragu::pcd::pasta::baked();
    let mut rng = StdRng::seed_from_u64(1);

    let t = Instant::now();
    let wallet = ApplicationBuilder::<Pasta, WalletRank, H>::new().register(Leaf)?.register(Join)?.finalize(pasta)?;
    println!("wallet app build            {:>7.2} s", secs(t));

    let t = Instant::now();
    let decompression = Decompression::new(wallet, &mut rng)?;
    let agg = ApplicationBuilder::<Agg, AggregatorRank, H>::new()
        .register(Leaf)?
        .register(Join)?
        .finalize_with(pasta, decompression)?;
    println!("aggregator app build        {:>7.2} s", secs(t));

    let wallet = agg.context().wallet();
    let t = Instant::now();
    let (leaf, ()) = wallet.seed(&mut rng, Leaf, Fp::from(7u64))?;
    println!("wallet seed                 {:>7.2} s", secs(t));
    let t = Instant::now();
    let compressed = wallet.compress(&leaf, &mut rng)?;
    println!("wallet compress             {:>7.2} s", secs(t));

    let t = Instant::now();
    let node = agg.decompress(&mut rng, &compressed)?;
    println!("aggregator decompress       {:>7.2} s", secs(t));

    let t = Instant::now();
    let (own, ()) = agg.seed(&mut rng, Leaf, Fp::from(5u64))?;
    println!("aggregator seed             {:>7.2} s", secs(t));
    let t = Instant::now();
    let (parent, ()) = agg.fuse(&mut rng, Join, (), node, own)?;
    println!("aggregator fuse             {:>7.2} s", secs(t));
    assert_eq!(*parent.data(), Fp::from(12u64));

    let t = Instant::now();
    let c = agg.compress(&parent, &mut rng)?;
    println!("aggregator compress         {:>7.2} s", secs(t));
    let t = Instant::now();
    assert!(agg.verify_compressed(&c)?);
    println!("aggregator verify           {:>7.3} s", secs(t));
    let bytes = c.proof().to_bytes().expect("encodes");
    println!("aggregator compressed proof {:>7} bytes", bytes.len());
    println!("uncompressed proof          {:>7} bytes", parent.proof().to_bytes().expect("encodes").len());
    Ok(())
}
