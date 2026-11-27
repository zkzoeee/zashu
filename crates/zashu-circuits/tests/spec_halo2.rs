//! `NUTZ-0` conformance of the Halo2 backend.
//! Run with: `cargo test --release -p zashu-circuits --test spec_halo2`

use zashu_circuits::spec::conformance;
use zashu_circuits::spec::halo2::Halo2;

#[test]
fn transactions_are_accepted() {
    conformance::tx_accepts::<Halo2>();
}

#[test]
fn forged_transactions_are_rejected() {
    conformance::tx_rejects::<Halo2>();
}

#[test]
fn operations_are_accepted() {
    conformance::op_accepts::<Halo2>();
}

#[test]
fn forged_operations_are_rejected() {
    conformance::op_rejects::<Halo2>();
}

#[test]
fn chains_are_accepted_and_rejected() {
    conformance::chain_accepts_and_rejects::<Halo2>();
}
