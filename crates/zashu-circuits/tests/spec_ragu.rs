//! `NUTZ-0` conformance of the Ragu backend.
//! Run with: `cargo test --release -p zashu-circuits --test spec_ragu`
#![cfg(feature = "ragu")]
use zashu_circuits::spec::conformance;
use zashu_circuits::spec::ragu::Ragu;

#[test]
fn transactions_are_accepted() {
    conformance::tx_accepts::<Ragu>();
}

#[test]
fn forged_transactions_are_rejected() {
    conformance::tx_rejects::<Ragu>();
}

#[test]
fn operations_are_accepted() {
    conformance::op_accepts::<Ragu>();
}

#[test]
fn forged_operations_are_rejected() {
    conformance::op_rejects::<Ragu>();
}

#[test]
fn chains_are_accepted_and_rejected() {
    conformance::chain_accepts_and_rejects::<Ragu>();
}
