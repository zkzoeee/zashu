//! The one Ragu application wallets and the mint prove in (`ragu` feature).
//!
//! It registers the Mode A root-binding fold steps and the Mode B transaction
//! steps together. Sharing a registry is what lets an aggregator application
//! (see `mode_a::ragu_aggregate`) decompress both an operation's fold proof
//! and its transaction proof and compare them.

use std::sync::OnceLock;

use ragu::circuits::polynomials::R;
use ragu::pasta::Pasta;
use ragu::{Application, ApplicationBuilder};

use crate::error::{CircuitError, Result};
use crate::mode_a::{ragu_backend::FoldStep, ragu_roots as a};
use crate::mode_b::ragu_backend as b;

pub(crate) type Rank = R<14>;
pub const RAGU_RANK: u32 = 14;
/// Largest header payload (7, the fold's `Transition`) plus Ragu's suffix slot.
pub(crate) const HEADER_SIZE: usize = 8;
pub(crate) type WalletApp = Application<'static, Pasta, Rank, HEADER_SIZE>;

/// Builds a fresh instance of the application. Every instance is the same
/// application: proofs made under one verify under another.
pub(crate) fn build() -> ragu::Result<WalletApp> {
    let pasta = ragu::pcd::pasta::baked();
    ApplicationBuilder::<Pasta, Rank, HEADER_SIZE>::new()
        // Mode A fold: indices 0..=9 (and 25, below)
        .register(a::ValueMint)?
        .register(a::ValueSwap)?
        .register(a::ValueMelt)?
        .register(FoldStep)?
        .register(a::UpdStart)?
        .register(a::UpdExtend)?
        .register(a::NoteInsert)?
        .register(a::PairStart)?
        .register(a::NfLow)?
        .register(a::NfInsert)?
        // Mode B transactions: indices 10..=24
        .register(b::PathStart)?
        .register(b::PathExtend)?
        .register(b::KeyStep)?
        .register(b::SpendStandard)?
        .register(b::SpendP2pk)?
        .register(b::SpendTimelock)?
        .register(b::SpendHtlcClaim)?
        .register(b::SpendHtlcRefund)?
        .register(b::OutputStep)?
        .register(b::MergeStep)?
        .register(b::FinalizeStep)?
        .register(b::KeysStart::<false>)?
        .register(b::KeysStart::<true>)?
        .register(b::KeysExtend)?
        .register(b::SpendMultisig)?
        // Mode A fold, continued: index 25
        .register(a::PairJoin)?
        .finalize(pasta)
}

pub(crate) fn wallet() -> Result<&'static WalletApp> {
    static APP: OnceLock<std::result::Result<WalletApp, String>> = OnceLock::new();
    APP.get_or_init(|| build().map_err(|e| e.to_string()))
        .as_ref()
        .map_err(|e| CircuitError::Plonk(format!("ragu application build: {e}")))
}
