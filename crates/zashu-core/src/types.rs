use serde::{Deserialize, Serialize};

use crate::field::hex32;
use crate::pedersen::ValueCommitment;
use crate::poseidon::{hash_mint_state, hash_note, hash_nullifier};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum PredicateId {
    StandardSpend = 0x00,
    P2PK = 0x01,
    Multisig = 0x02,
    Timelock = 0x03,
    PrivateHTLC = 0x04,
}

impl TryFrom<u8> for PredicateId {
    type Error = &'static str;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x00 => Ok(Self::StandardSpend),
            0x01 => Ok(Self::P2PK),
            0x02 => Ok(Self::Multisig),
            0x03 => Ok(Self::Timelock),
            0x04 => Ok(Self::PrivateHTLC),
            _ => Err("unknown predicate_id"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Note {
    pub value: u64,
    #[serde(with = "hex32")]
    pub owner_pk: [u8; 32],
    pub predicate_id: u8,
    #[serde(with = "hex32")]
    pub predicate_params_hash: [u8; 32],
    #[serde(with = "hex32")]
    pub rho: [u8; 32],
    #[serde(with = "hex32")]
    pub r: [u8; 32],
}

impl Note {
    pub fn commitment(&self) -> NoteCommitment {
        NoteCommitment(hash_note(
            self.value,
            &self.owner_pk,
            self.predicate_id,
            &self.predicate_params_hash,
            &self.rho,
            &self.r,
        ))
    }

    /// The note's single nullifier; see [`hash_nullifier`].
    pub fn nullifier(&self) -> Nullifier {
        Nullifier(hash_nullifier(&self.r, &self.rho))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct NoteCommitment(#[serde(with = "hex32")] pub [u8; 32]);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Nullifier(#[serde(with = "hex32")] pub [u8; 32]);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MintState {
    pub epoch: u64,
    pub total_liabilities: u64,
    #[serde(with = "hex32")]
    pub nullifier_acc_root: [u8; 32],
    #[serde(with = "hex32")]
    pub note_acc_root: [u8; 32],
    #[serde(with = "hex32")]
    pub event_log_hash: [u8; 32],
}

impl MintState {
    pub fn genesis(nullifier_acc_root: [u8; 32], note_acc_root: [u8; 32]) -> Self {
        Self {
            epoch: 0,
            total_liabilities: 0,
            nullifier_acc_root,
            note_acc_root,
            event_log_hash: [0u8; 32],
        }
    }

    pub fn state_hash(&self) -> [u8; 32] {
        hash_mint_state(
            self.epoch,
            self.total_liabilities,
            &self.nullifier_acc_root,
            &self.note_acc_root,
            &self.event_log_hash,
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReserveUtxo {
    pub txid: String,
    pub vout: u32,
    pub value_sats: u64,
    pub script_pubkey: String,
    pub signature: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReservesAttestation {
    #[serde(with = "hex32")]
    pub challenge: [u8; 32],
    pub utxos: Vec<ReserveUtxo>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SolvencyBundle {
    pub version: String,
    #[serde(with = "hex32")]
    pub mint_id: [u8; 32],
    #[serde(with = "hex32")]
    pub genesis_state_hash: [u8; 32],
    pub state: MintState,
    pub pcd_proof: String,
    pub reserves: ReservesAttestation,
    pub mint_signature: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NoteOutputRecord {
    pub cm: NoteCommitment,
    pub cv: ValueCommitment,
    pub leaf_index: u64,
}
