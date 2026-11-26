use group::{Curve, Group, GroupEncoding};
use pasta_curves::arithmetic::CurveExt;
use pasta_curves::pallas;
use serde::{Deserialize, Serialize};

use crate::error::{Result, ZashuError};
use crate::field::{fq_from_u64, hex32, Fq, PallasPoint};

/// Generator for note value `v`: nothing-up-my-sleeve hash-to-curve.
pub fn generator_g_val() -> PallasPoint {
    pallas::Point::hash_to_curve("zashu-pedersen-v1")(b"G_val")
}

/// Generator for blinding factor `r_v`: nothing-up-my-sleeve hash-to-curve.
pub fn generator_h_blind() -> PallasPoint {
    pallas::Point::hash_to_curve("zashu-pedersen-v1")(b"H_blind")
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValueCommitment {
    #[serde(with = "hex32")]
    pub bytes: [u8; 32],
}

impl ValueCommitment {
    pub fn commit(value: u64, blind: Fq) -> Self {
        let point = generator_g_val() * fq_from_u64(value) + generator_h_blind() * blind;
        Self::from_point(point)
    }

    pub fn zero() -> Self {
        Self::from_point(PallasPoint::identity())
    }

    pub fn from_point(point: PallasPoint) -> Self {
        let affine = point.to_affine();
        Self {
            bytes: affine.to_bytes(),
        }
    }

    pub fn to_point(&self) -> Result<PallasPoint> {
        let affine: Option<pallas::Affine> = Option::from(pallas::Affine::from_bytes(&self.bytes));
        affine
            .map(PallasPoint::from)
            .ok_or(ZashuError::InvalidPointEncoding)
    }

    pub fn add(&self, other: &Self) -> Result<Self> {
        let p1 = self.to_point()?;
        let p2 = other.to_point()?;
        Ok(Self::from_point(p1 + p2))
    }

    pub fn sub(&self, other: &Self) -> Result<Self> {
        let p1 = self.to_point()?;
        let p2 = other.to_point()?;
        Ok(Self::from_point(p1 - p2))
    }

    pub fn sum(commitments: &[Self]) -> Result<Self> {
        let mut acc = PallasPoint::identity();
        for c in commitments {
            acc += c.to_point()?;
        }
        Ok(Self::from_point(acc))
    }

    pub fn verify_balance(inputs: &[Self], outputs: &[Self]) -> Result<bool> {
        let lhs = Self::sum(inputs)?;
        let rhs = Self::sum(outputs)?;
        Ok(lhs == rhs)
    }
}
