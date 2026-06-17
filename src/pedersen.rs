use ark_ec::{AffineRepr, PrimeGroup};
use ark_ff::{AdditiveGroup, PrimeField};
use ark_secp256k1::{Affine, Fq, Fr, Projective};
use sha2::{Digest, Sha256};

use crate::shamir::Share;

/// Classical Pedersen VSS commitments for the demo.
///
/// This gives setup-bound operation-time openings, but relies on discrete-log
/// binding over secp256k1 and is therefore not the PQ-clean profile a production
/// deployment would want.
#[derive(Clone, Debug)]
pub struct PedersenPolyCommitment {
    pub coeffs: Vec<Projective>,
}

#[derive(Clone, Debug)]
pub struct CoefficientCommitments {
    pub coeff_id: u64,
    pub k1: PedersenPolyCommitment,
    pub k2: PedersenPolyCommitment,
}

pub fn commit_polynomial(values: &[Fr], blinds: &[Fr]) -> PedersenPolyCommitment {
    assert_eq!(values.len(), blinds.len(), "commitment length mismatch");
    let coeffs = values
        .iter()
        .zip(blinds)
        .map(|(value, blind)| commit_value(*value, *blind))
        .collect();
    PedersenPolyCommitment { coeffs }
}

pub fn aggregate_commitments(commitments: &[PedersenPolyCommitment]) -> PedersenPolyCommitment {
    assert!(!commitments.is_empty(), "need at least one commitment");
    let len = commitments[0].coeffs.len();
    assert!(
        commitments
            .iter()
            .all(|commitment| commitment.coeffs.len() == len),
        "commitment degree mismatch"
    );

    let mut coeffs = vec![Projective::ZERO; len];
    for commitment in commitments {
        for (acc, point) in coeffs.iter_mut().zip(&commitment.coeffs) {
            *acc += point;
        }
    }
    PedersenPolyCommitment { coeffs }
}

pub fn verify_share(
    commitment: &PedersenPolyCommitment,
    value_share: &Share,
    blind_share: &Share,
) -> bool {
    value_share.index == blind_share.index
        && commit_value(value_share.value, blind_share.value)
            == evaluate_commitment(commitment, value_share.index)
}

pub fn verify_evaluation_share(
    k1_commitment: &PedersenPolyCommitment,
    k2_commitment: &PedersenPolyCommitment,
    member_index: u32,
    x: Fr,
    eval_share: Fr,
    eval_blind: Fr,
) -> bool {
    let expected = evaluate_commitment(k1_commitment, member_index).mul_bigint(x.into_bigint())
        + evaluate_commitment(k2_commitment, member_index);
    commit_value(eval_share, eval_blind) == expected
}

fn evaluate_commitment(commitment: &PedersenPolyCommitment, index: u32) -> Projective {
    let x = Fr::from(index as u64);
    let mut power = Fr::from(1u64);
    let mut result = Projective::ZERO;

    for coeff in &commitment.coeffs {
        result += coeff.mul_bigint(power.into_bigint());
        power *= x;
    }

    result
}

fn commit_value(value: Fr, blind: Fr) -> Projective {
    Projective::generator().mul_bigint(value.into_bigint())
        + h_generator().mul_bigint(blind.into_bigint())
}

fn h_generator() -> Projective {
    for counter in 0u32.. {
        let mut hasher = Sha256::new();
        hasher.update(b"dual-gate-demo-pedersen-h");
        hasher.update(counter.to_be_bytes());
        let x = Fq::from_be_bytes_mod_order(&hasher.finalize());

        if let Some(point) = Affine::get_point_from_x_unchecked(x, false) {
            return point.into_group();
        }
    }

    unreachable!("try-and-increment hash-to-curve should find a point")
}
