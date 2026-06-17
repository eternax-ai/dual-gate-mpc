use ark_ff::{AdditiveGroup, Field, UniformRand};
use ark_secp256k1::Fr;
use rand::Rng;

#[derive(Clone, Debug)]
pub struct Share {
    /// 1-indexed member identifier (evaluation point).
    pub index: u32,
    pub value: Fr,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RobustReconstruction {
    pub secret: Fr,
    pub accepted_indices: Vec<u32>,
    pub corrected_errors: usize,
}

/// Split `secret` into `n` shares with threshold `t` (need `t` shares to reconstruct).
/// Uses a random degree-(t-1) polynomial with `secret` as the constant term.
pub fn split<R: Rng>(secret: Fr, t: u32, n: u32, rng: &mut R) -> Vec<Share> {
    let coeffs = random_polynomial(secret, t, rng);
    shares_from_coefficients(&coeffs, n)
}

pub fn random_polynomial<R: Rng>(secret: Fr, t: u32, rng: &mut R) -> Vec<Fr> {
    assert!(t >= 1, "need t >= 1");
    let mut coeffs = Vec::with_capacity(t as usize);
    coeffs.push(secret);
    for _ in 1..t {
        coeffs.push(Fr::rand(rng));
    }
    coeffs
}

pub fn shares_from_coefficients(coeffs: &[Fr], n: u32) -> Vec<Share> {
    assert!(!coeffs.is_empty(), "need at least one coefficient");
    (1..=n)
        .map(|i| {
            let x = Fr::from(i as u64);
            let value = eval_poly(coeffs, x);
            Share { index: i, value }
        })
        .collect()
}

/// Reconstruct the secret (polynomial evaluated at 0) from `shares`.
/// Requires at least `t` shares for a degree-(t-1) polynomial.
pub fn reconstruct(shares: &[Share]) -> Fr {
    let t = shares.len();
    let mut secret = Fr::ZERO;
    for (i, share_i) in shares.iter().enumerate().take(t) {
        let xi = Fr::from(share_i.index as u64);
        let mut basis = Fr::from(1u64);
        for (j, share_j) in shares.iter().enumerate().take(t) {
            if i == j {
                continue;
            }
            let xj = Fr::from(share_j.index as u64);
            // basis *= xj / (xj - xi)
            basis *= xj * (xj - xi).inverse().unwrap();
        }
        secret += share_i.value * basis;
    }
    secret
}

/// Reconstruct a degree-(threshold-1) Shamir secret while rejecting malformed
/// shares. With m submitted shares this corrects up to floor((m-threshold)/2)
/// bad shares using Berlekamp-Welch decoding for the Reed-Solomon code.
pub fn reconstruct_robust(shares: &[Share], threshold: u32) -> Option<RobustReconstruction> {
    let threshold = threshold as usize;
    if threshold == 0 || shares.len() < threshold {
        return None;
    }

    let max_errors = (shares.len() - threshold) / 2;
    for error_count in (0..=max_errors).rev() {
        let Some(poly) = berlekamp_welch(shares, threshold, error_count) else {
            continue;
        };

        let accepted_indices: Vec<u32> = shares
            .iter()
            .filter(|share| eval_poly(&poly, Fr::from(share.index as u64)) == share.value)
            .map(|share| share.index)
            .collect();
        let corrected_errors = shares.len() - accepted_indices.len();

        if accepted_indices.len() >= threshold && corrected_errors <= error_count {
            return Some(RobustReconstruction {
                secret: poly[0],
                accepted_indices,
                corrected_errors,
            });
        }
    }

    None
}

fn berlekamp_welch(shares: &[Share], threshold: usize, error_count: usize) -> Option<Vec<Fr>> {
    let q_len = threshold + error_count;
    let unknowns = q_len + error_count;
    let mut rows = Vec::with_capacity(shares.len());

    for share in shares {
        let x = Fr::from(share.index as u64);
        let y = share.value;
        let powers = powers(x, q_len.max(error_count + 1));
        let mut row = vec![Fr::ZERO; unknowns + 1];

        row[..q_len].copy_from_slice(&powers[..q_len]);
        for k in 0..error_count {
            row[q_len + k] = -y * powers[k];
        }
        row[unknowns] = y * powers[error_count];
        rows.push(row);
    }

    let solution = solve_linear_system(rows, unknowns)?;
    let q = solution[..q_len].to_vec();
    let mut error_locator = solution[q_len..].to_vec();
    error_locator.push(Fr::from(1u64));
    divide_exact(&q, &error_locator, threshold)
}

fn powers(x: Fr, count: usize) -> Vec<Fr> {
    let mut powers = Vec::with_capacity(count);
    let mut power = Fr::from(1u64);
    for _ in 0..count {
        powers.push(power);
        power *= x;
    }
    powers
}

fn solve_linear_system(mut rows: Vec<Vec<Fr>>, unknowns: usize) -> Option<Vec<Fr>> {
    let mut pivot_row = 0;
    let mut pivot_cols = Vec::with_capacity(unknowns);

    for col in 0..unknowns {
        let pivot = (pivot_row..rows.len()).find(|&r| rows[r][col] != Fr::ZERO);
        let Some(pivot) = pivot else {
            continue;
        };

        rows.swap(pivot_row, pivot);
        let inv = rows[pivot_row][col].inverse()?;
        for c in col..=unknowns {
            rows[pivot_row][c] *= inv;
        }

        let normalized_pivot = rows[pivot_row].clone();
        for (r, row) in rows.iter_mut().enumerate() {
            if r == pivot_row {
                continue;
            }
            let factor = row[col];
            if factor == Fr::ZERO {
                continue;
            }
            for (c, pivot_value) in normalized_pivot
                .iter()
                .enumerate()
                .take(unknowns + 1)
                .skip(col)
            {
                row[c] -= factor * *pivot_value;
            }
        }

        pivot_cols.push(col);
        pivot_row += 1;
        if pivot_row == unknowns {
            break;
        }
    }

    for row in &rows {
        let all_zero = row[..unknowns].iter().all(|value| *value == Fr::ZERO);
        if all_zero && row[unknowns] != Fr::ZERO {
            return None;
        }
    }

    if pivot_row != unknowns {
        return None;
    }

    let mut solution = vec![Fr::ZERO; unknowns];
    for (row_idx, pivot_col) in pivot_cols.into_iter().enumerate() {
        solution[pivot_col] = rows[row_idx][unknowns];
    }
    Some(solution)
}

fn divide_exact(dividend: &[Fr], divisor: &[Fr], quotient_len: usize) -> Option<Vec<Fr>> {
    let mut remainder = dividend.to_vec();
    let divisor_degree = divisor.len().checked_sub(1)?;
    let leading = *divisor.last()?;
    if leading == Fr::ZERO || remainder.len() < divisor.len() {
        return None;
    }

    let mut quotient = vec![Fr::ZERO; quotient_len];
    for k in (0..quotient_len).rev() {
        let rem_index = divisor_degree + k;
        let coeff = remainder[rem_index] * leading.inverse()?;
        quotient[k] = coeff;
        for j in 0..=divisor_degree {
            remainder[j + k] -= coeff * divisor[j];
        }
    }

    if remainder[..divisor_degree]
        .iter()
        .any(|value| *value != Fr::ZERO)
    {
        return None;
    }

    Some(quotient)
}

pub fn eval_poly(coeffs: &[Fr], x: Fr) -> Fr {
    let mut result = Fr::ZERO;
    let mut power = Fr::from(1u64);
    for c in coeffs {
        result += *c * power;
        power *= x;
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    #[test]
    fn roundtrip_2_of_3() {
        let secret = Fr::from(42u64);
        let shares = split(secret, 2, 3, &mut OsRng);
        assert_eq!(shares.len(), 3);

        // Any 2 shares reconstruct the secret
        assert_eq!(reconstruct(&shares[0..2]), secret);
        assert_eq!(reconstruct(&shares[1..3]), secret);
        assert_eq!(reconstruct(&[shares[0].clone(), shares[2].clone()]), secret);
    }

    #[test]
    fn roundtrip_3_of_5() {
        let secret = Fr::rand(&mut OsRng);
        let shares = split(secret, 3, 5, &mut OsRng);

        assert_eq!(reconstruct(&shares[0..3]), secret);
        assert_eq!(reconstruct(&shares[2..5]), secret);
        assert_eq!(
            reconstruct(&[shares[0].clone(), shares[2].clone(), shares[4].clone()]),
            secret
        );
    }

    #[test]
    fn below_threshold_gives_wrong_value() {
        let secret = Fr::from(99u64);
        let shares = split(secret, 3, 5, &mut OsRng);
        // Only 2 shares for a t=3 scheme — should NOT reconstruct correctly
        let wrong = reconstruct(&shares[0..2]);
        assert_ne!(wrong, secret);
    }

    #[test]
    fn robust_reconstruction_corrects_one_bad_share() {
        let secret = Fr::from(1234u64);
        let mut shares = split(secret, 3, 5, &mut OsRng);
        shares[4].value += Fr::from(99u64);

        let decoded = reconstruct_robust(&shares, 3).unwrap();

        assert_eq!(decoded.secret, secret);
        assert_eq!(decoded.corrected_errors, 1);
        assert_eq!(decoded.accepted_indices, vec![1, 2, 3, 4]);
    }

    #[test]
    fn robust_reconstruction_rejects_too_many_bad_shares() {
        let secret = Fr::from(1234u64);
        let mut shares = split(secret, 3, 5, &mut OsRng);
        shares[3].value += Fr::from(99u64);
        shares[4].value += Fr::from(100u64);

        assert!(reconstruct_robust(&shares, 3).is_none());
    }
}
