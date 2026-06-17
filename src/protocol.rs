use ark_ff::{AdditiveGroup, UniformRand};
use ark_secp256k1::Fr;
use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};

use crate::field::{field_to_bytes, hash_to_field};
use crate::pedersen::{self, CoefficientCommitments};
use crate::shamir::{self, Share};

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

#[derive(Clone, Debug)]
pub struct MemberKey {
    pub signing_key: SigningKey,
    pub verifying_key: VerifyingKey,
}

/// Per-member share of one coefficient pair (k1, k2) for a single operation slot.
#[derive(Clone, Debug)]
pub struct CoefficientShare {
    pub coeff_id: u64,
    pub k1_share: Share,
    pub k2_share: Share,
    pub k1_blind_share: Share,
    pub k2_blind_share: Share,
}

/// Output of JRSS setup: per-member coefficient shares for a batch of operation slots.
#[derive(Clone, Debug)]
pub struct SetupOutput {
    /// member_shares[i] = shares for member i (0-indexed), one per coefficient slot.
    pub member_shares: Vec<Vec<CoefficientShare>>,
    /// Number of members.
    pub n: u32,
    /// Threshold.
    pub t: u32,
    /// Share-correctness profile activated for this setup.
    pub share_profile: ShareCorrectnessProfile,
}

/// A signed contribution from one custody member for one operation.
#[derive(Clone, Debug)]
pub struct Contribution {
    pub member_index: u32,
    pub eval_share: Fr,
    pub opening: ShareOpening,
    pub envelope: Vec<u8>,
    pub signature: ed25519_dalek::Signature,
}

/// The result of a successful authorization.
#[derive(Clone, Debug)]
pub struct AuthorizationReceipt {
    pub sigma: Fr,
    pub coeff_id: u64,
    pub message_hash: [u8; 32],
    pub member_bitmap: Vec<u32>,
}

/// Policy binding a custody account.
#[derive(Clone, Debug)]
pub struct CustodyPolicy {
    pub address: [u8; 20],
    pub policy_id: u64,
    pub threshold: u32,
    pub member_keys: Vec<VerifyingKey>,
    pub share_profile: ShareCorrectnessProfile,
    /// Tracks which coefficient IDs have been consumed.
    pub consumed_coeffids: Vec<u64>,
}

#[derive(Clone, Copy, Debug)]
pub enum ShareCorrectnessProfileKind {
    HashCommitted,
    Pedersen,
    ExternalAvssTranscript,
}

#[derive(Clone, Debug)]
pub enum ShareCorrectnessProfile {
    /// Post-quantum-clean operation-time openings. Setup commits each member's
    /// slot shares with a collision-resistant hash bound under `setuproot`; at
    /// operation time the member reveals the shares inside the gate-1-signed
    /// envelope and the verifier recomputes the commitment. Hash-only, so it is
    /// the recommended profile for a PQ deployment. Reveals single-use slot
    /// material (presignature model), which is consumed under finality.
    HashCommitted {
        commitments: Vec<HashShareCommitments>,
        setuproot: [u8; 32],
    },
    /// Classical discrete-log Pedersen openings. Demonstrates public VSS-style
    /// operation-time checks, but relies on discrete-log binding and is therefore
    /// not PQ-clean. Kept as a classical demonstrator.
    Pedersen {
        commitments: Vec<CoefficientCommitments>,
    },
    /// Adapter for an existing VSS/AVSS setup transcript that already handled
    /// dealing, complaints, and agreement externally, but does not export cheap
    /// public operation-time openings. Provides only Berlekamp-Welch robust
    /// decoding: an honest-majority *liveness* mechanism, not a share-correctness
    /// (anti-forgery) mechanism. It does NOT defend the keys-without-shares
    /// adversary; use only when member signing keys and coefficient shares share
    /// one compromise domain.
    ExternalAvssTranscript,
}

/// Per-slot hash commitments to each member's coefficient shares.
#[derive(Clone, Debug)]
pub struct HashShareCommitments {
    pub coeff_id: u64,
    /// per_member[i] commits member (i+1)'s shares for this slot.
    pub per_member: Vec<[u8; 32]>,
}

#[derive(Clone, Debug)]
pub enum ShareOpening {
    /// PQ-clean: reveal the member's slot shares; the verifier recomputes the
    /// hash commitment and the affine evaluation.
    HashCommitted { k1_share: Fr, k2_share: Fr },
    Pedersen { eval_blind: Fr },
    None,
}

impl ShareOpening {
    fn envelope_bytes(&self) -> Vec<u8> {
        match self {
            ShareOpening::HashCommitted { k1_share, k2_share } => {
                let mut bytes = Vec::with_capacity(1 + 64);
                bytes.push(2);
                bytes.extend_from_slice(&field_to_bytes(k1_share));
                bytes.extend_from_slice(&field_to_bytes(k2_share));
                bytes
            }
            ShareOpening::Pedersen { eval_blind } => {
                let mut bytes = Vec::with_capacity(1 + 32);
                bytes.push(1);
                bytes.extend_from_slice(&field_to_bytes(eval_blind));
                bytes
            }
            ShareOpening::None => vec![0],
        }
    }
}

/// Collision-resistant commitment to a member's slot shares. The shares are
/// uniform 256-bit field elements, so the commitment is hiding under hash
/// one-wayness and binding under collision resistance; both are PQ-clean.
fn commit_share(coeff_id: u64, member_index: u32, k1_share: Fr, k2_share: Fr) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"custody-share-commit");
    hasher.update(coeff_id.to_be_bytes());
    hasher.update(member_index.to_be_bytes());
    hasher.update(field_to_bytes(&k1_share));
    hasher.update(field_to_bytes(&k2_share));
    hasher.finalize().into()
}

/// Compact binding root over all per-member slot commitments. A production
/// deployment stores only this root on chain and supplies Merkle paths at
/// operation time; the demo additionally retains the commitment list.
fn compute_setuproot(commitments: &[HashShareCommitments]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"custody-setuproot");
    for commitment in commitments {
        hasher.update(commitment.coeff_id.to_be_bytes());
        for c in &commitment.per_member {
            hasher.update(c);
        }
    }
    hasher.finalize().into()
}

#[derive(Clone, Copy, Debug)]
pub struct Operation<'a> {
    pub op_type: &'a str,
    pub nonce: u64,
    pub message: &'a [u8],
}

// ---------------------------------------------------------------------------
// JRSS: dealer-free coefficient setup
// ---------------------------------------------------------------------------

/// Run dealer-free JRSS to generate `batch_size` coefficient pairs shared at
/// threshold `t` among `n` members. Each member contributes randomness; no
/// single party learns the full (k1, k2).
pub fn jrss_setup(t: u32, n: u32, batch_size: usize) -> SetupOutput {
    jrss_setup_with_profile(t, n, batch_size, ShareCorrectnessProfileKind::Pedersen)
}

pub fn jrss_setup_with_profile(
    t: u32,
    n: u32,
    batch_size: usize,
    profile_kind: ShareCorrectnessProfileKind,
) -> SetupOutput {
    let mut rng = OsRng;
    let mut member_shares: Vec<Vec<CoefficientShare>> =
        (0..n).map(|_| Vec::with_capacity(batch_size)).collect();
    let mut commitments = Vec::with_capacity(batch_size);
    let mut hash_commitments = Vec::with_capacity(batch_size);

    for slot in 0..batch_size {
        let coeff_id = slot as u64;

        // Each member j contributes random a_j, b_j and Shamir-shares them.
        // We sum the shares locally: [k1]_i = sum_j [a_j]_i, [k2]_i = sum_j [b_j]_i.
        let mut k1_accum: Vec<Fr> = vec![Fr::ZERO; n as usize];
        let mut k2_accum: Vec<Fr> = vec![Fr::ZERO; n as usize];
        let mut k1_blind_accum: Vec<Fr> = vec![Fr::ZERO; n as usize];
        let mut k2_blind_accum: Vec<Fr> = vec![Fr::ZERO; n as usize];
        let mut k1_dealer_commitments = Vec::with_capacity(n as usize);
        let mut k2_dealer_commitments = Vec::with_capacity(n as usize);

        for _j in 0..n {
            let a_j = Fr::rand(&mut rng);
            let b_j = Fr::rand(&mut rng);
            let a_poly = shamir::random_polynomial(a_j, t, &mut rng);
            let b_poly = shamir::random_polynomial(b_j, t, &mut rng);
            let a_blind_poly = shamir::random_polynomial(Fr::rand(&mut rng), t, &mut rng);
            let b_blind_poly = shamir::random_polynomial(Fr::rand(&mut rng), t, &mut rng);
            let a_shares = shamir::shares_from_coefficients(&a_poly, n);
            let b_shares = shamir::shares_from_coefficients(&b_poly, n);
            let a_blind_shares = shamir::shares_from_coefficients(&a_blind_poly, n);
            let b_blind_shares = shamir::shares_from_coefficients(&b_blind_poly, n);
            let a_commitment = matches!(profile_kind, ShareCorrectnessProfileKind::Pedersen)
                .then(|| pedersen::commit_polynomial(&a_poly, &a_blind_poly));
            let b_commitment = matches!(profile_kind, ShareCorrectnessProfileKind::Pedersen)
                .then(|| pedersen::commit_polynomial(&b_poly, &b_blind_poly));

            for i in 0..n as usize {
                if let (Some(a_commitment), Some(b_commitment)) = (&a_commitment, &b_commitment) {
                    assert!(pedersen::verify_share(
                        a_commitment,
                        &a_shares[i],
                        &a_blind_shares[i]
                    ));
                    assert!(pedersen::verify_share(
                        b_commitment,
                        &b_shares[i],
                        &b_blind_shares[i]
                    ));
                }
                k1_accum[i] += a_shares[i].value;
                k2_accum[i] += b_shares[i].value;
                k1_blind_accum[i] += a_blind_shares[i].value;
                k2_blind_accum[i] += b_blind_shares[i].value;
            }

            if let (Some(a_commitment), Some(b_commitment)) = (a_commitment, b_commitment) {
                k1_dealer_commitments.push(a_commitment);
                k2_dealer_commitments.push(b_commitment);
            }
        }

        if matches!(profile_kind, ShareCorrectnessProfileKind::Pedersen) {
            commitments.push(CoefficientCommitments {
                coeff_id,
                k1: pedersen::aggregate_commitments(&k1_dealer_commitments),
                k2: pedersen::aggregate_commitments(&k2_dealer_commitments),
            });
        }

        if matches!(profile_kind, ShareCorrectnessProfileKind::HashCommitted) {
            let per_member = (0..n as usize)
                .map(|i| commit_share(coeff_id, (i + 1) as u32, k1_accum[i], k2_accum[i]))
                .collect();
            hash_commitments.push(HashShareCommitments {
                coeff_id,
                per_member,
            });
        }

        for i in 0..n as usize {
            member_shares[i].push(CoefficientShare {
                coeff_id,
                k1_share: Share {
                    index: (i + 1) as u32,
                    value: k1_accum[i],
                },
                k2_share: Share {
                    index: (i + 1) as u32,
                    value: k2_accum[i],
                },
                k1_blind_share: Share {
                    index: (i + 1) as u32,
                    value: k1_blind_accum[i],
                },
                k2_blind_share: Share {
                    index: (i + 1) as u32,
                    value: k2_blind_accum[i],
                },
            });
        }
    }

    SetupOutput {
        member_shares,
        n,
        t,
        share_profile: match profile_kind {
            ShareCorrectnessProfileKind::HashCommitted => {
                let setuproot = compute_setuproot(&hash_commitments);
                ShareCorrectnessProfile::HashCommitted {
                    commitments: hash_commitments,
                    setuproot,
                }
            }
            ShareCorrectnessProfileKind::Pedersen => {
                ShareCorrectnessProfile::Pedersen { commitments }
            }
            ShareCorrectnessProfileKind::ExternalAvssTranscript => {
                ShareCorrectnessProfile::ExternalAvssTranscript
            }
        },
    }
}

// ---------------------------------------------------------------------------
// Per-operation: member approval (Gate 1 + Gate 2 share production)
// ---------------------------------------------------------------------------

/// Derive the canonical message binding.
fn bind_message(address: &[u8; 20], policy_id: u64, op_type: &str, nonce: u64, msg: &[u8]) -> Fr {
    let msg_hash = Sha256::digest(msg);
    let mut data = Vec::new();
    data.extend_from_slice(address);
    data.extend_from_slice(&policy_id.to_be_bytes());
    data.extend_from_slice(op_type.as_bytes());
    data.extend_from_slice(&nonce.to_be_bytes());
    data.extend_from_slice(&msg_hash);
    hash_to_field(b"custody-op", &data)
}

/// Derive the common affine scalar x.
fn derive_x(m_parallel_n: Fr, coeff_id: u64) -> Fr {
    let mut data = Vec::new();
    data.extend_from_slice(&field_to_bytes(&m_parallel_n));
    data.extend_from_slice(&coeff_id.to_be_bytes());
    hash_to_field(b"custody-affine-x", &data)
}

/// Build the contribution envelope bytes for signing.
fn build_envelope(
    address: &[u8; 20],
    policy_id: u64,
    coeff_id: u64,
    member_index: u32,
    m_parallel_n: Fr,
    eval_share: Fr,
    opening: &ShareOpening,
) -> Vec<u8> {
    let mut envelope = Vec::new();
    envelope.extend_from_slice(b"custody-share");
    envelope.extend_from_slice(address);
    envelope.extend_from_slice(&policy_id.to_be_bytes());
    envelope.extend_from_slice(&coeff_id.to_be_bytes());
    envelope.extend_from_slice(&member_index.to_be_bytes());
    envelope.extend_from_slice(&field_to_bytes(&m_parallel_n));
    envelope.extend_from_slice(&field_to_bytes(&eval_share));
    envelope.extend_from_slice(&opening.envelope_bytes());
    envelope
}

/// A custody member approves an operation: evaluates its affine share and signs
/// the contribution envelope (Gate 1 + Gate 2 share production).
pub fn approve(
    member_key: &MemberKey,
    coeff_share: &CoefficientShare,
    policy: &CustodyPolicy,
    member_index: u32,
    op_type: &str,
    nonce: u64,
    message: &[u8],
) -> Contribution {
    let m_par_n = bind_message(&policy.address, policy.policy_id, op_type, nonce, message);
    let x = derive_x(m_par_n, coeff_share.coeff_id);
    let eval_share = coeff_share.k1_share.value * x + coeff_share.k2_share.value;
    let opening = match &policy.share_profile {
        ShareCorrectnessProfile::HashCommitted { .. } => ShareOpening::HashCommitted {
            k1_share: coeff_share.k1_share.value,
            k2_share: coeff_share.k2_share.value,
        },
        ShareCorrectnessProfile::Pedersen { .. } => ShareOpening::Pedersen {
            eval_blind: coeff_share.k1_blind_share.value * x + coeff_share.k2_blind_share.value,
        },
        ShareCorrectnessProfile::ExternalAvssTranscript => ShareOpening::None,
    };
    let operation = Operation {
        op_type,
        nonce,
        message,
    };

    sign_evaluation_share(
        member_key,
        policy,
        member_index,
        coeff_share.coeff_id,
        operation,
        eval_share,
        opening,
    )
}

/// Sign a caller-provided evaluation share. Honest members call `approve`;
/// tests use this lower-level helper to model a stolen signing key that signs
/// malformed field elements without knowing the matching coefficient share.
pub fn sign_evaluation_share(
    member_key: &MemberKey,
    policy: &CustodyPolicy,
    member_index: u32,
    coeff_id: u64,
    operation: Operation<'_>,
    eval_share: Fr,
    opening: ShareOpening,
) -> Contribution {
    let m_par_n = bind_message(
        &policy.address,
        policy.policy_id,
        operation.op_type,
        operation.nonce,
        operation.message,
    );
    let envelope = build_envelope(
        &policy.address,
        policy.policy_id,
        coeff_id,
        member_index,
        m_par_n,
        eval_share,
        &opening,
    );

    let signature = member_key.signing_key.sign(&envelope);

    Contribution {
        member_index,
        eval_share,
        opening,
        envelope,
        signature,
    }
}

// ---------------------------------------------------------------------------
// Authorization: verify contributions and reconstruct (enforcement layer)
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub enum AuthError {
    BelowThreshold {
        have: usize,
        need: u32,
    },
    InvalidSignature {
        member_index: u32,
    },
    EnvelopeMismatch {
        member_index: u32,
    },
    CoeffIdConsumed(u64),
    DuplicateMember(u32),
    UnknownMember(u32),
    UnknownCommitment(u64),
    InvalidShareOpening {
        member_index: u32,
    },
    MalformedShares {
        submitted: usize,
        threshold: u32,
        max_correctable: usize,
    },
}

fn verify_share_opening(
    profile: &ShareCorrectnessProfile,
    coeff_id: u64,
    x: Fr,
    contribution: &Contribution,
) -> Result<(), AuthError> {
    match profile {
        ShareCorrectnessProfile::HashCommitted { commitments, .. } => {
            let Some(commitment) = commitments
                .iter()
                .find(|commitment| commitment.coeff_id == coeff_id)
            else {
                return Err(AuthError::UnknownCommitment(coeff_id));
            };

            let ShareOpening::HashCommitted { k1_share, k2_share } = &contribution.opening else {
                return Err(AuthError::InvalidShareOpening {
                    member_index: contribution.member_index,
                });
            };

            let slot = (contribution.member_index as usize)
                .checked_sub(1)
                .filter(|i| *i < commitment.per_member.len());
            let Some(slot) = slot else {
                return Err(AuthError::UnknownMember(contribution.member_index));
            };

            // Binding: revealed shares must match the setup commitment, and the
            // affine evaluation used for reconstruction must match the revealed
            // shares. A stolen signing key without the shares fails the first
            // check; a tampered evaluation fails the second.
            let recomputed =
                commit_share(coeff_id, contribution.member_index, *k1_share, *k2_share);
            if recomputed == commitment.per_member[slot]
                && contribution.eval_share == *k1_share * x + *k2_share
            {
                Ok(())
            } else {
                Err(AuthError::InvalidShareOpening {
                    member_index: contribution.member_index,
                })
            }
        }
        ShareCorrectnessProfile::Pedersen { commitments } => {
            let Some(commitment) = commitments
                .iter()
                .find(|commitment| commitment.coeff_id == coeff_id)
            else {
                return Err(AuthError::UnknownCommitment(coeff_id));
            };

            let ShareOpening::Pedersen { eval_blind } = &contribution.opening else {
                return Err(AuthError::InvalidShareOpening {
                    member_index: contribution.member_index,
                });
            };

            if pedersen::verify_evaluation_share(
                &commitment.k1,
                &commitment.k2,
                contribution.member_index,
                x,
                contribution.eval_share,
                *eval_blind,
            ) {
                Ok(())
            } else {
                Err(AuthError::InvalidShareOpening {
                    member_index: contribution.member_index,
                })
            }
        }
        ShareCorrectnessProfile::ExternalAvssTranscript => {
            if matches!(contribution.opening, ShareOpening::None) {
                Ok(())
            } else {
                Err(AuthError::InvalidShareOpening {
                    member_index: contribution.member_index,
                })
            }
        }
    }
}

/// Verify all contributions and reconstruct the authorization value.
/// This is the enforcement layer's validation logic.
pub fn authorize(
    policy: &mut CustodyPolicy,
    contributions: &[Contribution],
    coeff_id: u64,
    op_type: &str,
    nonce: u64,
    message: &[u8],
) -> Result<AuthorizationReceipt, AuthError> {
    // G3: coefficient ID not consumed
    if policy.consumed_coeffids.contains(&coeff_id) {
        return Err(AuthError::CoeffIdConsumed(coeff_id));
    }

    // Check for duplicate members
    let mut seen = Vec::new();
    for c in contributions {
        if seen.contains(&c.member_index) {
            return Err(AuthError::DuplicateMember(c.member_index));
        }
        seen.push(c.member_index);
    }

    // G1: verify signatures and envelope binding
    let m_par_n = bind_message(&policy.address, policy.policy_id, op_type, nonce, message);
    let x = derive_x(m_par_n, coeff_id);

    for c in contributions {
        let idx = (c.member_index - 1) as usize;
        if idx >= policy.member_keys.len() {
            return Err(AuthError::UnknownMember(c.member_index));
        }

        let expected_envelope = build_envelope(
            &policy.address,
            policy.policy_id,
            coeff_id,
            c.member_index,
            m_par_n,
            c.eval_share,
            &c.opening,
        );
        if c.envelope != expected_envelope {
            return Err(AuthError::EnvelopeMismatch {
                member_index: c.member_index,
            });
        }

        policy.member_keys[idx]
            .verify(&c.envelope, &c.signature)
            .map_err(|_| AuthError::InvalidSignature {
                member_index: c.member_index,
            })?;

        verify_share_opening(&policy.share_profile, coeff_id, x, c)?;
    }

    // G1: quorum check
    if contributions.len() < policy.threshold as usize {
        return Err(AuthError::BelowThreshold {
            have: contributions.len(),
            need: policy.threshold,
        });
    }

    // G2: robustly decode the degree-(threshold-1) evaluation polynomial.
    let shares: Vec<Share> = contributions
        .iter()
        .map(|c| Share {
            index: c.member_index,
            value: c.eval_share,
        })
        .collect();
    let Some(decoded) = shamir::reconstruct_robust(&shares, policy.threshold) else {
        return Err(AuthError::MalformedShares {
            submitted: contributions.len(),
            threshold: policy.threshold,
            max_correctable: (contributions.len() - policy.threshold as usize) / 2,
        });
    };

    // Consume the coefficient ID
    policy.consumed_coeffids.push(coeff_id);

    let message_hash = {
        let h = Sha256::digest(message);
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&h);
        arr
    };

    Ok(AuthorizationReceipt {
        sigma: decoded.secret,
        coeff_id,
        message_hash,
        member_bitmap: decoded.accepted_indices,
    })
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

pub fn generate_member_key() -> MemberKey {
    let signing_key = SigningKey::generate(&mut OsRng);
    let verifying_key = signing_key.verifying_key();
    MemberKey {
        signing_key,
        verifying_key,
    }
}
