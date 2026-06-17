use ark_secp256k1::Fr;
use dual_gate_demo::protocol::*;
use ed25519_dalek::Signer;

fn make_policy(t: u32, keys: &[MemberKey], setup: &SetupOutput) -> CustodyPolicy {
    CustodyPolicy {
        address: [0xAA; 20],
        policy_id: 1,
        threshold: t,
        member_keys: keys.iter().map(|k| k.verifying_key).collect(),
        share_profile: setup.share_profile.clone(),
        consumed_coeffids: Vec::new(),
    }
}

fn operation<'a>(op_type: &'a str, nonce: u64, message: &'a [u8]) -> Operation<'a> {
    Operation {
        op_type,
        nonce,
        message,
    }
}

fn approve_slot(
    keys: &[MemberKey],
    setup: &SetupOutput,
    policy: &CustodyPolicy,
    member: usize,
    coeff_slot: usize,
    op_type: &str,
    nonce: u64,
    message: &[u8],
) -> Contribution {
    approve(
        &keys[member - 1],
        &setup.member_shares[member - 1][coeff_slot],
        policy,
        member as u32,
        op_type,
        nonce,
        message,
    )
}

// ---------------------------------------------------------------------------
// Happy-path tests
// ---------------------------------------------------------------------------

#[test]
fn test_2_of_3_happy_path() {
    let keys: Vec<MemberKey> = (0..3).map(|_| generate_member_key()).collect();
    let setup = jrss_setup(2, 3, 4);
    let mut policy = make_policy(2, &keys, &setup);
    let message = b"withdraw 100 ETH to 0xdead";

    let c1 = approve_slot(&keys, &setup, &policy, 1, 0, "withdraw", 0, message);
    let c2 = approve_slot(&keys, &setup, &policy, 2, 0, "withdraw", 0, message);
    let receipt = authorize(&mut policy, &[c1, c2], 0, "withdraw", 0, message).unwrap();

    assert_eq!(receipt.coeff_id, 0);
    assert_eq!(receipt.member_bitmap, vec![1, 2]);
    assert!(policy.consumed_coeffids.contains(&0));
}

#[test]
fn test_3_of_5_happy_path() {
    let keys: Vec<MemberKey> = (0..5).map(|_| generate_member_key()).collect();
    let setup = jrss_setup(3, 5, 4);
    let mut policy = make_policy(3, &keys, &setup);
    let message = b"mint 1M USDC";

    let c1 = approve_slot(&keys, &setup, &policy, 1, 0, "mint", 0, message);
    let c3 = approve_slot(&keys, &setup, &policy, 3, 0, "mint", 0, message);
    let c5 = approve_slot(&keys, &setup, &policy, 5, 0, "mint", 0, message);
    let receipt = authorize(&mut policy, &[c1, c3, c5], 0, "mint", 0, message).unwrap();

    assert_eq!(receipt.member_bitmap, vec![1, 3, 5]);
}

#[test]
fn test_any_quorum_reconstructs_same_sigma() {
    let keys: Vec<MemberKey> = (0..5).map(|_| generate_member_key()).collect();
    let setup = jrss_setup(3, 5, 4);
    let policy = make_policy(3, &keys, &setup);
    let message = b"rotate keys";

    let contributions: Vec<Contribution> = (1..=5)
        .map(|member| approve_slot(&keys, &setup, &policy, member, 0, "rotate", 0, message))
        .collect();

    let mut policy_a = make_policy(3, &keys, &setup);
    let receipt_a = authorize(
        &mut policy_a,
        &[
            contributions[0].clone(),
            contributions[1].clone(),
            contributions[2].clone(),
        ],
        0,
        "rotate",
        0,
        message,
    )
    .unwrap();

    let mut policy_b = make_policy(3, &keys, &setup);
    let receipt_b = authorize(
        &mut policy_b,
        &[
            contributions[0].clone(),
            contributions[2].clone(),
            contributions[4].clone(),
        ],
        0,
        "rotate",
        0,
        message,
    )
    .unwrap();

    assert_eq!(receipt_a.sigma, receipt_b.sigma);
}

// ---------------------------------------------------------------------------
// Pedersen VSS opening checks
// ---------------------------------------------------------------------------

#[test]
fn test_pedersen_opening_rejects_signed_malformed_eval_share() {
    let keys: Vec<MemberKey> = (0..5).map(|_| generate_member_key()).collect();
    let setup = jrss_setup(3, 5, 4);
    let policy = make_policy(3, &keys, &setup);
    let message = b"rotate keys";

    let mut contributions: Vec<Contribution> = (1..=5)
        .map(|member| approve_slot(&keys, &setup, &policy, member, 0, "rotate", 0, message))
        .collect();

    contributions[4] = sign_evaluation_share(
        &keys[4],
        &policy,
        5,
        0,
        operation("rotate", 0, message),
        contributions[4].eval_share + Fr::from(123u64),
        contributions[4].opening.clone(),
    );

    let mut policy_with_bad_share = make_policy(3, &keys, &setup);
    let result = authorize(
        &mut policy_with_bad_share,
        &contributions,
        0,
        "rotate",
        0,
        message,
    );

    assert!(matches!(
        result,
        Err(AuthError::InvalidShareOpening { member_index: 5 })
    ));
}

#[test]
fn test_pedersen_opening_rejects_signed_malformed_blind() {
    let keys: Vec<MemberKey> = (0..5).map(|_| generate_member_key()).collect();
    let setup = jrss_setup(3, 5, 4);
    let policy = make_policy(3, &keys, &setup);
    let message = b"rotate keys";

    let mut contributions: Vec<Contribution> = (1..=5)
        .map(|member| approve_slot(&keys, &setup, &policy, member, 0, "rotate", 0, message))
        .collect();

    let ShareOpening::Pedersen { eval_blind } = contributions[3].opening.clone() else {
        panic!("expected Pedersen opening");
    };
    contributions[3] = sign_evaluation_share(
        &keys[3],
        &policy,
        4,
        0,
        operation("rotate", 0, message),
        contributions[3].eval_share,
        ShareOpening::Pedersen {
            eval_blind: eval_blind + Fr::from(456u64),
        },
    );

    let mut policy_with_bad_blind = make_policy(3, &keys, &setup);
    let result = authorize(
        &mut policy_with_bad_blind,
        &contributions,
        0,
        "rotate",
        0,
        message,
    );

    assert!(matches!(
        result,
        Err(AuthError::InvalidShareOpening { member_index: 4 })
    ));
}

#[test]
fn test_missing_coefficient_commitment_rejected() {
    let keys: Vec<MemberKey> = (0..3).map(|_| generate_member_key()).collect();
    let setup = jrss_setup(2, 3, 4);
    let mut policy = make_policy(2, &keys, &setup);
    policy.share_profile = ShareCorrectnessProfile::Pedersen {
        commitments: Vec::new(),
    };
    let message = b"withdraw";

    let c1 = approve_slot(&keys, &setup, &policy, 1, 0, "withdraw", 0, message);
    let c2 = approve_slot(&keys, &setup, &policy, 2, 0, "withdraw", 0, message);
    let result = authorize(&mut policy, &[c1, c2], 0, "withdraw", 0, message);

    assert!(matches!(result, Err(AuthError::UnknownCommitment(0))));
}

// ---------------------------------------------------------------------------
// PQ-clean hash-committed openings (recommended profile)
// ---------------------------------------------------------------------------

#[test]
fn test_hash_committed_happy_path() {
    let keys: Vec<MemberKey> = (0..5).map(|_| generate_member_key()).collect();
    let setup = jrss_setup_with_profile(3, 5, 4, ShareCorrectnessProfileKind::HashCommitted);
    let mut policy = make_policy(3, &keys, &setup);
    let message = b"rotate keys";

    let c1 = approve_slot(&keys, &setup, &policy, 1, 0, "rotate", 0, message);
    let c3 = approve_slot(&keys, &setup, &policy, 3, 0, "rotate", 0, message);
    let c5 = approve_slot(&keys, &setup, &policy, 5, 0, "rotate", 0, message);
    let receipt = authorize(&mut policy, &[c1, c3, c5], 0, "rotate", 0, message).unwrap();

    assert_eq!(receipt.member_bitmap, vec![1, 3, 5]);
    assert!(policy.consumed_coeffids.contains(&0));
}

#[test]
fn test_hash_committed_rejects_keys_without_shares() {
    // The property the affine gate exists to provide: an attacker holding t
    // member signing keys but NOT their coefficient shares cannot authorize.
    // Hash openings bind shares to setup, so fabricated shares are rejected.
    let keys: Vec<MemberKey> = (0..3).map(|_| generate_member_key()).collect();
    let setup = jrss_setup_with_profile(2, 3, 4, ShareCorrectnessProfileKind::HashCommitted);
    let mut policy = make_policy(2, &keys, &setup);
    let message = b"withdraw everything";

    let forged: Vec<Contribution> = (1..=2)
        .map(|member| {
            sign_evaluation_share(
                &keys[member - 1],
                &policy,
                member as u32,
                0,
                operation("withdraw", 0, message),
                Fr::from(member as u64 * 7 + 1),
                ShareOpening::HashCommitted {
                    k1_share: Fr::from(member as u64 * 11 + 3),
                    k2_share: Fr::from(member as u64 * 13 + 5),
                },
            )
        })
        .collect();

    let result = authorize(&mut policy, &forged, 0, "withdraw", 0, message);
    assert!(matches!(result, Err(AuthError::InvalidShareOpening { .. })));
}

#[test]
fn test_hash_committed_rejects_tampered_eval() {
    // Correct revealed shares but a tampered affine evaluation: the
    // eval-consistency half of the opening check rejects it.
    let keys: Vec<MemberKey> = (0..5).map(|_| generate_member_key()).collect();
    let setup = jrss_setup_with_profile(3, 5, 4, ShareCorrectnessProfileKind::HashCommitted);
    let policy = make_policy(3, &keys, &setup);
    let message = b"rotate keys";

    let honest: Vec<Contribution> = (1..=3)
        .map(|member| approve_slot(&keys, &setup, &policy, member, 0, "rotate", 0, message))
        .collect();

    let ShareOpening::HashCommitted { k1_share, k2_share } = honest[2].opening.clone() else {
        panic!("expected hash-committed opening");
    };
    let tampered = sign_evaluation_share(
        &keys[2],
        &policy,
        3,
        0,
        operation("rotate", 0, message),
        honest[2].eval_share + Fr::from(1u64),
        ShareOpening::HashCommitted { k1_share, k2_share },
    );

    let mut policy_with_bad = make_policy(3, &keys, &setup);
    let result = authorize(
        &mut policy_with_bad,
        &[honest[0].clone(), honest[1].clone(), tampered],
        0,
        "rotate",
        0,
        message,
    );
    assert!(matches!(
        result,
        Err(AuthError::InvalidShareOpening { member_index: 3 })
    ));
}

// ---------------------------------------------------------------------------
// External AVSS transcript profile: existing setup, no public operation-time openings
// ---------------------------------------------------------------------------

#[test]
fn test_external_avss_transcript_profile_corrects_one_signed_malformed_share() {
    let keys: Vec<MemberKey> = (0..5).map(|_| generate_member_key()).collect();
    let setup =
        jrss_setup_with_profile(3, 5, 4, ShareCorrectnessProfileKind::ExternalAvssTranscript);
    let policy = make_policy(3, &keys, &setup);
    let message = b"rotate keys";

    let honest: Vec<Contribution> = (1..=5)
        .map(|member| approve_slot(&keys, &setup, &policy, member, 0, "rotate", 0, message))
        .collect();

    let mut expected_policy = make_policy(3, &keys, &setup);
    let expected = authorize(&mut expected_policy, &honest, 0, "rotate", 0, message).unwrap();

    let malformed = sign_evaluation_share(
        &keys[4],
        &policy,
        5,
        0,
        operation("rotate", 0, message),
        honest[4].eval_share + Fr::from(123u64),
        ShareOpening::None,
    );

    let mut policy_with_bad_share = make_policy(3, &keys, &setup);
    let receipt = authorize(
        &mut policy_with_bad_share,
        &[
            honest[0].clone(),
            honest[1].clone(),
            honest[2].clone(),
            honest[3].clone(),
            malformed,
        ],
        0,
        "rotate",
        0,
        message,
    )
    .unwrap();

    assert_eq!(receipt.sigma, expected.sigma);
    assert_eq!(receipt.member_bitmap, vec![1, 2, 3, 4]);
}

// ---------------------------------------------------------------------------
// Binding and rejection cases
// ---------------------------------------------------------------------------

#[test]
fn test_different_messages_different_sigma() {
    let keys: Vec<MemberKey> = (0..3).map(|_| generate_member_key()).collect();
    let setup = jrss_setup(2, 3, 4);
    let msg_a = b"withdraw 100";
    let msg_b = b"withdraw 200";

    let policy_a = make_policy(2, &keys, &setup);
    let c1a = approve_slot(&keys, &setup, &policy_a, 1, 0, "withdraw", 0, msg_a);
    let c2a = approve_slot(&keys, &setup, &policy_a, 2, 0, "withdraw", 0, msg_a);

    let policy_b = make_policy(2, &keys, &setup);
    let c1b = approve_slot(&keys, &setup, &policy_b, 1, 1, "withdraw", 1, msg_b);
    let c2b = approve_slot(&keys, &setup, &policy_b, 2, 1, "withdraw", 1, msg_b);

    let mut verify_a = make_policy(2, &keys, &setup);
    let receipt_a = authorize(&mut verify_a, &[c1a, c2a], 0, "withdraw", 0, msg_a).unwrap();
    let mut verify_b = make_policy(2, &keys, &setup);
    let receipt_b = authorize(&mut verify_b, &[c1b, c2b], 1, "withdraw", 1, msg_b).unwrap();

    assert_ne!(receipt_a.sigma, receipt_b.sigma);
}

#[test]
fn test_below_threshold_rejected() {
    let keys: Vec<MemberKey> = (0..3).map(|_| generate_member_key()).collect();
    let setup = jrss_setup(2, 3, 4);
    let mut policy = make_policy(2, &keys, &setup);
    let message = b"withdraw";

    let c1 = approve_slot(&keys, &setup, &policy, 1, 0, "withdraw", 0, message);
    let result = authorize(&mut policy, &[c1], 0, "withdraw", 0, message);

    assert!(matches!(result, Err(AuthError::BelowThreshold { .. })));
}

#[test]
fn test_coefficient_reuse_rejected() {
    let keys: Vec<MemberKey> = (0..3).map(|_| generate_member_key()).collect();
    let setup = jrss_setup(2, 3, 4);
    let mut policy = make_policy(2, &keys, &setup);
    let message = b"withdraw";

    let c1 = approve_slot(&keys, &setup, &policy, 1, 0, "withdraw", 0, message);
    let c2 = approve_slot(&keys, &setup, &policy, 2, 0, "withdraw", 0, message);
    authorize(
        &mut policy,
        &[c1.clone(), c2.clone()],
        0,
        "withdraw",
        0,
        message,
    )
    .unwrap();

    let result = authorize(&mut policy, &[c1, c2], 0, "withdraw", 0, message);
    assert!(matches!(result, Err(AuthError::CoeffIdConsumed(0))));
}

#[test]
fn test_wrong_signature_rejected() {
    let keys: Vec<MemberKey> = (0..3).map(|_| generate_member_key()).collect();
    let impostor = generate_member_key();
    let setup = jrss_setup(2, 3, 4);
    let mut policy = make_policy(2, &keys, &setup);
    let message = b"withdraw";

    let c1 = approve_slot(&keys, &setup, &policy, 1, 0, "withdraw", 0, message);
    let mut c2 = approve_slot(&keys, &setup, &policy, 2, 0, "withdraw", 0, message);
    c2.signature = impostor.signing_key.sign(&c2.envelope);

    let result = authorize(&mut policy, &[c1, c2], 0, "withdraw", 0, message);
    assert!(matches!(result, Err(AuthError::InvalidSignature { .. })));
}

#[test]
fn test_message_substitution_rejected() {
    let keys: Vec<MemberKey> = (0..3).map(|_| generate_member_key()).collect();
    let setup = jrss_setup(2, 3, 4);
    let mut policy = make_policy(2, &keys, &setup);
    let real_msg = b"withdraw 100";
    let fake_msg = b"withdraw 999999";

    let c1 = approve_slot(&keys, &setup, &policy, 1, 0, "withdraw", 0, real_msg);
    let c2 = approve_slot(&keys, &setup, &policy, 2, 0, "withdraw", 0, real_msg);
    let result = authorize(&mut policy, &[c1, c2], 0, "withdraw", 0, fake_msg);

    assert!(matches!(result, Err(AuthError::EnvelopeMismatch { .. })));
}

#[test]
fn test_duplicate_member_rejected() {
    let keys: Vec<MemberKey> = (0..3).map(|_| generate_member_key()).collect();
    let setup = jrss_setup(2, 3, 4);
    let mut policy = make_policy(2, &keys, &setup);
    let message = b"withdraw";

    let c1 = approve_slot(&keys, &setup, &policy, 1, 0, "withdraw", 0, message);
    let result = authorize(&mut policy, &[c1.clone(), c1], 0, "withdraw", 0, message);

    assert!(matches!(result, Err(AuthError::DuplicateMember(1))));
}

#[test]
fn test_multiple_operations_sequential() {
    let keys: Vec<MemberKey> = (0..3).map(|_| generate_member_key()).collect();
    let setup = jrss_setup(2, 3, 4);
    let mut policy = make_policy(2, &keys, &setup);

    for slot in 0u64..4 {
        let message = format!("operation {slot}");
        let c1 = approve_slot(
            &keys,
            &setup,
            &policy,
            1,
            slot as usize,
            "op",
            slot,
            message.as_bytes(),
        );
        let c2 = approve_slot(
            &keys,
            &setup,
            &policy,
            2,
            slot as usize,
            "op",
            slot,
            message.as_bytes(),
        );
        let receipt =
            authorize(&mut policy, &[c1, c2], slot, "op", slot, message.as_bytes()).unwrap();
        assert_eq!(receipt.coeff_id, slot);
    }

    assert_eq!(policy.consumed_coeffids.len(), 4);
}
