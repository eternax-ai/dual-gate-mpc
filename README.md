# Dual-Gate Custody: Threshold Authorization with Authenticated Member Contributions

A minimal reference implementation of the dual-gate custody protocol. The construction provides MPC-equivalent threshold custody authorization using only standard cryptographic primitives: a prime field, Shamir secret sharing, a hash function, and any signature scheme.

No novel cryptography is required. No dependency on any specific signature family.

## The problem

MPC custody distributes a signing key so that no single compromise moves funds. For ECDSA this works via threshold signatures (CMP/GG, FROST). Hash-based post-quantum signatures (SPHINCS+/SLH-DSA) cannot be threshold-signed — there is no algebraic structure to distribute the signing computation.

## The solution

Do not threshold the signature. Threshold the authorization instead.

Two gates must both pass over the same canonical message for a custody operation to execute:

- **Gate 1 (authentication):** Each approving member signs a contribution envelope with their registered key. Any signature scheme works — the construction is agnostic.
- **Gate 2 (authorization):** The enforcement layer reconstructs an affine authorization value from the signed evaluation shares using Lagrange interpolation.

```
Setup:
  JRSS distributes Shamir shares of (k1, k2) — no party knows the full coefficients.

Per operation:
  x = H("custody-affine-x" || M || coeff_id)
  Each member i computes: share_i = [k1]_i * x + [k2]_i
  Each member i signs: sig_i = Sign(sk_i, envelope(M, coeff_id, i, share_i))

Verification:
  Check t valid signatures from distinct registered members.
  Lagrange-interpolate the shares to reconstruct sigma = k1*x + k2.
  Consume the coefficient ID so it cannot be reused.
```

That's it.

## Security properties

| Property | Guarantee | Basis |
|---|---|---|
| Threshold secrecy | < t shares reveal zero information about (k1, k2) | Shamir (information-theoretic) |
| Unforgeability | Forgery probability 1/p ~ 2^{-256} | Schwartz-Zippel (information-theoretic) |
| Message binding | Cannot retarget a contribution to a different operation | Envelope signature (EUF-CMA) |
| Coefficient reuse prevention | Same coefficients cannot be evaluated twice | Finality + coefficient-id consumption |
| Verifier independence | Enforcement layer cannot produce gate 2, only verify it | Verifier sees evaluation shares, never coefficient shares |

## What this demo tests

13 tests covering the full protocol:

| Test | What it verifies |
|---|---|
| `test_2_of_3_happy_path` | 2-of-3 quorum authorizes successfully |
| `test_3_of_5_happy_path` | 3-of-5 quorum authorizes successfully |
| `test_any_quorum_reconstructs_same_sigma` | Any t-of-n subset of all n members reconstructs the same authorization value |
| `test_different_messages_different_sigma` | Different operations produce different authorization values |
| `test_below_threshold_rejected` | Fewer than t contributions are rejected |
| `test_coefficient_reuse_rejected` | Reusing a consumed coefficient ID is rejected |
| `test_wrong_signature_rejected` | A forged signature (wrong key) is rejected |
| `test_message_substitution_rejected` | A relay substituting the message is rejected |
| `test_duplicate_member_rejected` | Same member contributing twice is rejected |
| `test_multiple_operations_sequential` | Multiple operations with different coefficient slots succeed sequentially |
| `roundtrip_2_of_3` | Shamir 2-of-3 reconstructs correctly |
| `roundtrip_3_of_5` | Shamir 3-of-5 reconstructs correctly |
| `below_threshold_gives_wrong_value` | Below-threshold Shamir reconstruction gives wrong value |

## Running

```bash
cargo test
```

## Architecture

```
src/
  lib.rs          — crate root
  field.rs        — domain-separated hash-to-field over secp256k1 base field (Fq, p ~ 2^256)
  shamir.rs       — Shamir secret sharing: split, reconstruct via Lagrange interpolation
  protocol.rs     — the dual-gate protocol:
                      jrss_setup()  — dealer-free coefficient generation
                      approve()     — member evaluates share + signs envelope (gate 1 + gate 2)
                      authorize()   — verify signatures, reconstruct, consume coeff id

tests/
  dual_gate.rs    — end-to-end protocol tests
```

## Dependencies

- `ark-ff`, `ark-secp256k1` — prime field arithmetic (secp256k1 base field, p ~ 2^256)
- `ed25519-dalek` — Ed25519 signatures for gate 1 (stand-in for any EUF-CMA scheme)
- `sha2` — SHA-256 for domain-separated hashing
- `rand` — randomness

Gate 1 uses Ed25519 as a concrete stand-in. In production, substitute SLH-DSA (post-quantum), ML-DSA, ECDSA, or any EUF-CMA-secure scheme. Gate 2 does not change.

## What this is not

- Not a threshold signature scheme. No signing key is distributed.
- Not a multisig. Below-threshold shares reveal zero information (information-theoretic, not computational).
- Not dependent on SILMARILS or any novel cryptographic primitive.
- Not production-ready. This is a protocol demonstration, not hardened code. Missing: constant-time field operations, side-channel protection, serialization, networking, persistent state.

## License

MIT OR Apache-2.0
