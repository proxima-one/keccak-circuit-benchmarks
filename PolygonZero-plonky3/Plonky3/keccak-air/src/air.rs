use core::borrow::Borrow;

use p3_air::{Air, AirBuilder, BaseAir};
use p3_field::AbstractField;
use p3_matrix::MatrixRowSlices;

use crate::columns::KeccakCols;
use crate::constants::rc_value_bit;
use crate::logic::{andn_gen, xor3_gen, xor_gen};
use crate::round_flags::eval_round_flags;
use crate::{BITS_PER_LIMB, NUM_ROUNDS, U64_LIMBS};

/// Assumes the field size is at least 16 bits.
pub struct KeccakAir {}

impl<F> BaseAir<F> for KeccakAir {}

impl<AB: AirBuilder> Air<AB> for KeccakAir {
    fn eval(&self, builder: &mut AB) {
        eval_round_flags(builder);

        let main = builder.main();
        let local: &KeccakCols<AB::Var> = main.row_slice(0).borrow();
        let next: &KeccakCols<AB::Var> = main.row_slice(1).borrow();

        // The export flag must be 0 or 1.
        builder.assert_bool(local.export);

        // If this is not the final step, the export flag must be off.
        let final_step = local.step_flags[NUM_ROUNDS - 1];
        let not_final_step = AB::Expr::ONE - final_step;
        builder
            .when(not_final_step.clone())
            .assert_zero(local.export);

        // If this is not the final step, the local and next preimages must match.
        for x in 0..5 {
            for y in 0..5 {
                for limb in 0..U64_LIMBS {
                    let diff = local.preimage[y][x][limb] - next.preimage[y][x][limb];
                    builder
                        .when_transition()
                        .assert_eq(not_final_step.clone(), diff);
                }
            }
        }

        // C'[x, z] = xor(C[x, z], C[x - 1, z], C[x + 1, z - 1]).
        for x in 0..5 {
            for z in 0..64 {
                let xor = xor3_gen::<AB::Expr>(
                    local.c[x][z].into(),
                    local.c[(x + 4) % 5][z].into(),
                    local.c[(x + 1) % 5][(z + 63) % 64].into(),
                );
                let c_prime = local.c_prime[x][z];
                builder.assert_eq(c_prime, xor);
            }
        }

        // Check that the input limbs are consistent with A' and D.
        // A[x, y, z] = xor(A'[x, y, z], D[x, y, z])
        //            = xor(A'[x, y, z], C[x - 1, z], C[x + 1, z - 1])
        //            = xor(A'[x, y, z], C[x, z], C'[x, z]).
        // The last step is valid based on the identity we checked above.
        // It isn't required, but makes this check a bit cleaner.
        for x in 0..5 {
            for y in 0..5 {
                let get_bit = |z| {
                    let a_prime: AB::Var = local.a_prime[y][x][z];
                    let c: AB::Var = local.c[x][z];
                    let c_prime: AB::Var = local.c_prime[x][z];
                    xor3_gen::<AB::Expr>(a_prime.into(), c.into(), c_prime.into())
                };

                for limb in 0..U64_LIMBS {
                    let a_limb = local.a[y][x][limb];
                    let computed_limb = (limb * BITS_PER_LIMB..(limb + 1) * BITS_PER_LIMB)
                        .rev()
                        .fold(AB::Expr::ZERO, |acc, z| acc.double() + get_bit(z));
                    builder.assert_eq(computed_limb, a_limb);
                }
            }
        }

        // xor_{i=0}^4 A'[x, i, z] = C'[x, z], so for each x, z,
        // diff * (diff - 2) * (diff - 4) = 0, where
        // diff = sum_{i=0}^4 A'[x, i, z] - C'[x, z]
        for x in 0..5 {
            for z in 0..64 {
                // TODO: from_fn
                let sum: AB::Expr = [0, 1, 2, 3, 4]
                    .map(|y| local.a_prime[y][x][z].into())
                    .into_iter()
                    .sum();
                let diff = sum - local.c_prime[x][z];
                let four = AB::Expr::from_canonical_u8(4);
                builder.assert_zero(diff.clone() * (diff.clone() - AB::Expr::TWO) * (diff - four));
            }
        }

        // A''[x, y] = xor(B[x, y], andn(B[x + 1, y], B[x + 2, y])).
        for x in 0..5 {
            for y in 0..5 {
                let get_bit = |z| {
                    let andn = andn_gen::<AB::Expr>(
                        local.b((x + 1) % 5, y, z).into(),
                        local.b((x + 2) % 5, y, z).into(),
                    );
                    xor_gen::<AB::Expr>(local.b(x, y, z).into(), andn)
                };

                for limb in 0..U64_LIMBS {
                    let computed_limb = (limb * BITS_PER_LIMB..(limb + 1) * BITS_PER_LIMB)
                        .rev()
                        .fold(AB::Expr::ZERO, |acc, z| acc.double() + get_bit(z));
                    builder.assert_eq(computed_limb, local.a_prime_prime[y][x][limb]);
                }
            }
        }

        // A'''[0, 0] = A''[0, 0] XOR RC
        for limb in 0..U64_LIMBS {
            let computed_a_prime_prime_0_0_limb = (limb * BITS_PER_LIMB
                ..(limb + 1) * BITS_PER_LIMB)
                .rev()
                .fold(AB::Expr::ZERO, |acc, z| {
                    acc.double() + local.a_prime_prime_0_0_bits[z]
                });
            let a_prime_prime_0_0_limb = local.a_prime_prime[0][0][limb];
            builder.assert_eq(computed_a_prime_prime_0_0_limb, a_prime_prime_0_0_limb);
        }

        let get_xored_bit = |i| {
            let mut rc_bit_i = AB::Expr::ZERO;
            for r in 0..NUM_ROUNDS {
                let this_round = local.step_flags[r];
                let this_round_constant = AB::Expr::from_canonical_u8(rc_value_bit(r, i));
                rc_bit_i += this_round * this_round_constant;
            }

            xor_gen::<AB::Expr>(local.a_prime_prime_0_0_bits[i].into(), rc_bit_i)
        };

        for limb in 0..U64_LIMBS {
            let a_prime_prime_prime_0_0_limb = local.a_prime_prime_prime_0_0_limbs[limb];
            let computed_a_prime_prime_prime_0_0_limb = (limb * BITS_PER_LIMB
                ..(limb + 1) * BITS_PER_LIMB)
                .rev()
                .fold(AB::Expr::ZERO, |acc, z| acc.double() + get_xored_bit(z));
            builder.assert_eq(
                computed_a_prime_prime_prime_0_0_limb,
                a_prime_prime_prime_0_0_limb,
            );
        }

        // Enforce that this round's output equals the next round's input.
        for x in 0..5 {
            for y in 0..5 {
                for limb in 0..U64_LIMBS {
                    let output = local.a_prime_prime_prime(x, y, limb);
                    let input = next.a[y][x][limb];
                    builder
                        .when_transition()
                        .when(not_final_step.clone())
                        .assert_eq(output, input);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::{generate_trace_rows, KeccakAir};
    use alloc::vec::Vec;
    use p3_baby_bear::BabyBear;
    use p3_challenger::DuplexChallenger;
    use p3_dft::Radix2Bowers;
    use p3_fri::{FriBasedPcs, FriConfigImpl, FriLdt};
    use p3_goldilocks::Goldilocks;
    use p3_keccak::Keccak256Hash;
    use p3_ldt::QuotientMmcs;
    use p3_mds::coset_mds::CosetMds;
    use p3_merkle_tree::MerkleTreeMmcs;
    use p3_poseidon::Poseidon;
    use p3_symmetric::compression::TruncatedPermutation;
    use p3_symmetric::hasher::SerializingHasher32;
    use p3_symmetric::{compression::CompressionFunctionFromHasher, sponge::PaddingFreeSponge};
    use p3_uni_stark::{prove, verify, StarkConfigImpl, VerificationError};
    use rand::thread_rng;

    #[test]
    fn test_keccak_bench() -> Result<(), VerificationError> {
        type Val = Goldilocks;
        type Domain = Val;
        type Challenge = Val;

        type MyMds = CosetMds<Val, 16>;
        let mds = MyMds::default();

        type Perm = Poseidon<Val, MyMds, 16, 5>;
        let perm = Perm::new_from_rng(4, 22, mds, &mut thread_rng()); // TODO: Use deterministic RNG

        type MyHash = SerializingHasher32<Val, Keccak256Hash>;
        let hash = MyHash::new(Keccak256Hash {});

        type MyCompress = CompressionFunctionFromHasher<Val, MyHash, 2, 8>;
        let compress = MyCompress::new(hash);

        // type MyHash = PaddingFreeSponge<Val, Perm, 16, 8, 8>;
        // let hash = MyHash::new(perm.clone());

        // type MyCompress = TruncatedPermutation<Val, Perm, 2, 8, 16>;
        // let compress = MyCompress::new(perm.clone());

        type MyMmcs = MerkleTreeMmcs<Val, [Val; 8], MyHash, MyCompress>;
        let mmcs = MyMmcs::new(hash, compress);

        type Dft = Radix2Bowers;
        let dft = Dft {};

        type Challenger = DuplexChallenger<Val, Perm, 16>;

        type Quotient = QuotientMmcs<Domain, Challenge, MyMmcs>;
        type MyFriConfig = FriConfigImpl<Val, Domain, Challenge, Quotient, MyMmcs, Challenger>;
        let fri_config = MyFriConfig::new(40, mmcs.clone());
        let ldt = FriLdt { config: fri_config };

        type Pcs = FriBasedPcs<MyFriConfig, MyMmcs, Dft, Challenger>;
        type MyConfig = StarkConfigImpl<Val, Domain, Challenge, Pcs, Dft, Challenger>;

        const NUM_PERMS: usize = 85;

        let input: Vec<[u64; 25]> = (0..NUM_PERMS).map(|_| rand::random()).collect();
        let trace = generate_trace_rows::<Val>(input, 8);

        let pcs = Pcs::new(dft, 1, mmcs, ldt);
        let config = StarkConfigImpl::new(pcs, Dft {});
        let mut challenger = Challenger::new(perm.clone());
        let proof = prove::<MyConfig, _>(&config, &KeccakAir {}, &mut challenger, trace);

        let mut challenger = Challenger::new(perm);
        verify(&config, &KeccakAir {}, &mut challenger, &proof)
    }
}
