use anyhow::Result;
use env_logger::{try_init_from_env, Env, DEFAULT_FILTER_ENV};
use plonky2::hash::hash_types::RichField;
use plonky2::plonk::config::{AlgebraicHasher, GenericConfig};
use plonky2::timed;
use plonky2::util::timing::TimingTree;
use plonky2_field::extension::Extendable;
use plonky2_field::polynomial::PolynomialValues;
use starky::proof::StarkProofWithPublicInputs;
use starky::stark::Stark;
use starky::verifier::verify_stark_proof;

use crate::keccak_permutation::keccak_permutation_stark::{KeccakPermutationStark, NUM_INPUTS};
use plonky2::plonk::config::Hasher;
use starky::config::StarkConfig;
use starky::prover::prove;
use std::time::{ Instant };
pub fn keccak256_permutation_proof<F, C, const D: usize>(
    states: Vec<[u64; NUM_INPUTS]>,
) -> Result<(
    StarkProofWithPublicInputs<F, C, D>,
    Vec<PolynomialValues<F>>,
    f32,
    f32
)>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    C::Hasher: AlgebraicHasher<F>,
    [(); C::Hasher::HASH_SIZE]:,
    [(); KeccakPermutationStark::<F, D>::COLUMNS]:,
    [(); KeccakPermutationStark::<F, D>::PUBLIC_INPUTS]:,
{
    let generate_sponge_proof = Instant::now();
    let config = StarkConfig::standard_fast_config();
    let stark = KeccakPermutationStark::<F, D>::default();

    let _ = try_init_from_env(Env::default().filter_or(DEFAULT_FILTER_ENV, "debug"));

    let mut timing = TimingTree::new("prove", log::Level::Debug);
    let permutation_poly_values = timed!(
        timing,
        "generate trace",
        stark.generate_trace(states.try_into().unwrap(), 8, &mut timing)
    );
    let generate_sponge_proof_time = generate_sponge_proof.elapsed().as_secs_f32();
    let proof_generation = Instant::now();
    let permutation_proof = prove::<F, C, KeccakPermutationStark<F, D>, D>(
        stark,
        &config,
        permutation_poly_values.clone(),
        None,
        &mut timing,
    )?;
    let proof_generation_time = proof_generation.elapsed().as_secs_f32();
    timing.print();
    Ok((permutation_proof, permutation_poly_values, generate_sponge_proof_time, proof_generation_time))
}

pub fn keccak256_permutation_verify<F, C, const D: usize>(
    proof: StarkProofWithPublicInputs<F, C, D>,
) -> Result<()>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    C::Hasher: AlgebraicHasher<F>,
    [(); C::Hasher::HASH_SIZE]:,
    [(); KeccakPermutationStark::<F, D>::COLUMNS]:,
    [(); KeccakPermutationStark::<F, D>::PUBLIC_INPUTS]:,
{
    let config = StarkConfig::standard_fast_config();
    let stark = KeccakPermutationStark::<F, D>::default();

    let _ = try_init_from_env(Env::default().filter_or(DEFAULT_FILTER_ENV, "debug"));

    let timing = TimingTree::new("verify", log::Level::Debug);

    let res = verify_stark_proof(stark, proof, &config);

    timing.print();

    res
}

#[cfg(test)]
mod tests {
    use anyhow::Result;
    use env_logger::{try_init_from_env, Env, DEFAULT_FILTER_ENV};

    use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};
    use plonky2_field::types::PrimeField64;
    use tiny_keccak::keccakf;

    use crate::keccak_permutation::columns::reg_output_limb;
    use crate::keccak_permutation::keccak_permutation_proof::{
        keccak256_permutation_proof, keccak256_permutation_verify,
    };
    use crate::keccak_permutation::keccak_permutation_stark::{
        KeccakPermutationStark, NUM_INPUTS, NUM_ROUNDS,
    };
    use starky::config::StarkConfig;
    use starky::stark_testing::{test_stark_circuit_constraints, test_stark_low_degree};

    const NUM_PERMS_1: usize = 1;
    //const NUM_PERMS_100: usize = 100;
    //const NUM_PERMS_1_000: usize = 1_000;

    #[test]
    #[ignore]
    fn test_stark_degree() -> Result<()> {
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;
        type S = KeccakPermutationStark<F, D>;

        let stark = S {
            f: Default::default(),
        };
        test_stark_low_degree(stark)
    }

    #[test]
    #[ignore]
    fn test_stark_circuit() -> Result<()> {
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;
        type S = KeccakPermutationStark<F, D>;

        let stark = S {
            f: Default::default(),
        };
        test_stark_circuit_constraints::<F, C, S, D>(stark)
    }

    #[test]
    #[ignore]
    fn keccak_correctness_test() -> Result<()> {
        let input: [u64; NUM_INPUTS] = rand::random();

        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;
        type S = KeccakPermutationStark<F, D>;

        let stark = S {
            f: Default::default(),
        };

        let rows = stark.generate_trace_rows(vec![input.try_into().unwrap()], 8);
        let last_row = rows[NUM_ROUNDS - 1];
        let output = (0..NUM_INPUTS)
            .map(|i| {
                let hi = last_row[reg_output_limb(2 * i + 1)].to_canonical_u64();
                let lo = last_row[reg_output_limb(2 * i)].to_canonical_u64();
                (hi << 32) | lo
            })
            .collect::<Vec<_>>();

        let expected = {
            let mut state = input;
            keccakf(&mut state);
            state
        };

        assert_eq!(output, expected);

        Ok(())
    }

    fn prove_verify(num_perm: usize) -> Result<()> {
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;
        type S = KeccakPermutationStark<F, D>;
        let config = StarkConfig::standard_fast_config();
        let stark = S::default();

        let _ = try_init_from_env(Env::default().filter_or(DEFAULT_FILTER_ENV, "debug"));

        let input: Vec<[u64; NUM_INPUTS]> = (0..num_perm).map(|_| rand::random()).collect();

        let (permutation_proof, _) = keccak256_permutation_proof::<F, C, D>(input)?;

        println!(
            "Proof size permutation (bytes): {}",
            permutation_proof.to_bytes().len()
        );

        keccak256_permutation_verify(permutation_proof)
    }

    #[test]
    #[ignore]
    fn test_keccak_permutation_stark_proof() -> Result<()> {
        prove_verify(NUM_PERMS_1)
        //prove_verify(NUM_PERMS_100)?;
        //prove_verify(NUM_PERMS_1_000)
    }
}
