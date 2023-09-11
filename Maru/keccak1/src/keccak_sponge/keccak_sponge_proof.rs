use env_logger::{try_init_from_env, Env, DEFAULT_FILTER_ENV};
use itertools::Itertools;

use anyhow::Result;

use plonky2::field::types::Field;
use plonky2::hash::hash_types::RichField;
use plonky2::plonk::config::{AlgebraicHasher, GenericConfig};
use plonky2::timed;
use plonky2::util::timing::TimingTree;
use plonky2::{field::goldilocks_field::GoldilocksField, plonk::config::PoseidonGoldilocksConfig};
use plonky2_field::extension::Extendable;
use plonky2_field::polynomial::PolynomialValues;
use starky::config::StarkConfig;
use log::{info};
use starky::proof::StarkProofWithPublicInputs;
use starky::prover::prove;
use starky::stark::Stark;
use starky::util::trace_rows_to_poly_values;
use starky::verifier::verify_stark_proof;
use std::time::{ Instant };
use crate::{
    keccak_sponge::columns::KECCAK_WIDTH_U32S,
    keccak_sponge::keccak_sponge_stark::{KeccakSpongeOp, KeccakSpongeStark},
};

use super::keccak_util::u8_to_u32_reverse;

use plonky2::plonk::config::Hasher;

// make a proof that the hash matches the message
pub fn keccak256_sponge_proof<F, C, const D: usize>(
    msg: &[u8],
    hash: &[u8],
) -> Result<(
    StarkProofWithPublicInputs<F, C, D>,
    Vec<[u32; KECCAK_WIDTH_U32S]>,
    Vec<PolynomialValues<F>>,
    f32,
    f32
)>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    C::Hasher: AlgebraicHasher<F>,
    [(); C::Hasher::HASH_SIZE]:,
    [(); KeccakSpongeStark::<F, D>::COLUMNS]:,
    [(); KeccakSpongeStark::<F, D>::PUBLIC_INPUTS]:,
{
    let _ = try_init_from_env(Env::default().filter_or(DEFAULT_FILTER_ENV, "debug"));
    let expected_hash: [F; 8] = u8_to_u32_reverse(hash)
        .iter()
        .map(|x| F::from_canonical_u32(*x))
        .collect_vec()
        .try_into()
        .expect("to field error");
    let generate_sponge_proof = Instant::now();
    let config = StarkConfig::standard_fast_config();
    let stark = KeccakSpongeStark::<F, D>::default();
    
    let mut timing = TimingTree::new("prove", log::Level::Debug);

    let mut sponge_operations: Vec<KeccakSpongeOp> = Vec::new();
    sponge_operations.push(KeccakSpongeOp {
        timestamp: 0,
        input: msg.to_vec(),
    });

    let (sponge_trace_rows, sponge_states) = timed!(
        timing,
        "generate trace",
        stark.generate_trace_rows(sponge_operations.try_into().unwrap(), 8)
    );

    let sponge_poly_values = timed!(
        timing,
        "convert to PolynomialValues",
        trace_rows_to_poly_values(sponge_trace_rows.clone())
    );
    let generate_sponge_proof_time = generate_sponge_proof.elapsed().as_secs_f32();
    let proof_generation = Instant::now();
    let sponge_proof = prove::<F, C, KeccakSpongeStark<F, D>, D>(
        stark,
        &config,
        sponge_poly_values.clone(),
        Some(expected_hash),
        &mut timing,
    )?;
    let proof_generation_time = proof_generation.elapsed().as_secs_f32();

    timing.print();

    Ok((sponge_proof, sponge_states, sponge_poly_values, generate_sponge_proof_time, proof_generation_time))
}

pub fn keccak256_sponge_verify<F, C, const D: usize>(
    proof: StarkProofWithPublicInputs<F, C, D>,
) -> Result<()>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    C::Hasher: AlgebraicHasher<F>,
    [(); C::Hasher::HASH_SIZE]:,
    [(); KeccakSpongeStark::<F, D>::COLUMNS]:,
    [(); KeccakSpongeStark::<F, D>::PUBLIC_INPUTS]:,
{
    let config = StarkConfig::standard_fast_config();
    let stark = KeccakSpongeStark::<F, D>::default();

    let _ = try_init_from_env(Env::default().filter_or(DEFAULT_FILTER_ENV, "debug"));

    let timing = TimingTree::new("verify", log::Level::Debug);

    let res = verify_stark_proof(stark, proof, &config);

    timing.print();

    res
}

#[cfg(test)]
mod tests {
    use crate::keccak_sponge::keccak_sponge_proof::keccak256_sponge_verify;
    use crate::keccak_sponge::{
        keccak_sponge_proof::keccak256_sponge_proof, keccak_sponge_stark::KeccakSpongeStark,
    };
    use anyhow::Result;
    use keccak_hash::keccak;
    use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};
    use starky::stark_testing::{test_stark_circuit_constraints, test_stark_low_degree};

    const MSG_1_BYTES: usize = 1;
    const MSG_100_BYTES: usize = 100;
    const MSG_1_000_BYTES: usize = 1_000;
    const MSG_500_000_BYTES: usize = 500_000;
    const MSG_1_000_000_BYTES: usize = 1_000_000;

    #[test]
    #[ignore]
    fn test_stark_degree() -> Result<()> {
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;
        type S = KeccakSpongeStark<F, D>;

        let stark = S::default();
        test_stark_low_degree(stark)
    }

    #[test]
    //#[ignore = "check why is failed"]
    fn test_stark_circuit() -> Result<()> {
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;
        type S = KeccakSpongeStark<F, D>;

        let stark = S::default();
        test_stark_circuit_constraints::<F, C, S, D>(stark)
    }

    fn prove_verify(msg_len: usize) -> Result<()> {
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;

        let input: Vec<u8> = (0..msg_len).map(|_| rand::random()).collect();
        let expected = keccak(&input);

        let (sponge_proof, _, _) = keccak256_sponge_proof::<F, C, D>(&input, expected.as_bytes())?;

        println!(
            "Proof size sponge (bytes): {}",
            sponge_proof.to_bytes().len()
        );

        keccak256_sponge_verify(sponge_proof)
    }

    #[test]
    #[ignore]
    fn test_keccak_sponge_stark_proof() -> Result<()> {
        prove_verify(MSG_1_BYTES)?;
        prove_verify(MSG_100_BYTES)?;
        prove_verify(MSG_1_000_BYTES)?;
        prove_verify(MSG_500_000_BYTES)?;
        prove_verify(MSG_1_000_000_BYTES)
    }
}
