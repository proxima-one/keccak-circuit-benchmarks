use anyhow::Result;
use itertools::Itertools;
use log::Level;
use plonky2::hash::hash_types::RichField;
use plonky2::plonk::circuit_data::CircuitData;
use plonky2::plonk::config::{AlgebraicHasher, GenericConfig, PoseidonGoldilocksConfig};
use plonky2::plonk::proof::ProofWithPublicInputs;
use plonky2::util::timing::TimingTree;

use plonky2_field::extension::Extendable;
use plonky2_field::goldilocks_field::GoldilocksField;
use starky::stark::Stark;

use crate::keccak_permutation::keccak_permutation_proof::{
    keccak256_permutation_proof,
    keccak256_permutation_verify,
};
use crate::keccak_permutation::keccak_permutation_stark::{KeccakPermutationStark, NUM_INPUTS};
use crate::keccak_sponge::keccak_sponge_proof::{keccak256_sponge_proof, keccak256_sponge_verify};
use crate::keccak_sponge::keccak_sponge_stark::KeccakSpongeStark;
use crate::stark_aggregation::{aggregation_sponge_permutation, u32_to_u64};
use plonky2::plonk::config::Hasher;
use std::time::{Instant};

pub fn keccak256<F, C, const D: usize>(
    msg: &[u8],
    hash: &[u8],
)
    -> Result<
        (
            CircuitData<F, C, D>,
            ProofWithPublicInputs<F, C, D>,
            f32,
            f32,
            f32,
            f32,
            f32,
            f32,
            usize,
            usize,
            usize,
            f32,
            f32,
            f32
        )
    >
    where
        F: RichField + Extendable<D>,
        C: GenericConfig<D, F=F>,
        C::Hasher: AlgebraicHasher<F>,
        [(); C::Hasher::HASH_SIZE]:,
        [(); KeccakSpongeStark::<F, D>::COLUMNS]:,
        [(); KeccakSpongeStark::<F, D>::PUBLIC_INPUTS]:,
        [(); KeccakPermutationStark::<F, D>::COLUMNS]:,
        [(); KeccakPermutationStark::<F, D>::PUBLIC_INPUTS]:
{
    let (sponge_proof, sponge_states, pol_values, sponge_circuit_time, proof_sponge_time) = keccak256_sponge_proof::<F, C, D>(&msg, hash)?;
    let sponge_proof_size = sponge_proof.to_bytes().len();
    let verify_sponge_proof = Instant::now();
    keccak256_sponge_verify::<F, C, D>(sponge_proof.clone())?;
    let input_permutation: Vec<[u64; NUM_INPUTS]> = sponge_states
        .iter()
        .map(|x| u32_to_u64(x).try_into().unwrap())
        .collect_vec();
    let verify_sponge_proof_time = verify_sponge_proof.elapsed().as_secs_f32();
    let (permutation_proof, _, circuit_perm_time, proof_permutations_time) = keccak256_permutation_proof::<F, C, D>(input_permutation)?;
    let permutations_proof_size = permutation_proof.to_bytes().len();
    let verify_permutations = Instant::now();
    keccak256_permutation_verify::<F, C, D>(permutation_proof.clone())?;
    let verify_permutation_proof_time = verify_permutations.elapsed().as_secs_f32();
    let (data, proof, aggregation_circuit_build_time, aggregation_sponge_permutations_proof_time) =
        aggregation_sponge_permutation(sponge_proof, permutation_proof)?;
    let aggregated_proof_size = proof.to_bytes().len();
    let timing = TimingTree::new("verify aggregation: sponge & permutation", Level::Debug);
    let verify_aggregation = Instant::now();
    data.verify(proof.clone())?;
    let verify_aggregation_time = verify_aggregation.elapsed().as_secs_f32();
    timing.print();
    Ok((
        data,
        proof,
        proof_sponge_time,
        verify_sponge_proof_time,
        proof_permutations_time,
        verify_permutation_proof_time,
        aggregation_sponge_permutations_proof_time,
        verify_aggregation_time,
        sponge_proof_size,
        permutations_proof_size,
        aggregated_proof_size,
        sponge_circuit_time,
        circuit_perm_time,
        aggregation_circuit_build_time
    ))
}
