use core::iter::once;
use std::time::Instant;

use anyhow::Result;
use itertools::Itertools;
use log::Level;
use plonky2::field::extension::Extendable;
use plonky2::fri::witness_util::set_fri_proof_target;
use plonky2::hash::hash_types::RichField;
use plonky2::iop::witness::{PartialWitness, Witness};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::{CircuitConfig, CircuitData};
use plonky2::plonk::config::{AlgebraicHasher, GenericConfig, PoseidonGoldilocksConfig};
use plonky2::plonk::proof::ProofWithPublicInputs;
use plonky2::util::timing::TimingTree;

use plonky2_field::goldilocks_field::GoldilocksField;
use starky::config::StarkConfig;
use starky::proof::{
    StarkOpeningSetTarget, StarkProof, StarkProofTarget, StarkProofWithPublicInputs,
    StarkProofWithPublicInputsTarget,
};
use starky::stark::Stark;

use crate::keccak_permutation::keccak_permutation_proof::{
    keccak256_permutation_proof, keccak256_permutation_verify,
};
use crate::keccak_permutation::keccak_permutation_stark::{KeccakPermutationStark, NUM_INPUTS};
use crate::keccak_sponge::keccak_sponge_proof::{keccak256_sponge_proof, keccak256_sponge_verify};
use crate::keccak_sponge::keccak_sponge_stark::KeccakSpongeStark;

pub fn aggregation_sponge_permutation<F, C, const D: usize>(
    sponge_proof: StarkProofWithPublicInputs<F, C, D>,
    permutation_proof: StarkProofWithPublicInputs<F, C, D>,
) -> Result<(CircuitData<F, C, D>, ProofWithPublicInputs<F, C, D>, f32, f32)>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    C::Hasher: AlgebraicHasher<F>,
{
    let aggregation_circuit_build_init = Instant::now();
    let config = StarkConfig::standard_fast_config();
    let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_config());

    let degree_bits = sponge_proof.proof.recover_degree_bits(&config);
    let stark_proof_with_pis_target = add_virtual_stark_proof_with_pis(
        &mut builder,
        KeccakSpongeStark::<F, D>::default(),
        &config,
        degree_bits,
    );

    let degree_bits = permutation_proof.proof.recover_degree_bits(&config);
    let stark_proof_target = add_virtual_stark_proof(
        &mut builder,
        KeccakPermutationStark::<F, D>::default(),
        &config,
        degree_bits,
    );

    let mut pw = PartialWitness::new();
    set_stark_proof_with_pis_target(&mut pw, &stark_proof_with_pis_target, &sponge_proof);
    // set PI (hash) from sponge stark
    builder.register_public_inputs(&stark_proof_with_pis_target.public_inputs);
    set_stark_proof_target(&mut pw, &stark_proof_target, &permutation_proof.proof);
    let data = builder.build::<C>();
    let aggregation_circuit_build_time = aggregation_circuit_build_init
        .elapsed()
        .as_secs_f32();
    let timing = TimingTree::new("prove aggregation: sponge & permutation", Level::Debug);
    let aggregation_sponge_permutations_proof = Instant::now();
    let proof = data.prove(pw)?;
    let aggregation_sponge_permutations_proof_time = aggregation_sponge_permutations_proof
        .elapsed()
        .as_secs_f32();
    timing.print();
    assert_eq!(sponge_proof.public_inputs, proof.public_inputs);
    Ok((data, proof, aggregation_circuit_build_time, aggregation_sponge_permutations_proof_time))
}

pub fn add_virtual_stark_proof_with_pis<
    F: RichField + Extendable<D>,
    S: Stark<F, D>,
    const D: usize,
>(
    builder: &mut CircuitBuilder<F, D>,
    stark: S,
    config: &StarkConfig,
    degree_bits: usize,
) -> StarkProofWithPublicInputsTarget<D> {
    let proof = add_virtual_stark_proof::<F, S, D>(builder, stark, config, degree_bits);
    let public_inputs = builder.add_virtual_targets(S::PUBLIC_INPUTS);
    StarkProofWithPublicInputsTarget {
        proof,
        public_inputs,
    }
}

pub fn add_virtual_stark_proof<F: RichField + Extendable<D>, S: Stark<F, D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    stark: S,
    config: &StarkConfig,
    degree_bits: usize,
) -> StarkProofTarget<D> {
    let fri_params = config.fri_params(degree_bits);
    let cap_height = fri_params.config.cap_height;

    let num_leaves_per_oracle = once(S::COLUMNS)
        .chain(
            stark
                .uses_permutation_args()
                .then(|| stark.num_permutation_batches(config)),
        )
        .chain(once(stark.quotient_degree_factor() * config.num_challenges))
        .collect_vec();

    let permutation_zs_cap = stark
        .uses_permutation_args()
        .then(|| builder.add_virtual_cap(cap_height));

    StarkProofTarget {
        trace_cap: builder.add_virtual_cap(cap_height),
        permutation_zs_cap,
        quotient_polys_cap: builder.add_virtual_cap(cap_height),
        openings: add_stark_opening_set_target::<F, S, D>(builder, stark, config),
        opening_proof: builder.add_virtual_fri_proof(&num_leaves_per_oracle, &fri_params),
    }
}

fn add_stark_opening_set_target<F: RichField + Extendable<D>, S: Stark<F, D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    stark: S,
    config: &StarkConfig,
) -> StarkOpeningSetTarget<D> {
    let num_challenges = config.num_challenges;
    StarkOpeningSetTarget {
        local_values: builder.add_virtual_extension_targets(S::COLUMNS),
        next_values: builder.add_virtual_extension_targets(S::COLUMNS),
        permutation_zs: stark
            .uses_permutation_args()
            .then(|| builder.add_virtual_extension_targets(stark.num_permutation_batches(config))),
        permutation_zs_next: stark
            .uses_permutation_args()
            .then(|| builder.add_virtual_extension_targets(stark.num_permutation_batches(config))),
        quotient_polys: builder
            .add_virtual_extension_targets(stark.quotient_degree_factor() * num_challenges),
    }
}

pub fn set_stark_proof_with_pis_target<F, C: GenericConfig<D, F = F>, W, const D: usize>(
    witness: &mut W,
    stark_proof_with_pis_target: &StarkProofWithPublicInputsTarget<D>,
    stark_proof_with_pis: &StarkProofWithPublicInputs<F, C, D>,
) where
    F: RichField + Extendable<D>,
    C::Hasher: AlgebraicHasher<F>,
    W: Witness<F>,
{
    let StarkProofWithPublicInputs {
        proof,
        public_inputs,
    } = stark_proof_with_pis;
    let StarkProofWithPublicInputsTarget {
        proof: pt,
        public_inputs: pi_targets,
    } = stark_proof_with_pis_target;

    // Set public inputs.
    for (&pi_t, &pi) in pi_targets.iter().zip_eq(public_inputs) {
        witness.set_target(pi_t, pi);
    }

    set_stark_proof_target(witness, pt, proof);
}

pub fn set_stark_proof_target<F, C: GenericConfig<D, F = F>, W, const D: usize>(
    witness: &mut W,
    proof_target: &StarkProofTarget<D>,
    proof: &StarkProof<F, C, D>,
) where
    F: RichField + Extendable<D>,
    C::Hasher: AlgebraicHasher<F>,
    W: Witness<F>,
{
    witness.set_cap_target(&proof_target.trace_cap, &proof.trace_cap);
    witness.set_cap_target(&proof_target.quotient_polys_cap, &proof.quotient_polys_cap);

    witness.set_fri_openings(
        &proof_target.openings.to_fri_openings(),
        &proof.openings.to_fri_openings(),
    );

    if let (Some(permutation_zs_cap_target), Some(permutation_zs_cap)) =
        (&proof_target.permutation_zs_cap, &proof.permutation_zs_cap)
    {
        witness.set_cap_target(permutation_zs_cap_target, permutation_zs_cap);
    }

    set_fri_proof_target(witness, &proof_target.opening_proof, &proof.opening_proof);
}

pub fn u32_to_u64(vecu32: &[u32]) -> Vec<u64> {
    assert!(vecu32.len() >= 2);
    assert_eq!(vecu32.len() % 2, 0);
    let mut vecu64: Vec<u64> = Vec::new();
    for i in (0..vecu32.len()).step_by(2) {
        let a: u64 = ((vecu32[i] as u64) << 32) | (vecu32[i + 1] as u64);
        vecu64.push(a);
    }
    vecu64
}
