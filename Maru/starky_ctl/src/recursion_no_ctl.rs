use core::iter::once;

use itertools::Itertools;
use plonky2::field::extension::Extendable;
use plonky2::fri::witness_util::set_fri_proof_target;
use plonky2::hash::hash_types::RichField;
use plonky2::iop::target::Target;
use plonky2::iop::witness::Witness;
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::config::{AlgebraicHasher, GenericConfig};

use crate::config::StarkConfig;
use crate::proof::{
    StarkOpeningSetTarget, StarkProof, StarkProofTarget, StarkProofWithPublicInputs,
    StarkProofWithPublicInputsTarget,
};
use crate::stark::Stark;

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
        permutation_ctl_zs: builder
            .add_virtual_extension_targets(stark.num_permutation_batches(config)),
        permutation_ctl_zs_next: builder
            .add_virtual_extension_targets(stark.num_permutation_batches(config)),
        quotient_polys: builder
            .add_virtual_extension_targets(stark.quotient_degree_factor() * num_challenges),
        ctl_zs_last: vec![],
    }
}

pub fn set_stark_proof_with_pis_target<F, C: GenericConfig<D, F = F>, W, const D: usize>(
    witness: &mut W,
    stark_proof_with_pis_target: &StarkProofWithPublicInputsTarget<D>,
    stark_proof_with_pis: &StarkProofWithPublicInputs<F, C, D>,
    zero: Target,
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
    for (&pi_t, &pi) in pi_targets.iter().zip(public_inputs.iter()) {
        witness.set_target(pi_t, pi);
    }

    set_stark_proof_target(witness, pt, proof, zero);
    println!("done");
}

pub fn set_stark_proof_target<F, C: GenericConfig<D, F = F>, W, const D: usize>(
    witness: &mut W,
    proof_target: &StarkProofTarget<D>,
    proof: &StarkProof<F, C, D>,
    zero: Target,
) where
    F: RichField + Extendable<D>,
    C::Hasher: AlgebraicHasher<F>,
    W: Witness<F>,
{
    witness.set_cap_target(&proof_target.trace_cap, &proof.trace_cap);

    witness.set_cap_target(&proof_target.quotient_polys_cap, &proof.quotient_polys_cap);

    witness.set_fri_openings(
        &proof_target.openings.to_fri_openings(zero),
        &proof.openings.to_fri_openings(),
    );

    if let (Some(permutation_zs_cap_target), permutation_zs_cap) = (
        &proof_target.permutation_zs_cap,
        &proof.permutation_ctl_zs_cap,
    ) {
        witness.set_cap_target(permutation_zs_cap_target, permutation_zs_cap);
    }

    println!(
        "len1 {:#?}, {:#?}",
        proof_target.opening_proof.pow_witness, proof.opening_proof.pow_witness
    );

    println!(
        "len2 {}, {}",
        proof_target.opening_proof.final_poly.0.len(),
        proof.opening_proof.final_poly.coeffs.len()
    );

    println!(
        "len3 {}, {}",
        proof_target.opening_proof.commit_phase_merkle_caps.len(),
        proof.opening_proof.commit_phase_merkle_caps.len()
    );

    println!(
        "len4 {}, {}",
        proof_target.opening_proof.query_round_proofs.len(),
        proof.opening_proof.query_round_proofs.len()
    );

    //initial_trees_proof.evals_proofs

    for (qt, q) in proof_target
        .opening_proof
        .query_round_proofs
        .iter()
        .zip_eq(&proof.opening_proof.query_round_proofs)
    {
        println!(
            "len5 {}, {}",
            qt.initial_trees_proof.evals_proofs.len(),
            q.initial_trees_proof.evals_proofs.len()
        );

        for (at, a) in qt
            .initial_trees_proof
            .evals_proofs
            .iter()
            .zip_eq(&q.initial_trees_proof.evals_proofs)
        {
            println!("len6 {}, {}", at.0.len(), a.0.len());
            println!("len7 {}, {}", at.1.siblings.len(), a.1.siblings.len());
        }

        println!("len8 {}, {}", qt.steps.len(), q.steps.len());

        for (st, s) in qt.steps.iter().zip_eq(&q.steps) {
            println!("len9 {}, {}", st.evals.len(), s.evals.len());
            println!(
                "len10 {}, {}",
                st.merkle_proof.siblings.len(),
                s.merkle_proof.siblings.len()
            );
        }
    }
    set_fri_proof_target(witness, &proof_target.opening_proof, &proof.opening_proof);
    println!("done5");
}
