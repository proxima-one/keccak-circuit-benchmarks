use std::time::Instant;
use anyhow::Result;
use log::Level;
use plonky2::field::extension::Extendable;
use plonky2::hash::hash_types::RichField;
use plonky2::hash::hashing::PlonkyPermutation;
use plonky2::iop::challenger::RecursiveChallenger;
use plonky2::iop::ext_target::ExtensionTarget;
use plonky2::iop::target::Target;
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::{CircuitConfig, CircuitData};
use plonky2::plonk::config::{AlgebraicHasher, GenericConfig};
use plonky2::plonk::proof::ProofWithPublicInputs;
use plonky2::util::reducing::ReducingFactorTarget;
use plonky2::util::timing::TimingTree;
use plonky2::with_context;
use plonky2_field::types::Field;

use starky_ctl::config::StarkConfig;

use starky_ctl::constraint_consumer::RecursiveConstraintConsumer;
use starky_ctl::cross_table_lookup::{
    verify_cross_table_lookups_circuit, CrossTableLookup, CtlCheckVarsTarget,
};
use starky_ctl::permutation::{
    PermutationChallenge, PermutationChallengeSet, PermutationCheckDataTarget,
};
use starky_ctl::proof::{StarkOpeningSetTarget, StarkProofChallengesTarget, StarkProofTarget};
use starky_ctl::recursion::{
    add_virtual_stark_proof, add_virtual_stark_proof_with_pis, set_stark_proof_target,
    set_stark_proof_with_pis_target,
};
use starky_ctl::stark::Stark;
use starky_ctl::table::Table;
use starky_ctl::vanishing_poly::eval_vanishing_poly_circuit;
use starky_ctl::vars::StarkEvaluationTargets;

use crate::keccak_ctl_stark::KeccakCtl;
use crate::keccak_permutation::keccak_permutation_stark::KeccakPermutationStark;
use crate::keccak_sponge::keccak_sponge_stark::KeccakSpongeStark;
use crate::keccak_xor::xor_stark::KeccakXORStark;
use crate::proof_ctl::KeccakCtlProof;

pub fn aggregation_sponge_permutation<
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    const D: usize,
>(
    all_stark: &KeccakCtl<F, D>,
    all_proof: KeccakCtlProof<F, C, D>,
) -> Result<(CircuitData<F, C, D>, ProofWithPublicInputs<F, C, D>, f32, f32)>
where
    C::Hasher: AlgebraicHasher<F>,
    [(); KeccakPermutationStark::<F, D>::COLUMNS]:,
    [(); KeccakPermutationStark::<F, D>::PUBLIC_INPUTS]:,
    [(); KeccakSpongeStark::<F, D>::COLUMNS]:,
    [(); KeccakSpongeStark::<F, D>::PUBLIC_INPUTS]:,
    [(); KeccakXORStark::<F, D>::COLUMNS]:,
{
    let config = StarkConfig::standard_fast_config();
    let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_config());
    let zero_target = builder.zero();
    let mut pw = PartialWitness::new();

    let mut challenger =
        RecursiveChallenger::<F, C::Hasher, D>::new(&mut builder);

    let degree_bits = all_proof.stark_proofs[Table::KeccakPermutation as usize]
        .proof
        .recover_degree_bits(&config);
    let num_ctl_zs = CrossTableLookup::num_ctl_zs(
        &all_stark.cross_table_lookups,
        Table::KeccakPermutation,
        config.num_challenges,
    );

    let perm_stark_proof_target = add_virtual_stark_proof(
        &mut builder,
        all_stark.keccak_permutation_stark,
        &config,
        degree_bits,
        num_ctl_zs,
    );

    challenger.observe_cap(&perm_stark_proof_target.trace_cap);

    let degree_bits = all_proof.stark_proofs[Table::KeccakSponge as usize]
        .proof
        .recover_degree_bits(&config);
    let num_ctl_zs = CrossTableLookup::num_ctl_zs(
        &all_stark.cross_table_lookups,
        Table::KeccakSponge,
        config.num_challenges,
    );

    let stark_proof_with_pis_target = add_virtual_stark_proof_with_pis(
        &mut builder,
        all_stark.keccak_sponge_stark,
        &config,
        degree_bits,
        num_ctl_zs,
    );

    challenger.observe_cap(&stark_proof_with_pis_target.proof.trace_cap);

    let degree_bits = all_proof.stark_proofs[Table::KeccakXor as usize]
        .proof
        .recover_degree_bits(&config);
    let num_ctl_zs = CrossTableLookup::num_ctl_zs(
        &all_stark.cross_table_lookups,
        Table::KeccakXor,
        config.num_challenges,
    );

    let xor_stark_proof_target = add_virtual_stark_proof(
        &mut builder,
        all_stark.keccak_xor_stark,
        &config,
        degree_bits,
        num_ctl_zs,
    );

    challenger.observe_cap(&xor_stark_proof_target.trace_cap);

    let ctl_challenges_target = PermutationChallengeSet {
        challenges: (0..config.num_challenges)
            .map(|_| PermutationChallenge {
                beta: challenger.get_challenge(&mut builder),
                gamma: challenger.get_challenge(&mut builder),
            })
            .collect(),
    };

    // permutation
    set_stark_proof_target(
        &mut pw,
        &perm_stark_proof_target,
        &all_proof.stark_proofs[Table::KeccakPermutation as usize].proof,
        zero_target,
    );

    let num_permutation_zs = all_stark
        .keccak_permutation_stark
        .num_permutation_batches(&config);
    let num_permutation_batch_size = all_stark.keccak_permutation_stark.permutation_batch_size();
    let ctl_vars = CtlCheckVarsTarget::from_proof(
        Table::KeccakPermutation,
        &perm_stark_proof_target,
        &all_stark.cross_table_lookups,
        &ctl_challenges_target,
        num_permutation_zs,
    );

    let challenges = perm_stark_proof_target.get_challenges::<F, C>(
        &mut builder,
        &mut challenger,
        num_permutation_zs > 0,
        num_permutation_batch_size,
        &config,
    );

    verify_stark_proof_with_challenges_circuit::<F, C, KeccakPermutationStark<F, D>, D>(
        &mut builder,
        all_stark.keccak_permutation_stark.clone(),
        perm_stark_proof_target.clone(),
        None,
        challenges,
        &ctl_vars,
        &config,
    );

    // sponge
    set_stark_proof_with_pis_target(
        &mut pw,
        &stark_proof_with_pis_target,
        &all_proof.stark_proofs[Table::KeccakSponge as usize],
        zero_target,
    );

    // set PI (hash) from sponge stark
    builder.register_public_inputs(&stark_proof_with_pis_target.public_inputs);

    let num_permutation_zs = all_stark
        .keccak_sponge_stark
        .num_permutation_batches(&config);
    let num_permutation_batch_size = all_stark.keccak_sponge_stark.permutation_batch_size();
    let ctl_vars = CtlCheckVarsTarget::from_proof(
        Table::KeccakSponge,
        &stark_proof_with_pis_target.proof,
        &all_stark.cross_table_lookups,
        &ctl_challenges_target,
        num_permutation_zs,
    );

    let challenges = stark_proof_with_pis_target.proof.get_challenges::<F, C>(
        &mut builder,
        &mut challenger,
        num_permutation_zs > 0,
        num_permutation_batch_size,
        &config,
    );

    verify_stark_proof_with_challenges_circuit::<F, C, KeccakSpongeStark<F, D>, D>(
        &mut builder,
        all_stark.keccak_sponge_stark.clone(),
        stark_proof_with_pis_target.proof.clone(),
        Some(stark_proof_with_pis_target.public_inputs),
        challenges,
        &ctl_vars,
        &config,
    );

    // XOR
    set_stark_proof_target(
        &mut pw,
        &xor_stark_proof_target,
        &all_proof.stark_proofs[Table::KeccakXor as usize].proof,
        zero_target,
    );

    let num_permutation_zs = all_stark.keccak_xor_stark.num_permutation_batches(&config);
    let num_permutation_batch_size = all_stark.keccak_xor_stark.permutation_batch_size();
    let ctl_vars = CtlCheckVarsTarget::from_proof(
        Table::KeccakXor,
        &xor_stark_proof_target,
        &all_stark.cross_table_lookups,
        &ctl_challenges_target,
        num_permutation_zs,
    );

    let challenges = xor_stark_proof_target.get_challenges::<F, C>(
        &mut builder,
        &mut challenger,
        num_permutation_zs > 0,
        num_permutation_batch_size,
        &config,
    );
 
    verify_stark_proof_with_challenges_circuit::<F, C, KeccakXORStark<F, D>, D>(
        &mut builder,
        all_stark.keccak_xor_stark.clone(),
        xor_stark_proof_target.clone(),
        None,
        challenges,
        &ctl_vars,
        &config,
    );
    // println!("CTL openings: {:?}", all_proof.stark_proofs[Table::KeccakPermutation as usize].proof.openings.ctl_zs_last);
    // println!("CTL openings: {:?}", all_proof.stark_proofs[Table::KeccakSponge as usize].proof.openings.ctl_zs_last);
    // println!("CTL openings: {:?}", all_proof.stark_proofs[Table::KeccakXor as usize].proof.openings.ctl_zs_last);

    verify_cross_table_lookups_circuit(
        &mut builder,
        all_stark.cross_table_lookups.clone(),
        [
            perm_stark_proof_target.openings.ctl_zs_last,
            stark_proof_with_pis_target.proof.openings.ctl_zs_last,
            xor_stark_proof_target.openings.ctl_zs_last,
        ],
        &config,
    );
    let build_agg_circuit = Instant::now();
    let data = builder.build::<C>();
    let build_agg_circuit_time = build_agg_circuit.elapsed().as_secs_f32();
    let timing = TimingTree::new("prove aggregation: sponge & permutation & xor", Level::Debug);
    let to_prove_agg = Instant::now();
    let proof = data.prove(pw)?;
    let to_prove_agg_time = to_prove_agg.elapsed().as_secs_f32();
    println!("PUBLIC INPUTS: {:?}", proof.public_inputs);
    timing.print();

    assert_eq!(
        all_proof.stark_proofs[Table::KeccakSponge as usize].public_inputs,
        proof.public_inputs[0..8]
    );
    Ok((data, proof, build_agg_circuit_time, to_prove_agg_time))
}

/// Recursively verifies an inner proof.
pub fn verify_stark_proof_with_challenges_circuit<
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    S: Stark<F, D>,
    const D: usize,
>(
    builder: &mut CircuitBuilder<F, D>,
    stark: S,
    proof: StarkProofTarget<D>,
    public_inputs: Option<Vec<Target>>,
    challenges: StarkProofChallengesTarget<D>,
    ctl_vars: &[CtlCheckVarsTarget<F, D>],
    inner_config: &StarkConfig,
) where
    C::Hasher: AlgebraicHasher<F>,
    [(); S::COLUMNS]:,
    [(); S::PUBLIC_INPUTS]:,
{
    //check_permutation_options(&stark, &proof_with_pis, &challenges).unwrap();

    let pi = if public_inputs.is_some() {
        public_inputs.unwrap()
    } else {
        vec![]
    };

    let zero = builder.zero();
    let one = builder.one_extension();

    let StarkOpeningSetTarget {
        local_values,
        next_values,
        permutation_ctl_zs,
        permutation_ctl_zs_next,
        quotient_polys,
        ctl_zs_last,
    } = &proof.openings;
    let vars = StarkEvaluationTargets {
        local_values: &local_values.to_vec().try_into().unwrap(),
        next_values: &next_values.to_vec().try_into().unwrap(),
        public_inputs: &pi
            .into_iter()
            .map(|t| builder.convert_to_ext(t))
            .collect::<Vec<_>>()
            .try_into()
            .unwrap(),
    };

    let degree_bits = proof.recover_degree_bits(inner_config);
    let zeta_pow_deg = builder.exp_power_of_2_extension(challenges.stark_zeta, degree_bits);
    let z_h_zeta = builder.sub_extension(zeta_pow_deg, one);
    let (l_0, l_last) =
        eval_l_0_and_l_last_circuit(builder, degree_bits, challenges.stark_zeta, z_h_zeta);
    let last =
        builder.constant_extension(F::Extension::primitive_root_of_unity(degree_bits).inverse());
    let z_last = builder.sub_extension(challenges.stark_zeta, last);

    let mut consumer = RecursiveConstraintConsumer::<F, D>::new(
        builder.zero_extension(),
        challenges.stark_alphas,
        z_last,
        l_0,
        l_last,
    );

    let permutation_data = stark
        .uses_permutation_args()
        .then(|| PermutationCheckDataTarget {
            local_zs: permutation_ctl_zs.clone(),
            next_zs: permutation_ctl_zs_next.clone(),
            permutation_challenge_sets: challenges.permutation_challenge_sets.unwrap(),
        });

    with_context!(
        builder,
        "evaluate vanishing polynomial",
        eval_vanishing_poly_circuit::<F, S, D>(
            builder,
            &stark,
            inner_config,
            vars,
            permutation_data,
            ctl_vars,
            &mut consumer,
        )
    );
    let vanishing_polys_zeta = consumer.accumulators();

    // Check each polynomial identity, of the form `vanishing(x) = Z_H(x) quotient(x)`, at zeta.
    let mut scale = ReducingFactorTarget::new(zeta_pow_deg);
    for (i, chunk) in quotient_polys
        .chunks(stark.quotient_degree_factor())
        .enumerate()
    {
        let recombined_quotient = scale.reduce(chunk, builder);
        let computed_vanishing_poly = builder.mul_extension(z_h_zeta, recombined_quotient);
        builder.connect_extension(vanishing_polys_zeta[i], computed_vanishing_poly);
    }

    let merkle_caps = vec![
        proof.trace_cap.clone(),
        proof.permutation_ctl_zs_cap.clone(),
        proof.quotient_polys_cap.clone(),
    ];

    let fri_instance = stark.fri_instance_target(
        builder,
        challenges.stark_zeta,
        F::primitive_root_of_unity(degree_bits),
        degree_bits,
        ctl_zs_last.len(),
        inner_config,
    );
    builder.verify_fri_proof::<C>(
        &fri_instance,
        &proof.openings.to_fri_openings(zero),
        &challenges.fri_challenges,
        &merkle_caps,
        &proof.opening_proof,
        &inner_config.fri_params(degree_bits),
    );
}

fn eval_l_0_and_l_last_circuit<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    log_n: usize,
    x: ExtensionTarget<D>,
    z_x: ExtensionTarget<D>,
) -> (ExtensionTarget<D>, ExtensionTarget<D>) {
    let n = builder.constant_extension(F::Extension::from_canonical_usize(1 << log_n));
    let g = builder.constant_extension(F::Extension::primitive_root_of_unity(log_n));
    let one = builder.one_extension();
    let l_0_deno = builder.mul_sub_extension(n, x, n);
    let l_last_deno = builder.mul_sub_extension(g, x, one);
    let l_last_deno = builder.mul_extension(n, l_last_deno);

    (
        builder.div_extension(z_x, l_0_deno),
        builder.div_extension(z_x, l_last_deno),
    )
}
