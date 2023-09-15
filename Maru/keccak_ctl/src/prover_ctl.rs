use std::any::type_name;
use std::time::Instant;

use anyhow::{ensure, Result};
use env_logger::try_init_from_env;
use itertools::Itertools;
use log::{debug, info};
use plonky2::field::extension::Extendable;
use plonky2::field::packable::Packable;
use plonky2::field::packed::PackedField;
use plonky2::field::polynomial::{PolynomialCoeffs, PolynomialValues};
use plonky2::field::types::Field;
use plonky2::field::zero_poly_coset::ZeroPolyOnCoset;
use plonky2::fri::oracle::PolynomialBatch;
use plonky2::hash::hash_types::RichField;
use plonky2::iop::challenger::Challenger;
use plonky2::plonk::config::GenericConfig;
use plonky2::timed;
use plonky2::util::timing::TimingTree;
use plonky2::util::transpose;
use plonky2_util::{log2_ceil, log2_strict};
use starky_ctl::permutation::get_permutation_challenge_set;
use starky_ctl::proof::StarkProofWithPublicInputs;
use starky_ctl::prover::prove_single_table;
use starky_ctl::stark::Stark;
use starky_ctl::table::{Table, NUM_TABLES};

use crate::keccak_ctl_stark::KeccakCtl;
use crate::keccak_permutation::keccak_permutation_stark::{KeccakPermutationStark, NUM_INPUTS};
use crate::keccak_sponge::columns::{KECCAK_RATE_BYTES, KECCAK_WIDTH_U32S};
use crate::keccak_sponge::keccak_sponge_stark::{KeccakSpongeOp, KeccakSpongeStark};
use crate::proof_ctl::KeccakCtlProof;
use plonky2::plonk::config::Hasher;
use tiny_keccak::keccakf;
use starky_ctl::config::StarkConfig;
use starky_ctl::constraint_consumer::ConstraintConsumer;
use starky_ctl::cross_table_lookup::{cross_table_lookup_data, CtlCheckVars, CtlData};
use starky_ctl::proof::{StarkOpeningSet, StarkProof};
use starky_ctl::vars::StarkEvaluationVars;
use crate::keccak_sponge::keccak_util::keccakf_u32s;
use crate::keccak_xor::xor_stark::KeccakXORStark;

pub fn generate_traces<F, C, const D: usize>(
    all_stark: &KeccakCtl<F, D>,
    msg: &[u8],
    timing: &mut TimingTree,
) -> ([Vec<PolynomialValues<F>>; NUM_TABLES], f32, f32, f32)
    where
        F: RichField + Extendable<D>,
        [(); KeccakPermutationStark::<F, D>::COLUMNS]:,
        [(); KeccakSpongeStark::<F, D>::COLUMNS]:,
        [(); KeccakXORStark::<F, D>::COLUMNS]:
{
    let sponge_operations = KeccakSpongeOp {
        input: msg.to_vec(),
    };
    let generate_sponge_circuit = Instant::now();
    let (sponge_poly_values, sponge_states, states_ctl) = timed!(
        timing,
        "generate sponge trace",
        all_stark
            .keccak_sponge_stark
            .generate_trace(sponge_operations, 8, timing)
    );
    let generate_sponge_circuit_time = generate_sponge_circuit.elapsed().as_secs_f32();
    let generate_xor_circuit = Instant::now();
    let xor_poly_values = timed!(
        timing,
        "generate xor trace",
        all_stark.keccak_xor_stark.generate_trace(
            states_ctl,
            8,
            timing
        )
    );
    let generate_xor_circuit_time = generate_xor_circuit.elapsed().as_secs_f32();
    let generate_permutations_circuit = Instant::now();
    let input_permutation: Vec<[u64; NUM_INPUTS]> = sponge_states
        .iter()
        .map(|x| u32_to_u64_reverse(x).try_into().unwrap())
        .collect_vec();
    let permutation_poly_values = timed!(
        timing,
        "generate permutation trace",
        all_stark
            .keccak_permutation_stark
            .generate_trace(input_permutation, 8, timing)
    );
    let generate_permutations_circuit_time = generate_permutations_circuit.elapsed().as_secs_f32();
    ([permutation_poly_values, sponge_poly_values, xor_poly_values],generate_sponge_circuit_time, generate_xor_circuit_time, generate_permutations_circuit_time)
}

/// Compute all STARK proofs.
pub fn prove_with_traces<F, C, const D: usize>(
    all_stark: &KeccakCtl<F, D>,
    config: &StarkConfig,
    trace_poly_values: [Vec<PolynomialValues<F>>; NUM_TABLES],
    public_inputs: Option<[F; KeccakSpongeStark::<F, D>::PUBLIC_INPUTS]>,
    timing: &mut TimingTree,
) -> (KeccakCtlProof<F, C, D>, f32, f32, f32, f32, usize, usize, usize)
    where
        F: RichField + Extendable<D>,
        C: GenericConfig<D, F = F>,
        [(); KeccakPermutationStark::<F, D>::COLUMNS]:,
        [(); KeccakPermutationStark::<F, D>::PUBLIC_INPUTS]:,
        [(); KeccakSpongeStark::<F, D>::COLUMNS]:,
        [(); KeccakSpongeStark::<F, D>::PUBLIC_INPUTS]:,
        [(); KeccakXORStark::<F, D>::COLUMNS]:,
{
    let generate_trace_commitments = Instant::now();
    let rate_bits = config.fri_config.rate_bits;
    let cap_height = config.fri_config.cap_height;

    let trace_commitments = timed!(
        timing,
        "compute all trace commitments",
        trace_poly_values
            .iter()
            .zip_eq(Table::all())
            .map(|(trace, table)| {
                timed!(
                    timing,
                    &format!("compute trace commitment for {:?}", table),
                    PolynomialBatch::<F, C, D>::from_values(
                        // TODO: Cloning this isn't great; consider having `from_values` accept a reference,
                        // or having `compute_permutation_z_polys` read trace values from the `PolynomialBatch`.
                        trace.clone(),
                        rate_bits,
                        false,
                        cap_height,
                        timing,
                        None,
                    )
                )
            })
            .collect::<Vec<_>>()
    );

    let trace_caps = trace_commitments
        .iter()
        .map(|c| c.merkle_tree.cap.clone())
        .collect::<Vec<_>>();
    let mut challenger = Challenger::<F, C::Hasher>::new();
    for cap in &trace_caps {
        challenger.observe_cap(cap);
    }

    let ctl_challenges = get_permutation_challenge_set(&mut challenger, config.num_challenges);

    let ctl_data_per_table = timed!(
        timing,
        "compute CTL data",
        cross_table_lookup_data::<F, D>(
            &trace_poly_values,
            &all_stark.cross_table_lookups,
            &ctl_challenges,
        )
    );
    let generate_trace_commitments_time = generate_trace_commitments.elapsed().as_secs_f32();
    let stark_proofs = timed!(
        timing,
        "compute all proofs given commitments",
        prove_with_commitments(
            all_stark,
            config,
            trace_poly_values,
            trace_commitments,
            public_inputs,
            ctl_data_per_table,
            &mut challenger,
            timing
        ).unwrap()
    );
    (KeccakCtlProof {
        stark_proofs: stark_proofs.0,
        ctl_challenges,
    }, stark_proofs.1, stark_proofs.2, stark_proofs.3, generate_trace_commitments_time, stark_proofs.4, stark_proofs.5, stark_proofs.6)
}

/// Compute proof for a single STARK table.
pub fn prove_with_commitments<F, C, const D: usize>(
    all_stark: &KeccakCtl<F, D>,
    config: &StarkConfig,
    trace_poly_values: [Vec<PolynomialValues<F>>; NUM_TABLES],
    trace_commitments: Vec<PolynomialBatch<F, C, D>>,
    public_inputs: Option<[F; KeccakSpongeStark::<F, D>::PUBLIC_INPUTS]>,
    ctl_data_per_table: [CtlData<F>; NUM_TABLES],
    challenger: &mut Challenger<F, C::Hasher>,
    timing: &mut TimingTree,
) -> Result<([StarkProofWithPublicInputs<F, C, D>; NUM_TABLES], f32, f32, f32, usize, usize, usize)>
    where
        F: RichField + Extendable<D>,
        C: GenericConfig<D, F = F>,
        [(); KeccakPermutationStark::<F, D>::COLUMNS]:,
        [(); KeccakPermutationStark::<F, D>::PUBLIC_INPUTS]:,
        [(); KeccakSpongeStark::<F, D>::COLUMNS]:,
        [(); KeccakSpongeStark::<F, D>::PUBLIC_INPUTS]:,
        [(); KeccakXORStark::<F, D>::COLUMNS]:,
{
    let generate_perm_proof = Instant::now();
    let keccak_permutation_proof = timed!(
        timing,
        "prove Keccak permutation STARK",
        prove_single_table(
            &all_stark.keccak_permutation_stark,
            config,
            &trace_poly_values[Table::KeccakPermutation as usize],
            &trace_commitments[Table::KeccakPermutation as usize],
            None,
            &ctl_data_per_table[Table::KeccakPermutation as usize],
            challenger,
            timing,
        )?
    );
    let generate_perm_proof_time = generate_perm_proof.elapsed().as_secs_f32();
    let generate_sponge_proof = Instant::now();
    let keccak_sponge_proof = timed!(
        timing,
        "prove Keccak sponge STARK",
        prove_single_table(
            &all_stark.keccak_sponge_stark,
            config,
            &trace_poly_values[Table::KeccakSponge as usize],
            &trace_commitments[Table::KeccakSponge as usize],
            public_inputs.try_into().unwrap(),
            &ctl_data_per_table[Table::KeccakSponge as usize],
            challenger,
            timing,
        )?
    );
    let generate_sponge_proof_time = generate_sponge_proof.elapsed().as_secs_f32();
    let generate_xor_proof = Instant::now();
    let keccak_xor_proof = timed!(
        timing,
        "prove Keccak XOR STARK",
        prove_single_table(
            &all_stark.keccak_xor_stark,
            config,
            &trace_poly_values[Table::KeccakXor as usize],
            &trace_commitments[Table::KeccakXor as usize],
            None,
            &ctl_data_per_table[Table::KeccakXor as usize],
            challenger,
            timing,
        )?
    );
    let generate_xor_proof_time = generate_xor_proof.elapsed().as_secs_f32();
    let keccak_permutation_proof_size = keccak_permutation_proof.clone().to_bytes().len();
    let keccak_sponge_proof_size = keccak_sponge_proof.clone().to_bytes().len();
    let keccak_xor_proof_size = keccak_xor_proof.clone().to_bytes().len();
    Ok(([keccak_permutation_proof, keccak_sponge_proof, keccak_xor_proof], generate_sponge_proof_time, generate_perm_proof_time, generate_xor_proof_time,keccak_permutation_proof_size,keccak_sponge_proof_size,keccak_xor_proof_size   ))
}

pub fn u32_to_u64_reverse(vecu32: &[u32]) -> Vec<u64> {
    assert!(vecu32.len() >= 2);
    assert_eq!(vecu32.len() % 2, 0);
    let mut vecu64: Vec<u64> = Vec::new();
    for i in (0..vecu32.len()).step_by(2) {
        let a: u64 = ((vecu32[i + 1] as u64) << 32) | (vecu32[i] as u64); //REVERSE
        vecu64.push(a);
    }
    vecu64
}

