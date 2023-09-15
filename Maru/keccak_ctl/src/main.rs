use std::borrow::Borrow;
use std::fs::File;
use std::io::Write;
use std::time::Instant;
use anyhow::Result;
use keccak_ctl::keccak_proof::keccak256proof_stark;
use keccak_ctl::verifier_ctl::keccak256verify_stark;
use keccak_hash::keccak;
use plonky2::{field::goldilocks_field::GoldilocksField, plonk::config::PoseidonGoldilocksConfig};
use keccak_ctl::stark_aggregation::aggregation_sponge_permutation;

const D: usize = 2;
type G = GoldilocksField;
type PG = PoseidonGoldilocksConfig;

fn bench_keccak_136_000() {
    std::fs::create_dir_all("bench").unwrap();
    let file_path = format!("bench/keccak_136_000.csv");
    let mut fs_results = File::create(file_path).unwrap();

    writeln!(
        fs_results,
        "{}", "generate_sponge_proof_time,"
            .to_owned() +
            "verify_sponge_time," +
            "verify_sponge_proof_time," +
            "generate_permutations_proof," +
            "verify_permutations," +
            "generate_xor_proof," +
            "verify_xor_time," +
            "keccak_sponge_proof_size," +
            "permutations_proof_size," +
            "xor_proof_size," +
            "verify_ctl_time," +
            "generate_sponge_traces," +
            "generate_permutations_traces," +
            "generate_xor_traces," +
            "generate_trace_commitments," +
            "verifier_config," +
            "build_agg_circuit," +
            "prove_aggregation," +
            "verify_aggregation," +
            "aggregated_proof_size," +
            "input_length"
    ).expect("File not exists");
    for i in 1..=1000 {
        let output = keccak_evaluate(i);
        writeln!(
            fs_results,
            "{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{}",
            output.0,
            output.1,
            output.2,
            output.3,
            output.4,
            output.5,
            output.6,
            output.7,
            output.8,
            output.15,
            output.10,
            output.11,
            output.12,
            output.13,
            output.14,
            output.16,
            output.17,
            output.18,
            output.19,
            output.9
        )
            .unwrap();
    }
}

fn keccak_evaluate(i: usize) -> (f32, f32, f32, f32, f32, f32, usize, usize, usize, usize, f32, f32, f32, f32, f32, f32, f32, f32, f32, usize) {
    let msg_len: usize = 136 * i;
    let input: Vec<u8> = (0..msg_len).map(|_| rand::random()).collect();
    let expected = keccak(&input);
    let (stark, proof, generate_sponge_traces, generate_xor_traces,
        generate_permutations_traces, generate_sponge_proof_time, generate_perm_proof_time, generate_xor_proof_time,
        generate_trace_commitments_time, keccak_permutation_proof_size,
        keccak_sponge_proof_size, keccak_xor_proof_size) = keccak256proof_stark::<G, PG, D>(&input, expected.as_bytes());
    let (verifier_config_time, verify_permutations_time, verify_sponge_time,
        verify_xor_time, verify_ctl_time) = keccak256verify_stark(stark.clone(), proof.clone());
    let (data, proof,
        build_agg_circuit_time, to_prove_agg_time) = aggregation_sponge_permutation(&stark, proof).unwrap();
    let verify_agg = Instant::now();
    data.verify(proof.clone()).unwrap();
    let verify_agg_time = verify_agg.elapsed().as_secs_f32();
    let agg_proof_size = proof.to_bytes().len();
    (
        generate_sponge_proof_time,
        verify_sponge_time,
        generate_perm_proof_time,
        verify_permutations_time,
        generate_xor_proof_time,
        verify_xor_time,
        keccak_sponge_proof_size,
        keccak_permutation_proof_size,
        keccak_xor_proof_size,
        msg_len,
        generate_sponge_traces,
        generate_permutations_traces,
        generate_xor_traces,
        generate_trace_commitments_time,
        verifier_config_time,
        verify_ctl_time,
        build_agg_circuit_time,
        to_prove_agg_time,
        verify_agg_time,
        agg_proof_size
    )
}


fn main() -> Result<()> {
    bench_keccak_136_000();

    // const MSG_LEN: usize = 136;
    // let input: Vec<u8> = (0..MSG_LEN).map(|_| rand::random()).collect();
    // let expected = keccak(&input);
    // let expected_false: Vec<u8> = (0..32).map(|_| rand::random()).collect();
    //
    // let (data, proof) = keccak256::<F, C, D>(&input, expected.as_bytes())?;
    //
    // data.verify(proof.clone())?;
    //
    // println!("Proof size: {} bytes", proof.to_bytes().len());
    Ok(())
}