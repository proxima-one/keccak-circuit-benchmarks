use env_logger::{try_init_from_env, Env, DEFAULT_FILTER_ENV};
use keccak256::{
    keccak256::{CircuitBuilderHashKeccak, WitnessHashKeccak, KECCAK256_R},
    types::CircuitBuilderHash,
};
use keccak_hash::keccak;
use plonky2::{
    iop::witness::PartialWitness,
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::CircuitConfig,
        config::{GenericConfig, KeccakGoldilocksConfig},
    },
    util::timing::TimingTree,
};
use rayon::vec;
use sha3::{Digest, Keccak256};
use std::time::{Instant};
use std::{
    fs::File,
    io::{BufRead, BufReader, Write},
};



fn benchmark(i: usize, block_num: usize) -> (usize, f32, f32, usize, f32){
    const D: usize = 2;
    type C = KeccakGoldilocksConfig;
    type F = <C as GenericConfig<D>>::F;
    let message_length = i * 136;
    let input_data: Vec<u8> = vec![1; message_length];
    let output_hash = keccak(&input_data);
    let config = CircuitConfig::standard_recursion_config();
    let mut circuit_builder = CircuitBuilder::<F, D>::new(config);
    let circuit_build_start_time = Instant::now();
    let hash_target = circuit_builder.add_virtual_hash_input_target(block_num, KECCAK256_R);
    let hash_output = circuit_builder.hash_keccak256(&hash_target);
    let circuit_data = circuit_builder.build::<C>();
    let circuit_building_time = circuit_build_start_time.elapsed().as_secs_f32();
    let mut hasher = Keccak256::new();
    hasher.update(input_data.as_slice());
    let hash_result = hasher.finalize();
    assert_eq!(hash_result[..], output_hash[..]);
    let proof_gen_start_time = Instant::now();
    let mut partial_witness = PartialWitness::new();
    partial_witness.set_keccak256_input_target(&hash_target, &input_data);
    partial_witness.set_keccak256_output_target(&hash_output, &output_hash.as_bytes());
    let proof = circuit_data.prove(partial_witness).unwrap();
    let proof_gen_time = proof_gen_start_time.elapsed().as_secs_f32();
    let proof_size = proof.to_bytes().len();
    let proof_verif_start_time = Instant::now();
    let verification_result = circuit_data.verify(proof);
    let proof_verif_time = proof_verif_start_time.elapsed().as_secs_f32();
    assert!(verification_result.is_ok());
    (input_data.len(), circuit_building_time, proof_gen_time, proof_size, proof_verif_time)
}

// cargo run --release
fn main() {
    std::fs::create_dir_all("bench").unwrap();
    let mut block_num : usize = 4;
    let file_path = format!("bench/keccak_jump_crypto.csv");
    let mut fs_results = File::create(file_path).unwrap();
    writeln!(
        fs_results,
        "msg_len,block_nums,time_build_curcuit,time_create_proof,proof_size,time_verify_proof"
    )   
    .unwrap();
    for i in 1..=1000{
        if i + 1 >= block_num{
            block_num += 4;
        }
        let output = benchmark(i, block_num);
        writeln!(
            fs_results,
            "{},{},{},{},{},{}",
        output.0,
        block_num,
        output.1,
        output.2,
        output.3,
        output.4,
        )
        .unwrap();
    }
}