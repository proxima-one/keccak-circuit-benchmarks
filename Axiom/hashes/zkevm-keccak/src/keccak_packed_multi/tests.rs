use std::vec;

use super::*;
use crate::halo2_proofs::{
    circuit::SimpleFloorPlanner,
    dev::MockProver,
    halo2curves::bn256::Fr,
    halo2curves::bn256::{Bn256, G1Affine},
    plonk::{create_proof, keygen_pk, keygen_vk, verify_proof},
    plonk::{Circuit, FirstPhase},
    poly::{
        commitment::ParamsProver,
        kzg::{
            commitment::{KZGCommitmentScheme, ParamsKZG, ParamsVerifierKZG},
            multiopen::{ProverSHPLONK, VerifierSHPLONK},
            strategy::SingleStrategy,
        },
    },
    transcript::{
        Blake2bRead, Blake2bWrite, Challenge255, TranscriptReadBuffer, TranscriptWriterBuffer,
    },
};
use rand_core::OsRng;
use log::{debug, info};
use std::time::{Duration, Instant};
use serde::{Deserialize, Serialize};
use std::{
    env::{set_var, var},
    fs::File,
    io::{BufRead, BufReader, Write},
};


/// KeccakCircuit
#[derive(Default, Clone, Debug)]
pub struct KeccakCircuit<F: Field> {
    inputs: Vec<Vec<u8>>,
    num_rows: Option<usize>,
    _marker: PhantomData<F>,
}

#[cfg(any(feature = "test", test))]
impl<F: Field> Circuit<F> for KeccakCircuit<F> {
    type Config = KeccakCircuitConfig<F>;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        // MockProver complains if you only have columns in SecondPhase, so let's just make an empty column in FirstPhase
        meta.advice_column();

        let challenge = meta.challenge_usable_after(FirstPhase);
        KeccakCircuitConfig::new(meta, challenge)
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        config.load_aux_tables(&mut layouter)?;
        let mut challenge = layouter.get_challenge(config.challenge);
        let mut first_pass = true;
        layouter.assign_region(
            || "keccak circuit",
            |mut region| {
                if first_pass {
                    first_pass = false;
                    return Ok(());
                }
                let (witness, squeeze_digests) = multi_keccak_phase0(&self.inputs, self.capacity());
                info!("Hi 1");
                config.assign(&mut region, &witness);

                #[cfg(feature = "halo2-axiom")]
                {
                    region.next_phase();
                    challenge = region.get_challenge(config.challenge);
                }
                multi_keccak_phase1(
                    &mut region,
                    &config.keccak_table,
                    self.inputs.iter().map(|v| v.as_slice()),
                    challenge,
                    squeeze_digests,
                );
                Ok(())
            },
        )?;

        Ok(())
    }
}

impl<F: Field> KeccakCircuit<F> {
    /// Creates a new circuit instance
    pub fn new(num_rows: Option<usize>, inputs: Vec<Vec<u8>>) -> Self {
        KeccakCircuit { inputs, num_rows, _marker: PhantomData }
    }

    /// The number of keccak_f's that can be done in this circuit
    pub fn capacity(&self) -> Option<usize> {
        // Subtract two for unusable rows
        self.num_rows.map(|num_rows| num_rows / ((NUM_ROUNDS + 1) * get_num_rows_per_round()) - 2)
    }
}

fn verify<F: Field>(k: u32, inputs: Vec<Vec<u8>>, _success: bool) {
    let circuit = KeccakCircuit::new(Some(2usize.pow(k)), inputs);
    let prover = MockProver::<F>::run(k, &circuit, vec![vec![]]).unwrap();
    assert_eq!(prover.verify(), Ok(()));
    prover.assert_satisfied();
}

/// Cmdline: KECCAK_ROWS=28 KECCAK_DEGREE=14 RUST_LOG=info cargo test -- --nocapture packed_multi_keccak_simple
#[test]
fn packed_multi_keccak_simple() {
    let _ = env_logger::builder().is_test(true).try_init();
    let k = 14;
    let num_vectors = 1;
    let vector_length = 136;

    let inputs: Vec<Vec<u8>> = (0..num_vectors)
        .map(|_| (0u8..vector_length).collect())
        .collect();
    verify::<Fr>(k, inputs, true);
}


fn test_packed_multi(i: i32, k: u32) -> (i32, usize, f64, f64, usize, f64, f64 ){
    let capacity = 1;
    let message_len = 136 * i;
    let inputs = (0..capacity)
        .map(|_| (0..message_len).map(|_| rand::random::<u8>()).collect_vec())
        .collect_vec();
    let start_setup = Instant::now();
    let params = ParamsKZG::<Bn256>::setup(k, OsRng);
    let circuit = KeccakCircuit::new(Some(2usize.pow(k)), inputs);
    let elapsed_setup = start_setup.elapsed();
    let circuit_build_time = elapsed_setup.as_secs_f64();
    let start_keygen_vk = Instant::now();
    let vk = keygen_vk(&params, &circuit).unwrap();
    let pk = keygen_pk(&params, vk, &circuit).unwrap();
    let verifier_params: ParamsVerifierKZG<Bn256> = params.verifier_params().clone();
    let mut transcript = Blake2bWrite::<_, G1Affine, Challenge255<_>>::init(vec![]);
    let elapsed_keygen_vk = start_keygen_vk.elapsed();
    let trusted_setup_time = elapsed_keygen_vk.as_secs_f64();
    let start_proof_gen = Instant::now();
    create_proof::<
        KZGCommitmentScheme<Bn256>,
        ProverSHPLONK<'_, Bn256>,
        Challenge255<G1Affine>,
        _,
        Blake2bWrite<Vec<u8>, G1Affine, Challenge255<G1Affine>>,
        _,
    >(&params, &pk, &[circuit.clone()], &[&[]], OsRng, &mut transcript)
    .expect("proof generation should not fail");
    let proof = transcript.finalize();
    let elapsed_proof_gen = start_proof_gen.elapsed();
    let proof_generation_time = elapsed_proof_gen.as_secs_f64();
    let start_proof_verif = Instant::now();
    let mut verifier_transcript = Blake2bRead::<_, G1Affine, Challenge255<_>>::init(&proof[..]);
    let strategy = SingleStrategy::new(&params);

    verify_proof::<
        KZGCommitmentScheme<Bn256>,
        VerifierSHPLONK<'_, Bn256>,
        Challenge255<G1Affine>,
        Blake2bRead<&[u8], G1Affine, Challenge255<G1Affine>>,
        SingleStrategy<'_, Bn256>,
    >(&verifier_params, pk.get_vk(), strategy, &[&[]], &mut verifier_transcript)
    .expect("failed to verify bench circuit");
    let elapsed_proof_verif = start_proof_verif.elapsed();
    let proof_verification_time = elapsed_proof_verif.as_secs_f64();

    (
        message_len,
        circuit.capacity().unwrap(),
        circuit_build_time,
        proof_generation_time,
        proof.len(),
        proof_verification_time,
        trusted_setup_time,
    )

}


#[derive(Serialize, Deserialize)]
pub struct KeccakBenchConfig {
    degree: u32,
    rows_per_round: usize,
}
/// Cmdline: RUST_LOG=info cargo test -- --nocapture packed_multi_keccak_prover
#[test]
fn packed_multi_keccak_prover() {
    let _ = env_logger::builder().is_test(true).try_init();
    let bench_params_file = File::open("data/config.json").unwrap();
    let bench_params_reader = BufReader::new(bench_params_file);
    let bench_params: Vec<KeccakBenchConfig> =
        serde_json::from_reader(bench_params_reader).unwrap();
    std::fs::create_dir_all("bench").unwrap();
    for bench_params in bench_params {
        let file_path = format!("bench/keccak_k_{}_r_{}.csv", bench_params.degree, bench_params.rows_per_round);
        let mut fs_results = File::create(file_path).unwrap();
        writeln!(
            fs_results,
            "msg_len,keccak_capacity,time_build_curcuit,time_create_proof,proof_size,time_verify_proof, trusted_setup_generation"
        )   
        .unwrap();
        set_var("KECCAK_ROWS", bench_params.rows_per_round.to_string());
        set_var("KECCAK_DEGREE", bench_params.degree.to_string());
        for i in 372..=1000{
            let output = test_packed_multi(i, bench_params.degree);
            writeln!(
                fs_results,
                "{},{},{},{},{},{},{}",
            output.0,
            output.1,
            output.2,
            output.3,
            output.4,
            output.5,
            output.6
            )
            .unwrap();
        }
    }
}


