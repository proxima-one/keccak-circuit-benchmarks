use std;
use criterion::{criterion_group, criterion_main, Criterion};
use p3_baby_bear::BabyBear;
use p3_challenger::DuplexChallenger;
use p3_dft::Radix2Bowers;
use p3_field::extension::quadratic::QuadraticBef;
use p3_fri::{FriBasedPcs, FriConfigImpl, FriLdt};
use p3_goldilocks::Goldilocks;
use p3_keccak::Keccak256Hash;
use p3_keccak_air::{generate_trace_rows, KeccakAir};
use p3_ldt::QuotientMmcs;
use p3_mds::coset_mds::CosetMds;
use p3_merkle_tree::MerkleTreeMmcs;
use p3_poseidon::Poseidon;
use p3_symmetric::compression::CompressionFunctionFromHasher;
use p3_symmetric::{hasher::SerializingHasher32};
use p3_uni_stark::{prove, verify, StarkConfigImpl, VerificationError};
use rand::thread_rng;

fn keccak_air_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("keccak_air_prover");
    group.sample_size(10);

    const NUM_PERMS: usize = 736; // 100,000 bytes - 736 perms

    let input: Vec<[u64; 25]> = (0..NUM_PERMS).map(|_| rand::random()).collect();
    group.bench_function("keccak_air_prover", move |b| {
        b.iter(|| keccak_prover_bench(input.clone()))
    });
}

fn keccak_prover_bench(input: Vec<[u64; 25]>) -> Result<(), VerificationError> {
    type Val = Goldilocks;
    type Domain = Val;
    type Challenge = Val;

    type MyMds = CosetMds<Val, 16>;
    let mds = MyMds::default();

    type Perm = Poseidon<Val, MyMds, 16, 5>;
    let perm = Perm::new_from_rng(4, 22, mds, &mut thread_rng());

    // If we use Keccak256Hash, uncomment the following:
    type MyHash = SerializingHasher32<Val, Keccak256Hash>;
    let hash = MyHash::new(Keccak256Hash {});

    type MyCompress = CompressionFunctionFromHasher<Val, MyHash, 2, 8>;
    let compress = MyCompress::new(hash);

    // // If we use PoseidonHash, uncomment the following:
    // type MyHash = PaddingFreeSponge<Val, Perm, 16, 8, 8>;
    // let hash = MyHash::new(perm.clone());

    // type MyCompress = TruncatedPermutation<Val, Perm, 2, 8, 16>;
    // let compress = MyCompress::new(perm.clone());

    type MyMmcs = MerkleTreeMmcs<Val, [Val; 8], MyHash, MyCompress>;
    let mmcs = MyMmcs::new(hash, compress);

    type Dft = Radix2Bowers;
    let dft = Dft {};

    type Challenger = DuplexChallenger<Val, Perm, 16>;

    type Quotient = QuotientMmcs<Domain, Challenge, MyMmcs>;
    type MyFriConfig = FriConfigImpl<Val, Domain, Challenge, Quotient, MyMmcs, Challenger>;
    let fri_config = MyFriConfig::new(50, mmcs.clone());
    let ldt = FriLdt { config: fri_config };

    type Pcs = FriBasedPcs<MyFriConfig, MyMmcs, Dft, Challenger>;
    type MyConfig = StarkConfigImpl<Val, Domain, Challenge, Pcs, Dft, Challenger>;

    let trace = generate_trace_rows::<Val>(input, 8);

    let pcs = Pcs::new(dft, 1, mmcs, ldt);
    let config = StarkConfigImpl::new(pcs, Dft {});
    let mut challenger = Challenger::new(perm.clone());
    let proof = prove::<MyConfig, _>(&config, &KeccakAir {}, &mut challenger, trace);
    let mut challenger = Challenger::new(perm);
    let ver = verify(&config, &KeccakAir {}, &mut challenger, &proof);
    ver
}

criterion_group!(benches, keccak_air_benchmark);
criterion_main!(benches);
