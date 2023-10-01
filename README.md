# keccak-circuit-benchmarks
Benchmarks of all public available SNARK/STARK keccak circuits

This repository contains benchmarks of implementations keccak circuits using different frameworks, and can be extended  more in the future (feel free to add new implementations). Short description of benchmarking and results of comparison implementations effectivness by Maru, Axiom, JumpCrypto you can find by [link](https://github.com/proxima-one/keccak-circuit-benchmarks/blob/master/short_description.pdf). The full benchmarking description of each params and operations used in circuit implementations you can find by [link](https://github.com/proxima-one/keccak-circuit-benchmarks/blob/master/full_description.pdf).


## Implementations
- [x] [Axiom using halo2-lib](https://github.com/axiom-crypto/halo2-lib/tree/community-edition/hashes/zkevm-keccak)
- [x] [JumpCrypto using plonky2](https://github.com/JumpCrypto/plonky2-crypto/blob/main/src/hash/keccak256.rs)
- [x] [Maru implementation using plonky2 and starky](https://github.com/proxima-one/keccak_ctl)
- [x] [Polygon Zero implementation using plonky3](https://github.com/Plonky3/Plonky3/blob/main/keccak-air/src/air.rs)
## Running benchmarks
Dependencies: rust with nightly

To run Axiom benchmark:


```
cd Axiom/hashes/zkevm-keccak
RUST_LOG=info cargo test -- --nocapture packed_multi_keccak_prover
```


To run JumpCrypto benchmark:

```
cd JumpCrypto
cargo run --release
```

To run Maru benchmark:

```
cd Maru/keccak_ctl
RUSTFLAGS=-Ctarget-cpu=native cargo run --release
```

To run Polygon Zero benchmark:

```
cd PolygonZero-plonky3/Plonky3/keccak-air
cargo bench -- --nocapture
```
