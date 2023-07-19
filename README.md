# keccak-circuit-benchmarks
Benchmarks of all public available SNARK/STARK keccak circuits

This repositore contains benchmarks of implementations keccak circuits using diffrenet frameworks, and can be extended  more in the future (feel free to add new implementations).


## Implementations
- [x] [Axiom using halo2-lib](https://github.com/axiom-crypto/halo2-lib/tree/community-edition/hashes/zkevm-keccak)
- [x] [JumpCrypto using plonky2](https://github.com/JumpCrypto/plonky2-crypto/blob/main/src/hash/keccak256.rs)


## Running benchmarks
rust with nightly

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