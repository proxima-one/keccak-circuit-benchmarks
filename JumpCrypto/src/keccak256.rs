use num::BigUint;
use plonky2::field::extension::Extendable;
use plonky2::field::types::PrimeField64;
use plonky2::hash::hash_types::RichField;
use plonky2::iop::witness::Witness;
use plonky2::plonk::circuit_builder::CircuitBuilder;

use crate::nonnative::biguint::CircuitBuilderBiguint;
use crate::types::{HashInputTarget, HashOutputTarget, WitnessHash};
use crate::u32::arithmetic_u32::{CircuitBuilderU32, U32Target};
use crate::u32::interleaved_u32::CircuitBuilderB32;

const KECCAK256_C: usize = 1600;
pub const KECCAK256_R: usize = 1088;

pub trait WitnessHashKeccak<F: PrimeField64>: Witness<F> {
    fn set_keccak256_input_target(&mut self, target: &HashInputTarget, value: &[u8]);
    fn set_keccak256_output_target(&mut self, target: &HashOutputTarget, value: &[u8]);
}

impl<T: Witness<F>, F: PrimeField64> WitnessHashKeccak<F> for T {
    fn set_keccak256_input_target(&mut self, target: &HashInputTarget, value: &[u8]) {
        let mut input_biguint = BigUint::from_bytes_le(value);
        let input_len_bits = value.len() * 8;
        let num_actual_blocks = 1 + input_len_bits / KECCAK256_R;
        let padded_len_bits = num_actual_blocks * KECCAK256_R;

        // bit right after the end of the message
        input_biguint.set_bit(input_len_bits as u64, true);

        // last bit of the last block
        input_biguint.set_bit(padded_len_bits as u64 - 1, true);

        self.set_hash_input_le_target(target, &input_biguint);
        self.set_hash_blocks_target(target, num_actual_blocks);
    }

    fn set_keccak256_output_target(&mut self, target: &HashOutputTarget, value: &[u8]) {
        self.set_hash_output_le_target(target, value);
    }
}

pub trait CircuitBuilderHashKeccak<F: RichField + Extendable<D>, const D: usize> {
    fn hash_keccak256(&mut self, hash: &HashInputTarget) -> HashOutputTarget;
    fn _hash_keccak256_f1600(&mut self, state: &mut [[U32Target; 2]; 25]);
}

#[rustfmt::skip]
pub const KECCAKF_ROTC: [u8; 24] = [
    1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14, 27, 41, 56, 8, 25, 43, 62,
    18, 39, 61, 20, 44
];

#[rustfmt::skip]
pub const KECCAKF_PILN: [usize; 24] = [
    10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4, 15, 23, 19, 13, 12, 2, 20,
    14, 22, 9, 6, 1
];

#[rustfmt::skip]
pub const KECCAKF_RNDC: [[u32; 2]; 24] = [
    [0x00000001, 0x00000000], [0x00008082, 0x00000000],
    [0x0000808A, 0x80000000], [0x80008000, 0x80000000],
    [0x0000808B, 0x00000000], [0x80000001, 0x00000000],
    [0x80008081, 0x80000000], [0x00008009, 0x80000000],
    [0x0000008A, 0x00000000], [0x00000088, 0x00000000],
    [0x80008009, 0x00000000], [0x8000000A, 0x00000000],
    [0x8000808B, 0x00000000], [0x0000008B, 0x80000000],
    [0x00008089, 0x80000000], [0x00008003, 0x80000000],
    [0x00008002, 0x80000000], [0x00000080, 0x80000000],
    [0x0000800A, 0x00000000], [0x8000000A, 0x80000000],
    [0x80008081, 0x80000000], [0x00008080, 0x80000000],
    [0x80000001, 0x00000000], [0x80008008, 0x80000000],
];

impl<F: RichField + Extendable<D>, const D: usize> CircuitBuilderHashKeccak<F, D>
    for CircuitBuilder<F, D>
{
    fn _hash_keccak256_f1600(&mut self, s: &mut [[U32Target; 2]; 25]) {
        let zero = self.zero_u32();
        let mut bc = [[zero; 2]; 5];

        let mut keccakf_rndc = Vec::new();
        for item in &KECCAKF_RNDC {
            keccakf_rndc.push([self.constant_u32(item[0]), self.constant_u32(item[1])]);
        }

        // for round in 0..24 {
        for rndc in keccakf_rndc.iter().take(24) {
            // Theta
            for i in 0..5 {
                bc[i] =
                    self.unsafe_xor_many_u64(&[s[i], s[i + 5], s[i + 10], s[i + 15], s[i + 20]]);
            }

            for i in 0..5 {
                let t1 = self.lrot_u64(&bc[(i + 1) % 5], 1);
                let t2 = self.xor_u64(&bc[(i + 4) % 5], &t1);
                for j in 0..5 {
                    s[5 * j + i] = self.xor_u64(&s[5 * j + i], &t2);
                }
            }

            // Rho Pi
            let mut t = s[1];
            for i in 0..24 {
                let j = KECCAKF_PILN[i];
                let tmp = s[j];
                s[j] = self.lrot_u64(&t, KECCAKF_ROTC[i]);
                t = tmp;
            }

            // Chi
            for j in 0..5 {
                for i in 0..5 {
                    bc[i] = s[5 * j + i];
                }
                for i in 0..5 {
                    let t1 = self.not_u64(&bc[(i + 1) % 5]);
                    let t2 = self.and_u64(&bc[(i + 2) % 5], &t1);
                    s[5 * j + i] = self.xor_u64(&s[5 * j + i], &t2);
                }
            }

            // Iota
            s[0] = self.xor_u64(&s[0], rndc);
        }
    }

    fn hash_keccak256(&mut self, hash: &HashInputTarget) -> HashOutputTarget {
        let output = self.add_virtual_biguint_target(8);

        let chunks_len = KECCAK256_R / 64;
        let zero = self.zero_u32();
        let mut state = [[zero; 2]; KECCAK256_C / 64];
        let mut next_state = [[zero; 2]; KECCAK256_C / 64];

        // first block. xor = use input as initial state
        for (i, s) in state.iter_mut().enumerate().take(chunks_len) {
            s[0] = hash.input.limbs[2 * i];
            s[1] = hash.input.limbs[2 * i + 1];
        }

        self._hash_keccak256_f1600(&mut state);

        // other blocks
        for (k, blk) in hash.blocks.iter().enumerate() {
            // xor
            let input_start = (k + 1) * chunks_len * 2;
            for (i, s) in state.iter().enumerate() {
                if i < chunks_len {
                    next_state[i][0] = self.xor_u32(s[0], hash.input.limbs[input_start + i * 2]);
                    next_state[i][1] =
                        self.xor_u32(s[1], hash.input.limbs[input_start + i * 2 + 1]);
                } else {
                    next_state[i][0] = s[0];
                    next_state[i][1] = s[1];
                }
            }

            self._hash_keccak256_f1600(&mut next_state);

            // conditionally set old or new state, depending if block needs to be processed
            for (i, s) in next_state.iter().enumerate() {
                state[i] = self.conditional_u64(s, &state[i], *blk);
            }
        }

        // squeeze
        let output_len = output.num_limbs();
        for (i, s) in state.iter().enumerate().take(output_len / 2) {
            self.connect_u32(s[0], output.limbs[2 * i]);
            self.connect_u32(s[1], output.limbs[2 * i + 1]);
        }

        output
    }
}

#[cfg(test)]
mod tests {
    use hex;
    use plonky2::hash::keccak;
    use plonky2::iop::witness::PartialWitness;
    use plonky2::plonk::circuit_builder::CircuitBuilder;
    use plonky2::plonk::circuit_data::CircuitConfig;
    use plonky2::plonk::config::{GenericConfig, KeccakGoldilocksConfig, PoseidonGoldilocksConfig};
    use plonky2::util::timing::TimingTree;
    use sha3::{Digest, Keccak256};

    use crate::keccak256::{CircuitBuilderHashKeccak, WitnessHashKeccak, KECCAK256_R};
    use crate::types::CircuitBuilderHash;
    use env_logger::{try_init_from_env, Env, DEFAULT_FILTER_ENV};
    use keccak_hash::keccak;

    #[test]
    #[ignore]
    fn test_keccak256_short() {
        let tests = [
            [
                // empty string
                "",
                "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470",
            ],
            [
                // empty trie
                "80",
                "56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421",
            ],
            [
                // short hash, e.g. last step of storage proof
                "e19f37a9fe364faab93b216da50a3214154f22a0a2b415b23a84c8169e8b636ee301",
                "19225e4ee19eb5a11e5260392e6d5154d4bc6a35d89c9d18bf6a63104e9bbcc2",
            ],
        ];

        // build circuit once
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;

        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);
        let hash_target = builder.add_virtual_hash_input_target(1, KECCAK256_R);
        let hash_output = builder.hash_keccak256(&hash_target);
        let num_gates = builder.num_gates();
        // let copy_constraints = builder.copy_constraints.len();
        let copy_constraints = "<private>";
        let data = builder.build::<C>();
        println!(
            "keccak256 num_gates={}, copy_constraints={}, quotient_degree_factor={}",
            num_gates, copy_constraints, data.common.quotient_degree_factor
        );

        for t in tests {
            let input = hex::decode(t[0]).unwrap();
            let output = hex::decode(t[1]).unwrap();

            // test program
            let mut hasher = Keccak256::new();
            hasher.update(input.as_slice());
            let result = hasher.finalize();
            assert_eq!(result[..], output[..]);

            // test circuit
            let mut pw = PartialWitness::new();
            pw.set_keccak256_input_target(&hash_target, &input);
            pw.set_keccak256_output_target(&hash_output, &output);

            let proof = data.prove(pw).unwrap();
            println!("Proof size short: {}", proof.to_bytes().len());

            assert!(data.verify(proof).is_ok());
        }
    }
}
