use plonky2::field::extension::Extendable;
use plonky2::field::types::Field;
use plonky2::hash::hash_types::RichField;

use crate::cross_table_lookup::{
    all_cross_table_lookups, Column, CrossTableLookup, TableWithColumns, NUM_TABLES,
};
use crate::keccak_permutation::keccak_permutation_stark;
use crate::keccak_permutation::keccak_permutation_stark::KeccakPermutationStark;
use crate::keccak_sponge::keccak_sponge_stark;
use crate::keccak_sponge::keccak_sponge_stark::KeccakSpongeStark;
use starky::config::StarkConfig;
use starky::stark::Stark;

#[derive(Clone)]
pub struct KeccakCtl<F: RichField + Extendable<D>, const D: usize> {
    pub keccak_permutation_stark: KeccakPermutationStark<F, D>,
    pub keccak_sponge_stark: KeccakSpongeStark<F, D>,
    pub cross_table_lookups: Vec<CrossTableLookup<F>>,
}

impl<F: RichField + Extendable<D>, const D: usize> Default for KeccakCtl<F, D> {
    fn default() -> Self {
        Self {
            keccak_permutation_stark: KeccakPermutationStark::default(),
            keccak_sponge_stark: KeccakSpongeStark::default(),
            cross_table_lookups: all_cross_table_lookups(),
        }
    }
}

impl<F: RichField + Extendable<D>, const D: usize> KeccakCtl<F, D> {
    pub fn nums_permutation_zs(&self, config: &StarkConfig) -> [usize; NUM_TABLES] {
        [
            self.keccak_permutation_stark
                .num_permutation_batches(config),
            self.keccak_sponge_stark.num_permutation_batches(config),
        ]
    }

    pub fn permutation_batch_sizes(&self) -> [usize; NUM_TABLES] {
        [
            self.keccak_permutation_stark.permutation_batch_size(),
            self.keccak_sponge_stark.permutation_batch_size(),
        ]
    }
}
