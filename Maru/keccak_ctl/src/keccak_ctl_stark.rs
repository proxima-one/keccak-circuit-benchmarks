use plonky2::field::extension::Extendable;
use plonky2::field::types::Field;
use plonky2::hash::hash_types::RichField;

use crate::keccak_permutation::ctl::{ctl_data, ctl_filter};
use crate::keccak_permutation::keccak_permutation_stark::KeccakPermutationStark;
use crate::keccak_sponge::ctl::{
    ctl_looking_full_filter, ctl_looking_keccak, ctl_looking_keccak_filter,
    ctl_looking_keccak_state,
};
use crate::keccak_sponge::keccak_sponge_stark::KeccakSpongeStark;
use crate::keccak_xor::ctl::{ctl_looking_xor, ctl_looking_xor_filter};
use crate::keccak_xor::xor_stark::KeccakXORStark;
use starky_ctl::config::StarkConfig;
use starky_ctl::cross_table_lookup::{CrossTableLookup, TableWithColumns};
use starky_ctl::stark::Stark;
use starky_ctl::table::{Table, NUM_TABLES};

#[derive(Clone)]
pub struct KeccakCtl<F: RichField + Extendable<D>, const D: usize> {
    pub keccak_permutation_stark: KeccakPermutationStark<F, D>,
    pub keccak_sponge_stark: KeccakSpongeStark<F, D>,
    pub keccak_xor_stark: KeccakXORStark<F, D>,
    pub cross_table_lookups: Vec<CrossTableLookup<F>>,
}

impl<F: RichField + Extendable<D>, const D: usize> Default for KeccakCtl<F, D> {
    fn default() -> Self {
        Self {
            keccak_permutation_stark: KeccakPermutationStark::default(),
            keccak_sponge_stark: KeccakSpongeStark::default(),
            keccak_xor_stark: KeccakXORStark::default(),
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
            self.keccak_xor_stark.num_permutation_batches(config),
        ]
    }

    pub fn permutation_batch_sizes(&self) -> [usize; NUM_TABLES] {
        [
            self.keccak_permutation_stark.permutation_batch_size(),
            self.keccak_sponge_stark.permutation_batch_size(),
            self.keccak_xor_stark.permutation_batch_size(),
        ]
    }
}

pub fn all_cross_table_lookups<F: Field>() -> Vec<CrossTableLookup<F>> {
    let ctls = vec![ctl_keccak_permutation(), ctl_keccak_xor()];
    ctls
}

pub fn ctl_keccak_permutation<F: Field>() -> CrossTableLookup<F> {
    let keccak_sponge_looking = TableWithColumns::new(
        Table::KeccakSponge,
        ctl_looking_keccak(),
        Some(ctl_looking_keccak_filter()),
    );
    let keccak_permutation_looked =
        TableWithColumns::new(Table::KeccakPermutation, ctl_data(), Some(ctl_filter()));
    CrossTableLookup::new(vec![keccak_sponge_looking], keccak_permutation_looked)
}

pub fn ctl_keccak_xor<F: Field>() -> CrossTableLookup<F> {
    let mut all_lookers = vec![];
    for i in 0..34 {
        let keccak_sponge_looking = TableWithColumns::new(
            Table::KeccakSponge,
            ctl_looking_keccak_state(i),
            Some(ctl_looking_full_filter()),
        );
        all_lookers.push(keccak_sponge_looking);
    }
    let xor_looked = TableWithColumns::new(
        Table::KeccakXor,
        ctl_looking_xor(),
        Some(ctl_looking_xor_filter()),
    );
    CrossTableLookup::new(all_lookers, xor_looked)
}
