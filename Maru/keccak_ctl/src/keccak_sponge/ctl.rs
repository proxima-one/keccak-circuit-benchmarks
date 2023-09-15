use plonky2::field::types::Field;
use std::iter::once;
use std::mem::size_of;

use crate::keccak_sponge::columns::*;
use starky_ctl::cross_table_lookup::Column;

pub fn ctl_looking_keccak<F: Field>() -> Vec<Column<F>> {
    let cols = KECCAK_SPONGE_COL_MAP;
    let col: Vec<Column<F>> =
        Column::singles([cols.xored_state_u32s.as_slice(), &cols.updated_state_u32s].concat())
            .collect();
    col
}

pub(crate) fn ctl_looking_keccak_state<F: Field>(i: usize) -> Vec<Column<F>> {
    let cols = KECCAK_SPONGE_COL_MAP;
    const U8S_PER_CTL: usize = 4;
    const U32S_PER_CTL: usize = 1;

    let mut res = vec![];
    res.push(Column::single(cols.original_rate_u32s[i]));
    res.extend(
        cols.block_bytes[i * U8S_PER_CTL..(i + 1) * U8S_PER_CTL]
            .chunks(size_of::<u32>())
            .map(|chunk| Column::le_bytes(chunk))
            .take(U32S_PER_CTL),
    );
    res.push(Column::single(cols.xored_state_u32s[i]));
    res
}

pub(crate) fn ctl_looking_full_filter<F: Field>() -> Column<F> {
    let cols = KECCAK_SPONGE_COL_MAP;
    let sum: Column<F> = Column::sum([cols.is_final_block, cols.is_full_input_block]);
    sum
}

pub(crate) fn ctl_looking_keccak_filter<F: Field>() -> Column<F> {
    let cols = KECCAK_SPONGE_COL_MAP;
    let sum: Column<F> =
        Column::sum(once(&cols.is_full_input_block).chain(&cols.is_final_input_len));
    sum
}
