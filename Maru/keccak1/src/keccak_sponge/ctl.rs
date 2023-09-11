use plonky2::field::types::Field;

use crate::cross_table_lookup::Column;
use crate::keccak_sponge::columns::*;

pub fn ctl_looking_keccak<F: Field>() -> Vec<Column<F>> {
    let cols = KECCAK_SPONGE_COL_MAP;
    Column::singles(
        [
            cols.xored_rate_u32s.as_slice(),
            &cols.original_capacity_u32s,
            &cols.updated_state_u32s,
        ]
        .concat(),
    )
    .collect()
}

pub(crate) fn ctl_looking_keccak_filter<F: Field>() -> Column<F> {
    let cols = KECCAK_SPONGE_COL_MAP;
    Column::sum([cols.is_full_input_block, cols.is_final_block])
}
