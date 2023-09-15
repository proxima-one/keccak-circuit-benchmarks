use plonky2_field::types::Field;

use starky_ctl::cross_table_lookup::Column;

use super::{
    columns::{reg_input_limb, reg_output_limb, REG_FILTER},
    keccak_permutation_stark::NUM_INPUTS,
};

pub fn ctl_data<F: Field>() -> Vec<Column<F>> {
    let mut res: Vec<_> = (0..2 * NUM_INPUTS).map(reg_input_limb).collect();
    res.extend(Column::singles((0..2 * NUM_INPUTS).map(reg_output_limb)));
    res
}

pub fn ctl_filter<F: Field>() -> Column<F> {
    let res = Column::single(REG_FILTER);
    res
}
