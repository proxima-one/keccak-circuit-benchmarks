use plonky2_field::types::Field;
use starky_ctl::cross_table_lookup::Column;
use crate::keccak_xor::columns::KECCAK_XOR_COL_MAP;

pub fn ctl_looking_xor<F: Field>() -> Vec<Column<F>> {
    let cols = KECCAK_XOR_COL_MAP;
    let mut outputs = vec![];
    let op0_column = Column::linear_combination(
        cols.op0[0..32]
            .iter()
            .enumerate()
            .map(|(j, &c)| (c, F::from_canonical_u32(1 << 31 - j))),
    );
    outputs.push(op0_column);
    let op1_column = Column::linear_combination(
        cols.op1[0..32]
            .iter()
            .enumerate()
            .map(|(j, &c)| (c, F::from_canonical_u32(1 << (31 - j)))),
    );
    outputs.push(op1_column);
    let res_column = Column::linear_combination(
        cols.res[0..32]
            .iter()
            .enumerate()
            .map(|(j, &c)| (c, F::from_canonical_u32(1 << (31 - j)))),
    );
    outputs.push(res_column);

    outputs
}

pub(crate) fn ctl_looking_xor_filter<F: Field>() -> Column<F> {
    let cols = KECCAK_XOR_COL_MAP;
    let sum: Column<F> = Column::single(cols.is_valid);
    sum
}