use crate::keccak_xor::columns::{XORColumnsView, NUM_XOR_COLUMNS};
use plonky2::field::extension::{Extendable, FieldExtension};
use plonky2::field::packed::PackedField;
use plonky2::field::polynomial::PolynomialValues;
use plonky2::hash::hash_types::RichField;
use plonky2::iop::ext_target::ExtensionTarget;
use plonky2::timed;
use plonky2::util::timing::TimingTree;
use starky_ctl::constraint_consumer::{ConstraintConsumer, RecursiveConstraintConsumer};
use starky_ctl::stark::Stark;
use starky_ctl::util::trace_rows_to_poly_values;
use starky_ctl::vars::{StarkEvaluationTargets, StarkEvaluationVars};
use std::borrow::Borrow;
use std::marker::PhantomData;

pub const NUM_INPUTS: usize = 3;

#[derive(Copy, Clone, Default)]
pub struct KeccakXORStark<F, const D: usize> {
    f: PhantomData<F>,
}

impl<F: RichField + Extendable<D>, const D: usize> KeccakXORStark<F, D> {
    pub fn generate_trace(
        &self,
        operations: Vec<[u32; NUM_INPUTS]>,
        min_rows: usize,
        timing: &mut TimingTree,
    ) -> Vec<PolynomialValues<F>> {
        // Generate the witness row-wise.
        let trace_rows = timed!(
            timing,
            "generate trace rows",
            self.generate_trace_rows(operations, min_rows)
        );
        let trace_polys = timed!(
            timing,
            "convert to PolynomialValues",
            trace_rows_to_poly_values(trace_rows)
        );
        trace_polys
    }

    fn generate_trace_rows_for_xor(
        &self,
        input: [u32; NUM_INPUTS],
        is_valid: bool,
    ) -> Vec<[F; NUM_XOR_COLUMNS]> {
        let mut rows: Vec<[F; NUM_XOR_COLUMNS]> = vec![];
        let op0_bits = self.u32_to_bit_array(input[0]);
        let op1_bits = self.u32_to_bit_array(input[1]);
        let res_bits = self.u32_to_bit_array(input[2]);
        let row = XORColumnsView {
            op0: op0_bits,
            op1: op1_bits,
            res: res_bits,
            is_valid: F::from_bool(is_valid),
            ..Default::default()
        };
        rows.push(row.into());
        rows
    }

    pub fn generate_trace_rows(
        &self,
        inputs: Vec<[u32; NUM_INPUTS]>,
        min_rows: usize,
    ) -> Vec<[F; NUM_XOR_COLUMNS]> {
        let num_rows = inputs.len().max(min_rows).next_power_of_two();
        let mut rows = Vec::with_capacity(num_rows);
        for input in inputs.iter() {
            let rows_for_perm = self.generate_trace_rows_for_xor(*input, true);
            rows.extend(rows_for_perm);
        }

        let pad_rows = self.generate_trace_rows_for_xor([0; NUM_INPUTS], false);
        while rows.len() < num_rows {
            rows.extend(&pad_rows);
        }
        rows.drain(num_rows..);
        rows
    }

    fn u32_to_bit_array(&self, n: u32) -> [F; 32] {
        let mut bit_array = [F::ZERO; 32];
        let mut mask = 1u32;

        for i in (0..32).rev() {
            bit_array[i] = if (n & mask) != 0 { F::ONE } else { F::ZERO };
            mask <<= 1;
        }
        bit_array
    }
}

impl<F: RichField + Extendable<D>, const D: usize> Stark<F, D> for KeccakXORStark<F, D> {
    const COLUMNS: usize = NUM_XOR_COLUMNS;
    const PUBLIC_INPUTS: usize = 0;

    fn eval_packed_generic<FE, P, const D2: usize>(
        &self,
        vars: StarkEvaluationVars<FE, P, { Self::COLUMNS }, { Self::PUBLIC_INPUTS }>,
        yield_constr: &mut ConstraintConsumer<P>,
    ) where
        FE: FieldExtension<D2, BaseField = F>,
        P: PackedField<Scalar = FE>,
    {
        let local_values: &XORColumnsView<P> = vars.local_values.borrow();
        for i in 0..32 {
            let bits_diff = local_values.op0[i] + local_values.op1[i]
                - local_values.op0[i].doubles() * local_values.op1[i];
            let filter = P::ZEROS - local_values.is_valid;
            yield_constr.constraint(filter * (bits_diff - local_values.res[i]));
        }
        yield_constr.constraint((P::ONES - local_values.is_valid) * local_values.is_valid);
    }

    fn eval_ext_circuit(
        &self,
        builder: &mut plonky2::plonk::circuit_builder::CircuitBuilder<F, D>,
        vars: StarkEvaluationTargets<D, { Self::COLUMNS }, { Self::PUBLIC_INPUTS }>,
        yield_constr: &mut RecursiveConstraintConsumer<F, D>,
    ) {
        let local_values: &XORColumnsView<ExtensionTarget<D>> = vars.local_values.borrow();
        let zero = builder.zero_extension();
        let one = builder.one_extension();
        let two = builder.two_extension();
        for i in 0..32 {
            let constraint = {
                let filter = builder.sub_extension(zero, local_values.is_valid);
                let add = builder.add_extension(local_values.op0[i], local_values.op1[i]);
                let mul = builder.mul_extension(two, local_values.op0[i]);
                let mul2 = builder.mul_extension(mul, local_values.op1[i]);
                let sub = builder.sub_extension(add, mul2);
                let sub2 = builder.sub_extension(sub, local_values.res[i]);
                builder.mul_extension(filter, sub2)
            };
            yield_constr.constraint(builder, constraint);
        }
        let sub = builder.sub_extension(one, local_values.is_valid);
        let constraint = builder.mul_extension(sub, local_values.is_valid);
        yield_constr.constraint(builder, constraint);
    }

    fn constraint_degree(&self) -> usize {
        3
    }
}
