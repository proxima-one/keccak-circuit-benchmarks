use std::borrow::Borrow;
use std::marker::PhantomData;

use itertools::Itertools;
use plonky2::field::extension::{Extendable, FieldExtension};
use plonky2::field::packed::PackedField;
use plonky2::field::polynomial::PolynomialValues;
use plonky2::hash::hash_types::RichField;
use plonky2::iop::ext_target::ExtensionTarget;
use plonky2::timed;
use plonky2::util::timing::TimingTree;

use crate::keccak_sponge::columns::*;
use crate::keccak_sponge::keccak_util::keccakf_u32s;
use starky::constraint_consumer::{ConstraintConsumer, RecursiveConstraintConsumer};
use starky::stark::Stark;
use starky::util::trace_rows_to_poly_values;
use starky::vars::{StarkEvaluationTargets, StarkEvaluationVars};

/// Information about a Keccak sponge operation needed for witness generation.
#[derive(Clone, Debug)]
pub struct KeccakSpongeOp {
    /// The timestamp at which inputs are read.
    pub timestamp: usize,

    /// The input that was read.
    pub input: Vec<u8>,
}

#[derive(Copy, Clone, Default)]
pub struct KeccakSpongeStark<F, const D: usize> {
    f: PhantomData<F>,
}

impl<F: RichField + Extendable<D>, const D: usize> KeccakSpongeStark<F, D> {
    pub fn generate_trace(
        &self,
        operations: Vec<KeccakSpongeOp>,
        min_rows: usize,
        timing: &mut TimingTree,
    ) -> Vec<PolynomialValues<F>> {
        // Generate the witness row-wise.
        let trace_rows = timed!(
            timing,
            "generate trace rows",
            self.generate_trace_rows(operations, min_rows).0
        );

        let trace_polys = timed!(
            timing,
            "convert to PolynomialValues",
            trace_rows_to_poly_values(trace_rows)
        );

        trace_polys
    }

    pub fn generate_trace_rows(
        &self,
        operations: Vec<KeccakSpongeOp>,
        min_rows: usize,
    ) -> (
        Vec<[F; NUM_KECCAK_SPONGE_COLUMNS]>,
        Vec<[u32; KECCAK_WIDTH_U32S]>,
    ) {
        let mut rows = vec![];
        let mut states = vec![];
        for op in operations {
            let rows_states = self.generate_rows_for_op(op);
            rows.extend(rows_states.0);
            states.extend(rows_states.1);
        }
        let padded_rows = rows.len().max(min_rows).next_power_of_two();
        for _ in rows.len()..padded_rows {
            rows.push(self.generate_padding_row());
        }
        (rows, states)
    }

    pub fn generate_rows_for_op(
        &self,
        op: KeccakSpongeOp,
    ) -> (
        Vec<[F; NUM_KECCAK_SPONGE_COLUMNS]>,
        Vec<[u32; KECCAK_WIDTH_U32S]>,
    ) {
        let mut rows = vec![];
        let mut states = vec![];

        let mut sponge_state = [0u32; KECCAK_WIDTH_U32S];

        let mut input_blocks = op.input.chunks_exact(KECCAK_RATE_BYTES);
        let mut already_absorbed_bytes = 0;
        for block in input_blocks.by_ref() {
            let row = self.generate_full_input_row(
                &op,
                already_absorbed_bytes,
                sponge_state,
                block.try_into().unwrap(),
            );

            sponge_state = row.updated_state_u32s.map(|f| f.to_canonical_u64() as u32);

            states.push(row.xored_state_u32s.map(|f| f.to_canonical_u64() as u32));

            rows.push(row.into());
            already_absorbed_bytes += KECCAK_RATE_BYTES;
        }

        let row = self.generate_final_row(
            &op,
            already_absorbed_bytes,
            sponge_state,
            input_blocks.remainder(),
        );

        states.push(row.xored_state_u32s.map(|f| f.to_canonical_u64() as u32));

        rows.push(row.into());

        (rows, states)
    }

    fn generate_full_input_row(
        &self,
        op: &KeccakSpongeOp,
        already_absorbed_bytes: usize,
        sponge_state: [u32; KECCAK_WIDTH_U32S],
        block: [u8; KECCAK_RATE_BYTES],
    ) -> KeccakSpongeColumnsView<F> {
        let mut row = KeccakSpongeColumnsView {
            is_full_input_block: F::ONE,
            ..Default::default()
        };

        row.block_bytes = block.map(F::from_canonical_u8);

        Self::generate_common_fields(&mut row, op, already_absorbed_bytes, sponge_state);
        row
    }

    fn generate_final_row(
        &self,
        op: &KeccakSpongeOp,
        already_absorbed_bytes: usize,
        sponge_state: [u32; KECCAK_WIDTH_U32S],
        final_inputs: &[u8],
    ) -> KeccakSpongeColumnsView<F> {
        assert_eq!(already_absorbed_bytes + final_inputs.len(), op.input.len());

        let mut row = KeccakSpongeColumnsView {
            is_final_block: F::ONE,
            ..Default::default()
        };

        for (block_byte, input_byte) in row.block_bytes.iter_mut().zip(final_inputs) {
            *block_byte = F::from_canonical_u8(*input_byte);
        }

        // pad10*1 rule
        if final_inputs.len() == KECCAK_RATE_BYTES - 1 {
            // Both 1s are placed in the same byte.
            row.block_bytes[final_inputs.len()] = F::from_canonical_u8(0b10000001);
        } else {
            row.block_bytes[final_inputs.len()] = F::ONE;
            row.block_bytes[KECCAK_RATE_BYTES - 1] = F::from_canonical_u8(0b10000000);
        }

        row.is_final_input_len[final_inputs.len()] = F::ONE;

        Self::generate_common_fields(&mut row, op, already_absorbed_bytes, sponge_state);
        row
    }

    /// Generate fields that are common to both full-input-block rows and final-block rows.
    /// Also updates the sponge state with a single absorption.
    fn generate_common_fields(
        row: &mut KeccakSpongeColumnsView<F>,
        op: &KeccakSpongeOp,
        already_absorbed_bytes: usize,
        mut sponge_state: [u32; KECCAK_WIDTH_U32S],
    ) {
        //row.context = F::from_canonical_usize(op.base_address.context);
        //row.segment = F::from_canonical_usize(op.base_address.segment);
        //row.virt = F::from_canonical_usize(op.base_address.virt);
        row.timestamp = F::from_canonical_usize(op.timestamp);
        row.len = F::from_canonical_usize(op.input.len());
        row.already_absorbed_bytes = F::from_canonical_usize(already_absorbed_bytes);

        row.original_rate_u32s = sponge_state[..KECCAK_RATE_U32S]
            .iter()
            .map(|x| F::from_canonical_u32(*x))
            .collect_vec()
            .try_into()
            .unwrap();

        row.original_capacity_u32s = sponge_state[KECCAK_RATE_U32S..]
            .iter()
            .map(|x| F::from_canonical_u32(*x))
            .collect_vec()
            .try_into()
            .unwrap();

        let block_u32s = (0..KECCAK_RATE_U32S).map(|i| {
            u32::from_le_bytes(
                row.block_bytes[i * 4..(i + 1) * 4]
                    .iter()
                    .map(|x| x.to_canonical_u64() as u8)
                    .collect_vec()
                    .try_into()
                    .unwrap(),
            )
        });

        // xor in the block
        for (state_i, block_i) in sponge_state.iter_mut().zip(block_u32s) {
            *state_i ^= block_i;
        }
        let xored_state_u32s: [u32; KECCAK_WIDTH_U32S] = sponge_state;
        row.xored_state_u32s = xored_state_u32s.map(F::from_canonical_u32);

        keccakf_u32s(&mut sponge_state);
        row.updated_state_u32s = sponge_state.map(F::from_canonical_u32);
    }

    fn generate_padding_row(&self) -> [F; NUM_KECCAK_SPONGE_COLUMNS] {
        // The default instance has is_full_input_block = is_final_block = 0,
        // indicating that it's a dummy/padding row.
        KeccakSpongeColumnsView::default().into()
    }
}

impl<F: RichField + Extendable<D>, const D: usize> Stark<F, D> for KeccakSpongeStark<F, D> {
    const COLUMNS: usize = NUM_KECCAK_SPONGE_COLUMNS;
    const PUBLIC_INPUTS: usize = 8;

    fn eval_packed_generic<FE, P, const D2: usize>(
        &self,
        vars: StarkEvaluationVars<FE, P, { Self::COLUMNS }, { Self::PUBLIC_INPUTS }>,
        yield_constr: &mut ConstraintConsumer<P>,
    ) where
        FE: FieldExtension<D2, BaseField = F>,
        P: PackedField<Scalar = FE>,
    {
        let local_values: &KeccakSpongeColumnsView<P> = vars.local_values.borrow();
        let next_values: &KeccakSpongeColumnsView<P> = vars.next_values.borrow();

        // Each flag (full-input block, final block or implied dummy flag) must be boolean.
        let is_full_input_block = local_values.is_full_input_block;
        yield_constr.constraint(is_full_input_block * (is_full_input_block - P::ONES));

        let is_final_block = local_values.is_final_block;
        yield_constr.constraint(is_final_block * (is_final_block - P::ONES));

        for &is_final_len in local_values.is_final_input_len.iter() {
            yield_constr.constraint(is_final_len * (is_final_len - P::ONES));
        }

        // Ensure that full-input block and final block flags are not set to 1 at the same time.
        yield_constr.constraint(is_final_block * is_full_input_block);

        // Sum of is_final_input_len should equal is_final_block (which will be 0 or 1).
        let is_final_input_len_sum: P = local_values.is_final_input_len.iter().copied().sum();
        yield_constr.constraint(is_final_input_len_sum - is_final_block);

        // If this is a full-input block, is_final_input_len should contain all 0s.
        yield_constr.constraint(is_full_input_block * is_final_input_len_sum);

        // If this is the first row, the original sponge state should be 0 and already_absorbed_bytes = 0.
        let already_absorbed_bytes = local_values.already_absorbed_bytes;
        yield_constr.constraint_first_row(already_absorbed_bytes);
        for &original_rate_elem in local_values.original_rate_u32s.iter() {
            yield_constr.constraint_first_row(original_rate_elem);
        }
        for &original_capacity_elem in local_values.original_capacity_u32s.iter() {
            yield_constr.constraint_first_row(original_capacity_elem);
        }

        // If this is a final block, the next row's original sponge state should be 0 and already_absorbed_bytes = 0.
        yield_constr.constraint_transition(is_final_block * next_values.already_absorbed_bytes);
        for &original_rate_elem in next_values.original_rate_u32s.iter() {
            yield_constr.constraint_transition(is_final_block * original_rate_elem);
        }
        for &original_capacity_elem in next_values.original_capacity_u32s.iter() {
            yield_constr.constraint_transition(is_final_block * original_capacity_elem);
        }

        // If this is a full-input block, the next row's address, time and len must match as well as its timestamp.
        yield_constr.constraint_transition(
            is_full_input_block * (local_values.context - next_values.context),
        );
        yield_constr.constraint_transition(
            is_full_input_block * (local_values.segment - next_values.segment),
        );
        yield_constr
            .constraint_transition(is_full_input_block * (local_values.virt - next_values.virt));
        yield_constr.constraint_transition(
            is_full_input_block * (local_values.timestamp - next_values.timestamp),
        );

        // If this is a full-input block, the next row's "before" should match our "after" state.
        for (&current_after, &next_before) in local_values
            .updated_state_u32s
            .iter()
            .zip(next_values.original_rate_u32s.iter())
        {
            yield_constr.constraint_transition(is_full_input_block * (next_before - current_after));
        }
        for (&current_after, &next_before) in local_values
            .updated_state_u32s
            .iter()
            .skip(KECCAK_RATE_U32S)
            .zip(next_values.original_capacity_u32s.iter())
        {
            yield_constr.constraint_transition(is_full_input_block * (next_before - current_after));
        }

        // If this is a full-input block, the next row's already_absorbed_bytes should be ours plus 136.
        yield_constr.constraint_transition(
            is_full_input_block
                * (already_absorbed_bytes + P::from(FE::from_canonical_u64(136))
                    - next_values.already_absorbed_bytes),
        );

        // A dummy row is always followed by another dummy row, so the prover can't put dummy rows "in between" to avoid the above checks.
        let is_dummy = P::ONES - is_full_input_block - is_final_block;
        yield_constr.constraint_transition(
            is_dummy * (next_values.is_full_input_block + next_values.is_final_block),
        );

        // If this is a final block, is_final_input_len implies `len - already_absorbed == i`.
        let offset = local_values.len - already_absorbed_bytes;
        for (i, &is_final_len) in local_values.is_final_input_len.iter().enumerate() {
            let entry_match = offset - P::from(FE::from_canonical_usize(i));
            yield_constr.constraint(is_final_len * entry_match);
        }

        // If this is a final block (is_final_block = 1), then this row contains a hash
        for i in 0..Self::PUBLIC_INPUTS {
            yield_constr.constraint(
                local_values.is_final_block
                    * (local_values.updated_state_u32s[i] - vars.public_inputs[i]),
            );
        }
    }

    fn eval_ext_circuit(
        &self,
        builder: &mut plonky2::plonk::circuit_builder::CircuitBuilder<F, D>,
        vars: StarkEvaluationTargets<D, { Self::COLUMNS }, { Self::PUBLIC_INPUTS }>,
        yield_constr: &mut RecursiveConstraintConsumer<F, D>,
    ) {
        let local_values: &KeccakSpongeColumnsView<ExtensionTarget<D>> = vars.local_values.borrow();
        let next_values: &KeccakSpongeColumnsView<ExtensionTarget<D>> = vars.next_values.borrow();

        let one = builder.one_extension();

        // Each flag (full-input block, final block or implied dummy flag) must be boolean.
        let is_full_input_block = local_values.is_full_input_block;
        let constraint = builder.mul_sub_extension(
            is_full_input_block,
            is_full_input_block,
            is_full_input_block,
        );
        yield_constr.constraint(builder, constraint);

        let is_final_block = local_values.is_final_block;
        let constraint = builder.mul_sub_extension(is_final_block, is_final_block, is_final_block);
        yield_constr.constraint(builder, constraint);

        for &is_final_len in local_values.is_final_input_len.iter() {
            let constraint = builder.mul_sub_extension(is_final_len, is_final_len, is_final_len);
            yield_constr.constraint(builder, constraint);
        }

        // Ensure that full-input block and final block flags are not set to 1 at the same time.
        let constraint = builder.mul_extension(is_final_block, is_full_input_block);
        yield_constr.constraint(builder, constraint);

        // Sum of is_final_input_len should equal is_final_block (which will be 0 or 1).
        let mut is_final_input_len_sum = builder.add_extension(
            local_values.is_final_input_len[0],
            local_values.is_final_input_len[1],
        );
        for &input_len in local_values.is_final_input_len.iter().skip(2) {
            is_final_input_len_sum = builder.add_extension(is_final_input_len_sum, input_len);
        }
        let constraint = builder.sub_extension(is_final_input_len_sum, is_final_block);
        yield_constr.constraint(builder, constraint);

        // If this is a full-input block, is_final_input_len should contain all 0s.
        let constraint = builder.mul_extension(is_full_input_block, is_final_input_len_sum);
        yield_constr.constraint(builder, constraint);

        // If this is the first row, the original sponge state should be 0 and already_absorbed_bytes = 0.
        let already_absorbed_bytes = local_values.already_absorbed_bytes;
        yield_constr.constraint_first_row(builder, already_absorbed_bytes);
        for &original_rate_elem in local_values.original_rate_u32s.iter() {
            yield_constr.constraint_first_row(builder, original_rate_elem);
        }
        for &original_capacity_elem in local_values.original_capacity_u32s.iter() {
            yield_constr.constraint_first_row(builder, original_capacity_elem);
        }

        // If this is a final block, the next row's original sponge state should be 0 and already_absorbed_bytes = 0.
        let constraint = builder.mul_extension(is_final_block, next_values.already_absorbed_bytes);
        yield_constr.constraint_transition(builder, constraint);
        for &original_rate_elem in next_values.original_rate_u32s.iter() {
            let constraint = builder.mul_extension(is_final_block, original_rate_elem);
            yield_constr.constraint_transition(builder, constraint);
        }
        for &original_capacity_elem in next_values.original_capacity_u32s.iter() {
            let constraint = builder.mul_extension(is_final_block, original_capacity_elem);
            yield_constr.constraint_transition(builder, constraint);
        }

        // If this is a full-input block, the next row's address, time and len must match as well as its timestamp.
        let context_diff = builder.sub_extension(local_values.context, next_values.context);
        let constraint = builder.mul_extension(is_full_input_block, context_diff);
        yield_constr.constraint_transition(builder, constraint);

        let segment_diff = builder.sub_extension(local_values.segment, next_values.segment);
        let constraint = builder.mul_extension(is_full_input_block, segment_diff);
        yield_constr.constraint_transition(builder, constraint);

        let virt_diff = builder.sub_extension(local_values.virt, next_values.virt);
        let constraint = builder.mul_extension(is_full_input_block, virt_diff);
        yield_constr.constraint_transition(builder, constraint);

        let timestamp_diff = builder.sub_extension(local_values.timestamp, next_values.timestamp);
        let constraint = builder.mul_extension(is_full_input_block, timestamp_diff);
        yield_constr.constraint_transition(builder, constraint);

        // If this is a full-input block, the next row's "before" should match our "after" state.
        for (&current_after, &next_before) in local_values
            .updated_state_u32s
            .iter()
            .zip(next_values.original_rate_u32s.iter())
        {
            let diff = builder.sub_extension(next_before, current_after);
            let constraint = builder.mul_extension(is_full_input_block, diff);
            yield_constr.constraint_transition(builder, constraint);
        }
        for (&current_after, &next_before) in local_values
            .updated_state_u32s
            .iter()
            .skip(KECCAK_RATE_U32S)
            .zip(next_values.original_capacity_u32s.iter())
        {
            let diff = builder.sub_extension(next_before, current_after);
            let constraint = builder.mul_extension(is_full_input_block, diff);
            yield_constr.constraint_transition(builder, constraint);
        }

        // If this is a full-input block, the next row's already_absorbed_bytes should be ours plus 136.
        let absorbed_bytes =
            builder.add_const_extension(already_absorbed_bytes, F::from_canonical_u64(136));
        let absorbed_diff =
            builder.sub_extension(absorbed_bytes, next_values.already_absorbed_bytes);
        let constraint = builder.mul_extension(is_full_input_block, absorbed_diff);
        yield_constr.constraint_transition(builder, constraint);

        // A dummy row is always followed by another dummy row, so the prover can't put dummy rows "in between" to avoid the above checks.
        let is_dummy = {
            let tmp = builder.sub_extension(one, is_final_block);
            builder.sub_extension(tmp, is_full_input_block)
        };
        let constraint = {
            let tmp =
                builder.add_extension(next_values.is_final_block, next_values.is_full_input_block);
            builder.mul_extension(is_dummy, tmp)
        };
        yield_constr.constraint_transition(builder, constraint);

        // If this is a final block, is_final_input_len implies `len - already_absorbed == i`.
        let offset = builder.sub_extension(local_values.len, already_absorbed_bytes);
        for (i, &is_final_len) in local_values.is_final_input_len.iter().enumerate() {
            let index = builder.constant_extension(F::from_canonical_usize(i).into());
            let entry_match = builder.sub_extension(offset, index);

            let constraint = builder.mul_extension(is_final_len, entry_match);
            yield_constr.constraint(builder, constraint);
        }
        // If this is a final block (is_final_block = 1), then this row contains a hash
        for i in 0..Self::PUBLIC_INPUTS {
            let hash_match = builder.sub_extension(vars.local_values[i], vars.public_inputs[i]);
            let constraint = builder.mul_extension(local_values.is_final_block, hash_match);
            yield_constr.constraint_transition(builder, constraint);
        }
    }

    fn constraint_degree(&self) -> usize {
        3
    }
}
