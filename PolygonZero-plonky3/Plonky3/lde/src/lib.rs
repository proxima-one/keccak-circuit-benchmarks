//! This crate contains a framework for low-degree tests (LDTs).

#![no_std]

mod naive;

pub use naive::*;

extern crate alloc;

use p3_field::{ExtensionField, Field, TwoAdicField};
use p3_matrix::dense::RowMajorMatrix;
use p3_matrix::MatrixRows;

/// Performs low-degree extensions, where both the original domain and the extended domain are
/// undefined, but must be consistent between calls with the same input height.
pub trait UndefinedLde<Val, Domain, In>
where
    Val: Field,
    Domain: ExtensionField<Val>,
    In: MatrixRows<Val>,
{
    type Out: MatrixRows<Domain>;

    fn lde_batch(&self, polys: In, extended_height: usize) -> Self::Out;
}

/// Performs low-degree extensions over (possibly trivial) cosets of multiplicative subgroups of the
/// domain, `Dom`.
pub trait TwoAdicLde<Val, Domain>
where
    Val: Field,
    Domain: ExtensionField<Val> + TwoAdicField,
{
    /// Given a batch of polynomials, each defined by `2^k` evaluations over the subgroup generated
    /// by `EF::primitive_root_of_unity(k)`, compute their evaluations over the (possibly trivial)
    /// coset `shift H`, where `H` is the subgroup generated by
    /// `EF::primitive_root_of_unity(k + added_bits)`.
    fn lde_batch(&self, polys: RowMajorMatrix<Val>, added_bits: usize) -> RowMajorMatrix<Domain>;
}

/// A specialization of `TwoAdicLde` where that evaluates polynomials over a multiplicative
/// subgroup of the domain `Dom`, or in other words, a trivial coset thereof.
pub trait TwoAdicSubgroupLde<Val, Domain>: TwoAdicLde<Val, Domain>
where
    Val: Field,
    Domain: ExtensionField<Val> + TwoAdicField,
{
}

/// A specialization of `TwoAdicLde` where that evaluates polynomials over a nontrivial coset of a
/// multiplicative subgroup of the domain `Dom`.
pub trait TwoAdicCosetLde<Val, Domain>: TwoAdicLde<Val, Domain>
where
    Val: Field,
    Domain: ExtensionField<Val> + TwoAdicField,
{
    fn shift(&self, lde_bits: usize) -> Domain;
}
