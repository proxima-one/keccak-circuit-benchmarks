use itertools::Itertools;
use plonky2::field::extension::{Extendable, FieldExtension};
use plonky2::fri::oracle::PolynomialBatch;
use plonky2::fri::proof::{
    CompressedFriProof, FriChallenges, FriChallengesTarget, FriProof, FriProofTarget,
};
use plonky2::fri::structure::{
    FriOpeningBatch, FriOpeningBatchTarget, FriOpenings, FriOpeningsTarget,
};
use plonky2::hash::hash_types::{MerkleCapTarget, RichField};
use plonky2::hash::merkle_tree::MerkleCap;
use plonky2::iop::ext_target::ExtensionTarget;
use plonky2::iop::target::Target;
use plonky2::plonk::config::GenericConfig;
//use plonky2::util::serialization::{Buffer, IoResult, Read, Write};
use maybe_rayon::*;
use serde::{Deserialize, Serialize};

use crate::config::StarkConfig;
use crate::permutation::PermutationChallengeSet;

use crate::serialization::Write;

#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq)]
#[serde(bound = "")]
pub struct StarkProof<F: RichField + Extendable<D>, C: GenericConfig<D, F = F>, const D: usize> {
    /// Merkle cap of LDEs of trace values.
    pub trace_cap: MerkleCap<F, C::Hasher>,
    /// Merkle cap of LDEs of permutation Z values.
    pub permutation_ctl_zs_cap: MerkleCap<F, C::Hasher>,
    /// Merkle cap of LDEs of trace values.
    pub quotient_polys_cap: MerkleCap<F, C::Hasher>,
    /// Purported values of each polynomial at the challenge point.
    pub openings: StarkOpeningSet<F, D>,
    /// A batch FRI argument for all openings.
    pub opening_proof: FriProof<F, C::Hasher, D>,
}

impl<F: RichField + Extendable<D>, C: GenericConfig<D, F = F>, const D: usize> StarkProof<F, C, D> {
    /// Recover the length of the trace from a STARK proof and a STARK config.
    pub fn recover_degree_bits(&self, config: &StarkConfig) -> usize {
        let initial_merkle_proof = &self.opening_proof.query_round_proofs[0]
            .initial_trees_proof
            .evals_proofs[0]
            .1;
        let lde_bits = config.fri_config.cap_height + initial_merkle_proof.siblings.len();
        lde_bits - config.fri_config.rate_bits
    }
    pub fn num_ctl_zs(&self) -> usize {
        self.openings.ctl_zs_last.len()
    }
}

#[derive(Clone, Debug)]
pub struct StarkProofTarget<const D: usize> {
    pub trace_cap: MerkleCapTarget,
    pub permutation_ctl_zs_cap: MerkleCapTarget,
    pub quotient_polys_cap: MerkleCapTarget,
    pub openings: StarkOpeningSetTarget<D>,
    pub opening_proof: FriProofTarget<D>,
}

impl<const D: usize> StarkProofTarget<D> {
    /// Recover the length of the trace from a STARK proof and a STARK config.
    pub fn recover_degree_bits(&self, config: &StarkConfig) -> usize {
        let initial_merkle_proof = &self.opening_proof.query_round_proofs[0]
            .initial_trees_proof
            .evals_proofs[0]
            .1;
        let lde_bits = config.fri_config.cap_height + initial_merkle_proof.siblings.len();
        lde_bits - config.fri_config.rate_bits
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq)]
#[serde(bound = "")]
pub struct StarkProofWithPublicInputs<
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    const D: usize,
> {
    pub proof: StarkProof<F, C, D>,
    pub public_inputs: Vec<F>,
}

impl<F: RichField + Extendable<D>, C: GenericConfig<D, F = F>, const D: usize>
    StarkProofWithPublicInputs<F, C, D>
{
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buffer = Vec::new();
        buffer
            .write_proof_with_public_inputs(self)
            .expect("Writing to a byte-vector cannot fail.");
        buffer
    }
}

pub struct StarkProofWithPublicInputsTarget<const D: usize> {
    pub proof: StarkProofTarget<D>,
    pub public_inputs: Vec<Target>,
}

pub struct CompressedStarkProof<
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    const D: usize,
> {
    /// Merkle cap of LDEs of trace values.
    pub trace_cap: MerkleCap<F, C::Hasher>,
    /// Purported values of each polynomial at the challenge point.
    pub openings: StarkOpeningSet<F, D>,
    /// A batch FRI argument for all openings.
    pub opening_proof: CompressedFriProof<F, C::Hasher, D>,
}

pub struct CompressedStarkProofWithPublicInputs<
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    const D: usize,
> {
    pub proof: CompressedStarkProof<F, C, D>,
    pub public_inputs: Vec<F>,
}

#[derive(Clone, Debug)]
pub struct StarkProofChallenges<F: RichField + Extendable<D>, const D: usize> {
    /// Randomness used in any permutation arguments.
    pub permutation_challenge_sets: Option<Vec<PermutationChallengeSet<F>>>,

    /// Random values used to combine STARK constraints.
    pub stark_alphas: Vec<F>,

    /// Point at which the STARK polynomials are opened.
    pub stark_zeta: F::Extension,

    pub fri_challenges: FriChallenges<F, D>,
}

pub struct StarkProofChallengesTarget<const D: usize> {
    pub permutation_challenge_sets: Option<Vec<PermutationChallengeSet<Target>>>,
    pub stark_alphas: Vec<Target>,
    pub stark_zeta: ExtensionTarget<D>,
    pub fri_challenges: FriChallengesTarget<D>,
}

/// Purported values of each polynomial at the challenge point.
#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
#[serde(bound = "")]
pub struct StarkOpeningSet<F: RichField + Extendable<D>, const D: usize> {
    /// Openings of trace polynomials at `zeta`.
    pub local_values: Vec<F::Extension>,
    /// Openings of trace polynomials at `g * zeta`.
    pub next_values: Vec<F::Extension>,
    /// Openings of permutations and cross-table lookups `Z` polynomials at `zeta`.
    pub permutation_ctl_zs: Vec<F::Extension>,
    /// Openings of permutations and cross-table lookups `Z` polynomials at `g * zeta`.
    pub permutation_ctl_zs_next: Vec<F::Extension>,
    /// Openings of cross-table lookups `Z` polynomials at `g^-1`.
    pub ctl_zs_last: Vec<F>,
    /// Openings of quotient polynomials at `zeta`.
    pub quotient_polys: Vec<F::Extension>,
}

impl<F: RichField + Extendable<D>, const D: usize> StarkOpeningSet<F, D> {
    pub fn new<C: GenericConfig<D, F = F>>(
        zeta: F::Extension,
        g: F,
        trace_commitment: &PolynomialBatch<F, C, D>,
        permutation_ctl_zs_commitment: &PolynomialBatch<F, C, D>,
        quotient_commitment: &PolynomialBatch<F, C, D>,
        degree_bits: usize,
        num_permutation_zs: usize,
    ) -> Self {
        let eval_commitment = |z: F::Extension, c: &PolynomialBatch<F, C, D>| {
            c.polynomials
                .par_iter()
                .map(|p| p.to_extension().eval(z))
                .collect::<Vec<_>>()
        };
        let eval_commitment_base = |z: F, c: &PolynomialBatch<F, C, D>| {
            c.polynomials
                .par_iter()
                .map(|p| p.eval(z))
                .collect::<Vec<_>>()
        };
        let zeta_next = zeta.scalar_mul(g);
        Self {
            local_values: eval_commitment(zeta, trace_commitment),
            next_values: eval_commitment(zeta_next, trace_commitment),
            permutation_ctl_zs: eval_commitment(zeta, permutation_ctl_zs_commitment),
            permutation_ctl_zs_next: eval_commitment(zeta_next, permutation_ctl_zs_commitment),
            ctl_zs_last: eval_commitment_base(
                F::primitive_root_of_unity(degree_bits).inverse(),
                permutation_ctl_zs_commitment,
            )[num_permutation_zs..]
                .to_vec(),
            quotient_polys: eval_commitment(zeta, quotient_commitment),
        }
    }

    pub fn to_fri_openings(&self) -> FriOpenings<F, D> {
        let zeta_batch = FriOpeningBatch {
            values: self
                .local_values
                .iter()
                .chain(&self.permutation_ctl_zs)
                .chain(&self.quotient_polys)
                .copied()
                .collect_vec(),
        };
        let zeta_next_batch = FriOpeningBatch {
            values: self
                .next_values
                .iter()
                .chain(&self.permutation_ctl_zs_next)
                .copied()
                .collect_vec(),
        };
        debug_assert!(!self.ctl_zs_last.is_empty());
        let ctl_last_batch = FriOpeningBatch {
            values: self
                .ctl_zs_last
                .iter()
                .copied()
                .map(F::Extension::from_basefield)
                .collect(),
        };

        FriOpenings {
            batches: vec![zeta_batch, zeta_next_batch, ctl_last_batch],
        }
    }
}

#[derive(Clone, Debug)]
pub struct StarkOpeningSetTarget<const D: usize> {
    pub local_values: Vec<ExtensionTarget<D>>,
    pub next_values: Vec<ExtensionTarget<D>>,
    pub permutation_ctl_zs: Vec<ExtensionTarget<D>>,
    pub permutation_ctl_zs_next: Vec<ExtensionTarget<D>>,
    pub ctl_zs_last: Vec<Target>,
    pub quotient_polys: Vec<ExtensionTarget<D>>,
}

impl<const D: usize> StarkOpeningSetTarget<D> {
    /*pub fn to_buffer(&self, buffer: &mut Vec<u8>) -> IoResult<()> {
        buffer.write_target_ext_vec(&self.local_values)?;
        buffer.write_target_ext_vec(&self.next_values)?;
        buffer.write_target_ext_vec(&self.permutation_ctl_zs)?;
        buffer.write_target_ext_vec(&self.permutation_ctl_zs_next)?;
        buffer.write_target_vec(&self.ctl_zs_last)?;
        buffer.write_target_ext_vec(&self.quotient_polys)?;
        Ok(())
    }

    pub fn from_buffer(buffer: &mut Buffer) -> IoResult<Self> {
        let local_values = buffer.read_target_ext_vec::<D>()?;
        let next_values = buffer.read_target_ext_vec::<D>()?;
        let permutation_ctl_zs = buffer.read_target_ext_vec::<D>()?;
        let permutation_ctl_zs_next = buffer.read_target_ext_vec::<D>()?;
        let ctl_zs_last = buffer.read_target_vec()?;
        let quotient_polys = buffer.read_target_ext_vec::<D>()?;

        Ok(Self {
            local_values,
            next_values,
            permutation_ctl_zs,
            permutation_ctl_zs_next,
            ctl_zs_last,
            quotient_polys,
        })
    }*/

    pub fn to_fri_openings(&self, zero: Target) -> FriOpeningsTarget<D> {
        let zeta_batch = FriOpeningBatchTarget {
            values: self
                .local_values
                .iter()
                .chain(&self.permutation_ctl_zs)
                .chain(&self.quotient_polys)
                .copied()
                .collect_vec(),
        };
        let zeta_next_batch = FriOpeningBatchTarget {
            values: self
                .next_values
                .iter()
                .chain(&self.permutation_ctl_zs_next)
                .copied()
                .collect_vec(),
        };
        debug_assert!(!self.ctl_zs_last.is_empty());
        let ctl_last_batch = FriOpeningBatchTarget {
            values: self
                .ctl_zs_last
                .iter()
                .copied()
                .map(|t| t.to_ext_target(zero))
                .collect(),
        };

        FriOpeningsTarget {
            batches: vec![zeta_batch, zeta_next_batch, ctl_last_batch],
        }
    }
}
