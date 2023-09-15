use plonky2::field::extension::Extendable;
use plonky2::hash::hash_types::RichField;
use plonky2::plonk::config::GenericConfig;

use starky_ctl::config::StarkConfig;
use starky_ctl::permutation::PermutationChallengeSet;
use starky_ctl::proof::StarkProofChallenges;
use starky_ctl::proof::StarkProofWithPublicInputs;
use starky_ctl::table::NUM_TABLES;

/// A STARK proof for each table.
#[derive(Clone)]
pub struct KeccakCtlProof<F: RichField + Extendable<D>, C: GenericConfig<D, F = F>, const D: usize>
{
    pub stark_proofs: [StarkProofWithPublicInputs<F, C, D>; NUM_TABLES],
    pub ctl_challenges: PermutationChallengeSet<F>,
}
impl<F: RichField + Extendable<D>, C: GenericConfig<D, F = F>, const D: usize>
    KeccakCtlProof<F, C, D>
{
    pub fn degree_bits(&self, config: &StarkConfig) -> [usize; NUM_TABLES] {
        core::array::from_fn(|i| self.stark_proofs[i].proof.recover_degree_bits(config))
    }
}
pub struct KeccakCtlProofChallenges<F: RichField + Extendable<D>, const D: usize> {
    pub stark_challenges: [StarkProofChallenges<F, D>; NUM_TABLES],
    pub ctl_challenges: PermutationChallengeSet<F>,
}
