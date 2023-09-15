use plonky2::field::extension::Extendable;
use plonky2::hash::hash_types::RichField;
use plonky2::iop::challenger::Challenger;
use plonky2::plonk::config::{GenericConfig, Hasher};

use starky_ctl::config::StarkConfig;
use starky_ctl::permutation::{get_permutation_challenge_set, PermutationChallengeSet};
use starky_ctl::table::NUM_TABLES;

use crate::keccak_ctl_stark::KeccakCtl;
use crate::proof_ctl::{KeccakCtlProof, KeccakCtlProofChallenges};

pub struct AllChallengerState<F: RichField + Extendable<D>, H: Hasher<F>, const D: usize> {
    /// Sponge state of the challenger before starting each proof,
    /// along with the final state after all proofs are done. This final state isn't strictly needed.
    pub states: [H::Permutation; NUM_TABLES + 1],
    pub ctl_challenges: PermutationChallengeSet<F>,
}

impl<F: RichField + Extendable<D>, C: GenericConfig<D, F = F>, const D: usize>
    KeccakCtlProof<F, C, D>
{
    /// Computes all Fiat-Shamir challenges used in the STARK proof.
    pub(crate) fn get_challenges(
        &self,
        all_stark: &KeccakCtl<F, D>,
        config: &StarkConfig,
    ) -> KeccakCtlProofChallenges<F, D> {
        let mut challenger = Challenger::<F, C::Hasher>::new();

        for proof in &self.stark_proofs {
            challenger.observe_cap(&proof.proof.trace_cap);
        }

        let ctl_challenges = get_permutation_challenge_set(&mut challenger, config.num_challenges);

        let num_permutation_zs = all_stark.nums_permutation_zs(config);
        let num_permutation_batch_sizes = all_stark.permutation_batch_sizes();

        KeccakCtlProofChallenges {
            stark_challenges: core::array::from_fn(|i| {
                challenger.compact();
                self.stark_proofs[i].proof.get_challenges(
                    &mut challenger,
                    num_permutation_zs[i] > 0,
                    num_permutation_batch_sizes[i],
                    config,
                )
            }),
            ctl_challenges,
        }
    }

    #[allow(unused)] // TODO: should be used soon
    pub(crate) fn get_challenger_states(
        &self,
        all_stark: &KeccakCtl<F, D>,
        config: &StarkConfig,
    ) -> AllChallengerState<F, C::Hasher, D> {
        let mut challenger = Challenger::<F, C::Hasher>::new();

        for proof in &self.stark_proofs {
            challenger.observe_cap(&proof.proof.trace_cap);
        }

        let ctl_challenges = get_permutation_challenge_set(&mut challenger, config.num_challenges);

        let num_permutation_zs = all_stark.nums_permutation_zs(config);
        let num_permutation_batch_sizes = all_stark.permutation_batch_sizes();

        let mut challenger_states = vec![challenger.compact()];
        for i in 0..NUM_TABLES {
            self.stark_proofs[i].proof.get_challenges(
                &mut challenger,
                num_permutation_zs[i] > 0,
                num_permutation_batch_sizes[i],
                config,
            );
            challenger_states.push(challenger.compact());
        }

        AllChallengerState {
            states: challenger_states.try_into().unwrap(),
            ctl_challenges,
        }
    }
}
