use anyhow::Result;
use log::Level;
use plonky2::hash::hash_types::RichField;
use plonky2::plonk::circuit_data::CircuitData;
use plonky2::plonk::config::{AlgebraicHasher, GenericConfig};
use plonky2::plonk::proof::ProofWithPublicInputs;

use plonky2_field::extension::Extendable;
use starky_ctl::stark::Stark;

use crate::keccak_permutation::keccak_permutation_stark::KeccakPermutationStark;
use crate::keccak_proof::keccak256proof_stark;
use crate::keccak_sponge::keccak_sponge_stark::KeccakSpongeStark;
use crate::keccak_xor::xor_stark::KeccakXORStark;
use crate::stark_aggregation::aggregation_sponge_permutation;
use crate::verifier_ctl::keccak256verify_stark;
use plonky2::plonk::config::Hasher;
use plonky2::util::timing::TimingTree;

pub fn keccak256<F, C, const D: usize>(
    msg: &[u8],
    hash: &[u8],
) -> Result<(CircuitData<F, C, D>, ProofWithPublicInputs<F, C, D>)>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    C::Hasher: AlgebraicHasher<F>,
    [(); C::Hasher::HASH_SIZE]:,
    [(); KeccakSpongeStark::<F, D>::COLUMNS]:,
    [(); KeccakSpongeStark::<F, D>::PUBLIC_INPUTS]:,
    [(); KeccakPermutationStark::<F, D>::COLUMNS]:,
    [(); KeccakPermutationStark::<F, D>::PUBLIC_INPUTS]:,
    [(); KeccakXORStark::<F, D>::COLUMNS]:,
{
    let (stark, proof, _, _, _, _, _, _, _, _, _, _ ) = keccak256proof_stark::<F, C, D>(msg, hash);

    keccak256verify_stark(stark.clone(), proof.clone());

    let (data, proof, _, _) = aggregation_sponge_permutation::<F, C, D>(&stark, proof)?;
    let timing = TimingTree::new("verify aggregation: sponge & permutation & xor", Level::Debug);
    data.verify(proof.clone())?;
    timing.print();
    Ok((data, proof))
}
