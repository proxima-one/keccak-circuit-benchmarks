use anyhow::Result;
use log::Level;
use plonky2::hash::hash_types::RichField;
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::VerifierCircuitTarget;
use plonky2::plonk::circuit_data::{CircuitConfig, CircuitData};
use plonky2::plonk::config::{AlgebraicHasher, GenericConfig};
use plonky2::plonk::proof::ProofWithPublicInputs;
use plonky2::util::timing::TimingTree;
use plonky2_field::extension::Extendable;

pub fn verification<F: RichField + Extendable<D>, C: GenericConfig<D, F = F>, const D: usize>(
    (data, proof): (&CircuitData<F, C, D>, &ProofWithPublicInputs<F, C, D>),
) -> Result<()> {
    let timing = TimingTree::new("verify", Level::Debug);
    let res = data.verify(proof.to_owned());
    timing.print();
    res
}

pub fn aggregation_two<F: RichField + Extendable<D>, C: GenericConfig<D, F = F>, const D: usize>(
    (data1, proof1): (&CircuitData<F, C, D>, &ProofWithPublicInputs<F, C, D>),
    data_proof_2: Option<(&CircuitData<F, C, D>, &ProofWithPublicInputs<F, C, D>)>,
) -> Result<(CircuitData<F, C, D>, ProofWithPublicInputs<F, C, D>)>
where
    C::Hasher: AlgebraicHasher<F>,
{
    verification((data1, proof1))?;
    let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_config());
    let proof_with_pis_target_1 = builder.add_virtual_proof_with_pis::<C>(&data1.common);
    let verifier_circuit_target_1 = VerifierCircuitTarget {
        constants_sigmas_cap: builder.add_virtual_cap(data1.common.config.fri_config.cap_height),
        circuit_digest: builder.add_virtual_hash(),
    };
    let mut pw = PartialWitness::new();
    pw.set_proof_with_pis_target(&proof_with_pis_target_1, proof1);
    pw.set_cap_target(
        &verifier_circuit_target_1.constants_sigmas_cap,
        &data1.verifier_only.constants_sigmas_cap,
    );
    pw.set_hash_target(
        verifier_circuit_target_1.circuit_digest,
        data1.verifier_only.circuit_digest,
    );
    builder.verify_proof::<C>(
        &proof_with_pis_target_1,
        &verifier_circuit_target_1,
        &data1.common,
    );
    if data_proof_2.is_some() {
        verification((data_proof_2.unwrap().0, data_proof_2.unwrap().1))?;
        let proof_with_pis_target_2 =
            builder.add_virtual_proof_with_pis::<C>(&data_proof_2.unwrap().0.common);
        let verifier_circuit_target_2 = VerifierCircuitTarget {
            constants_sigmas_cap: builder
                .add_virtual_cap(data_proof_2.unwrap().0.common.config.fri_config.cap_height),
            circuit_digest: builder.add_virtual_hash(),
        };
        pw.set_proof_with_pis_target(&proof_with_pis_target_2, data_proof_2.unwrap().1);
        pw.set_cap_target(
            &verifier_circuit_target_2.constants_sigmas_cap,
            &data_proof_2.unwrap().0.verifier_only.constants_sigmas_cap,
        );
        pw.set_hash_target(
            verifier_circuit_target_2.circuit_digest,
            data_proof_2.unwrap().0.verifier_only.circuit_digest,
        );
        builder.verify_proof::<C>(
            &proof_with_pis_target_2,
            &verifier_circuit_target_2,
            &data_proof_2.unwrap().0.common,
        );
    }
    let data_new = builder.build::<C>();
    let timing = TimingTree::new("prove", Level::Debug);
    let proof_new = data_new.prove(pw)?;
    timing.print();
    Ok((data_new, proof_new))
}
