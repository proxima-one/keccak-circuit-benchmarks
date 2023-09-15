#[cfg(feature = "std")]
use crate::hash::merkle_proofs::MerkleProof;
use crate::proof::{StarkOpeningSet, StarkProof, StarkProofWithPublicInputs};
use core::convert::Infallible;
use core::fmt::{Debug, Display, Formatter};

use plonky2::fri::proof::{FriInitialTreeProof, FriProof, FriQueryRound, FriQueryStep};
use plonky2::hash::hash_types::RichField;
use plonky2::hash::merkle_proofs::MerkleProof;
use plonky2::hash::merkle_tree::MerkleCap;
use plonky2::plonk::config::{GenericConfig, GenericHashOut, Hasher};
use plonky2_field::extension::{Extendable, FieldExtension};
use plonky2_field::types::PrimeField64;

/// A no_std compatible variant of `std::io::Error`
#[derive(Debug)]
pub struct IoError;

impl Display for IoError {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        Debug::fmt(self, f)
    }
}

/// A no_std compatible variant of `std::io::Result`
pub type IoResult<T> = Result<T, IoError>;

/// Writing
pub trait Write {
    /// Error Type
    type Error;

    /// Writes all `bytes` to `self`.
    fn write_all(&mut self, bytes: &[u8]) -> IoResult<()>;

    /// Writes a byte `x` to `self`.
    #[inline]
    fn write_u8(&mut self, x: u8) -> IoResult<()> {
        self.write_all(&[x])
    }

    /// Writes a word `x` to `self.`
    #[inline]
    fn write_u32(&mut self, x: u32) -> IoResult<()> {
        self.write_all(&x.to_le_bytes())
    }

    /// Writes an element `x` from the field `F` to `self`.
    #[inline]
    fn write_field<F>(&mut self, x: F) -> IoResult<()>
    where
        F: PrimeField64,
    {
        self.write_all(&x.to_canonical_u64().to_le_bytes())
    }

    /// Writes a vector `v` of elements from the field `F` to `self`.
    #[inline]
    fn write_field_vec<F>(&mut self, v: &[F]) -> IoResult<()>
    where
        F: PrimeField64,
    {
        for &a in v {
            self.write_field(a)?;
        }
        Ok(())
    }

    /// Writes an element `x` from the field extension of `F` to `self`.
    #[inline]
    fn write_field_ext<F, const D: usize>(&mut self, x: F::Extension) -> IoResult<()>
    where
        F: RichField + Extendable<D>,
    {
        for &a in &x.to_basefield_array() {
            self.write_field(a)?;
        }
        Ok(())
    }

    /// Writes a vector `v` of elements from the field extension of `F` to `self`.
    #[inline]
    fn write_field_ext_vec<F, const D: usize>(&mut self, v: &[F::Extension]) -> IoResult<()>
    where
        F: RichField + Extendable<D>,
    {
        for &a in v {
            self.write_field_ext::<F, D>(a)?;
        }
        Ok(())
    }

    /// Writes a hash `h` to `self`.
    #[inline]
    fn write_hash<F, H>(&mut self, h: H::Hash) -> IoResult<()>
    where
        F: RichField,
        H: Hasher<F>,
    {
        self.write_all(&h.to_bytes())
    }

    /// Writes `cap`, a value of type [`MerkleCap`], to `self`.
    #[inline]
    fn write_merkle_cap<F, H>(&mut self, cap: &MerkleCap<F, H>) -> IoResult<()>
    where
        F: RichField,
        H: Hasher<F>,
    {
        for &a in &cap.0 {
            self.write_hash::<F, H>(a)?;
        }
        Ok(())
    }

    /// Writes a value `os` of type [`OpeningSet`] to `self.`
    #[inline]
    fn write_opening_set<F, const D: usize>(&mut self, os: &StarkOpeningSet<F, D>) -> IoResult<()>
    where
        F: RichField + Extendable<D>,
    {
        self.write_field_ext_vec::<F, D>(&os.local_values)?;
        self.write_field_ext_vec::<F, D>(&os.next_values)?;
        self.write_field_ext_vec::<F, D>(&os.permutation_ctl_zs)?;
        self.write_field_ext_vec::<F, D>(&os.permutation_ctl_zs_next)?;
        self.write_field_vec(&os.ctl_zs_last)?;
        self.write_field_ext_vec::<F, D>(&os.quotient_polys)
    }

    /// Writes a value `p` of type [`MerkleProof`] to `self.`
    #[inline]
    fn write_merkle_proof<F, H>(&mut self, p: &MerkleProof<F, H>) -> IoResult<()>
    where
        F: RichField,
        H: Hasher<F>,
    {
        let length = p.siblings.len();
        self.write_u8(
            length
                .try_into()
                .expect("Merkle proof length must fit in u8."),
        )?;
        for &h in &p.siblings {
            self.write_hash::<F, H>(h)?;
        }
        Ok(())
    }

    /// Writes a value `fitp` of type [`FriInitialTreeProof`] to `self.`
    #[inline]
    fn write_fri_initial_proof<F, C, const D: usize>(
        &mut self,
        fitp: &FriInitialTreeProof<F, C::Hasher>,
    ) -> IoResult<()>
    where
        F: RichField + Extendable<D>,
        C: GenericConfig<D, F = F>,
    {
        for (v, p) in &fitp.evals_proofs {
            self.write_field_vec(v)?;
            self.write_merkle_proof(p)?;
        }
        Ok(())
    }

    /// Writes a value `fqs` of type [`FriQueryStep`] to `self.`
    #[inline]
    fn write_fri_query_step<F, C, const D: usize>(
        &mut self,
        fqs: &FriQueryStep<F, C::Hasher, D>,
    ) -> IoResult<()>
    where
        F: RichField + Extendable<D>,
        C: GenericConfig<D, F = F>,
    {
        self.write_field_ext_vec::<F, D>(&fqs.evals)?;
        self.write_merkle_proof(&fqs.merkle_proof)
    }

    /// Writes a value `fqrs` of type [`FriQueryRound`] to `self.`
    #[inline]
    fn write_fri_query_rounds<F, C, const D: usize>(
        &mut self,
        fqrs: &[FriQueryRound<F, C::Hasher, D>],
    ) -> IoResult<()>
    where
        F: RichField + Extendable<D>,
        C: GenericConfig<D, F = F>,
    {
        for fqr in fqrs {
            self.write_fri_initial_proof::<F, C, D>(&fqr.initial_trees_proof)?;
            for fqs in &fqr.steps {
                self.write_fri_query_step::<F, C, D>(fqs)?;
            }
        }
        Ok(())
    }

    /// Writes a value `fq` of type [`FriProof`] to `self.`
    #[inline]
    fn write_fri_proof<F, C, const D: usize>(
        &mut self,
        fp: &FriProof<F, C::Hasher, D>,
    ) -> IoResult<()>
    where
        F: RichField + Extendable<D>,
        C: GenericConfig<D, F = F>,
    {
        for cap in &fp.commit_phase_merkle_caps {
            self.write_merkle_cap(cap)?;
        }
        self.write_fri_query_rounds::<F, C, D>(&fp.query_round_proofs)?;
        self.write_field_ext_vec::<F, D>(&fp.final_poly.coeffs)?;
        self.write_field(fp.pow_witness)
    }

    /// Writes a value `proof` of type [`Proof`] to `self.`
    #[inline]
    fn write_proof<F, C, const D: usize>(&mut self, proof: &StarkProof<F, C, D>) -> IoResult<()>
    where
        F: RichField + Extendable<D>,
        C: GenericConfig<D, F = F>,
    {
        self.write_merkle_cap(&proof.trace_cap)?;
        self.write_merkle_cap(&proof.permutation_ctl_zs_cap)?;
        self.write_merkle_cap(&proof.quotient_polys_cap)?;
        self.write_opening_set(&proof.openings)?;
        self.write_fri_proof::<F, C, D>(&proof.opening_proof)
    }

    /// Writes a value `proof_with_pis` of type [`ProofWithPublicInputs`] to `self.`
    #[inline]
    fn write_proof_with_public_inputs<F, C, const D: usize>(
        &mut self,
        proof_with_pis: &StarkProofWithPublicInputs<F, C, D>,
    ) -> IoResult<()>
    where
        F: RichField + Extendable<D>,
        C: GenericConfig<D, F = F>,
    {
        let StarkProofWithPublicInputs {
            proof,
            public_inputs,
        } = proof_with_pis;
        self.write_proof(proof)?;
        self.write_field_vec(public_inputs)
    }
}

impl Write for Vec<u8> {
    type Error = Infallible;

    #[inline]
    fn write_all(&mut self, bytes: &[u8]) -> IoResult<()> {
        self.extend_from_slice(bytes);
        Ok(())
    }
}
