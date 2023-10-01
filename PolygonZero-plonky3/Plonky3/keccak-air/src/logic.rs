use p3_field::{AbstractField, PrimeField32, PrimeField64};

pub(crate) fn xor<F: PrimeField32, const N: usize>(xs: [F; N]) -> F {
    xs.into_iter().fold(F::ZERO, |acc, x| {
        debug_assert!(x.is_zero() || x.is_one());
        F::from_canonical_u32(acc.as_canonical_u32() ^ x.as_canonical_u32())
    })
}

/// Computes the arithmetic generalization of `xor(x, y)`, i.e. `x + y - 2 x y`.
pub(crate) fn xor_gen<F: AbstractField>(x: F, y: F) -> F {
    x.clone() + y.clone() - x * y.double()
}

/// Computes the arithmetic generalization of `xor3(x, y, z)`.
pub(crate) fn xor3_gen<F: AbstractField>(x: F, y: F, z: F) -> F {
    xor_gen(x, xor_gen(y, z))
}

pub(crate) fn andn<F: PrimeField32>(x: F, y: F) -> F {
    debug_assert!(x.is_zero() || x.is_one());
    debug_assert!(y.is_zero() || y.is_one());
    let x = x.as_canonical_u32();
    let y = y.as_canonical_u32();
    F::from_canonical_u32(!x & y)
}

pub(crate) fn andn_gen<F: AbstractField>(x: F, y: F) -> F {
    (F::ONE - x) * y
}

pub(crate) fn xor_64<F: PrimeField64, const N: usize>(xs: [F; N]) -> F {
    xs.into_iter().fold(F::ZERO, |acc, x| {
        debug_assert!(x.is_zero() || x.is_one());
        F::from_canonical_u64(acc.as_canonical_u64() ^ x.as_canonical_u64())
    })
}

pub(crate) fn andn_64<F: PrimeField64>(x: F, y: F) -> F {
    debug_assert!(x.is_zero() || x.is_one());
    debug_assert!(y.is_zero() || y.is_one());
    let x = x.as_canonical_u64();
    let y = y.as_canonical_u64();
    F::from_canonical_u64(!x & y)
}
