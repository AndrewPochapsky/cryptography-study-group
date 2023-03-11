#[cfg(test)]
mod testing;

use std::ops::Mul;

use ark_bls12_381::{Bls12_381, FrConfig, G1Projective, G2Projective};
use ark_ec::pairing::Pairing;
use ark_ff::{Fp, MontBackend};

type Scalar = Fp<MontBackend<FrConfig, 4>, 4>;

fn bls_sign(private_key: Scalar, message: G2Projective) -> G2Projective {
    message.mul(private_key)
}

fn bls_verify(
    public_key: G1Projective,
    g: G1Projective,
    signature: G2Projective,
    message: G2Projective,
) -> bool {
    Bls12_381::pairing(public_key, message) == Bls12_381::pairing(g, signature)
}
