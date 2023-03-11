use std::ops::Mul;

use ark_bls12_381::{Fr as ScalarField, G1Projective, G2Projective};
use ark_ff::UniformRand;

use crate::{bls_sign, bls_verify};

#[test]
fn test_signature() {
    let mut rng = ark_std::rand::thread_rng();

    let g = G1Projective::rand(&mut rng);
    let private_key = ScalarField::rand(&mut rng);
    let public_key = g.mul(private_key);
    let message = G2Projective::rand(&mut rng);

    let signature = bls_sign(private_key, message);

    assert!(bls_verify(public_key, g, signature, message));
}
