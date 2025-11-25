#![no_std]
use soroban_sdk::{
    contract, contractimpl, contracttype,
    crypto::bn254::{Fr, G1Affine, G2Affine},
    Env, Vec,
};

#[derive(Clone)]
#[contracttype]
pub struct MockProof {
    pub g1: Vec<G1Affine>,
    pub g2: Vec<G2Affine>,
}

#[contract]
pub struct Contract;

#[contractimpl]
impl Contract {
    pub fn verify_pairing(env: Env, proof: MockProof) -> bool {
        env.crypto().bn254().pairing_check(proof.g1, proof.g2)
    }

    pub fn g1_add(a: G1Affine, b: G1Affine) -> G1Affine {
        a + b
    }

    pub fn g1_mul(p: G1Affine, s: Fr) -> G1Affine {
        p * s
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use soroban_sdk::{crypto::bn254, vec, Env, U256};
    extern crate std;

    use std::ops::Add;

    use crate::{Contract, ContractClient};

    use ark_bn254::{Fq2 as Fp2, G1Affine, G2Affine};
    use ark_ec::CurveGroup;
    use ark_ff::UniformRand;
    use ark_serialize::CanonicalSerialize;

    // Helper function to serialize G1 point in Ethereum-compatible format
    // Ethereum format: big-endian X || big-endian Y (64 bytes total)
    // Arkworks format: little-endian X || little-endian Y
    fn serialize_g1_ethereum(point: &G1Affine) -> [u8; 64] {
        let mut bytes = [0u8; 64];

        // Serialize X coordinate (32 bytes)
        let mut x_bytes = [0u8; 32];
        point.x.serialize_uncompressed(&mut x_bytes[..]).unwrap();
        x_bytes.reverse(); // Convert from little-endian to big-endian
        bytes[0..32].copy_from_slice(&x_bytes);

        // Serialize Y coordinate (32 bytes)
        let mut y_bytes = [0u8; 32];
        point.y.serialize_uncompressed(&mut y_bytes[..]).unwrap();
        y_bytes.reverse(); // Convert from little-endian to big-endian
        bytes[32..64].copy_from_slice(&y_bytes);

        bytes
    }

    // Helper function to serialize G2 point in Ethereum-compatible format
    // Ethereum format for Fp2: big-endian c1 || big-endian c0 (where c0+c1*i)
    // Arkworks format for Fp2: little-endian c0 || little-endian c1
    fn serialize_g2_ethereum(point: &G2Affine) -> [u8; 128] {
        let mut bytes = [0u8; 128];

        // Serialize X coordinate (Fp2, 64 bytes)
        serialize_fp2_ethereum(&point.x, &mut bytes[0..64]);

        // Serialize Y coordinate (Fp2, 64 bytes)
        serialize_fp2_ethereum(&point.y, &mut bytes[64..128]);

        bytes
    }

    // Helper to serialize Fp2 element in Ethereum format
    // Ethereum: big-endian c1 || big-endian c0
    // Arkworks: little-endian c0 || little-endian c1
    fn serialize_fp2_ethereum(fp2: &Fp2, output: &mut [u8]) {
        // Serialize c0 (real part)
        let mut c0_bytes = [0u8; 32];
        fp2.c0.serialize_uncompressed(&mut c0_bytes[..]).unwrap();
        c0_bytes.reverse(); // Convert to big-endian

        // Serialize c1 (imaginary part)
        let mut c1_bytes = [0u8; 32];
        fp2.c1.serialize_uncompressed(&mut c1_bytes[..]).unwrap();
        c1_bytes.reverse(); // Convert to big-endian

        // Ethereum format: c1 || c0
        output[0..32].copy_from_slice(&c1_bytes);
        output[32..64].copy_from_slice(&c0_bytes);
    }

    #[test]
    fn test_add_and_mul() {
        let env = Env::default();
        let contract_id = env.register(Contract, ());
        let client = ContractClient::new(&env, &contract_id);

        // Generate random points
        let mut rng = ark_std::test_rng();

        let a_point = G1Affine::rand(&mut rng);
        let a_bytes = serialize_g1_ethereum(&a_point);

        let a_bn254 = bn254::G1Affine::from_array(&env, &a_bytes);

        let scalar: bn254::Fr = U256::from_u32(&env, 2).into();

        // G + G = 2G
        assert_eq!(
            client.g1_add(&a_bn254, &a_bn254),
            client.g1_mul(&a_bn254, &scalar)
        );
    }

    // Test e(P, Q+R) = e(P, Q)*e(P, R)
    // We verify: e(-P, Q+R) * e(P, Q) * e(P, R) = 1
    #[test]
    fn test_pairing() {
        let env = Env::default();
        let contract_id = env.register(Contract, ());
        let client = ContractClient::new(&env, &contract_id);

        // Generate random points
        let mut rng = ark_std::test_rng();
        let p = G1Affine::rand(&mut rng);
        let neg_p = -p;
        let q = G2Affine::rand(&mut rng);
        let r = G2Affine::rand(&mut rng);
        let q_plus_r = &q.add(&r).into_affine();

        // Serialize points using Ethereum-compatible format
        let p_bytes = serialize_g1_ethereum(&p);
        let neg_p_bytes = serialize_g1_ethereum(&neg_p);
        let q_bytes = serialize_g2_ethereum(&q);
        let r_bytes = serialize_g2_ethereum(&r);
        let q_plus_r_bytes = serialize_g2_ethereum(q_plus_r);

        // Create proof
        let proof = MockProof {
            g1: vec![
                &env,
                bn254::G1Affine::from_array(&env, &neg_p_bytes),
                bn254::G1Affine::from_array(&env, &p_bytes),
                bn254::G1Affine::from_array(&env, &p_bytes),
            ],
            g2: vec![
                &env,
                bn254::G2Affine::from_array(&env, &q_plus_r_bytes),
                bn254::G2Affine::from_array(&env, &q_bytes),
                bn254::G2Affine::from_array(&env, &r_bytes),
            ],
        };

        assert!(client.verify_pairing(&proof));
    }
}
