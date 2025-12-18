#![no_std]
use soroban_sdk::{
    contract, contractimpl, contracttype,
    crypto::bn254::{Bn254G1Affine, Bn254G2Affine, Fr},
    Env, Vec,
};

#[derive(Clone)]
#[contracttype]
pub struct MockProof {
    pub g1: Vec<Bn254G1Affine>,
    pub g2: Vec<Bn254G2Affine>,
}

#[contract]
pub struct Contract;

#[contractimpl]
impl Contract {
    pub fn verify_pairing(env: Env, proof: MockProof) -> bool {
        env.crypto().bn254().pairing_check(proof.g1, proof.g2)
    }

    pub fn g1_add(a: Bn254G1Affine, b: Bn254G1Affine) -> Bn254G1Affine {
        a + b
    }

    pub fn g1_mul(p: Bn254G1Affine, s: Fr) -> Bn254G1Affine {
        p * s
    }

    pub fn g1_msm(env: Env, points: Vec<Bn254G1Affine>, scalars: Vec<Fr>) -> Bn254G1Affine {
        env.crypto().bn254().g1_msm(points, scalars)
    }

    pub fn fr_add(a: Fr, b: Fr) -> Fr {
        a + b
    }

    pub fn fr_sub(a: Fr, b: Fr) -> Fr {
        a - b
    }

    pub fn fr_mul(a: Fr, b: Fr) -> Fr {
        a * b
    }

    pub fn fr_pow(base: Fr, exp: u64) -> Fr {
        base.pow(exp)
    }

    pub fn fr_inv(base: Fr) -> Fr {
        base.inv()
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use soroban_sdk::{vec, Env, U256};
    extern crate std;

    use crate::{Contract, ContractClient};

    // From https://github.com/ethereum/go-ethereum/blob/master/core/vm/testdata/precompiles/bn256Add.json
    fn parse_ethereum_g1_add_input(input: &str) -> ([u8; 64], [u8; 64]) {
        let bytes = hex::decode(input).unwrap();
        assert_eq!(bytes.len(), 128); // Two G1 points (64 bytes each)

        let g1_1: [u8; 64] = bytes[0..64].try_into().unwrap();
        let g1_2: [u8; 64] = bytes[64..128].try_into().unwrap();
        (g1_1, g1_2)
    }

    fn parse_ethereum_pairing_input(
        input: &str,
    ) -> (std::vec::Vec<[u8; 64]>, std::vec::Vec<[u8; 128]>) {
        let bytes = hex::decode(input).unwrap();
        assert_eq!(bytes.len() % 192, 0); // Each pair is 192 bytes

        let num_pairs = bytes.len() / 192;
        let mut g1_points = std::vec::Vec::new();
        let mut g2_points = std::vec::Vec::new();

        for i in 0..num_pairs {
            let offset = i * 192;
            g1_points.push(bytes[offset..offset + 64].try_into().unwrap());
            g2_points.push(bytes[offset + 64..offset + 192].try_into().unwrap());
        }
        (g1_points, g2_points)
    }

    #[test]
    fn test_add_and_mul() {
        let env = Env::default();
        let contract_id = env.register(Contract, ());
        let client = ContractClient::new(&env, &contract_id);

        let add_input = "23f16f1bcc31bd002746da6fa3825209af9a356ccd99cf79604a430dd592bcd90a03caeda9c5aa40cdc9e4166e083492885dad36c72714e3697e34a4bc72ccaa21315394462f1a39f87462dbceb92718b220e4f80af516f727ad85380fadefbc2e4f40ea7bbe2d4d71f13c84fd2ae24a4a24d9638dd78349d0dee8435a67cca6";
        let (g1_x_bytes, g1_y_bytes) = parse_ethereum_g1_add_input(add_input);

        let x_bn254 = Bn254G1Affine::from_array(&env, &g1_x_bytes);
        let y_bn254 = Bn254G1Affine::from_array(&env, &g1_y_bytes);

        let expected_x_plus_y = hex::decode("013f227997b410cbd96b137a114f5b12d5a3a53d7482797bcd1f116ff30ff1931effebc79dee208d036553beae8ca71afb3b4c00979560db3991c7e67c49103c").unwrap();
        assert_eq!(
            client.g1_add(&x_bn254, &y_bn254).to_array(),
            expected_x_plus_y.as_slice()
        );

        let scalar: Fr = U256::from_u32(&env, 2).into();

        // G + G = 2G
        assert_eq!(
            client.g1_add(&x_bn254, &x_bn254),
            client.g1_mul(&x_bn254, &scalar)
        );
    }

    // From https://github.com/ethereum/go-ethereum/blob/master/core/vm/testdata/precompiles/bn256Pairing.json
    #[test]
    fn test_pairing() {
        let env = Env::default();
        let contract_id = env.register(Contract, ());
        let client = ContractClient::new(&env, &contract_id);

        // Ethereum pairing check input
        let pairing_input = "1c76476f4def4bb94541d57ebba1193381ffa7aa76ada664dd31c16024c43f593034dd2920f673e204fee2811c678745fc819b55d3e9d294e45c9b03a76aef41209dd15ebff5d46c4bd888e51a93cf99a7329636c63514396b4a452003a35bf704bf11ca01483bfa8b34b43561848d28905960114c8ac04049af4b6315a416782bb8324af6cfc93537a2ad1a445cfd0ca2a71acd7ac41fadbf933c2a51be344d120a2a4cf30c1bf9845f20c6fe39e07ea2cce61f0c9bb048165fe5e4de877550111e129f1cf1097710d41c4ac70fcdfa5ba2023c6ff1cbeac322de49d1b6df7c2032c61a830e3c17286de9462bf242fca2883585b93870a73853face6a6bf411198e9393920d483a7260bfb731fb5d25f1aa493335a9e71297e485b7aef312c21800deef121f1e76426a00665e5c4479674322d4f75edadd46debd5cd992f6ed090689d0585ff075ec9e99ad690c3395bc4b313370b38ef355acdadcd122975b12c85ea5db8c6deb4aab71808dcb408fe3d1e7690c43d37b4ce6cc0166fa7daa";

        let (g1_points, g2_points) = parse_ethereum_pairing_input(pairing_input);

        // Convert to Soroban SDK types
        let g1_vec = vec![
            &env,
            Bn254G1Affine::from_array(&env, &g1_points[0]),
            Bn254G1Affine::from_array(&env, &g1_points[1]),
        ];

        let g2_vec = vec![
            &env,
            Bn254G2Affine::from_array(&env, &g2_points[0]),
            Bn254G2Affine::from_array(&env, &g2_points[1]),
        ];

        let proof = MockProof {
            g1: g1_vec,
            g2: g2_vec,
        };

        // This should return true for valid pairing
        assert!(client.verify_pairing(&proof));
    }

    #[test]
    fn test_g1_negation() {
        let env = Env::default();

        let negated_input = "00000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000000130644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd45";
        let bytes = hex::decode(negated_input).unwrap();
        assert_eq!(bytes.len(), 128);

        let g1_bytes: [u8; 64] = bytes[0..64].try_into().unwrap();
        let g1_negaed_bytes: [u8; 64] = bytes[64..128].try_into().unwrap();

        let g1 = Bn254G1Affine::from_array(&env, &g1_bytes);
        let g1_negated = Bn254G1Affine::from_array(&env, &g1_negaed_bytes);

        assert_eq!(-g1, g1_negated);
    }

    #[test]
    fn test_g1_msm() {
        let env = Env::default();
        let contract_id = env.register(Contract, ());
        let client = ContractClient::new(&env, &contract_id);

        // BN254 generator point G1 = (1, 2)
        let g1_bytes: [u8; 64] = [
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 1, // X = 1
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 2, // Y = 2
        ];
        let g1 = Bn254G1Affine::from_array(&env, &g1_bytes);

        let scalar_one: Fr = U256::from_u32(&env, 1).into();
        let scalar_two: Fr = U256::from_u32(&env, 2).into();

        // Test: G1 * 1 + G1 * 1 = G1 * 2 (using MSM vs scalar mul)
        let points = vec![&env, g1.clone(), g1.clone()];
        let scalars = vec![&env, scalar_one.clone(), scalar_one.clone()];

        let msm_result = client.g1_msm(&points, &scalars);
        let expected = client.g1_mul(&g1, &scalar_two);

        assert_eq!(msm_result, expected);

        // Test: G1 * 1 + (-G1) * 1 = identity (zero point)
        let neg_g1 = -g1.clone();
        let points_cancel = vec![&env, g1.clone(), neg_g1];
        let scalars_cancel = vec![&env, scalar_one.clone(), scalar_one];

        let cancel_result = client.g1_msm(&points_cancel, &scalars_cancel);

        // Zero point is encoded as 64 zero bytes
        let zero_bytes = [0u8; 64];
        assert_eq!(cancel_result.to_array(), zero_bytes.as_slice());
    }

    #[test]
    fn test_fr_add() {
        let env = Env::default();
        let contract_id = env.register(Contract, ());
        let client = ContractClient::new(&env, &contract_id);

        let a: Fr = U256::from_u32(&env, 2).into();
        let b: Fr = U256::from_u32(&env, 3).into();
        let zero: Fr = U256::from_u32(&env, 0).into();

        // 2 + 3 = 5
        let result = client.fr_add(&a, &b);
        let expected: Fr = U256::from_u32(&env, 5).into();
        assert_eq!(result.to_u256(), expected.to_u256());

        // a + 0 = a (identity)
        let result_identity = client.fr_add(&a, &zero);
        assert_eq!(result_identity.to_u256(), a.to_u256());

        // a + b = b + a (commutativity)
        let ab = client.fr_add(&a, &b);
        let ba = client.fr_add(&b, &a);
        assert_eq!(ab.to_u256(), ba.to_u256());
    }

    #[test]
    fn test_fr_sub() {
        let env = Env::default();
        let contract_id = env.register(Contract, ());
        let client = ContractClient::new(&env, &contract_id);

        let a: Fr = U256::from_u32(&env, 5).into();
        let b: Fr = U256::from_u32(&env, 3).into();
        let zero: Fr = U256::from_u32(&env, 0).into();

        // 5 - 3 = 2
        let result = client.fr_sub(&a, &b);
        let expected: Fr = U256::from_u32(&env, 2).into();
        assert_eq!(result.to_u256(), expected.to_u256());

        // a - 0 = a (identity)
        let result_identity = client.fr_sub(&a, &zero);
        assert_eq!(result_identity.to_u256(), a.to_u256());

        // a - a = 0
        let result_zero = client.fr_sub(&a, &a);
        assert_eq!(result_zero.to_u256(), zero.to_u256());
    }

    #[test]
    fn test_fr_mul() {
        let env = Env::default();
        let contract_id = env.register(Contract, ());
        let client = ContractClient::new(&env, &contract_id);

        let a: Fr = U256::from_u32(&env, 2).into();
        let b: Fr = U256::from_u32(&env, 3).into();
        let one: Fr = U256::from_u32(&env, 1).into();
        let zero: Fr = U256::from_u32(&env, 0).into();

        // 2 * 3 = 6
        let result = client.fr_mul(&a, &b);
        let expected: Fr = U256::from_u32(&env, 6).into();
        assert_eq!(result.to_u256(), expected.to_u256());

        // a * 1 = a (identity)
        let result_identity = client.fr_mul(&a, &one);
        assert_eq!(result_identity.to_u256(), a.to_u256());

        // a * 0 = 0
        let result_zero = client.fr_mul(&a, &zero);
        assert_eq!(result_zero.to_u256(), zero.to_u256());

        // a * b = b * a (commutativity)
        let ab = client.fr_mul(&a, &b);
        let ba = client.fr_mul(&b, &a);
        assert_eq!(ab.to_u256(), ba.to_u256());
    }

    #[test]
    fn test_fr_pow() {
        let env = Env::default();
        let contract_id = env.register(Contract, ());
        let client = ContractClient::new(&env, &contract_id);

        let a: Fr = U256::from_u32(&env, 2).into();
        let one: Fr = U256::from_u32(&env, 1).into();

        // 2^0 = 1
        let result_zero_exp = client.fr_pow(&a, &0u64);
        assert_eq!(result_zero_exp.to_u256(), one.to_u256());

        // 2^1 = 2
        let result_one_exp = client.fr_pow(&a, &1u64);
        assert_eq!(result_one_exp.to_u256(), a.to_u256());

        // 2^10 = 1024
        let result = client.fr_pow(&a, &10u64);
        let expected: Fr = U256::from_u32(&env, 1024).into();
        assert_eq!(result.to_u256(), expected.to_u256());

        // 3^5 = 243
        let three: Fr = U256::from_u32(&env, 3).into();
        let result_3_5 = client.fr_pow(&three, &5u64);
        let expected_243: Fr = U256::from_u32(&env, 243).into();
        assert_eq!(result_3_5.to_u256(), expected_243.to_u256());
    }

    #[test]
    fn test_fr_inv() {
        let env = Env::default();
        let contract_id = env.register(Contract, ());
        let client = ContractClient::new(&env, &contract_id);

        let one: Fr = U256::from_u32(&env, 1).into();

        // 1^(-1) = 1
        let result_one_inv = client.fr_inv(&one);
        assert_eq!(result_one_inv.to_u256(), one.to_u256());

        // For any a, a * a^(-1) = 1
        let a: Fr = U256::from_u32(&env, 7).into();
        let a_inv = client.fr_inv(&a);
        let product = client.fr_mul(&a, &a_inv);
        assert_eq!(product.to_u256(), one.to_u256());

        // Another test: 2 * 2^(-1) = 1
        let two: Fr = U256::from_u32(&env, 2).into();
        let two_inv = client.fr_inv(&two);
        let product_two = client.fr_mul(&two, &two_inv);
        assert_eq!(product_two.to_u256(), one.to_u256());
    }
}
