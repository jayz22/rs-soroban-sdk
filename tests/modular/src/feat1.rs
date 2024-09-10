use soroban_sdk::contractimpl;

use crate::Contract;
use crate::ContractClient;

#[contractimpl]
impl Contract {
    pub fn one() -> u32 {
        1
    }
}