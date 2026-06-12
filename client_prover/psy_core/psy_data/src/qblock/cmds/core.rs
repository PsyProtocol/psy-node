use plonky2::hash::hash_types::RichField;
use serde::{Deserialize, Serialize};

use super::{deploy_contract::QBCDeployContract, register_user::QBCRegisterUser, update_user::QBCUpdateUser};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(bound = "for<'de2> F: Deserialize<'de2>")]

pub struct PsyBlockCommands<F: RichField> {
    pub register_users: Vec<QBCRegisterUser<F>>,
    pub deploy_contracts: Vec<QBCDeployContract<F>>,
    pub update_users: Vec<QBCUpdateUser<F>>,
}
