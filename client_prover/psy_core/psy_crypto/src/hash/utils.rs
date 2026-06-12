use itertools::Itertools;
use plonky2::hash::hash_types::RichField;
use psy_client_common::data::qhashout::QHashOut;

use super::{core::sha256::CoreSha256Hasher, traits::hasher::FieldQHasher};

pub fn safe_hash_fixed_length<H: FieldQHasher<F>, F: RichField>(data: &[F]) -> QHashOut<F> {
    let data_len = data.len();
    let data_len_felt = F::from_canonical_u64(data_len as u64);
    let mut preimage = Vec::with_capacity(data_len + 2);
    preimage.push(data_len_felt);
    preimage.extend_from_slice(data);
    preimage.push(data_len_felt);
    H::q_hash_many(&preimage)
}

pub fn gen_dapen_contract_function_method_id(method_name: String, args: &[(String, usize)]) -> u32 {
    // method id = sha256(methodName(arg0[arg0_size],arg1[arg1_size]))&0xffffffff

    let arg_portion = args.iter().map(|(arg_name, arg_size)| format!("{}[{}]", arg_name, arg_size)).join(",");

    let preimage = format!("{}({})", method_name, arg_portion);

    let hash_raw = CoreSha256Hasher::hash_bytes(preimage.as_bytes());
    let method_id = u32::from_le_bytes([hash_raw.0[0], hash_raw.0[1], hash_raw.0[2], hash_raw.0[3]]);

    method_id
}
