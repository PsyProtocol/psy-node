use anyhow::{anyhow, ensure};
use plonky2::{field::goldilocks_field::GoldilocksField, plonk::circuit_data::CommonCircuitData};

use crate::protocol::GuardianSignError;

type F = GoldilocksField;
type Result<T, E = GuardianSignError> = std::result::Result<T, E>;

/// Exact `bincode::serialize` size for a valid D=2 Poseidon EndCap proof.
/// Serde encodes every Vec length as u64; fields, extension elements and hashes
/// occupy 8, 16 and 32 bytes. This counts shape, not proof validity.
pub fn approved_endcap_proof_bound(common: &CommonCircuitData<F, 2>) -> anyhow::Result<usize> {
    let c = &common.config;
    let f = &common.fri_params;
    ensure!(c.fri_config.cap_height == f.config.cap_height
        && c.fri_config.rate_bits == f.config.rate_bits
        && c.fri_config.num_query_rounds == f.config.num_query_rounds,
        "inconsistent EndCap FRI configuration");
    let bytes = (|| -> Option<usize> {
        let power = |bits: usize| 1usize.checked_shl(u32::try_from(bits).ok()?);
        let challenges = c.num_challenges;
        let preprocessed = common.num_constants.checked_add(c.num_routed_wires)?;
        let lookups = challenges.checked_mul(common.num_lookup_polys)?;
        let partial = challenges.checked_mul(common.num_partial_products)?;
        let quotient = challenges.checked_mul(common.quotient_degree_factor)?;
        let openings = preprocessed.checked_add(c.num_wires)?
            .checked_add(challenges.checked_mul(2)?)?
            .checked_add(lookups.checked_mul(2)?)?
            .checked_add(partial)?.checked_add(quotient)?;
        let salt = plonky2::plonk::plonk_common::salt_size(f.hiding);
        let leaves = preprocessed.checked_add(c.num_wires)?
            .checked_add(challenges)?.checked_add(partial)?.checked_add(lookups)?
            .checked_add(quotient)?.checked_add(salt.checked_mul(3)?)?;
        let mut depth = f.degree_bits.checked_add(f.config.rate_bits)?
            .checked_sub(f.config.cap_height)?;
        let mut query_bytes = leaves.checked_mul(8)?
            .checked_add(depth.checked_mul(32)?.checked_add(16)?.checked_mul(4)?)?
            .checked_add(16)?;
        let mut final_bits = f.degree_bits;
        for &arity_bits in &f.reduction_arity_bits {
            depth = depth.checked_sub(arity_bits)?;
            final_bits = final_bits.checked_sub(arity_bits)?;
            query_bytes = query_bytes.checked_add(power(arity_bits)?.checked_mul(16)?)?
                .checked_add(16)?.checked_add(depth.checked_mul(32)?)?;
        }
        let cap_bytes = power(f.config.cap_height)?.checked_mul(32)?.checked_add(8)?;
        let caps = f.reduction_arity_bits.len().checked_add(3)?.checked_mul(cap_bytes)?;
        caps.checked_add(openings.checked_mul(16)?)?.checked_add(9 * 8)?
            .checked_add(query_bytes.checked_mul(f.config.num_query_rounds)?)?
            .checked_add(power(final_bits)?.checked_mul(16)?)?
            .checked_add(40)?
            .checked_add(common.num_public_inputs.checked_mul(8)?)
    })().ok_or_else(|| anyhow!("invalid or overflowing EndCap proof shape"))?;
    Ok(bytes)
}

pub fn approved_endcap_max_proof_bytes() -> Result<u32> {
    let common = psy_plonky2_basic_helpers::lookalike::standard::get_end_cap_type_e_common_data::<plonky2::plonk::config::PoseidonGoldilocksConfig, 2>();
    u32::try_from(approved_endcap_proof_bound(&common).map_err(|_| GuardianSignError::AuthorizationMismatch)?)
        .map_err(|_| GuardianSignError::AuthorizationMismatch)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bound_matches_library_serialization() {
        let mut builder = plonky2::plonk::circuit_builder::CircuitBuilder::<F, 2>::new(plonky2::plonk::circuit_data::CircuitConfig::standard_recursion_config());
        let value = builder.zero();
        builder.register_public_input(value);
        let circuit = builder.build::<plonky2::plonk::config::PoseidonGoldilocksConfig>();
        let proof = circuit.prove(plonky2::iop::witness::PartialWitness::new()).unwrap();
        assert_eq!(approved_endcap_proof_bound(&circuit.common).unwrap(), bincode::serialize(&proof).unwrap().len());
        circuit.verify(proof).unwrap();
    }

    #[test]
    fn rejects_overflow_and_impossible_merkle_depths() {
        let builder = plonky2::plonk::circuit_builder::CircuitBuilder::<F, 2>::new(plonky2::plonk::circuit_data::CircuitConfig::standard_recursion_config());
        let common = builder.build::<plonky2::plonk::config::PoseidonGoldilocksConfig>().common;
        let mut invalid = common.clone();
        invalid.num_public_inputs = usize::MAX;
        assert!(approved_endcap_proof_bound(&invalid).is_err());
        invalid = common.clone();
        invalid.fri_params.degree_bits = usize::MAX;
        assert!(approved_endcap_proof_bound(&invalid).is_err());
        invalid = common.clone();
        invalid.fri_params.reduction_arity_bits = vec![common.fri_params.degree_bits + 1];
        assert!(approved_endcap_proof_bound(&invalid).is_err());
        invalid = common.clone();
        invalid.config.fri_config.cap_height = usize::BITS as usize;
        invalid.fri_params.config.cap_height = usize::BITS as usize;
        assert!(approved_endcap_proof_bound(&invalid).is_err());
        invalid = common;
        invalid.fri_params.config.num_query_rounds += 1;
        assert!(approved_endcap_proof_bound(&invalid).is_err());
    }
}
