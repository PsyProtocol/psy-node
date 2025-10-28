use plonky2::plonk::{circuit_data::{CircuitData, CommonCircuitData}, config::{AlgebraicHasher, GenericConfig}};

use crate::lookalike::{custom::get_lookalike_custom, types::QCircuitCommonGatesType};


pub fn get_guta_type_c_lookalike_circuit_data<C: GenericConfig<D>, const D: usize>() -> CircuitData<C::F, C, D>
where
    C::Hasher: AlgebraicHasher<C::F>,
{
    get_lookalike_custom::<C, D>(QCircuitCommonGatesType::C, 13, 15)
}

pub fn get_guta_type_c_common_data<C: GenericConfig<D>, const D: usize>(
) -> CommonCircuitData<C::F, D>
where
    C::Hasher: AlgebraicHasher<C::F>,
{
    get_guta_type_c_lookalike_circuit_data::<C, D>().common
}

pub fn get_agg_state_transition_type_d_lookalike_circuit_data<C: GenericConfig<D>, const D: usize>(
) -> CircuitData<C::F, C, D>
where
    C::Hasher: AlgebraicHasher<C::F>,
{
    get_lookalike_custom::<C, D>(QCircuitCommonGatesType::D, 13, 19)
}

pub fn get_agg_state_transition_type_d_common_data<C: GenericConfig<D>, const D: usize>(
) -> CommonCircuitData<C::F, D>
where
    C::Hasher: AlgebraicHasher<C::F>,
{
    get_agg_state_transition_type_d_lookalike_circuit_data::<C, D>().common
}

pub fn get_agg_user_registration_deploy_guta_type_f_lookalike_circuit_data<C: GenericConfig<D>, const D: usize>(
) -> CircuitData<C::F, C, D>
where
    C::Hasher: AlgebraicHasher<C::F>,
{
    get_lookalike_custom::<C, D>(QCircuitCommonGatesType::F, 12, 19)
}

pub fn get_agg_user_registration_deploy_guta_type_f_common_data<C: GenericConfig<D>, const D: usize>(
) -> CommonCircuitData<C::F, D>
where
    C::Hasher: AlgebraicHasher<C::F>,
{
    get_agg_user_registration_deploy_guta_type_f_lookalike_circuit_data::<C, D>().common
}

pub fn get_end_cap_type_e_lookalike_circuit_data<C: GenericConfig<D>, const D: usize>(
) -> CircuitData<C::F, C, D>
where
    C::Hasher: AlgebraicHasher<C::F>,
{
    get_lookalike_custom::<C, D>(QCircuitCommonGatesType::E, 12, 4)
}

pub fn get_end_cap_type_e_common_data<C: GenericConfig<D>, const D: usize>(
) -> CommonCircuitData<C::F, D>
where
    C::Hasher: AlgebraicHasher<C::F>,
{
    get_end_cap_type_e_lookalike_circuit_data::<C, D>().common
}
