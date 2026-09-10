//! prove-proxy: wallet-facing (user) and relayer-facing (system) proving RPCs.
//!
//! `user` and `system` are separate `#[rpc]` traits so a process can register
//! exactly one family; see `assemble_rpc_module` (Task 3).

pub mod user;

#[cfg(feature = "gnark-wrap")]
pub mod system;
#[cfg(feature = "gnark-wrap")]
pub mod types;

use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};

pub(crate) type C = PoseidonGoldilocksConfig;
pub(crate) type F = <C as GenericConfig<D>>::F;
pub(crate) const D: usize = 2;
