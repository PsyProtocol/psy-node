use parth_core::{felt::{QFelt, QFelt64, QFeltSized, ToQFelts}, utils::QPGenRandom};
use psy_io::{PsyReaderExtensions, PsyWriterExtensions};
use psy_serialize::{FallbackPsySerializeCanonical, PsyCanonicalSerializeMetadata};


pub const PM_JOBS_COMPLETED_STATS_SIZE: usize = 3;

#[pderive::serialize_copy_f_ts]
#[ts(export, concrete(F = parth_core::PF), rename = "PMJobsCompletedStats")]
#[repr(C)]
pub struct PPMJobsCompletedStats<F> {
    pub deploy_contracts_completed: F,
    pub register_users_completed: F, 
    pub gutas_completed: F,
}

impl<F: Copy> PPMJobsCompletedStats<F> {
    pub fn new_empty_with_zero(zero: F) -> Self {
        Self {
            deploy_contracts_completed: zero,
            register_users_completed: zero,
            gutas_completed: zero,
        }
    }

    pub fn new_deploy_contracts_with_zero(zero: F, count: F) -> Self {
        Self {
            deploy_contracts_completed: count,
            register_users_completed: zero,
            gutas_completed: zero,
        }
    }

    pub fn new_register_users_with_zero(zero: F, count: F) -> Self {
        Self {
            deploy_contracts_completed: zero,
            register_users_completed: count,
            gutas_completed: zero,
        }
    }

    pub fn new_gutas_with_zero(zero: F, count: F) -> Self {
        Self {
            deploy_contracts_completed: zero,
            register_users_completed: zero,
            gutas_completed: count,
        }
    }
}
impl<F: QFelt> PPMJobsCompletedStats<F> {
    pub fn new_empty() -> Self {
        Self {
            deploy_contracts_completed: F::ZERO_VALUE,
            register_users_completed: F::ZERO_VALUE,
            gutas_completed: F::ZERO_VALUE,
        }
    }

    pub fn new_deploy_contracts(count: F) -> Self {
        Self {
            deploy_contracts_completed: count,
            register_users_completed: F::ZERO_VALUE,
            gutas_completed: F::ZERO_VALUE,
        }
    }

    pub fn new_register_users(count: F) -> Self {
        Self {
            deploy_contracts_completed: F::ZERO_VALUE,
            register_users_completed: count,
            gutas_completed: F::ZERO_VALUE,
        }
    }

    pub fn new_gutas(count: F) -> Self {
        Self {
            deploy_contracts_completed: F::ZERO_VALUE,
            register_users_completed: F::ZERO_VALUE,
            gutas_completed: count,
        }
    }

    pub fn combine(&self, other: &Self) -> Self {
        Self {
            deploy_contracts_completed: self.deploy_contracts_completed + other.deploy_contracts_completed,
            register_users_completed: self.register_users_completed + other.register_users_completed,
            gutas_completed: self.gutas_completed + other.gutas_completed,
        }
    }

    pub fn total(&self) -> F {
        self.deploy_contracts_completed + self.register_users_completed + self.gutas_completed
    }
}
impl<F: QFelt> QFeltSized for PPMJobsCompletedStats<F> {
    fn q_felt_size() -> usize {
        PM_JOBS_COMPLETED_STATS_SIZE
    }
}

impl<F: QFelt> ToQFelts<F> for PPMJobsCompletedStats<F> {
    fn to_qfelts(&self) -> Vec<F> {
        vec![
            self.deploy_contracts_completed,
            self.register_users_completed,
            self.gutas_completed,
        ]
    }

    fn from_qfelts(felts: &[F]) -> Self {
        if felts.len() != PM_JOBS_COMPLETED_STATS_SIZE {
            panic!("Invalid number of elements for PMJobsCompletedStats, expected {} got {}", PM_JOBS_COMPLETED_STATS_SIZE, felts.len());
        }
        PPMJobsCompletedStats {
            deploy_contracts_completed: felts[0],
            register_users_completed: felts[1], 
            gutas_completed: felts[2],
        }
    }
}


impl<F: QPGenRandom> QPGenRandom for PPMJobsCompletedStats<F> {
    fn qp_rand_gen() -> Self where Self: Sized {
        Self {
            deploy_contracts_completed: F::qp_rand_gen(),
            register_users_completed: F::qp_rand_gen(),
            gutas_completed: F::qp_rand_gen(),
        }
    }
}

impl<F: QFelt64> PsyCanonicalSerializeMetadata for PPMJobsCompletedStats<F> {
    const IS_FIXED_SIZE: bool = true;
    const FIXED_SIZE: usize = 24; // 3 * 8 bytes for F = QFelt64
}
impl<F: QFelt64> FallbackPsySerializeCanonical for PPMJobsCompletedStats<F> {
    fn fallback_pio_serialized_size(&self) -> usize {
        24
    }
    
    fn fallback_pio_write_to_io<W: psy_io::Write>(&self, writer: &mut W) -> anyhow::Result<()> {
        writer.psy_write_u64(self.register_users_completed.to_u64_value())?;
        writer.psy_write_u64(self.gutas_completed.to_u64_value())?;
        writer.psy_write_u64(self.deploy_contracts_completed.to_u64_value())?;
        Ok(())
    }
    
    fn fallback_pio_read_from_io<R: psy_io::Read>(reader: &mut R) -> anyhow::Result<Self> {
        
        let register_users_completed = F::from_u64_value(reader.psy_read_u64()?);
        let gutas_completed = F::from_u64_value(reader.psy_read_u64()?);
        let deploy_contracts_completed = F::from_u64_value(reader.psy_read_u64()?);

        Ok(Self {
            deploy_contracts_completed,
            register_users_completed,
            gutas_completed,
        })
    }

}

#[cfg(all(feature = "serialize_speedy", target_endian = "little"))]
psy_serialize::impl_psy_canonical_serialize_for_speedy!(
    PPMJobsCompletedStats,
    { F: QFelt64 } => { F }
);
#[cfg(not(all(feature = "serialize_speedy", target_endian = "little")))]
impl<F: QFelt64> psy_serialize::AutoImplementFallbackPsySerializeCanonical for PPMJobsCompletedStats<F> {}


pser::impl_psy_ser_basic_tests_fallback!(
    PPMJobsCompletedStats,
    { parth_core::PF },
    ppm_jobs_completed_stats
);

#[cfg(test)]
mod tests  {
    use parth_core::felt::{FromPrimitiveValuesFelt, QFelt64};
    use psy_serialize::PsyIOReadWrite;

    use crate::v1::qdata::pm_jobs_completed_stats::PPMJobsCompletedStats;

    fn testz<F: QFelt64 + speedy::Readable<'static, speedy::LittleEndian> + speedy::Writable<speedy::LittleEndian>>(x: &PPMJobsCompletedStats<F>) 
    {
        let _bytes = x.pio_get_variable_serialized_size();
    }
    #[test]
    fn test_gg(){
        let stats = super::PPMJobsCompletedStats::<parth_core::PF> {
            deploy_contracts_completed: parth_core::PF::from_u64_value(10),
            register_users_completed: parth_core::PF::from_u64_value(20),
            gutas_completed: parth_core::PF::from_u64_value(30),
        };
        testz(&stats);
    }
}