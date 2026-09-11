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
        // Preserve the legacy fallback wire order. These bytes have no version
        // marker, so changing the order would silently reinterpret stored data.
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


// The legacy fallback order predates and differs from Speedy's struct-field
// order, so this type cannot use the cross-encoding equality test.
pser::impl_psy_ser_basic_tests!(
    PPMJobsCompletedStats,
    { parth_core::PF },
    ppm_jobs_completed_stats
);

#[cfg(test)]
mod tests  {
    use parth_core::felt::{FromPrimitiveValuesFelt, QFelt64, QFeltSized, ToQFelts};
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

    #[test]
    fn constructors_combine_total_and_felts_preserve_all_counters() {
        type F = parth_core::PF;
        let zero = F::from_u64_value(0);
        let deploy = PPMJobsCompletedStats::new_deploy_contracts(F::from_u64_value(2));
        let users = PPMJobsCompletedStats::new_register_users(F::from_u64_value(3));
        let gutas = PPMJobsCompletedStats::new_gutas(F::from_u64_value(5));
        assert_eq!(PPMJobsCompletedStats::new_empty(), PPMJobsCompletedStats::new_empty_with_zero(zero));
        assert_eq!(PPMJobsCompletedStats::new_deploy_contracts_with_zero(zero, F::from_u64_value(2)), deploy);
        assert_eq!(PPMJobsCompletedStats::new_register_users_with_zero(zero, F::from_u64_value(3)), users);
        assert_eq!(PPMJobsCompletedStats::new_gutas_with_zero(zero, F::from_u64_value(5)), gutas);

        let combined = deploy.combine(&users).combine(&gutas);
        assert_eq!(combined.total(), F::from_u64_value(10));
        let felts: Vec<F> = combined.to_qfelts();
        assert_eq!(felts.len(), PPMJobsCompletedStats::<F>::q_felt_size());
        assert_eq!(PPMJobsCompletedStats::from_qfelts(&felts), combined);
    }

    #[test]
    #[should_panic(expected = "Invalid number of elements for PMJobsCompletedStats")]
    fn from_qfelts_rejects_wrong_felt_count() {
        let stats = super::PPMJobsCompletedStats::<parth_core::PF>::new_register_users(parth_core::PF::from_u64_value(1));
        let felts: Vec<parth_core::PF> = stats.to_qfelts();
        assert_eq!(felts.len(), 3);
        let _ = super::PPMJobsCompletedStats::<parth_core::PF>::from_qfelts(&felts[..2]);
    }

    #[test]
    fn combine_with_empty_is_identity_and_empty_total_is_zero() {
        type F = parth_core::PF;
        let stats = super::PPMJobsCompletedStats::<F>::new_gutas(F::from_u64_value(8));
        let empty = super::PPMJobsCompletedStats::<F>::new_empty();
        assert_eq!(empty.total(), F::from_u64_value(0));
        assert_eq!(stats.combine(&empty), stats);
        assert_eq!(empty.combine(&stats), stats);
    }

    #[test]
    fn fallback_io_preserves_legacy_register_gutas_deploy_order() {
        use psy_serialize::FallbackPsySerializeCanonical;

        let stats = super::PPMJobsCompletedStats::<parth_core::PF> {
            deploy_contracts_completed: parth_core::PF::from_u64_value(10),
            register_users_completed: parth_core::PF::from_u64_value(20),
            gutas_completed: parth_core::PF::from_u64_value(30),
        };
        let bytes = stats.fallback_psy_ser_to_bytes_vec().unwrap();
        assert_eq!(bytes.len(), 24);
        assert_eq!(u64::from_le_bytes(bytes[0..8].try_into().unwrap()), 20);
        assert_eq!(u64::from_le_bytes(bytes[8..16].try_into().unwrap()), 30);
        assert_eq!(u64::from_le_bytes(bytes[16..24].try_into().unwrap()), 10);
        assert_eq!(
            super::PPMJobsCompletedStats::<parth_core::PF>::fallback_psy_ser_from_slice(&bytes).unwrap(),
            stats
        );
    }
}
