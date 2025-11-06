use parth_common::memory_stores::simple_memory_merkle_store::SimpleMemoryMerkleStore;
use parth_core::{
    crypto::hash::traits::MerkleZeroHasher,
    data::{db::row::QDatabaseSingleIdTableRowNoCheckpointIdLike, serializable::QPDSerializable},
    impl_qpq_serialize_bincode,
    protocol::core_types::QHashBase,
    utils::{QPGenRandom, debug_code_string::QToCodeString, qp_random_bytes_vec_in_range_insecure},
};
use pser::{QBytesDeserialize, QBytesSerialize};
use psy_io::{PsyReaderExtensions, PsyWriterExtensions};
use psy_serialize::{PsyCanonicalDatabaseSerializeBaseSingle, PsyIOReadWrite, FallbackPsySerializeCanonical, PsyCanonicalSerializeMetadata};
use ts_rs::TS;

#[pderive::serialize_clone]
#[derive(TS)]
#[ts(export)]
#[repr(C)]
pub struct ContractFunctionCodeDefinition {
    // TODO: in the future method id = sha256(functionName(arg0[arg0_size],arg1[arg1_size]))&0xffffffff
    // CURRENT: sha256(functionName + "-|-" + args_count)&0xffffffff
    pub method_id: u32,
    pub num_inputs: u32,
    pub num_outputs: u32,
    pub vm_type: u32,
    pub code: Vec<u8>,
}
impl QToCodeString for ContractFunctionCodeDefinition {
    fn to_debug_code_string(&self) -> String {
        format!(r#"
        (
            ContractFunctionCodeDefinition {{
                method_id: {},
                num_inputs: {},
                num_outputs: {},
                vm_type: {},
                code: hex_literal::hex!("{}").to_vec(),
            }},
            "{}"
        ),
        "#,
            self.method_id,
            self.num_inputs,
            self.num_outputs,
            self.vm_type,
            hex::encode(&self.code),
            hex::encode(&self.psy_ser_to_bytes_vec().unwrap())
        )
    }
}

impl FallbackPsySerializeCanonical for ContractFunctionCodeDefinition {
    fn fallback_pio_serialized_size(&self) -> usize {
        4 + 4 + 4 + 4 + 4 + self.code.len()
    }
    
    fn fallback_pio_write_to_io<W: psy_io::Write>(&self, writer: &mut W) -> anyhow::Result<()> {
        writer.psy_write_u32(self.method_id)?;
        writer.psy_write_u32(self.num_inputs)?;
        writer.psy_write_u32(self.num_outputs)?;
        writer.psy_write_u32(self.vm_type)?;
        writer.psy_write_bytes_vec(&self.code)?;

        Ok(())
    }
    
    fn fallback_pio_read_from_io<R: psy_io::Read>(reader: &mut R) -> anyhow::Result<Self> {
        let method_id = reader.psy_read_u32()?;
        let num_inputs = reader.psy_read_u32()?;
        let num_outputs = reader.psy_read_u32()?;
        let vm_type = reader.psy_read_u32()?;
        let code = reader.psy_read_bytes_vec()?;

        Ok(Self {
            method_id,
            num_inputs,
            num_outputs,
            vm_type,
            code,
        })
    }

}

#[cfg(all(feature = "serialize_speedy", target_endian = "little"))]
psy_serialize::impl_psy_canonical_serialize_for_speedy!(ContractFunctionCodeDefinition);
#[cfg(not(all(feature = "serialize_speedy", target_endian = "little")))]
impl AutoImplementFallbackPsySerializeCanonical for ContractFunctionCodeDefinition {}


impl PsyCanonicalSerializeMetadata for ContractFunctionCodeDefinition {
    const IS_FIXED_SIZE: bool = false;
    const FIXED_SIZE: usize = 0;
}


impl QPGenRandom for ContractFunctionCodeDefinition {
    fn qp_rand_gen() -> Self {
        Self {
            method_id: QPGenRandom::qp_rand_gen(),
            num_inputs: QPGenRandom::qp_rand_gen(),
            num_outputs: QPGenRandom::qp_rand_gen(),
            vm_type: QPGenRandom::qp_rand_gen(),
            code: qp_random_bytes_vec_in_range_insecure(32, 1024),
        }
    }
}

#[pderive::serialize_copy]
#[derive(TS)]
#[ts(export)]
pub struct SimpleContractFunctionCodeDefinition {
    pub method_id: u32,
    pub num_inputs: u32,
    pub num_outputs: u32,
    pub vm_type: u32,
}
impl QPGenRandom for SimpleContractFunctionCodeDefinition {
    fn qp_rand_gen() -> Self {
        Self {
            method_id: QPGenRandom::qp_rand_gen(),
            num_inputs: QPGenRandom::qp_rand_gen(),
            num_outputs: QPGenRandom::qp_rand_gen(),
            vm_type: QPGenRandom::qp_rand_gen(),
        }
    }
}
impl_qpq_serialize_bincode!(SimpleContractFunctionCodeDefinition);

#[pderive::serialize_clone_ts_export]
#[repr(C)]
pub struct ContractCodeDefinition {
    pub state_tree_height: u16,
    pub functions: Vec<ContractFunctionCodeDefinition>,
}
impl PsyCanonicalSerializeMetadata for ContractCodeDefinition {
    const IS_FIXED_SIZE: bool = false;
    const FIXED_SIZE: usize = 0;
}
impl FallbackPsySerializeCanonical for ContractCodeDefinition {
    fn fallback_pio_serialized_size(&self) -> usize {
        2 + 4 + self.functions.iter().map(|f| f.fallback_pio_serialized_size()).sum::<usize>()
    }
    
    fn fallback_pio_write_to_io<W: psy_io::Write>(&self, writer: &mut W) -> anyhow::Result<()> {
        writer.psy_write_u16(self.state_tree_height)?;
        writer.psy_write_vec_length(self.functions.len())?;
        for function in &self.functions {
            function.pio_write_to_io(writer)?;
        }
        Ok(())
    }
    
    fn fallback_pio_read_from_io<R: psy_io::Read>(reader: &mut R) -> anyhow::Result<Self> {
        let state_tree_height = reader.psy_read_u16()?;
        let function_count = reader.psy_read_vec_length()?;
        
        let mut function_defs = Vec::with_capacity(function_count);
        for _ in 0..function_count {
            let function = ContractFunctionCodeDefinition::pio_read_from_io(&mut *reader)?;
            function_defs.push(function);
        }
        Ok(Self {
            state_tree_height,
            functions: function_defs,
        })
    }

}

#[cfg(all(feature = "serialize_speedy", target_endian = "little"))]
psy_serialize::impl_psy_canonical_serialize_for_speedy!(ContractCodeDefinition);
#[cfg(not(all(feature = "serialize_speedy", target_endian = "little")))]
impl AutoImplementFallbackPsySerializeCanonical for ContractCodeDefinition {}




pser::impl_psy_ser_basic_tests!(
    ContractCodeDefinition,
    { },
    contract_code_definition
);
impl_qpq_serialize_bincode!(ContractCodeDefinition);
impl QPGenRandom for ContractCodeDefinition {
    fn qp_rand_gen() -> Self {
        let num_functions: usize = (<u32 as QPGenRandom>::qp_rand_gen() % 30) as usize;
        Self {
            state_tree_height: QPGenRandom::qp_rand_gen(),
            functions: QPGenRandom::qp_rand_gen_vec(num_functions),
        }
    }
}


#[pderive::serialize_clone_ts_export]
#[repr(C)]
pub struct ContractCodeDefinitionWithContractId {
    pub contract_id: u64,
    pub code_definition: ContractCodeDefinition,
}
impl ContractCodeDefinitionWithContractId {
    pub fn new(contract_id: u64, code_definition: ContractCodeDefinition) -> Self {
        Self {
            contract_id,
            code_definition,
        }
    }
}
impl PsyCanonicalSerializeMetadata for ContractCodeDefinitionWithContractId {
    const IS_FIXED_SIZE: bool = false;
    const FIXED_SIZE: usize = 0;
}
impl FallbackPsySerializeCanonical for ContractCodeDefinitionWithContractId {
    fn fallback_pio_serialized_size(&self) -> usize {
        8 + self.code_definition.pio_serialized_size()
    }
    
    fn fallback_pio_write_to_io<W: psy_io::Write>(&self, writer: &mut W) -> anyhow::Result<()> {
        writer.psy_write_u64(self.contract_id)?;
        self.code_definition.pio_write_to_io(writer)?;
        Ok(())
    }
    
    fn fallback_pio_read_from_io<R: psy_io::Read>(reader: &mut R) -> anyhow::Result<Self> {
        let contract_id = reader.psy_read_u64()?;
        let code_definition = ContractCodeDefinition::pio_read_from_io(reader)?;
        Ok(Self {
            contract_id,
            code_definition,
        })
    }

}

#[cfg(all(feature = "serialize_speedy", target_endian = "little"))]
psy_serialize::impl_psy_canonical_serialize_for_speedy!(ContractCodeDefinitionWithContractId);
#[cfg(not(all(feature = "serialize_speedy", target_endian = "little")))]
impl AutoImplementFallbackPsySerializeCanonical for ContractCodeDefinitionWithContractId {}




pser::impl_psy_ser_basic_tests!(
    ContractCodeDefinitionWithContractId,
    { },
    contract_code_definition_with_contract_id
);
impl_qpq_serialize_bincode!(ContractCodeDefinitionWithContractId);
impl QPGenRandom for ContractCodeDefinitionWithContractId {
    fn qp_rand_gen() -> Self {
        Self {
            contract_id: QPGenRandom::qp_rand_gen(),
            code_definition: ContractCodeDefinition::qp_rand_gen(),
        }
    }
}

impl QDatabaseSingleIdTableRowNoCheckpointIdLike<ContractCodeDefinition> for ContractCodeDefinitionWithContractId {
    
    fn get_row_obj_id(&self) -> u64 {
        self.contract_id
    }

    fn get_row_value_ref(&self) -> &ContractCodeDefinition {
        &self.code_definition
    }
}


#[pderive::serialize_clone]
#[derive(TS)]
#[ts(export)]
pub struct SimpleContractCodeDefinition {
    pub state_tree_height: u16,
    pub functions: Vec<SimpleContractFunctionCodeDefinition>,
}
impl_qpq_serialize_bincode!(SimpleContractCodeDefinition);

impl From<&ContractCodeDefinition> for SimpleContractCodeDefinition {
    fn from(value: &ContractCodeDefinition) -> Self {
        Self {
            state_tree_height: value.state_tree_height,
            functions: value
                .functions
                .clone()
                .into_iter()
                .map(|f| SimpleContractFunctionCodeDefinition {
                    method_id: f.method_id,
                    num_inputs: f.num_inputs,
                    num_outputs: f.num_outputs,
                    vm_type: f.vm_type,
                })
                .collect(),
        }
    }
}
#[pderive::serialize_clone]
#[derive(TS)]
#[ts(export)]
pub struct RootConfig {
    pub genesis: GenesisConfig,
}

#[pderive::serialize_clone]
#[derive(TS)]
#[ts(export)]
pub struct GenesisConfig {
    pub precompiles: Vec<ContractConfig>,
}

#[pderive::serialize_clone]
#[derive(TS)]
#[ts(export)]
pub struct PrecompileConfig {
    pub contracts: Vec<ContractConfig>,
}

#[pderive::serialize_clone]
#[derive(TS)]
#[ts(export)]
pub struct ContractConfig {
    pub name: String,
    pub path: String,
    pub contract_name: String,
    pub method_names: Vec<String>,
}
impl_qpq_serialize_bincode!(RootConfig);
impl_qpq_serialize_bincode!(GenesisConfig);
impl_qpq_serialize_bincode!(PrecompileConfig);
impl_qpq_serialize_bincode!(ContractConfig);

#[pderive::serialize_clone_hash_ts]
#[ts(export, concrete(Hash = parth_core::PHash), rename = "QBCDeployContract")]
pub struct PQBCDeployContract<Hash> {
    pub deployer: Hash,
    pub code_definition: ContractCodeDefinition,
    pub function_whitelist: Vec<Hash>,
}

impl<Hash: QHashBase> PQBCDeployContract<Hash> {
    pub fn new(deployer: Hash, code_definition: ContractCodeDefinition, function_whitelist: Vec<Hash>) -> Self {
        Self {
            deployer,
            code_definition,
            function_whitelist,
        }
    }
    pub fn split_into_tuple(self) -> (Hash, ContractCodeDefinition, Vec<Hash>) {
        (self.deployer, self.code_definition, self.function_whitelist)
    }
    pub fn into_with_whitelist_root<H: MerkleZeroHasher<Hash>>(
        self,
        contract_function_tree_height: u8,
    ) -> anyhow::Result<PQBCDeployContractWithRoot<Hash>> {
        PQBCDeployContractWithRoot::<Hash>::new::<H>(
            self.deployer,
            self.code_definition,
            self.function_whitelist,
            contract_function_tree_height,
        )
    }
}

#[pderive::serialize_clone_hash_ts]
#[ts(export, concrete(Hash = parth_core::PHash), rename = "QBCDeployContractWithRoot")]
pub struct PQBCDeployContractWithRoot<Hash> {
    pub deployer: Hash,
    pub code_definition: ContractCodeDefinition,
    pub function_whitelist: Vec<Hash>,
    pub function_whitelist_root: Hash,
}

impl<Hash: QHashBase> PQBCDeployContractWithRoot<Hash> {
    pub fn new<H: MerkleZeroHasher<Hash>>(
        deployer: Hash,
        code_definition: ContractCodeDefinition,
        function_whitelist: Vec<Hash>,
        contract_function_tree_height: u8,
    ) -> anyhow::Result<Self> {
        let mut t = SimpleMemoryMerkleStore::<H, Hash>::new(contract_function_tree_height);
        for (i, l) in function_whitelist.iter().enumerate() {
            t.set_leaf(i as u64, *l);
        }
        let function_whitelist_root = t.get_root();

        Ok(Self {
            deployer,
            code_definition,
            function_whitelist,
            function_whitelist_root,
        })
    }
}

#[cfg(test)]
mod test_ser {
    use psy_serialize::{PsyCanonicalDatabaseSerializeBaseSingle, PsySerializeCanonical};
    use speedy::{Readable, Writable};

    use super::*;

    #[test]
    fn test_contract_function_code_definition_serialize_round_trip() {
        let original = ContractFunctionCodeDefinition::qp_rand_gen();
        let serialized = original.psy_ser_to_bytes_vec().unwrap();
        let deserialized = ContractFunctionCodeDefinition::psy_ser_from_slice(&serialized).unwrap();
        assert_eq!(original.method_id, deserialized.method_id);
        assert_eq!(original.num_inputs, deserialized.num_inputs);
        assert_eq!(original.num_outputs, deserialized.num_outputs);
        assert_eq!(original.vm_type, deserialized.vm_type);
        assert_eq!(original.code, deserialized.code);

        let speedy_bytes = original.write_to_vec().unwrap();
        let speedy_deserialized = ContractFunctionCodeDefinition::read_from_buffer(&speedy_bytes).unwrap();
        assert_eq!(original.method_id, speedy_deserialized.method_id);
        assert_eq!(original.num_inputs, speedy_deserialized.num_inputs);
        assert_eq!(original.num_outputs, speedy_deserialized.num_outputs);
        assert_eq!(original.vm_type, speedy_deserialized.vm_type);
        assert_eq!(original.code, speedy_deserialized.code);

        println!("pretty: {:#?}", original);

        println!("speedy_bytes: {}", hex::encode(&speedy_bytes));
        println!("qpd_bytes: {}", hex::encode(&serialized));
    }

    /*
    fn print_test_case(case: &ContractFunctionCodeDefinition) {
        println!(r#"
        (
            ContractFunctionCodeDefinition {{
                method_id: {},
                num_inputs: {},
                num_outputs: {},
                vm_type: {},
                code: hex_literal::hex!("{}").to_vec(),
            }},
            "{}"
        ),
        "#,
            case.method_id,
            case.num_inputs,
            case.num_outputs,
            case.vm_type,
            hex::encode(&case.code),
            hex::encode(&case.write_to_vec().unwrap())
        );
    }

    #[test]
    fn make_test_cases() {
        let basic_cases = vec![
            ContractFunctionCodeDefinition {
                method_id: 1,
                num_inputs: 2,
                num_outputs: 3,
                vm_type: 4,
                code: vec![10, 20, 30, 40, 50],
            },
            ContractFunctionCodeDefinition {
                method_id: 0,
                num_inputs: 0,
                num_outputs: 0,
                vm_type: 0,
                code: vec![],
            },
            ContractFunctionCodeDefinition {
                method_id: 0,
                num_inputs: 0,
                num_outputs: 0,
                vm_type: 0,
                code: vec![0,0,0],
            },
            ContractFunctionCodeDefinition {
                method_id: 0,
                num_inputs: 0,
                num_outputs: 0,
                vm_type: 0,
                code: vec![0,0,0,0,0,0],
            },
            ContractFunctionCodeDefinition {
                method_id: 0,
                num_inputs: 0,
                num_outputs: 0,
                vm_type: 0,
                code: vec![1,0,0,0,0,0],
            },
            ContractFunctionCodeDefinition {
                method_id: 0,
                num_inputs: 0,
                num_outputs: 0,
                vm_type: 0,
                code: vec![0,0,0,0,0,1],
            },
            ContractFunctionCodeDefinition {
                method_id: 0,
                num_inputs: 0,
                num_outputs: 0,
                vm_type: 0,
                code: vec![0u8;1025],
            },
            ContractFunctionCodeDefinition {
                method_id: 1,
                num_inputs: 0,
                num_outputs: 1,
                vm_type: 0,
                code: vec![0,0,0,0,0,1],
            },
            ContractFunctionCodeDefinition {
                method_id: u32::MAX,
                num_inputs: u32::MAX,
                num_outputs: u32::MAX,
                vm_type: u32::MAX,
                code: vec![],
            },
            ContractFunctionCodeDefinition {
                method_id: u32::MAX,
                num_inputs: u32::MAX,
                num_outputs: u32::MAX,
                vm_type: u32::MAX,
                code: vec![],
            },
            ContractFunctionCodeDefinition {
                method_id: u32::MAX,
                num_inputs: u32::MAX,
                num_outputs: u32::MAX,
                vm_type: 0,
                code: vec![0],
            },
        ];
        for case in basic_cases.iter() {
            print_test_case(case);
        }
        for _ in 0..16 {
            let case = ContractFunctionCodeDefinition::qp_rand_gen();
            print_test_case(&case);
        }
    }
    */

    fn fuzz_fallback_random<T: QPGenRandom + FallbackPsySerializeCanonical + std::fmt::Debug + PartialEq + PsySerializeCanonical>(count: usize) {
        for _ in 0..count {
            let original: T = QPGenRandom::qp_rand_gen();
            let serialized_canonical = original.psy_ser_to_bytes_vec().unwrap();
            let serialized_fallback = original.fallback_psy_ser_to_bytes_vec().unwrap();
            assert_eq!(serialized_canonical, serialized_fallback, "Canonical and fallback serialized bytes do not match! Original: {:?}, Canonical Bytes: {:?}, Fallback Bytes: {:?}", original, serialized_canonical, serialized_fallback);
            let deserialized_canonical = T::psy_ser_from_slice(&serialized_canonical).unwrap();
            let deserialized_fallback = T::fallback_psy_ser_from_slice(&serialized_fallback).unwrap();
            assert_eq!(deserialized_canonical, deserialized_fallback, "Canonical and fallback deserialized objects do not match! Original: {:?}, Canonical: {:?}, Fallback: {:?}", original, deserialized_canonical, deserialized_fallback);

        }
    }

    #[test]
    fn fuzz_fallback_random_contract_function_code_definition() {
        fuzz_fallback_random::<ContractFunctionCodeDefinition>(10000);
    }



    #[test]
    fn enforce_consistent_serialization_contract_function_code_definition() {
        let pairs = vec![

        (
            ContractFunctionCodeDefinition {
                method_id: 1,
                num_inputs: 2,
                num_outputs: 3,
                vm_type: 4,
                code: hex_literal::hex!("0a141e2832").to_vec(),
            },
            "01000000020000000300000004000000050000000a141e2832"
        ),
        

        (
            ContractFunctionCodeDefinition {
                method_id: 0,
                num_inputs: 0,
                num_outputs: 0,
                vm_type: 0,
                code: hex_literal::hex!("").to_vec(),
            },
            "0000000000000000000000000000000000000000"
        ),
        

        (
            ContractFunctionCodeDefinition {
                method_id: 0,
                num_inputs: 0,
                num_outputs: 0,
                vm_type: 0,
                code: hex_literal::hex!("000000").to_vec(),
            },
            "0000000000000000000000000000000003000000000000"
        ),
        

        (
            ContractFunctionCodeDefinition {
                method_id: 0,
                num_inputs: 0,
                num_outputs: 0,
                vm_type: 0,
                code: hex_literal::hex!("000000000000").to_vec(),
            },
            "0000000000000000000000000000000006000000000000000000"
        ),
        

        (
            ContractFunctionCodeDefinition {
                method_id: 0,
                num_inputs: 0,
                num_outputs: 0,
                vm_type: 0,
                code: hex_literal::hex!("010000000000").to_vec(),
            },
            "0000000000000000000000000000000006000000010000000000"
        ),
        

        (
            ContractFunctionCodeDefinition {
                method_id: 0,
                num_inputs: 0,
                num_outputs: 0,
                vm_type: 0,
                code: hex_literal::hex!("000000000001").to_vec(),
            },
            "0000000000000000000000000000000006000000000000000001"
        ),
        

        (
            ContractFunctionCodeDefinition {
                method_id: 0,
                num_inputs: 0,
                num_outputs: 0,
                vm_type: 0,
                code: hex_literal::hex!("0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000").to_vec(),
            },
            "00000000000000000000000000000000010400000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        ),
        

        (
            ContractFunctionCodeDefinition {
                method_id: 1,
                num_inputs: 0,
                num_outputs: 1,
                vm_type: 0,
                code: hex_literal::hex!("000000000001").to_vec(),
            },
            "0100000000000000010000000000000006000000000000000001"
        ),
        

        (
            ContractFunctionCodeDefinition {
                method_id: 4294967295,
                num_inputs: 4294967295,
                num_outputs: 4294967295,
                vm_type: 4294967295,
                code: hex_literal::hex!("").to_vec(),
            },
            "ffffffffffffffffffffffffffffffff00000000"
        ),
        

        (
            ContractFunctionCodeDefinition {
                method_id: 4294967295,
                num_inputs: 4294967295,
                num_outputs: 4294967295,
                vm_type: 4294967295,
                code: hex_literal::hex!("").to_vec(),
            },
            "ffffffffffffffffffffffffffffffff00000000"
        ),
        

        (
            ContractFunctionCodeDefinition {
                method_id: 4294967295,
                num_inputs: 4294967295,
                num_outputs: 4294967295,
                vm_type: 0,
                code: hex_literal::hex!("00").to_vec(),
            },
            "ffffffffffffffffffffffff000000000100000000"
        ),
            (
                ContractFunctionCodeDefinition {
                    method_id: 1,
                    num_inputs: 2,
                    num_outputs: 3,
                    vm_type: 4,
                    code: vec![10, 20, 30, 40, 50],
                },
                "01000000020000000300000004000000050000000a141e2832",
            ),
            (
                ContractFunctionCodeDefinition {
                    method_id: 3388034734,
                    num_inputs: 608089709,
                    num_outputs: 4192835368,
                    vm_type: 3401409856,
                    code: hex_literal::hex!("001f1454ba8ddc9bba161b89f39e1f3861fcf645da05e4a3f69058eac0ee0a8b4f7533af7212e674d439fdba27004a010198a713f2a3a620bc420404780a02db8805d62e5d7b4d92316c643dad21783d130ff83a03f7065514ab067564aabd443ca3a84e80ac1eb5a784c96c2e615410cb8b3b67e8edc549e2341e7ef4be68dcbaef230fe38cd81478fc488411750add0ddf5ff0536689822cc18b4ec851ca233537fcaebac4507f5d0d22df9880cd5bd46d20ef31d15769dee292d8b125025788563b47dd40f50585848e53cac4e808d35bd2b28176cc94bd061ebb4686600ec47abe917814045c9040c9c5a88cb13113bd1a5c9302839ad917c05a4d0adbad728640ed2c976270991679fd8f217b393a468394f489635eaf06d1e6b65e7d6891d5919b2c48763c74dd80807881a37e22b3332012f1c5ef04d89a86d7da4b3170afc0c6bdb42bd6f42cf84b94b5081ddecbe62d1c65e861b96c2fbd366cf85dd8ba12f47d84feeaadca23b6994b66ad6db1e2452405d3aa1061b6319297a420dcc2bec3d244b6fb43d79c01ac917f89cfad4870b3809a0fc2447a39cebc9cd198d396cbe2c73530c24178d0b0cabd752e8e9a3f4024e145154ceb53f5908b1d87ef54743afb7dfd904586d1ef4168d108299b6f6e13ce2592df38be4a5565f1649843fdce2509edfb5524704d837c7b63b7079bffdd180c1d082b14d05ddceb2f80260b3878b3f9a3bae2b1a19003a197cbb9af1894536f7bf30884b2dadbea1d4aa45a074590d946add590b2d567f44c4bf3c7a7b2c0517e5c5696ba5a523b1b7c6c38d9f637ab7314d86988ba3bd698882c560bc5e406b19d7abdc8fca3f29d90046307e7ef6a8a704daa0f46c76197484105dece390a").to_vec(),
                },
                "ae4ef1c96db63e242897e9f94065bdca78020000001f1454ba8ddc9bba161b89f39e1f3861fcf645da05e4a3f69058eac0ee0a8b4f7533af7212e674d439fdba27004a010198a713f2a3a620bc420404780a02db8805d62e5d7b4d92316c643dad21783d130ff83a03f7065514ab067564aabd443ca3a84e80ac1eb5a784c96c2e615410cb8b3b67e8edc549e2341e7ef4be68dcbaef230fe38cd81478fc488411750add0ddf5ff0536689822cc18b4ec851ca233537fcaebac4507f5d0d22df9880cd5bd46d20ef31d15769dee292d8b125025788563b47dd40f50585848e53cac4e808d35bd2b28176cc94bd061ebb4686600ec47abe917814045c9040c9c5a88cb13113bd1a5c9302839ad917c05a4d0adbad728640ed2c976270991679fd8f217b393a468394f489635eaf06d1e6b65e7d6891d5919b2c48763c74dd80807881a37e22b3332012f1c5ef04d89a86d7da4b3170afc0c6bdb42bd6f42cf84b94b5081ddecbe62d1c65e861b96c2fbd366cf85dd8ba12f47d84feeaadca23b6994b66ad6db1e2452405d3aa1061b6319297a420dcc2bec3d244b6fb43d79c01ac917f89cfad4870b3809a0fc2447a39cebc9cd198d396cbe2c73530c24178d0b0cabd752e8e9a3f4024e145154ceb53f5908b1d87ef54743afb7dfd904586d1ef4168d108299b6f6e13ce2592df38be4a5565f1649843fdce2509edfb5524704d837c7b63b7079bffdd180c1d082b14d05ddceb2f80260b3878b3f9a3bae2b1a19003a197cbb9af1894536f7bf30884b2dadbea1d4aa45a074590d946add590b2d567f44c4bf3c7a7b2c0517e5c5696ba5a523b1b7c6c38d9f637ab7314d86988ba3bd698882c560bc5e406b19d7abdc8fca3f29d90046307e7ef6a8a704daa0f46c76197484105dece390a",
            ),
        (
            ContractFunctionCodeDefinition {
                method_id: 2587730450,
                num_inputs: 2549974541,
                num_outputs: 3021015973,
                vm_type: 2651008100,
                code: hex_literal::hex!("0c75f01f76bad67e4079ddfb09a75eee73401a641827e995907af7ba344c39d8688291561aea807ec9e520bafae7cc06c38177b2f1779014b01beb402ce3e5fac3bb77d73a4f1ad2b26c022afb7e384356bbf2a010b50920213968a729ed76c14126e7542a7114e9d149f49a15202bfdaa83b48da9db938b47db669703abc9380190b1f0ba6d0780de95452517dcedff7e14f9f53f0f85629bdcb2ed7375861c4aa8210c16bc4be203cef49f25dfed598d6aacdd713c94100f65803526810ba3b9d2200a5f4d44474b80d518ebed4e4a3c234649d9a37873a0a555538e283813a79d41add42d144c14ff2449b4bfc9eebea202e6bf93500a3f8d72e6f1d0cc40b83d9a9d21c0281eba213c870298006ce987ba9a19d62efdf04fb95bed3e191741080383d384d4e05bf6385a36f073c766dc87d21ef5d2298f0a45679ea9796c21c51126eed833b55be32a1b0b368109dd4a74ce2a9e79ebc785032f7bccc89052d87ef6071b7d706a8eb3eeae6202e0ab2824563e71e768198a04111b05c7956c2df60243c8a296838c17bedb3a381c48ab1ddd3bde65e63cde1ebbac591fca588e7aea74dfd228ba9beac75a5eb5ded1aa76d249e83b59688c6ab3964d5677580fa52dbfc2caee6daf9c64601e8bb2c88061415d958aea65d892af520ea04e059fc4da4f83bf11c0de40c1ead8df72c883e506362d70de1cc7513ec91d2c826092b469926dd8c0595db0d69c204362d446f95be50aaf86c046499360c4ecded8ea3945ec67e991d97f397c9a2d08440ac5441bf69de93b5a8350705d6be8395dc4e2cf3b06fe641c7eab1288de598a8783be4380169a0ebe9270a8df41fed9b497cd0462a05a2cbc95a14536f48225571f804be2b8").to_vec(),
            },
            "12a23d9a0d86fd97a50b11b4642c039e760200000c75f01f76bad67e4079ddfb09a75eee73401a641827e995907af7ba344c39d8688291561aea807ec9e520bafae7cc06c38177b2f1779014b01beb402ce3e5fac3bb77d73a4f1ad2b26c022afb7e384356bbf2a010b50920213968a729ed76c14126e7542a7114e9d149f49a15202bfdaa83b48da9db938b47db669703abc9380190b1f0ba6d0780de95452517dcedff7e14f9f53f0f85629bdcb2ed7375861c4aa8210c16bc4be203cef49f25dfed598d6aacdd713c94100f65803526810ba3b9d2200a5f4d44474b80d518ebed4e4a3c234649d9a37873a0a555538e283813a79d41add42d144c14ff2449b4bfc9eebea202e6bf93500a3f8d72e6f1d0cc40b83d9a9d21c0281eba213c870298006ce987ba9a19d62efdf04fb95bed3e191741080383d384d4e05bf6385a36f073c766dc87d21ef5d2298f0a45679ea9796c21c51126eed833b55be32a1b0b368109dd4a74ce2a9e79ebc785032f7bccc89052d87ef6071b7d706a8eb3eeae6202e0ab2824563e71e768198a04111b05c7956c2df60243c8a296838c17bedb3a381c48ab1ddd3bde65e63cde1ebbac591fca588e7aea74dfd228ba9beac75a5eb5ded1aa76d249e83b59688c6ab3964d5677580fa52dbfc2caee6daf9c64601e8bb2c88061415d958aea65d892af520ea04e059fc4da4f83bf11c0de40c1ead8df72c883e506362d70de1cc7513ec91d2c826092b469926dd8c0595db0d69c204362d446f95be50aaf86c046499360c4ecded8ea3945ec67e991d97f397c9a2d08440ac5441bf69de93b5a8350705d6be8395dc4e2cf3b06fe641c7eab1288de598a8783be4380169a0ebe9270a8df41fed9b497cd0462a05a2cbc95a14536f48225571f804be2b8"
        ),
        

        (
            ContractFunctionCodeDefinition {
                method_id: 641683341,
                num_inputs: 2410381066,
                num_outputs: 3547858408,
                vm_type: 252710338,
                code: hex_literal::hex!("1ef1ca3187fc6ca7f5e8c20c00d3115e46d8b6864f339bfe1ad5b26faff7a1ac97429fdf048bc0f1e70896205952f6d1efdb6064a028403fbc82e8351caf8eecd7af15511887d1e4a2101a3a4f52282d33f12cd71b9139858231eb35f49e8eb1740fd1cb400d0a63004c2f6d603c59f3ea7af51d4faf4155f2cde7e6e329b748ffb44d7aaf64a61c7414a87cfded85cc1ae148aecf44584558d0cf2d03d12c9b6c99cd8bf10773abadb2c189eb01279b94db5780bb05dcc54a9943966f1ce32b3d554a48c85cdb8d2c3886862cca4ac577c66daf0edffa16196eb65663bc875675d49adccf0521f1fa435b0532e2beff19eb312d0ee3031c26ca42fff1624f852300f58ce9bc6d22476f16f364a3db85d7eeebd2959356ff505515a788e5b67fe483f75e4ff0e7330eabd93541639be1eb109b681cedb0e84993df0728bda3af1561d6cf43ed22372f842f4e9b5f0c5f6718cf65fc5cce4d0068f2184739efa420c823b7e1f0393cab87c083d8f90bac3c6ed87bb617243cb8514884ec").to_vec(),
            },
            "8d4f3f260a7fab8fe80578d3c20d100f7d0100001ef1ca3187fc6ca7f5e8c20c00d3115e46d8b6864f339bfe1ad5b26faff7a1ac97429fdf048bc0f1e70896205952f6d1efdb6064a028403fbc82e8351caf8eecd7af15511887d1e4a2101a3a4f52282d33f12cd71b9139858231eb35f49e8eb1740fd1cb400d0a63004c2f6d603c59f3ea7af51d4faf4155f2cde7e6e329b748ffb44d7aaf64a61c7414a87cfded85cc1ae148aecf44584558d0cf2d03d12c9b6c99cd8bf10773abadb2c189eb01279b94db5780bb05dcc54a9943966f1ce32b3d554a48c85cdb8d2c3886862cca4ac577c66daf0edffa16196eb65663bc875675d49adccf0521f1fa435b0532e2beff19eb312d0ee3031c26ca42fff1624f852300f58ce9bc6d22476f16f364a3db85d7eeebd2959356ff505515a788e5b67fe483f75e4ff0e7330eabd93541639be1eb109b681cedb0e84993df0728bda3af1561d6cf43ed22372f842f4e9b5f0c5f6718cf65fc5cce4d0068f2184739efa420c823b7e1f0393cab87c083d8f90bac3c6ed87bb617243cb8514884ec"
        ),
        

        (
            ContractFunctionCodeDefinition {
                method_id: 747455649,
                num_inputs: 3344863541,
                num_outputs: 1584875755,
                vm_type: 563148720,
                code: hex_literal::hex!("338ad60aca03efd2dee1d8b801c0753ad637098747e81cf91daa1ef50d7946c32717cd79653bfe229884b16597ee373e6d64246faa4e497010e77eaf89ef4ef9e3f2fcb372d843403fd258e684b41e5d18e7fa17929c01bad907fbfc4de954d0b7285d8d39b59a7158d82c13ea0a178484d638511a31fd8a0192bb572adb5cc17e82249a8bd21936f7ccddc3066ff620de63996f9b89a25f2864db0d368b750a4f64799b9a3f7954c0a678fa1dbd9675c66d4ca01159af28b73a78d118b959e770b51476de81c8ee65ee372af776f42b1cb902954cb7ba9f293276c61fee088e6539f3c1e395ac420f570fe42ee2a1dbb883ed530af1d6027836e6467827479c797b6e59e5013cc33133cbd5adb0e0463d4daa92e62d9b59a4887f57eacd99507de6b2f9b253796b83eb24c90f4b9222cf7e2afd67ff057c4fff300d44bacf7ed05cf4b5419df6841089c88b07fd99a96af787429720563d85a0c60ba298c920d83a13dbf53b6973e44bac260acfdc6d66e650a2af9e747b048e2e1ae206ec86cd59447fe434344f8c855696a8d9eb634f16f831e8f834e80c4ca20aee7b9f4945e76fc104561a2a6345ea7da32c7a1a89d717f53307a5e6f92ba0e647cb8104d197d8b317706dd1504a5183eaf4f7d9ca425b7288fcf2a75fc2e23915d033163c6bc6816c8c2c460da2328dca0696623c1a300e818b1bc43cf1e6d89067169df21e53cfc8ba06c18be15980ddaf7ebe83b7820330216af2627db5614b9270dd5e74377d8176ce7f4ab76caaf9c0fc9fa648dccab9f35633000eef56d4e84d0e1d6a7cbd10f59c4f3263bb99c96d55204b2bccc0169093fe8018f3f6186e1e4fe96441678eac93e9bcaf59ebf0e312c1eef5057864d8f27e0d6a8682259a5d5a314d150203134dd187b356dc41464ebf0959feb94760e606ff7e4ac8b25a871adb04f1085748fc46fd7828139f3806090841521b820931b803fad7faee1bfec0b12183ba1bb307d8e852bf1e56b47223ea47c3958bd3bb7437498009a0592de3a388efeb1f64cd7c346007a660a84906242d919ce078e34e6f09b35eee49b7d4a149d3cd3d773d9492ffc3770fbe947bb472ab84e10f49bc346f3fb2d9df61e290d10edc941215a17f2a141f1b4fcc01f3f304040b0b044921").to_vec(),
            },
            "a1448d2c35915ec7eb48775eb0f7902139030000338ad60aca03efd2dee1d8b801c0753ad637098747e81cf91daa1ef50d7946c32717cd79653bfe229884b16597ee373e6d64246faa4e497010e77eaf89ef4ef9e3f2fcb372d843403fd258e684b41e5d18e7fa17929c01bad907fbfc4de954d0b7285d8d39b59a7158d82c13ea0a178484d638511a31fd8a0192bb572adb5cc17e82249a8bd21936f7ccddc3066ff620de63996f9b89a25f2864db0d368b750a4f64799b9a3f7954c0a678fa1dbd9675c66d4ca01159af28b73a78d118b959e770b51476de81c8ee65ee372af776f42b1cb902954cb7ba9f293276c61fee088e6539f3c1e395ac420f570fe42ee2a1dbb883ed530af1d6027836e6467827479c797b6e59e5013cc33133cbd5adb0e0463d4daa92e62d9b59a4887f57eacd99507de6b2f9b253796b83eb24c90f4b9222cf7e2afd67ff057c4fff300d44bacf7ed05cf4b5419df6841089c88b07fd99a96af787429720563d85a0c60ba298c920d83a13dbf53b6973e44bac260acfdc6d66e650a2af9e747b048e2e1ae206ec86cd59447fe434344f8c855696a8d9eb634f16f831e8f834e80c4ca20aee7b9f4945e76fc104561a2a6345ea7da32c7a1a89d717f53307a5e6f92ba0e647cb8104d197d8b317706dd1504a5183eaf4f7d9ca425b7288fcf2a75fc2e23915d033163c6bc6816c8c2c460da2328dca0696623c1a300e818b1bc43cf1e6d89067169df21e53cfc8ba06c18be15980ddaf7ebe83b7820330216af2627db5614b9270dd5e74377d8176ce7f4ab76caaf9c0fc9fa648dccab9f35633000eef56d4e84d0e1d6a7cbd10f59c4f3263bb99c96d55204b2bccc0169093fe8018f3f6186e1e4fe96441678eac93e9bcaf59ebf0e312c1eef5057864d8f27e0d6a8682259a5d5a314d150203134dd187b356dc41464ebf0959feb94760e606ff7e4ac8b25a871adb04f1085748fc46fd7828139f3806090841521b820931b803fad7faee1bfec0b12183ba1bb307d8e852bf1e56b47223ea47c3958bd3bb7437498009a0592de3a388efeb1f64cd7c346007a660a84906242d919ce078e34e6f09b35eee49b7d4a149d3cd3d773d9492ffc3770fbe947bb472ab84e10f49bc346f3fb2d9df61e290d10edc941215a17f2a141f1b4fcc01f3f304040b0b044921"
        ),
        

        (
            ContractFunctionCodeDefinition {
                method_id: 1319823627,
                num_inputs: 532168210,
                num_outputs: 3001906338,
                vm_type: 2161419988,
                code: hex_literal::hex!("7e2f1100ff7f16577983fa237605a447ab405b914f7e2fd17be2a547ac720d0ee865981d7b3f0aa947ec80ded76ccd1e6688df1aaa01b541ee8b70292d45fef2fa5fe62df2bc57cb2a8a92ff5b6645b54d9bd927f0aada7d14555eb79a01201f08c2dd4ae1103b7f3560c579d59964acd9ad086957fd4ff09bcc4c196c48f508b86571e93f96d0fea00881b297b8aea88351f3a1213501355e3c2c104d661948db79d00df19d7f2024d066b3a7c6183d9c635f90ce8021c208455c1eed5eba660f05563000da54a6e9a450ba8e8c4f58de0ac94e7873a1f8243ccac41ce419c4d8d5d5dfa87de208ee0f38df867245044be587e0cb7c3e2463ee6716c32208b5da2871c1aab544ebd5593c4b7c502a69f934dab1244b5ea7c4da099ec5f88b3f7ee1a0e807d425d288c86529e59339ecde6c857c692f28d2b98544bbfc533aafb2855ca189687b6f759991cb985c3acc22f7d8d69d1e93df21fe9ce2a49e8ea40ca600ba5a6b98cf9cdea1a7ac4db952961c0fcf490ebcb3e8b891cfcf0790bea621ac537c5aefd1e6053b653bd0e69e624c152665e9f6b8d8c968b196d48c8fe390815ea2158912779535c1dadf48a756a0196857a20473cf99a310e5f9c34e7e5ac868f19addefad06e8d4262e689cef6d930311fc19a7d41feae6cc75ca50db39b58634bacbb4b2162d736a9308c510929a508bd9da0bf215b13745e79650fbd0a3df428e6865d964c80e93e62568c8b08a90f951a9fef6bafcc9e9").to_vec(),
            },
            "0be9aa4e123eb81fa274edb2d4a6d4801d0200007e2f1100ff7f16577983fa237605a447ab405b914f7e2fd17be2a547ac720d0ee865981d7b3f0aa947ec80ded76ccd1e6688df1aaa01b541ee8b70292d45fef2fa5fe62df2bc57cb2a8a92ff5b6645b54d9bd927f0aada7d14555eb79a01201f08c2dd4ae1103b7f3560c579d59964acd9ad086957fd4ff09bcc4c196c48f508b86571e93f96d0fea00881b297b8aea88351f3a1213501355e3c2c104d661948db79d00df19d7f2024d066b3a7c6183d9c635f90ce8021c208455c1eed5eba660f05563000da54a6e9a450ba8e8c4f58de0ac94e7873a1f8243ccac41ce419c4d8d5d5dfa87de208ee0f38df867245044be587e0cb7c3e2463ee6716c32208b5da2871c1aab544ebd5593c4b7c502a69f934dab1244b5ea7c4da099ec5f88b3f7ee1a0e807d425d288c86529e59339ecde6c857c692f28d2b98544bbfc533aafb2855ca189687b6f759991cb985c3acc22f7d8d69d1e93df21fe9ce2a49e8ea40ca600ba5a6b98cf9cdea1a7ac4db952961c0fcf490ebcb3e8b891cfcf0790bea621ac537c5aefd1e6053b653bd0e69e624c152665e9f6b8d8c968b196d48c8fe390815ea2158912779535c1dadf48a756a0196857a20473cf99a310e5f9c34e7e5ac868f19addefad06e8d4262e689cef6d930311fc19a7d41feae6cc75ca50db39b58634bacbb4b2162d736a9308c510929a508bd9da0bf215b13745e79650fbd0a3df428e6865d964c80e93e62568c8b08a90f951a9fef6bafcc9e9"
        ),
        

        (
            ContractFunctionCodeDefinition {
                method_id: 2124631658,
                num_inputs: 1550178085,
                num_outputs: 2026134206,
                vm_type: 3415317525,
                code: hex_literal::hex!("80b5acc41542c8f8235b9f8e1b07bc7252dbf7293a8352900f8239dcd204abc41b181e42fba15f5ab27707af8aa532420a4a52f1b5904efe86caa4c72116085554f6d58e192d0cf55c96e4edcf6d859998ecb990493f2ce437db50bca9fef5fbcc0bb4f3bd24778f1d139247bd67128e653c75775764dd044235f67834a2cd1bf24b02803106fadba5e3c4833371629a728833e43881744054").to_vec(),
            },
            "6a4ea37e25d7655cbe5ac478159c91cb9900000080b5acc41542c8f8235b9f8e1b07bc7252dbf7293a8352900f8239dcd204abc41b181e42fba15f5ab27707af8aa532420a4a52f1b5904efe86caa4c72116085554f6d58e192d0cf55c96e4edcf6d859998ecb990493f2ce437db50bca9fef5fbcc0bb4f3bd24778f1d139247bd67128e653c75775764dd044235f67834a2cd1bf24b02803106fadba5e3c4833371629a728833e43881744054"
        ),
        

        (
            ContractFunctionCodeDefinition {
                method_id: 2025822552,
                num_inputs: 1931388968,
                num_outputs: 1794179897,
                vm_type: 3926435616,
                code: hex_literal::hex!("06519238a615bcd006ac4dace097577ddde4099ea916d69c49cbc9a741a786313c14939f935cfd81ef83e37743a6040c9d191ff4e70b0bb6734414aee2101ebe26eb27bd1b20cfcb774920d969c811bcd10da3caae26a2600499dddd357e3ef261c2a87884746f7885ea01213622d06d1afb1475c13d40414e7e35a0127169843e5754dcdeac07d56f8a77d2964ee1f8126f751e49b3639a5185b802ae6eea37fe864fd8c390134b85b8655429e148a02da067bbd43a49d56e6788103b59c3201efead46be9883d0ffaca371ae65cb7fcded1a7558b8dfe4170ad5c110fc984e2162bd2445695ffa94eb5c66af7d9da5251afc3e915cd2fdacebdbea1ad51b5a17f1cd28bc7360edb2119b51036e2aae52144a8576c2b2da64e1573066e0b7883cf329dc2495794473d2130091e694a109c7abd20cb5f14cb817c8334338e2111e51fbc53b9466bf81b539807b0962ddc9f83cd560f4bbd69c1fc2b159dafa2980977a003e750f17487ce502f8f1f80338d81f803fc49ef9bbfd9c47715b7cf139729475784b227616b1eaeeaf110658527fd2c15f91c493388270e2e346f4df868faf29d1f0888183707ec37af8ee083a622356a7961b72dadc9a9b0a47987e08bd41379a4861d789d228e0085a6a7206d2fa13").to_vec(),
            },
            "5899bf7828a81e733903f16a20a708ead401000006519238a615bcd006ac4dace097577ddde4099ea916d69c49cbc9a741a786313c14939f935cfd81ef83e37743a6040c9d191ff4e70b0bb6734414aee2101ebe26eb27bd1b20cfcb774920d969c811bcd10da3caae26a2600499dddd357e3ef261c2a87884746f7885ea01213622d06d1afb1475c13d40414e7e35a0127169843e5754dcdeac07d56f8a77d2964ee1f8126f751e49b3639a5185b802ae6eea37fe864fd8c390134b85b8655429e148a02da067bbd43a49d56e6788103b59c3201efead46be9883d0ffaca371ae65cb7fcded1a7558b8dfe4170ad5c110fc984e2162bd2445695ffa94eb5c66af7d9da5251afc3e915cd2fdacebdbea1ad51b5a17f1cd28bc7360edb2119b51036e2aae52144a8576c2b2da64e1573066e0b7883cf329dc2495794473d2130091e694a109c7abd20cb5f14cb817c8334338e2111e51fbc53b9466bf81b539807b0962ddc9f83cd560f4bbd69c1fc2b159dafa2980977a003e750f17487ce502f8f1f80338d81f803fc49ef9bbfd9c47715b7cf139729475784b227616b1eaeeaf110658527fd2c15f91c493388270e2e346f4df868faf29d1f0888183707ec37af8ee083a622356a7961b72dadc9a9b0a47987e08bd41379a4861d789d228e0085a6a7206d2fa13"
        ),
        

        (
            ContractFunctionCodeDefinition {
                method_id: 1547151617,
                num_inputs: 4065267804,
                num_outputs: 4050972418,
                vm_type: 3952533318,
                code: hex_literal::hex!("8819a011f46f91f4af8fee9d68102aee11935c2f552d7d6364efa18f026ead1319d5f93a376b7b9b9987fc091c34cb8371195ccaac462a7dbb007febaba297a3f7acba244dc5935b16ec483e6c9e6086b89f98d21fcf4899fa48a2d8a9421d2769cb9078e032eb4dcff5ba501bd64ce2bce854268b4204f9eba5a004c2c047123361d89bbf06829a505f90f6db87596b053e11e66636ea031bd3eb377386ca1648f0bad11be5083ccbd0ec07b80b062b57ffb16ae8593457baaa94c0fcf6932fbc147daf8343283c81b1cce38f561767a4852d7018c6ff311ed841e902aedf101c0cc72f18c251e3237f4270f601c9f0be71c8cec3a019de22510fea0372cffecc9c860f0bc9d6306b4a06127c257ec0bc93966de98ed16e8ac06306bb716a4aef646779685ba76c7b9ae500e1cbf55a1757aff7b2b1e6bd9568da3978e02d11a11c55d9e6906d8ba0a12fdd61e80f64e7dcec308a93d575cc48cb00d90eaa363ac34b224c3f2f22eaa11ed96656901a8f936814eb38edd008c8fc43c26088f3aa3de791ce812abc7b5f4774aba07de9abda6a8595223f70d9c1fd8d96d9d37020b68281c591938ca4a310d982ff2e5eb59f16274ed97312e40e8d8771ccd58b56243bbba46cac69b8effd8cce492927424606d8deb7bb6a6bbc9dfc05c7fcfd8e81e821523b81f4f4c01a12cf23ee9221bf648d2fa96e866723813cf371931c9816d8eedfeea542447fac0ef4c370a0198636f0d19f69c99c915187ef26616600a0fab8775ab36512c080af1b9aad6b5c852de4d7cfb0bf7a1af3c8431717673019610e1194f90371ae07f650be6034d1417896ba0ae23836eb672edafb7e123d28aa5218a223bfad64b51803acdb44534181683a3784c55f793faf6cf4ddc77753d0354ff19d693d7a6fd25f8c79de07123049157e588154f6812830628245b16fefffca03e5501804bbc8cf1f8c5d23ba8f787296f40c").to_vec(),
            },
            "01a9375c5c104ff202ef74f146df96ebb80200008819a011f46f91f4af8fee9d68102aee11935c2f552d7d6364efa18f026ead1319d5f93a376b7b9b9987fc091c34cb8371195ccaac462a7dbb007febaba297a3f7acba244dc5935b16ec483e6c9e6086b89f98d21fcf4899fa48a2d8a9421d2769cb9078e032eb4dcff5ba501bd64ce2bce854268b4204f9eba5a004c2c047123361d89bbf06829a505f90f6db87596b053e11e66636ea031bd3eb377386ca1648f0bad11be5083ccbd0ec07b80b062b57ffb16ae8593457baaa94c0fcf6932fbc147daf8343283c81b1cce38f561767a4852d7018c6ff311ed841e902aedf101c0cc72f18c251e3237f4270f601c9f0be71c8cec3a019de22510fea0372cffecc9c860f0bc9d6306b4a06127c257ec0bc93966de98ed16e8ac06306bb716a4aef646779685ba76c7b9ae500e1cbf55a1757aff7b2b1e6bd9568da3978e02d11a11c55d9e6906d8ba0a12fdd61e80f64e7dcec308a93d575cc48cb00d90eaa363ac34b224c3f2f22eaa11ed96656901a8f936814eb38edd008c8fc43c26088f3aa3de791ce812abc7b5f4774aba07de9abda6a8595223f70d9c1fd8d96d9d37020b68281c591938ca4a310d982ff2e5eb59f16274ed97312e40e8d8771ccd58b56243bbba46cac69b8effd8cce492927424606d8deb7bb6a6bbc9dfc05c7fcfd8e81e821523b81f4f4c01a12cf23ee9221bf648d2fa96e866723813cf371931c9816d8eedfeea542447fac0ef4c370a0198636f0d19f69c99c915187ef26616600a0fab8775ab36512c080af1b9aad6b5c852de4d7cfb0bf7a1af3c8431717673019610e1194f90371ae07f650be6034d1417896ba0ae23836eb672edafb7e123d28aa5218a223bfad64b51803acdb44534181683a3784c55f793faf6cf4ddc77753d0354ff19d693d7a6fd25f8c79de07123049157e588154f6812830628245b16fefffca03e5501804bbc8cf1f8c5d23ba8f787296f40c"
        ),
        

        (
            ContractFunctionCodeDefinition {
                method_id: 2677734875,
                num_inputs: 1069240425,
                num_outputs: 2112609060,
                vm_type: 3786736087,
                code: hex_literal::hex!("7c1ae54ba7d5d815b0de97ae4f3899337651fcdd1da19fddabfd5f9ffc5d1d15a969583a7a66c67db15c18f646e621f09cb26ad0002ef2ba98946054b6334117f8c1d58687d6b8dc17a5a683a1ff233b123e708b746c7faa12cf99ae3ab0417ee62f6107be6ec4ec6026290e40426502003101fd9067a3c631f52b6c246b06c442701f35f7fa5f9d34eb1f850747610a05558af3090a5e360672f7bacdbf4eefe98e6457a380c9050f86514f72ec41941e916ca8f1af43adccb4a511fb471e6affe486d2aea4cec7625eb2eb2f469bb32fa1d1ea39cb92ede31283f40d09dcb3d0e2b0e0db8b55c475403fd15714432672c886ca77d90768d16dcf44848b248003362a99e8").to_vec(),
            },
            "dbfd9a9f6950bb3f24dbeb7dd701b5e1050100007c1ae54ba7d5d815b0de97ae4f3899337651fcdd1da19fddabfd5f9ffc5d1d15a969583a7a66c67db15c18f646e621f09cb26ad0002ef2ba98946054b6334117f8c1d58687d6b8dc17a5a683a1ff233b123e708b746c7faa12cf99ae3ab0417ee62f6107be6ec4ec6026290e40426502003101fd9067a3c631f52b6c246b06c442701f35f7fa5f9d34eb1f850747610a05558af3090a5e360672f7bacdbf4eefe98e6457a380c9050f86514f72ec41941e916ca8f1af43adccb4a511fb471e6affe486d2aea4cec7625eb2eb2f469bb32fa1d1ea39cb92ede31283f40d09dcb3d0e2b0e0db8b55c475403fd15714432672c886ca77d90768d16dcf44848b248003362a99e8"
        ),
        

        (
            ContractFunctionCodeDefinition {
                method_id: 3071912302,
                num_inputs: 2618019390,
                num_outputs: 2810913822,
                vm_type: 3773055977,
                code: hex_literal::hex!("a9c0a0d01e52e36fbc5b3de939f433b9a2bfe20139ebc6e5cee4cfcde5f94c28632ededf525a33ed73df09dd6289b69c4828212e71e36c117de8ceaeef1b73820a10a414e949ac792b687a5b14d8c8a493f24aea274115b3a64ebc9f5d53dfaa2377b0ea8970e470c5fb0d8d865f675484e98876c6dfaa328f6db6401e245d30227bb9fab30c3c7fc6531276c258a74fc10abbed9e96f04070b32c94bd67c5a0306e500898d34bc19d793e6a63c6cf69ece3ef473c354b7cb8d4b5be5109a73057e6aa1e78d65fe2f85d75d0e61a250c1bd866874c6fb9bd4bd35047d41d1e16ad120038e039d52349f137dcdc17a9abcbc7c2ddbca6dce0bed5f02ce4720a1e5fe54e3db0fbb5ba3b4d26fe864fee9fd08732913a9e9b55738ebdd7a25bd967a53535182a0e0e4d4f6d400241863186cb995dcd3a6e09ae86bf7da4e44369355a3d3319feb94832aa2d2c79a0e5415deec891f52ed7c8dc07d5edf6c0ca5ecdf2aa32d8bc649395f375fb86bcca5030a12267ed6cbfb300ff69e64c58fda8754772f818b9d1dd1670865dfa00edea22f7b0b14cb8cb2026b8814e59ad4e39f6ed0413908bf607b2c693559a06c894b0abc20f9d8e33d246b9478c7eb17d612f5bf5e810cd77b236db288c96ab7457ae41993b0ccdf815bcf34f4d33e78eb715cd08a7ce9ffa8ec697f62e318c7974007b058295ec399ea7129c90f3f44428230daa5c55ab54060be3ff3132b9adc67f920924ee94f4c1b818bc51c162be8cca953397f989a463b251091a3ffdbb206a313383939065b5a6bda7b62bce36644a228bdd8246da9afab935891b28347d08e07eeaa51c2d0fca966bde84b718b97fd048d0e6d5").to_vec(),
            },
            "6ea919b73ece0b9c1e248ba7e943e4e065020000a9c0a0d01e52e36fbc5b3de939f433b9a2bfe20139ebc6e5cee4cfcde5f94c28632ededf525a33ed73df09dd6289b69c4828212e71e36c117de8ceaeef1b73820a10a414e949ac792b687a5b14d8c8a493f24aea274115b3a64ebc9f5d53dfaa2377b0ea8970e470c5fb0d8d865f675484e98876c6dfaa328f6db6401e245d30227bb9fab30c3c7fc6531276c258a74fc10abbed9e96f04070b32c94bd67c5a0306e500898d34bc19d793e6a63c6cf69ece3ef473c354b7cb8d4b5be5109a73057e6aa1e78d65fe2f85d75d0e61a250c1bd866874c6fb9bd4bd35047d41d1e16ad120038e039d52349f137dcdc17a9abcbc7c2ddbca6dce0bed5f02ce4720a1e5fe54e3db0fbb5ba3b4d26fe864fee9fd08732913a9e9b55738ebdd7a25bd967a53535182a0e0e4d4f6d400241863186cb995dcd3a6e09ae86bf7da4e44369355a3d3319feb94832aa2d2c79a0e5415deec891f52ed7c8dc07d5edf6c0ca5ecdf2aa32d8bc649395f375fb86bcca5030a12267ed6cbfb300ff69e64c58fda8754772f818b9d1dd1670865dfa00edea22f7b0b14cb8cb2026b8814e59ad4e39f6ed0413908bf607b2c693559a06c894b0abc20f9d8e33d246b9478c7eb17d612f5bf5e810cd77b236db288c96ab7457ae41993b0ccdf815bcf34f4d33e78eb715cd08a7ce9ffa8ec697f62e318c7974007b058295ec399ea7129c90f3f44428230daa5c55ab54060be3ff3132b9adc67f920924ee94f4c1b818bc51c162be8cca953397f989a463b251091a3ffdbb206a313383939065b5a6bda7b62bce36644a228bdd8246da9afab935891b28347d08e07eeaa51c2d0fca966bde84b718b97fd048d0e6d5"
        ),
        

        (
            ContractFunctionCodeDefinition {
                method_id: 730482078,
                num_inputs: 1794512632,
                num_outputs: 2510242676,
                vm_type: 1096875886,
                code: hex_literal::hex!("6c96f3c86458b6060b378f0b523538d6ccc0e3d0fd43032fedd13ccefc730550b44b8f5e627104dd6c5e53796a0816f9469aadddae7448bd8525115a435fc1aba011cee8426629b4e8117af1f7fe783fe40a0ba8fd91ba6964b3c4202f8ae566c5b264d353e098cd0cc5e65cbf0ce6a487c2883095ea38ad4e091d734c70a36e34f44c76be805d659a1ec171d999f71e1387a3ba0e54fe2d1d4d0034f68d0821e184059be32133f5727e2a2e8f459a30e21bff90b2ec00248a18ab48d187906a0acc3b0f37208f30288f680e41b8d79dba044f68372cba76ebdb343b928538e89f42613596e705b834e9f910613d808c8cdb505ce7abdfe2dafd3bf37ca0bac3eb65f48a5fecd02195be5e99151386345458df5a633739d07228b32b5eb54e3d24f496de3776a16c127614ffc3e8e50c99125d5248fe82cdb55ee6af6c317781a24b25c6a70b792c4f878d4e8a430976a40c847ca51d87f5be7ed07e8483bf2024c0fa0536bb470503a174a76ed056d53e2fc964dc69286ddb4d498ce57609e017b71455ebc08d365e306004c73bf357f163f3554d2b4d8699b04a7cc8230f22d04fbab9cd9e5a558a8c8269dd6c4bd86abf877ab68c3860f2308d18162f59c57c6cd37fbbf45fbc92d0eefacd2f7e23ec39a334dd5362dc333b0fbd53a5044858959c919eedff98ca8f20badfc293be61a2e62db99d04f2686b4b6e914193ca9307a7f87083347eb1e25be9d8b5807cf741b1b2ec9983c18803a08b07f5042f1c86412a77e68e676b2120aeb2d59afde03d4acc56615ef0425941b6a9b4af06285ac1b1005a441bd36f284bc725718744e138d670edf46759cfa3f52475a08e979f0baa38637de1ff0ebe53e6faf73093c35395b33bbfd5be7b96e3f66d57087997348099cbd5cdbbded0b1d119e261d49249ef787e5f44150322475a1c881766914db2cc63eb3a6f9419eba8fc5c93ea5eb382d08c879be96d5b8d8c32210c676b12f8b54e055a6729f944cf475165c02e1145670feffa1d20767b1430ffe1b6b1144ccacae9a283da002e75ba6dd238a0a8467c2ddf44376b821cea778d2423d89550f0b9535040990a696acd1a9e16aaea4b2316aa931ce79041136fde229a160c").to_vec(),
            },
            "9e458a2bf816f66a74439f956eff6041230300006c96f3c86458b6060b378f0b523538d6ccc0e3d0fd43032fedd13ccefc730550b44b8f5e627104dd6c5e53796a0816f9469aadddae7448bd8525115a435fc1aba011cee8426629b4e8117af1f7fe783fe40a0ba8fd91ba6964b3c4202f8ae566c5b264d353e098cd0cc5e65cbf0ce6a487c2883095ea38ad4e091d734c70a36e34f44c76be805d659a1ec171d999f71e1387a3ba0e54fe2d1d4d0034f68d0821e184059be32133f5727e2a2e8f459a30e21bff90b2ec00248a18ab48d187906a0acc3b0f37208f30288f680e41b8d79dba044f68372cba76ebdb343b928538e89f42613596e705b834e9f910613d808c8cdb505ce7abdfe2dafd3bf37ca0bac3eb65f48a5fecd02195be5e99151386345458df5a633739d07228b32b5eb54e3d24f496de3776a16c127614ffc3e8e50c99125d5248fe82cdb55ee6af6c317781a24b25c6a70b792c4f878d4e8a430976a40c847ca51d87f5be7ed07e8483bf2024c0fa0536bb470503a174a76ed056d53e2fc964dc69286ddb4d498ce57609e017b71455ebc08d365e306004c73bf357f163f3554d2b4d8699b04a7cc8230f22d04fbab9cd9e5a558a8c8269dd6c4bd86abf877ab68c3860f2308d18162f59c57c6cd37fbbf45fbc92d0eefacd2f7e23ec39a334dd5362dc333b0fbd53a5044858959c919eedff98ca8f20badfc293be61a2e62db99d04f2686b4b6e914193ca9307a7f87083347eb1e25be9d8b5807cf741b1b2ec9983c18803a08b07f5042f1c86412a77e68e676b2120aeb2d59afde03d4acc56615ef0425941b6a9b4af06285ac1b1005a441bd36f284bc725718744e138d670edf46759cfa3f52475a08e979f0baa38637de1ff0ebe53e6faf73093c35395b33bbfd5be7b96e3f66d57087997348099cbd5cdbbded0b1d119e261d49249ef787e5f44150322475a1c881766914db2cc63eb3a6f9419eba8fc5c93ea5eb382d08c879be96d5b8d8c32210c676b12f8b54e055a6729f944cf475165c02e1145670feffa1d20767b1430ffe1b6b1144ccacae9a283da002e75ba6dd238a0a8467c2ddf44376b821cea778d2423d89550f0b9535040990a696acd1a9e16aaea4b2316aa931ce79041136fde229a160c"
        ),
        

        (
            ContractFunctionCodeDefinition {
                method_id: 2026686066,
                num_inputs: 4147187816,
                num_outputs: 3531214782,
                vm_type: 1652762409,
                code: hex_literal::hex!("28bc0ed12e49f86b3aa5667205a7ca801e8d3342ec81eb94f1f0a4f07f42ce883ebf84dab0257ed98dfd367607d1c8578994e2156a93aae5d805fb133ac490030bf05a87e77d940349e2c6414e7dc6592853d33b5d2ef78752fa32bfbc2babaf203200b5552f4391c1ce397db887416cbcd1bef2308e5d9ba8b03f3e48207747e1d9dcb128762561d0ccfa5b11c60334ea7a24bb3b3f13a1c6a278f7ff36a5398dd3bf1fafd7735ee6d465e0b2747d25547242afbc153d834917fdb38b45ce22e27bf0083b26bec4794a5f93f938a3746e8606296f84080d004a2bf680543fb0bce4979d5ee8077fc527831be07b2d398f003d9fcd5522aae63d45a83a3e6e8a3e9ecf2ead6a091e5de8a8835017734256336400d37fb7cb8bc0389ce399be5cb739f8b371983fd17e53c1c5ab530415beb8c34ded770938d3a638660dd4b64960ffa1cf5ab0fdf36c4fa12508b61d4b32ffd765deca5370a453c3e872efd627267affac347d9755f47b5cb9e8037fee93e4c7f960eaa7c10d9bc79afa396f70f36cd7be23debb23995a9d5d1c799d417e1331d849f8507285527fe3f529a67f91cf3347bfd890ebc9f89ec07f271e6db7138d2d17781545a5cb6c2916e3674f9604a8a427d615a59ec0e21d00614e210324c9d79edf5fb28895cda638d17557b2ac068688e5cd1771d0a2432fa4fbdc63c54237df15d8beb5138ac8ee5d7dc3e19a2fcecbc5920112a8f77418dfa22241afa2561702344929659a39784ce39e68c0bcfcf74ee641ff72aa8df4b71f60fea9bb02ff3ad35f6f6e710bb7e5edbf4a9e94dc1172289befeacb978fb22ad674ef9d89e3ca317b725a").to_vec(),
            },
            "72c6cc78681031f7be0f7ad2292783625a02000028bc0ed12e49f86b3aa5667205a7ca801e8d3342ec81eb94f1f0a4f07f42ce883ebf84dab0257ed98dfd367607d1c8578994e2156a93aae5d805fb133ac490030bf05a87e77d940349e2c6414e7dc6592853d33b5d2ef78752fa32bfbc2babaf203200b5552f4391c1ce397db887416cbcd1bef2308e5d9ba8b03f3e48207747e1d9dcb128762561d0ccfa5b11c60334ea7a24bb3b3f13a1c6a278f7ff36a5398dd3bf1fafd7735ee6d465e0b2747d25547242afbc153d834917fdb38b45ce22e27bf0083b26bec4794a5f93f938a3746e8606296f84080d004a2bf680543fb0bce4979d5ee8077fc527831be07b2d398f003d9fcd5522aae63d45a83a3e6e8a3e9ecf2ead6a091e5de8a8835017734256336400d37fb7cb8bc0389ce399be5cb739f8b371983fd17e53c1c5ab530415beb8c34ded770938d3a638660dd4b64960ffa1cf5ab0fdf36c4fa12508b61d4b32ffd765deca5370a453c3e872efd627267affac347d9755f47b5cb9e8037fee93e4c7f960eaa7c10d9bc79afa396f70f36cd7be23debb23995a9d5d1c799d417e1331d849f8507285527fe3f529a67f91cf3347bfd890ebc9f89ec07f271e6db7138d2d17781545a5cb6c2916e3674f9604a8a427d615a59ec0e21d00614e210324c9d79edf5fb28895cda638d17557b2ac068688e5cd1771d0a2432fa4fbdc63c54237df15d8beb5138ac8ee5d7dc3e19a2fcecbc5920112a8f77418dfa22241afa2561702344929659a39784ce39e68c0bcfcf74ee641ff72aa8df4b71f60fea9bb02ff3ad35f6f6e710bb7e5edbf4a9e94dc1172289befeacb978fb22ad674ef9d89e3ca317b725a"
        ),
        

        (
            ContractFunctionCodeDefinition {
                method_id: 2641111504,
                num_inputs: 2049059328,
                num_outputs: 2964957202,
                vm_type: 80396741,
                code: hex_literal::hex!("92c0687f9b17198ab10e3bd93dea0ec94e766dbbd712bd5d0596e56658276192ce709f14f10800c90a1db32438ca4c266284f9e886b1f502e5873fccd2ce2895d64bc9126d0a110784f8f228881e3e1061ea239f5a38091ad2035aa348a775205759d49c087d9d87a95dd682c0619404378bf69f66b46ff382be313aca9c0181f68152ad3ec47a65ec15514368510e417f01c01c0275d6dcd7d8a4bb48c58ae9c7f73186212f725fbd18dcb0e63fec7389c8e633db062127372aabaf45c70b0f458b8aa986268e054828b1627eb4aae5f6a222f556f6314da8096557ee176c3b818ba69389c210cc3a2c71ebaa92ee57570a072042c0abaec7276bb1d34d4993dd5a45a2be0fafcccd238b6b84475e18d6bc7688f32aeaad9f1e150b1bbd7b9ccfaa6e5848016ff33f81698632022bdd01a5dacc816864eed5da31b063202c98571c674e120e122c08f10647f9f44793e4162a318616e65581ab4e8b1f283387599d2d4bcc76cdd6a2d6b625d2a42e24982bccdf2a559e52bcbedc90520230a2fae1f7984c36250cf55a7aacdf788b37f0dc1707f93afc63d2af8f406f77bbcae2d5c21fa28f1a12a22335da1d68467bf3419a049eb63405e29cba1861ffb688634b3eb223affe69c77dfa4194a7c3dcffdf7f08cc9b31585f4e6d41e1d7f673cad0043fd702a7494e2467b4c0577f8c9d05b0c361b73b395a69019184f6").to_vec(),
            },
            "d0296c9d002a227a12a8b9b0c5c1ca04fe01000092c0687f9b17198ab10e3bd93dea0ec94e766dbbd712bd5d0596e56658276192ce709f14f10800c90a1db32438ca4c266284f9e886b1f502e5873fccd2ce2895d64bc9126d0a110784f8f228881e3e1061ea239f5a38091ad2035aa348a775205759d49c087d9d87a95dd682c0619404378bf69f66b46ff382be313aca9c0181f68152ad3ec47a65ec15514368510e417f01c01c0275d6dcd7d8a4bb48c58ae9c7f73186212f725fbd18dcb0e63fec7389c8e633db062127372aabaf45c70b0f458b8aa986268e054828b1627eb4aae5f6a222f556f6314da8096557ee176c3b818ba69389c210cc3a2c71ebaa92ee57570a072042c0abaec7276bb1d34d4993dd5a45a2be0fafcccd238b6b84475e18d6bc7688f32aeaad9f1e150b1bbd7b9ccfaa6e5848016ff33f81698632022bdd01a5dacc816864eed5da31b063202c98571c674e120e122c08f10647f9f44793e4162a318616e65581ab4e8b1f283387599d2d4bcc76cdd6a2d6b625d2a42e24982bccdf2a559e52bcbedc90520230a2fae1f7984c36250cf55a7aacdf788b37f0dc1707f93afc63d2af8f406f77bbcae2d5c21fa28f1a12a22335da1d68467bf3419a049eb63405e29cba1861ffb688634b3eb223affe69c77dfa4194a7c3dcffdf7f08cc9b31585f4e6d41e1d7f673cad0043fd702a7494e2467b4c0577f8c9d05b0c361b73b395a69019184f6"
        ),
        

        (
            ContractFunctionCodeDefinition {
                method_id: 2469581698,
                num_inputs: 3168513432,
                num_outputs: 2886576783,
                vm_type: 1696121384,
                code: hex_literal::hex!("777fd77df8c5f215dee37af3381cbfd44615bea650997036156ac88efe1bfdbedb838b9d94d95978b764d0211cede104d95ed2bda1ebc3222a954d40820806e4071fd9ed168f59a7db9e41acf962faa6655c675f574eb95fa5e000d8d6dd325f20ffb0da61650353b595cddddf379dba088f4632c7a1dd6f629cb24104b82fc7d7b3122c5fa2f19b35b92b109f658bd419cb92c0a3997ecbf94273e56eec0bab5df4717a368478bcc75a3de332eee31148bbc7554fb12bfc222135208b502f8e2308caa270b3a256bcd6191e4745f1a759f91265cced36a5e3c7c82eb52e849f356a46923c420515214d8b9021f21f4b03373fb045c7e197e5a65348d416d915360884200601ffde2d8ad38aab8ee3e38aa3bbeb4ba6c1760aed7157784de4bbd0b2b6fa3b969d748c6c3d17a1571ea98b0a2c2724caf81b10e568e08435eeea5da3ea649c4fb33c21891b7b7491c6934471ff1418d6bf97cb60b67b29ad04047cc9ad99b0781e9f6c").to_vec(),
            },
            "82d3329398addbbc8faa0dac28c2186569010000777fd77df8c5f215dee37af3381cbfd44615bea650997036156ac88efe1bfdbedb838b9d94d95978b764d0211cede104d95ed2bda1ebc3222a954d40820806e4071fd9ed168f59a7db9e41acf962faa6655c675f574eb95fa5e000d8d6dd325f20ffb0da61650353b595cddddf379dba088f4632c7a1dd6f629cb24104b82fc7d7b3122c5fa2f19b35b92b109f658bd419cb92c0a3997ecbf94273e56eec0bab5df4717a368478bcc75a3de332eee31148bbc7554fb12bfc222135208b502f8e2308caa270b3a256bcd6191e4745f1a759f91265cced36a5e3c7c82eb52e849f356a46923c420515214d8b9021f21f4b03373fb045c7e197e5a65348d416d915360884200601ffde2d8ad38aab8ee3e38aa3bbeb4ba6c1760aed7157784de4bbd0b2b6fa3b969d748c6c3d17a1571ea98b0a2c2724caf81b10e568e08435eeea5da3ea649c4fb33c21891b7b7491c6934471ff1418d6bf97cb60b67b29ad04047cc9ad99b0781e9f6c"
        ),
        

        (
            ContractFunctionCodeDefinition {
                method_id: 4134553726,
                num_inputs: 1443052145,
                num_outputs: 1214650565,
                vm_type: 46461334,
                code: hex_literal::hex!("a95f46028e80181949ea8038e917fe631421d24581c710b48b36d4e6afec15a0fd5905450a52e774ea8cc610f09216493b5cd892f1e12b0152c2ac59c6e08f47d47231522cecc3da7abc32157de9fd433f0323bd265a787164db12f4f8313291c7bec4876a63de1aa4137e03bd676e057f6c6823021984f658e3564163066044f6c41143ff4107dc26ce1b6a1a89d95598ca223591dcf400ea45a76a373a68e863e0c432caf4145564ccd7ae179d70b6c799bc1516bb00b6bf122bb4895fc3056ca1631382ed0f2526cf1262fa0ca86df20e129bde3069c5420312533f3a88e739a6efc9153cd33dae7a880798abc7150ea82e75546b2785c1dbfc32ee6276422d8024c538d5c1b40c0c0891f2fedc68f1b8761e950106993c821c76e7c5dac03ebedf1055ab5b690ba725692dc82f00d0c6bcfa9890c39db36efeadb050cb7d422b89b1608c23ba993cb7f53c9eba462c51cf1c59be7c61ca8ce25099c5fd4b219bec3971d8a7d4b526c0f2a94ca868feaf1d8bb199c035d13adfa4d44448cbcad9f25279e103b2f535adb719ac18a3752bf9ed9390abf354f0a69e21f866332e01cff6e02ac1ef522d3e021f64fa1c01038839e7fac68fc0180d03faf338cb248e68b931a0d18898643aaa9d2adda1d6108023d986d1d21618609d67dd55").to_vec(),
            },
            "7e4870f6713a0356c518664896f1c402df010000a95f46028e80181949ea8038e917fe631421d24581c710b48b36d4e6afec15a0fd5905450a52e774ea8cc610f09216493b5cd892f1e12b0152c2ac59c6e08f47d47231522cecc3da7abc32157de9fd433f0323bd265a787164db12f4f8313291c7bec4876a63de1aa4137e03bd676e057f6c6823021984f658e3564163066044f6c41143ff4107dc26ce1b6a1a89d95598ca223591dcf400ea45a76a373a68e863e0c432caf4145564ccd7ae179d70b6c799bc1516bb00b6bf122bb4895fc3056ca1631382ed0f2526cf1262fa0ca86df20e129bde3069c5420312533f3a88e739a6efc9153cd33dae7a880798abc7150ea82e75546b2785c1dbfc32ee6276422d8024c538d5c1b40c0c0891f2fedc68f1b8761e950106993c821c76e7c5dac03ebedf1055ab5b690ba725692dc82f00d0c6bcfa9890c39db36efeadb050cb7d422b89b1608c23ba993cb7f53c9eba462c51cf1c59be7c61ca8ce25099c5fd4b219bec3971d8a7d4b526c0f2a94ca868feaf1d8bb199c035d13adfa4d44448cbcad9f25279e103b2f535adb719ac18a3752bf9ed9390abf354f0a69e21f866332e01cff6e02ac1ef522d3e021f64fa1c01038839e7fac68fc0180d03faf338cb248e68b931a0d18898643aaa9d2adda1d6108023d986d1d21618609d67dd55"
        ),
        

        (
            ContractFunctionCodeDefinition {
                method_id: 2034795867,
                num_inputs: 2658111837,
                num_outputs: 1429464242,
                vm_type: 818842155,
                code: hex_literal::hex!("10723e2cfdc1203f5fab50d5e26b3afa6339ed54190d586d0bdf8beecdf5801c5bf03b0f9455e1e8cad016985df34706f8acb6eb207f642ea82d4d428a20b1ce9da0f36a5bbcc7d399b2655d330a87b3a25032e40b27a5dccdd67fbf02fb11972684ff18e86e9be96c27daf8116978e71eba541841bdc95dea2b1a277ef214f4cb15e3913984c6e3f68d4cd8f2ab7df8783d0fe79581d78472cb7c55c512736fbde8c2c3b07b81f7382bea1b896808919af07036b0290a46c63946ff8840ea369461c9874cbcb8f34d3549a053333a091815590d7c01169052d41626eecc3106bbe1d85d1c7006288241174914a73a1b357f990617418c167b06304067a71e2b7c75e29260b8eccc1ff9e755ae2646d418a74d82415d3fbe4d065740bf7cf8f864a0d965085dfbc11e0ac099f0d5736a4464b20516c0832787affd85be344701ee931ec124be1d27f3e0dac1cb3c491e6a2ae4ea0bacce0fe53486660500023cff58911f98281057d950419d6d77e245773561cec4b2aabe55a64ab85cbbef9a0efa84f0ddf6d5ba5b0f5f330ffb3ecf05052e879fcbbc064a68321c03ba2a3f949c17babc006118242a0cf09a74ff0fcd335579105e60955d9cd011cdf4f68161a17e62986e30b9e650d2a4a99e2597b78be237a87b0cca2acd7e23d677e896d7").to_vec(),
            },
            "5b8548795d916f9eb2e433552b8ace30e101000010723e2cfdc1203f5fab50d5e26b3afa6339ed54190d586d0bdf8beecdf5801c5bf03b0f9455e1e8cad016985df34706f8acb6eb207f642ea82d4d428a20b1ce9da0f36a5bbcc7d399b2655d330a87b3a25032e40b27a5dccdd67fbf02fb11972684ff18e86e9be96c27daf8116978e71eba541841bdc95dea2b1a277ef214f4cb15e3913984c6e3f68d4cd8f2ab7df8783d0fe79581d78472cb7c55c512736fbde8c2c3b07b81f7382bea1b896808919af07036b0290a46c63946ff8840ea369461c9874cbcb8f34d3549a053333a091815590d7c01169052d41626eecc3106bbe1d85d1c7006288241174914a73a1b357f990617418c167b06304067a71e2b7c75e29260b8eccc1ff9e755ae2646d418a74d82415d3fbe4d065740bf7cf8f864a0d965085dfbc11e0ac099f0d5736a4464b20516c0832787affd85be344701ee931ec124be1d27f3e0dac1cb3c491e6a2ae4ea0bacce0fe53486660500023cff58911f98281057d950419d6d77e245773561cec4b2aabe55a64ab85cbbef9a0efa84f0ddf6d5ba5b0f5f330ffb3ecf05052e879fcbbc064a68321c03ba2a3f949c17babc006118242a0cf09a74ff0fcd335579105e60955d9cd011cdf4f68161a17e62986e30b9e650d2a4a99e2597b78be237a87b0cca2acd7e23d677e896d7"
        ),
        

        (
            ContractFunctionCodeDefinition {
                method_id: 4273582487,
                num_inputs: 590609605,
                num_outputs: 2910160249,
                vm_type: 3602484079,
                code: hex_literal::hex!("34dea3da1ed71afcee1d1cdb7bb37abdce5d43ef2fd561485e747894b97094cb9724dde678efac90dcd4bac15e6879747257660fdbf2d676e3636f67b884167720a411d71da29ec88702c90018da02622df96b07870616c3c47968ff619ff2f97888af26ce927d9721862666e1d99a40156385e4c6faa4f3d37aa2bf28fa3eb9dfc72d75e194099fc5829a08ce916225512d9397f4547d7e4a6a53a7e00257daf63e63ad01f9").to_vec(),
            },
            "97b1b9fec5fc3323798575ad6f8bb9d6a600000034dea3da1ed71afcee1d1cdb7bb37abdce5d43ef2fd561485e747894b97094cb9724dde678efac90dcd4bac15e6879747257660fdbf2d676e3636f67b884167720a411d71da29ec88702c90018da02622df96b07870616c3c47968ff619ff2f97888af26ce927d9721862666e1d99a40156385e4c6faa4f3d37aa2bf28fa3eb9dfc72d75e194099fc5829a08ce916225512d9397f4547d7e4a6a53a7e00257daf63e63ad01f9"
        ),
        


        ];
        
        for pair in pairs {
            let bytes = pair.0.write_to_vec().unwrap();
            //pair.0.psy_ser_to_bytes_vec()

            let bytes_canonical = pair.0.psy_ser_to_bytes_vec().unwrap();
            assert_eq!(bytes, bytes_canonical);

            let hex_string = hex::encode(&bytes);
            assert_eq!(hex_string, pair.1);

        }
    }
}
