use psy_serialize::PsySerializeCanonical;
#[cfg(all(feature = "rand",feature = "std"))]
use psy_serialize::PsySerializeCanonicalAsyncSafe;

#[cfg(feature = "std")]
use crate::utils::QPGenRandom;

pub trait QToCodeString {
    fn to_debug_code_string(&self) -> String;
    fn dbg_vec_of_self_to_debug_code_string(data: &[Self]) -> String
    where
        Self: Sized,
    {
        if data.len() == 0 {
            "vec![]".to_string()
        } else if data.len() == 1 {
            format!("vec![{}]", data[0].to_debug_code_string())
        } else {
            let parts = data.iter().map(|v| v.to_debug_code_string()).collect::<Vec<String>>();
            let first = &parts[0];
            let is_duplicate_array = parts.iter().all(|p| p == first);
            if is_duplicate_array {
                format!("vec![{}; {}]", first, data.len())
            } else {
                format!(
                    "vec![\n    {}\n]",
                    data.iter().map(|v| v.to_debug_code_string()).collect::<Vec<String>>().join(",\n    ")
                )
            }
        }
    }
}
pub trait QToCodeStringWithDebug: std::fmt::Debug {
    fn to_debug_code_string(&self) -> String {
        format!("{:#?}", self)
    }
}

pub fn get_psy_ser_test_case_string<T: QToCodeString + PsySerializeCanonical>(value: &T) -> String {
    format!(
        "({}, \"{}\")",
        value.to_debug_code_string(),
        hex::encode(value.psy_ser_to_bytes_vec().unwrap())
    )
}

pub fn get_psy_ser_test_cases_string<T: QToCodeString + PsySerializeCanonical>(value: &[T]) -> String {
    format!(
        "vec![\n    {}\n]",
        value
            .iter()
            .map(|v| get_psy_ser_test_case_string(v))
            .collect::<Vec<String>>()
            .join(",\n    ")
    )
}

#[cfg(feature = "std")]
pub fn generate_and_print_psy_ser_canonical_known_round_trip_serializations<
    T: QPGenRandom + psy_serialize::PsyCanonicalSerializationExamples + PsySerializeCanonicalAsyncSafe + QToCodeString + Clone + crate::generic_traits::QNamedType,
>() {

    let mut examples = T::psy_ser_canoical_known_round_trip_serializations();

    let exs = T::qp_rand_gen_vec(5).into_iter().map(|x| {
        let bytes = x.psy_ser_to_bytes_vec().unwrap();
        (x, bytes)
    }).collect::<Vec<_>>();
    examples.extend_from_slice(&exs);
    const BASE_INDENT: &str = "    ";
    const TAB_INDENT: &str = "    ";
    let inner_parts = examples
        .iter()
        .map(|(value, bytes)| format!("{BASE_INDENT}{TAB_INDENT}(\n{BASE_INDENT}{TAB_INDENT}{TAB_INDENT}{},\n{BASE_INDENT}{TAB_INDENT}{TAB_INDENT}hex_literal::hex!(\"{}\").to_vec(),\n{BASE_INDENT}{TAB_INDENT}{TAB_INDENT})", value.to_debug_code_string(), hex::encode(bytes)))
        .collect::<Vec<String>>()
        .join(&format!(",\n{BASE_INDENT}"));


    println!(
        "fn psy_ser_canoical_known_round_trip_serializations() -> Vec<({}, Vec<u8>)> \n{{\n    vec![{}]\n}}",
        T::q_type_name(),
        inner_parts
    );
}

#[cfg(all(feature = "rand",feature = "std"))]
pub fn generate_and_print_psy_ser_canonical_known_round_trip_serializations_replace_hash256_with_generic_hash<
    T: QPGenRandom + psy_serialize::PsyCanonicalSerializationExamples + PsySerializeCanonicalAsyncSafe + QToCodeString + Clone + crate::generic_traits::QNamedType,
>() {
    let mut examples = T::psy_ser_canoical_known_round_trip_serializations();

    let exs = T::qp_rand_gen_vec(5).into_iter().map(|x| {
        let bytes = x.psy_ser_to_bytes_vec().unwrap();
        (x, bytes)
    }).collect::<Vec<_>>();
    examples.extend_from_slice(&exs);
    const BASE_INDENT: &str = "    ";
    const TAB_INDENT: &str = "    ";
    let inner_parts = examples
        .iter()
        .map(|(value, bytes)| format!("{BASE_INDENT}{TAB_INDENT}(\n{BASE_INDENT}{TAB_INDENT}{TAB_INDENT}{},\n{BASE_INDENT}{TAB_INDENT}{TAB_INDENT}hex_literal::hex!(\"{}\").to_vec(),\n{BASE_INDENT}{TAB_INDENT}{TAB_INDENT})", value.to_debug_code_string(), hex::encode(bytes)))
        .collect::<Vec<String>>()
        .join(&format!(",\n{BASE_INDENT}"));

    let result = format!(
        "fn psy_ser_canoical_known_round_trip_serializations() -> Vec<({}, Vec<u8>)> \n{{\n    vec![{}]\n}}",
        T::q_type_name(),
        inner_parts
    )
    .replace("Hash256::from_hex_string(\"", "Hash::from_owned_32bytes(hex_literal::hex!(\"")
    .replace("\").unwrap()", "\"))");
    println!("{}", result);
}
