use psy_serialize::PsySerializeCanonical;

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
