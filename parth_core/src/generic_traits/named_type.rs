pub trait QStaticNamedType {
    fn q_static_type_name() -> &'static str;
}
pub trait QNamedType {
    fn q_type_name() -> String;
}
impl<T: QStaticNamedType> QNamedType for T {
    fn q_type_name() -> String {
        T::q_static_type_name().to_string()
    }
}
impl QStaticNamedType for u8 {
    fn q_static_type_name() -> &'static str {
        "u8"
    }
}
impl QStaticNamedType for u16 {
    fn q_static_type_name() -> &'static str {
        "u16"
    }
}
impl QStaticNamedType for u32 {
    fn q_static_type_name() -> &'static str {
        "u32"
    }
}
impl QStaticNamedType for u64 {
    fn q_static_type_name() -> &'static str {
        "u64"
    }
}
impl QStaticNamedType for u128 {
    fn q_static_type_name() -> &'static str {
        "u128"
    }
}
impl QStaticNamedType for usize {
    fn q_static_type_name() -> &'static str {
        "usize"
    }
}
impl QStaticNamedType for bool {
    fn q_static_type_name() -> &'static str {
        "bool"
    }
}
impl QStaticNamedType for String {
    fn q_static_type_name() -> &'static str {
        "String"
    }
}
impl<T: QNamedType, const N: usize> QNamedType for [T; N] {
    fn q_type_name() -> String {
        format!("[{}; {}]", T::q_type_name(), N)
    }
}
impl<T: QNamedType> QNamedType for Vec<T> {
    fn q_type_name() -> String {
        format!("Vec<{}>", T::q_type_name())
    }
}
impl<T: QNamedType, U: QNamedType> QNamedType for (T, U) {
    fn q_type_name() -> String {
        format!("({}, {})", T::q_type_name(), U::q_type_name())
    }
}

impl<T: QNamedType, U: QNamedType, V: QNamedType> QNamedType for (T, U, V) {
    fn q_type_name() -> String {
        format!("({}, {}, {})", T::q_type_name(), U::q_type_name(), V::q_type_name())
    }
}