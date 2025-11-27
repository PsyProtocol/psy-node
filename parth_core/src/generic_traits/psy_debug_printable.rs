pub trait PsyDebugPrintable {
    fn psy_debug_print(&self) -> String;
}


impl PsyDebugPrintable for u16 {
    fn psy_debug_print(&self) -> String {
        format!("{}u16", self)
    }
}
impl PsyDebugPrintable for u32 {
    fn psy_debug_print(&self) -> String {
        format!("{}u32", self)
    }
}
impl PsyDebugPrintable for u64 {
    fn psy_debug_print(&self) -> String {
        format!("{}u64", self)
    }
}
impl PsyDebugPrintable for u128 {
    fn psy_debug_print(&self) -> String {
        format!("{}u128", self)
    }
}
impl PsyDebugPrintable for bool {
    fn psy_debug_print(&self) -> String {
        format!("{}", self)
    }
}
impl PsyDebugPrintable for String {
    fn psy_debug_print(&self) -> String {
        format!("\"{}\"", self)
    }
}
impl<T: PsyDebugPrintable, const N: usize> PsyDebugPrintable for [T; N] {
    fn psy_debug_print(&self) -> String {
        let elements: Vec<String> = self.iter().map(|elem| elem.psy_debug_print()).collect();
        format!("[{}]", elements.join(", "))
    }
}
impl<T: PsyDebugPrintable> PsyDebugPrintable for Vec<T> {
    fn psy_debug_print(&self) -> String {
        let elements: Vec<String> = self.iter().map(|elem| elem.psy_debug_print()).collect();
        format!("Vec[{}]", elements.join(", "))
    }
}

impl PsyDebugPrintable for Vec<u8> {
    fn psy_debug_print(&self) -> String {
        format!("hex!({})", hex::encode(&self))
    }
}
