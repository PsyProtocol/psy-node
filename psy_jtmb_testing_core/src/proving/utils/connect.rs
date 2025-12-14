use std::fmt::Debug;

/// Equivalent to `builder.connect(x, y)` or `builder.assert_eq(x, y)`.
/// Errors if a != b, representing a broken constraint.
pub fn jtmb_connect<T: PartialEq + Debug>(a: T, b: T, msg: &str) -> anyhow::Result<()> {
    if a != b {
        Err(anyhow::anyhow!("Constraint Failed [{}]: {:?} != {:?}", msg, a, b))
    } else {
        Ok(())
    }
}

/// Equivalent to `builder.connect_hashes(x, y)`.
pub fn jtmb_connect_ref<T: PartialEq + Debug>(a: &T, b: &T, msg: &str) -> anyhow::Result<()> {
    if a != b {
        Err(anyhow::anyhow!("Constraint Failed [{}]: {:?} != {:?}", msg, a, b))
    } else {
        Ok(())
    }
}