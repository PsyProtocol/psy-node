use core::hint::unreachable_unchecked;

#[inline(always)]
pub fn assume(p: bool) {
    debug_assert!(p);
    if !p {
        unsafe {
            unreachable_unchecked();
        }
    }
}


pub const fn bits_u64(n: u64) -> usize {
    (64 - n.leading_zeros()) as usize
}

/// Computes `ceil(log_2(n))`.
#[must_use]
pub const fn log2_ceil(n: usize) -> usize {
    (usize::BITS - n.saturating_sub(1).leading_zeros()) as usize
}

/// Computes `log_2(n)`, panicking if `n` is not a power of two.
pub fn log2_strict(n: usize) -> usize {
    let res = n.trailing_zeros();
    assert!(n.wrapping_shr(res) == 1, "Not a power of two: {n}");
    // Tell the optimizer about the semantics of `log2_strict`. i.e. it can replace `n` with
    // `1 << res` and vice versa.
    assume(n == 1 << res);
    res as usize
}

pub const fn ceil_div_usize(a: usize, b: usize) -> usize {
    (a + b - 1) / b
}