//! Checked unsigned N*32-bit arithmetic expanded into existing scalar DPN operations.
//!
//! `N == 1` (the u32 lane) emits the native single-limb `op_u32_*` opcodes so the
//! op graph matches the u32 paths that predate this type; `N >= 2` uses the
//! multi-limb carry/borrow expansion introduced for u256. No new opcodes and no
//! new `DPNContext` methods — every operation decomposes into existing scalar ops.
use std::{fmt, str::FromStr};
use super::{context_trait::{ContextFelt, DPNContext}, op_types::DPNOpType};

/// N base-2^32 digits, least significant first.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Uint<const N: usize>(pub [u32; N]);

pub type U64 = Uint<2>;
pub type U128 = Uint<4>;
pub type U256 = Uint<8>;

impl<const N: usize> FromStr for Uint<N> {
    type Err = String;
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let name = format!("u{}", 32 * N);
        let (digits, radix) = match value.strip_prefix("0x").or_else(|| value.strip_prefix("0X")) {
            Some(digits) => (digits, 16u64),
            None => (value, 10u64),
        };
        if digits.is_empty() { return Err(format!("empty {name} literal")); }
        let mut limbs = [0u32; N];
        for digit in digits.chars() {
            let mut carry = digit.to_digit(radix as u32).ok_or("invalid uint digit")? as u64;
            for limb in &mut limbs {
                let product = *limb as u64 * radix + carry;
                *limb = product as u32;
                carry = product >> 32;
            }
            if carry != 0 { return Err(format!("{name} literal overflow")); }
        }
        Ok(Self(limbs))
    }
}

impl<const N: usize> fmt::Display for Uint<N> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut limbs = self.0;
        let mut digits = Vec::new();
        while limbs.iter().any(|limb| *limb != 0) {
            let mut remainder = 0u64;
            for limb in limbs.iter_mut().rev() {
                let value = (remainder << 32) | *limb as u64;
                *limb = (value / 10) as u32;
                remainder = value % 10;
            }
            digits.push((b'0' + remainder as u8) as char);
        }
        if digits.is_empty() { return formatter.write_str("0"); }
        for digit in digits.iter().rev() { write!(formatter, "{digit}")?; }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug)]
pub struct UintValue<F: ContextFelt, const N: usize>(pub [F; N]);

pub type U64Value<F> = UintValue<F, 2>;
pub type U128Value<F> = UintValue<F, 4>;
pub type U256Value<F> = UintValue<F, 8>;

impl<F: ContextFelt, const N: usize> UintValue<F, N> {
    fn is_constant<C: DPNContext<F>>(ctx: &C, value: F) -> bool {
        matches!(ctx.get_op_type(value), DPNOpType::Constant | DPNOpType::ConstantU32 | DPNOpType::ConstantTrue | DPNOpType::ConstantFalse)
    }
    fn split_bits<C: DPNContext<F>>(ctx: &mut C, value: F, width: u64) -> Vec<F> {
        if Self::is_constant(ctx, value) {
            let value = ctx.get_constant_value(value);
            return (0..width).map(|bit| if (value >> bit) & 1 == 0 { ctx.op_false() } else { ctx.op_true() }).collect();
        }
        ctx.split_bits(value, width)
    }
    fn sum_bits<C: DPNContext<F>>(ctx: &mut C, bits: &[F]) -> F {
        if bits.iter().all(|bit| Self::is_constant(ctx, *bit)) {
            let value = bits.iter().enumerate().fold(0u32, |value, (i, bit)| value | ((ctx.get_constant_value(*bit) as u32) << i));
            return ctx.op_const_u32(value);
        }
        ctx.sum_bits(bits)
    }
    fn felt_add<C: DPNContext<F>>(ctx: &mut C, a: F, b: F) -> F {
        let a = ctx.op_cast_felt(a);
        let b = ctx.op_cast_felt(b);
        ctx.op_add(a, b)
    }
    fn felt_sub<C: DPNContext<F>>(ctx: &mut C, a: F, b: F) -> F {
        let a = ctx.op_cast_felt(a);
        let b = ctx.op_cast_felt(b);
        ctx.op_sub(a, b)
    }
    fn felt_mul<C: DPNContext<F>>(ctx: &mut C, a: F, b: F) -> F {
        let a = ctx.op_cast_felt(a);
        let b = ctx.op_cast_felt(b);
        ctx.op_mul(a, b)
    }
    pub fn from_limbs<C: DPNContext<F>>(ctx: &mut C, limbs: [F; N]) -> Self {
        Self(limbs.map(|limb| ctx.op_cast_u32(limb)))
    }
    pub fn constant<C: DPNContext<F>>(ctx: &mut C, value: Uint<N>) -> Self {
        Self(value.0.map(|limb| ctx.op_const_u32(limb)))
    }
    pub fn from_felt<C: DPNContext<F>>(ctx: &mut C, value: F) -> Self {
        if N == 1 {
            // Native lane: CastU32 range-checks the value into a single limb.
            return Self(std::array::from_fn(|_| ctx.op_cast_u32(value)));
        }
        let (low, high) = Self::split(ctx, value, 64);
        let zero = ctx.op_const_u32(0);
        let mut limbs = [zero; N];
        limbs[0] = low;
        if N > 1 { limbs[1] = high; }
        Self::from_limbs(ctx, limbs)
    }
    pub fn to_u32<C: DPNContext<F>>(self, ctx: &mut C) -> F {
        let value = Self::from_limbs(ctx, self.0);
        let zero = ctx.op_const_u32(0);
        for limb in &value.0[1..] { ctx.assert_eq(*limb, zero, "uint to u32 overflow"); }
        value.0[0]
    }
    pub fn to_felt<C: DPNContext<F>>(self, ctx: &mut C) -> F {
        if N == 1 {
            return ctx.op_cast_felt(self.0[0]);
        }
        let value = Self::from_limbs(ctx, self.0);
        let zero = ctx.op_const_u32(0);
        for limb in &value.0[2..] { ctx.assert_eq(*limb, zero, "uint to felt overflow"); }
        // p = (u32::MAX << 32) + 1: only low=0 is canonical at high=u32::MAX.
        let max = ctx.op_const_u32(u32::MAX);
        let high_max = ctx.op_eq(value.0[1], max);
        let low_nonzero = ctx.op_neq(value.0[0], zero);
        let invalid = ctx.op_bool_and(high_max, low_nonzero);
        ctx.assert_eq(invalid, zero, "uint to felt overflow");
        let base = ctx.op_const(1u64 << 32);
        let high = Self::felt_mul(ctx, value.0[1], base);
        Self::felt_add(ctx, high, value.0[0])
    }
    fn split<C: DPNContext<F>>(ctx: &mut C, value: F, width: u64) -> (F, F) {
        let bits = Self::split_bits(ctx, value, width);
        let low = Self::sum_bits(ctx, &bits[..32]);
        let high = Self::sum_bits(ctx, &bits[32..]);
        if width == 64 {
            let max = ctx.op_const_u32(u32::MAX);
            let zero = ctx.op_const_u32(0);
            let high_max = ctx.op_eq(high, max);
            let low_nonzero = ctx.op_neq(low, zero);
            let invalid = ctx.op_bool_and(high_max, low_nonzero);
            ctx.assert_eq(invalid, zero, "uint noncanonical 64-bit decomposition");
        }
        (ctx.op_cast_u32(low), ctx.op_cast_u32(high))
    }
    /// Slice-based so div_rem can drive it on N+1 scratch limbs (stable Rust
    /// cannot express `[F; N + 1]` arrays generically).
    fn sub_limbs<C: DPNContext<F>>(ctx: &mut C, a: &[F], b: &[F]) -> (Vec<F>, F) {
        let zero = ctx.op_const_u32(0);
        let base = ctx.op_const(1u64 << 32);
        let one = ctx.op_const_u32(1);
        let mut borrow = zero;
        let mut result = Vec::with_capacity(a.len());
        for i in 0..a.len() {
            // 0 <= B+a-b-borrow <= 2B-1; never a field wrap.
            let value = Self::felt_add(ctx, base, a[i]);
            let value = Self::felt_sub(ctx, value, b[i]);
            let value = Self::felt_sub(ctx, value, borrow);
            let (low, high) = Self::split(ctx, value, 33);
            borrow = Self::felt_sub(ctx, one, high);
            result.push(low);
        }
        (result, borrow)
    }
    pub fn add<C: DPNContext<F>>(self, ctx: &mut C, other: Self) -> Self {
        if N == 1 {
            return Self(std::array::from_fn(|_| ctx.op_u32_add(self.0[0], other.0[0])));
        }
        let a = Self::from_limbs(ctx, self.0);
        let b = Self::from_limbs(ctx, other.0);
        let zero = ctx.op_const_u32(0);
        let mut carry = zero;
        let limbs = std::array::from_fn(|i| {
            let value = Self::felt_add(ctx, a.0[i], b.0[i]);
            let value = Self::felt_add(ctx, value, carry);
            let (low, high) = Self::split(ctx, value, 33);
            carry = high;
            low
        });
        ctx.assert_eq(carry, zero, "uint addition overflow");
        Self(limbs)
    }
    pub fn sub<C: DPNContext<F>>(self, ctx: &mut C, other: Self) -> Self {
        if N == 1 {
            return Self(std::array::from_fn(|_| ctx.op_u32_sub(self.0[0], other.0[0])));
        }
        let a = Self::from_limbs(ctx, self.0);
        let b = Self::from_limbs(ctx, other.0);
        let (limbs, borrow) = Self::sub_limbs(ctx, &a.0, &b.0);
        let zero = ctx.op_const_u32(0);
        ctx.assert_eq(borrow, zero, "uint subtraction underflow");
        Self(std::array::from_fn(|i| limbs[i]))
    }
    pub fn mul<C: DPNContext<F>>(self, ctx: &mut C, other: Self) -> Self {
        if N == 1 {
            return Self(std::array::from_fn(|_| ctx.op_u32_mul(self.0[0], other.0[0])));
        }
        let a = Self::from_limbs(ctx, self.0);
        let b = Self::from_limbs(ctx, other.0);
        let zero = ctx.op_const_u32(0);
        let mut limbs = vec![zero; 2 * N];
        for i in 0..N {
            let mut carry = zero;
            for j in 0..N {
                // Split each product before accumulation: product+two carries could exceed p.
                let product = Self::felt_mul(ctx, a.0[i], b.0[j]);
                let (low, high) = Self::split(ctx, product, 64);
                let sum = Self::felt_add(ctx, limbs[i+j], low);
                let sum = Self::felt_add(ctx, sum, carry);
                let (low, extra) = Self::split(ctx, sum, 34);
                limbs[i+j] = low;
                carry = Self::felt_add(ctx, high, extra);
                carry = ctx.op_cast_u32(carry);
            }
            limbs[i+N] = carry;
        }
        for limb in &limbs[N..] { ctx.assert_eq(*limb, zero, "uint multiplication overflow"); }
        Self(std::array::from_fn(|i| limbs[i]))
    }
    pub fn eq<C: DPNContext<F>>(self, ctx: &mut C, other: Self) -> F {
        if N == 1 {
            return ctx.op_eq(self.0[0], other.0[0]);
        }
        let a = Self::from_limbs(ctx, self.0);
        let b = Self::from_limbs(ctx, other.0);
        let equal: Vec<_> = (0..N).map(|i| ctx.op_eq(a.0[i], b.0[i])).collect();
        ctx.op_bool_and_many(&equal)
    }
    pub fn lt<C: DPNContext<F>>(self, ctx: &mut C, other: Self) -> F {
        if N == 1 {
            return ctx.op_lt(self.0[0], other.0[0]);
        }
        let a = Self::from_limbs(ctx, self.0);
        let b = Self::from_limbs(ctx, other.0);
        Self::sub_limbs(ctx, &a.0, &b.0).1
    }
    pub fn div_rem<C: DPNContext<F>>(self, ctx: &mut C, other: Self) -> (Self, Self) {
        if N == 1 {
            // Native lane: U32Div/U32Mod carry their own zero-divisor check.
            let quotient = ctx.op_u32_div(self.0[0], other.0[0]);
            let remainder = ctx.op_u32_mod(self.0[0], other.0[0]);
            return (Self(std::array::from_fn(|_| quotient)), Self(std::array::from_fn(|_| remainder)));
        }
        let a = Self::from_limbs(ctx, self.0);
        let b = Self::from_limbs(ctx, other.0);
        let zero = ctx.op_const_u32(0);
        let is_zero = b.eq(ctx, Self([zero; N]));
        ctx.assert_eq(is_zero, zero, "uint division by zero");
        let bits: Vec<_> = a.0.iter().flat_map(|limb| Self::split_bits(ctx, *limb, 32)).collect();
        let mut remainder = vec![zero; N + 1];
        let mut divisor = vec![zero; N + 1];
        divisor[..N].copy_from_slice(&b.0);
        let mut quotient = vec![zero; 32 * N];
        for i in (0..32 * N).rev() {
            let mut carry = bits[i];
            for limb in remainder.iter_mut() {
                let doubled = Self::felt_add(ctx, *limb, *limb);
                let shifted = Self::felt_add(ctx, doubled, carry);
                let (low, high) = Self::split(ctx, shifted, 33);
                *limb = low;
                carry = high;
            }
            let (difference, borrow) = Self::sub_limbs(ctx, &remainder, &divisor);
            let take = ctx.op_bool_not(borrow);
            for j in 0..N + 1 { remainder[j] = ctx.op_select(take, difference[j], remainder[j]); }
            quotient[i] = take;
        }
        ctx.assert_eq(remainder[N], zero, "uint remainder overflow");
        let quotient = std::array::from_fn(|i| Self::sum_bits(ctx, &quotient[i*32..(i+1)*32]));
        (Self::from_limbs(ctx, quotient), Self::from_limbs(ctx, std::array::from_fn(|i| remainder[i])))
    }
    pub fn bitand<C: DPNContext<F>>(self, ctx: &mut C, other: Self) -> Self {
        let a = Self::from_limbs(ctx, self.0);
        let b = Self::from_limbs(ctx, other.0);
        Self(std::array::from_fn(|i| ctx.op_u32_and(a.0[i], b.0[i])))
    }
    pub fn bitor<C: DPNContext<F>>(self, ctx: &mut C, other: Self) -> Self {
        let a = Self::from_limbs(ctx, self.0);
        let b = Self::from_limbs(ctx, other.0);
        Self(std::array::from_fn(|i| ctx.op_u32_or(a.0[i], b.0[i])))
    }
    pub fn bitxor<C: DPNContext<F>>(self, ctx: &mut C, other: Self) -> Self {
        let a = Self::from_limbs(ctx, self.0);
        let b = Self::from_limbs(ctx, other.0);
        Self(std::array::from_fn(|i| ctx.op_u32_xor(a.0[i], b.0[i])))
    }
    pub fn not<C: DPNContext<F>>(self, ctx: &mut C) -> Self {
        let max = Self::constant(ctx, Uint([u32::MAX; N]));
        self.bitxor(ctx, max)
    }
    fn shift<C: DPNContext<F>>(self, ctx: &mut C, distance: F, left: bool) -> Self {
        if N == 1 {
            // Native lane: U32Shift* already folds distance >= 32 to zero.
            let shifted = if left { ctx.op_u32_shl(self.0[0], distance) } else { ctx.op_u32_shr(self.0[0], distance) };
            return Self(std::array::from_fn(|_| shifted));
        }
        let value = Self::from_limbs(ctx, self.0);
        let distance = ctx.op_cast_u32(distance);
        let distance_bits = Self::split_bits(ctx, distance, 32);
        let zero = ctx.op_const_u32(0);
        let width = 32 * N;
        let stages = (width as u32).next_power_of_two().trailing_zeros() as usize;
        let mut bits: Vec<_> = value.0.iter().flat_map(|limb| Self::split_bits(ctx, *limb, 32)).collect();
        for stage in 0..stages {
            let step = 1usize << stage;
            bits = (0usize..width).map(|i| {
                let source = if left { i.checked_sub(step) } else { i.checked_add(step).filter(|j| *j < width) };
                ctx.op_select(distance_bits[stage], source.map(|j| bits[j]).unwrap_or(zero), bits[i])
            }).collect();
        }
        let oversized = ctx.op_bool_or_many(&distance_bits[stages..]);
        let limbs = std::array::from_fn(|i| {
            let limb = Self::sum_bits(ctx, &bits[i*32..(i+1)*32]);
            ctx.op_select(oversized, zero, limb)
        });
        Self::from_limbs(ctx, limbs)
    }
    pub fn shl<C: DPNContext<F>>(self, ctx: &mut C, distance: F) -> Self { self.shift(ctx, distance, true) }
    pub fn shr<C: DPNContext<F>>(self, ctx: &mut C, distance: F) -> Self { self.shift(ctx, distance, false) }
    /// Native u32 lane only: `**` on wider uints is rejected by sema and never
    /// reaches the VM.
    pub fn pow<C: DPNContext<F>>(self, ctx: &mut C, other: Self) -> Self {
        assert!(N == 1, "pow is native to the u32 lane");
        let powered = ctx.op_u32_exp(self.0[0], other.0[0]);
        Self(std::array::from_fn(|_| powered))
    }
}

#[cfg(test)]
mod tests {
    use super::{Uint, UintValue, U256Value};
    use crate::dpn::ops::{context_trait::DPNContext, exec_context::QExecContext, sym_felt::SymFeltRef};
    use crate::dpn::eval::{cache::SimpleEvalCache, simple::DummyContextEvalInput, traits::ContextEval};

    fn resolve<const N: usize>(ctx: &QExecContext, value: UintValue<SymFeltRef, N>, inputs: Vec<u64>, valid: bool) -> Uint<N> {
        let input = DummyContextEvalInput::new(inputs);
        let mut cache = SimpleEvalCache::new();
        let limbs = value.0.map(|limb| ctx.store.resolve_felt_ref_cached(limb, &input, &mut cache) as u32);
        let accepted = ctx.assertions.iter().all(|assertion| {
            ctx.store.resolve_felt_ref_cached(assertion.left, &input, &mut cache)
                == ctx.store.resolve_felt_ref_cached(assertion.right, &input, &mut cache)
        });
        assert_eq!(accepted, valid);
        Uint(limbs)
    }

    #[test]
    fn u256_division_compiles_and_evaluates_on_a_default_size_stack() {
        // Pin Rust's default spawned-thread stack size even if the test runner
        // inherits RUST_MIN_STACK. No enlarged stack may hide deep traversal.
        std::thread::Builder::new().stack_size(2 * 1024 * 1024).spawn(|| {
            use crate::dpn::{eval::exec_eval::exec_eval_simple, vm::{compile::PsyCompileResult, exec::SimpleDPNExecutor}};
            use plonky2::field::{goldilocks_field::GoldilocksField, types::{Field, PrimeField64}};
            let mut ctx = QExecContext::new();
            let a = std::array::from_fn(|_| ctx.add_u32_input());
            let b = std::array::from_fn(|_| ctx.add_u32_input());
            let a = U256Value::from_limbs(&mut ctx, a);
            let b = U256Value::from_limbs(&mut ctx, b);
            let (quotient, remainder) = a.div_rem(&mut ctx, b);
            let outputs: Vec<_> = quotient.0.into_iter().chain(remainder.0).collect();
            let function = PsyCompileResult::compile_exec("division".into(), 0, &ctx.store, &ctx, &outputs);
            for (numerator, denominator) in [
                ([u32::MAX; 8], [0, 0, 0, 0, 0, 0, 0, 0x80000000]),
                ([u32::MAX; 8], [3, 0, 0, 0, 0, 0, 0, 0]),
                ([7, 0, 0, 0, 0, 0, 0, 0], [11, 0, 0, 0, 0, 0, 0, 0]),
            ] {
                let oracle = |limbs: [u32; 8]| alloy_primitives::U256::from_le_slice(&limbs.into_iter().flat_map(u32::to_le_bytes).collect::<Vec<_>>());
                let expected: Vec<u64> = [oracle(numerator) / oracle(denominator), oracle(numerator) % oracle(denominator)]
                    .into_iter().flat_map(|value| value.to_le_bytes::<32>().chunks_exact(4).map(|limb| u32::from_le_bytes(limb.try_into().unwrap()) as u64).collect::<Vec<_>>()).collect();
                let inputs: Vec<_> = numerator.into_iter().chain(denominator).map(u64::from).collect();
                assert_eq!(exec_eval_simple(inputs.clone(), &ctx, Some(outputs.clone())), expected);
                // Also run the compiled instruction graph, including assertions.
                let zero = GoldilocksField::ZERO;
                let mut executor = SimpleDPNExecutor::new_with_contract_ctx(inputs.into_iter().map(GoldilocksField::from_canonical_u64).collect(), zero, zero, zero, zero, zero, [zero; 4], [zero; 4]);
                for definition in &function.definitions { executor.process_var_def(definition); }
                for assertion in &function.assertions { assert_eq!(executor.resolve_target(assertion.left), executor.resolve_target(assertion.right)); }
                assert_eq!(executor.resolve_targets(&function.circuit_outputs).into_iter().map(|value| value.to_canonical_u64()).collect::<Vec<_>>(), expected);
            }
        }).unwrap().join().unwrap();
    }

    /// The original u256 arithmetic test, width-generic for N >= 2: limb 0 is a
    /// felt input, the rest are zero constants, so carry/borrow/product shapes
    /// are identical at every width.
    fn wide_arithmetic_checks<const N: usize>() {
        let one = || Uint::<N>(std::array::from_fn(|i| (i == 0) as u32));
        let two = || Uint::<N>(std::array::from_fn(|i| (i == 0) as u32 * 2));
        let zero = || Uint::<N>([0; N]);
        let max = || Uint::<N>([u32::MAX; N]);
        let mut ctx = QExecContext::new();
        let base = UintValue::<_, N>::from_limbs(&mut ctx, std::array::from_fn(|_| SymFeltRef::new_constant(0)));
        let input = ctx.add_input();
        let mut limbs = base.0;
        limbs[0] = input;
        let a = UintValue::<_, N>::from_limbs(&mut ctx, limbs);
        let one_value = UintValue::<_, N>::constant(&mut ctx, one());
        let sum = a.add(&mut ctx, one_value);
        assert_eq!(resolve(&ctx, sum, vec![u32::MAX as u64], true).0[0], 0);
        assert_eq!(resolve(&ctx, sum, vec![u32::MAX as u64], true).0[1], 1);
        let difference = sum.sub(&mut ctx, one_value);
        assert_eq!(resolve(&ctx, difference, vec![u32::MAX as u64], true).0[0], u32::MAX);
        let product = a.mul(&mut ctx, a);
        let resolved = resolve(&ctx, product, vec![u32::MAX as u64], true).0;
        let expected: u128 = u32::MAX as u128 * u32::MAX as u128;
        assert_eq!(resolved[0], (expected & 0xffff_ffff) as u32);
        assert_eq!(resolved[1], (expected >> 32) as u32);
        let mut ctx = QExecContext::new();
        let max_value = UintValue::<_, N>::constant(&mut ctx, max());
        let one_value = UintValue::<_, N>::constant(&mut ctx, one());
        let sum = max_value.add(&mut ctx, one_value);
        resolve(&ctx, sum, vec![], false);
        let mut ctx = QExecContext::new();
        let max_value = UintValue::<_, N>::constant(&mut ctx, max());
        let two_value = UintValue::<_, N>::constant(&mut ctx, two());
        let product = max_value.mul(&mut ctx, two_value);
        resolve(&ctx, product, vec![], false);
        let mut ctx = QExecContext::new();
        let zero_value = UintValue::<_, N>::constant(&mut ctx, zero());
        let one_value = UintValue::<_, N>::constant(&mut ctx, one());
        let difference = zero_value.sub(&mut ctx, one_value);
        resolve(&ctx, difference, vec![], false);
    }

    #[test]
    fn u64_width_checks_carry_borrow_and_full_product() { wide_arithmetic_checks::<2>(); }

    #[test]
    fn u128_width_checks_carry_borrow_and_full_product() { wide_arithmetic_checks::<4>(); }

    #[test]
    fn u256_width_checks_carry_borrow_and_full_product() { wide_arithmetic_checks::<8>(); }

    #[test]
    fn u64_to_felt_rejects_full_width() {
        // 2^64 - 1 is not canonical in the Goldilocks field: the canonical
        // decomposition check must reject it even though limbs[2..] is empty.
        let mut ctx = QExecContext::new();
        let value = UintValue::<_, 2>::constant(&mut ctx, Uint([u32::MAX, u32::MAX]));
        let felt = value.to_felt(&mut ctx);
        let converted = UintValue::<_, 2>::from_felt(&mut ctx, felt);
        resolve(&ctx, converted, vec![], false);
    }

    #[test]
    fn u128_literals_cover_full_width_and_reject_overflow() {
        let max = "340282366920938463463374607431768211455";
        assert_eq!(max.parse::<super::U128>().unwrap(), Uint([u32::MAX; 4]));
        assert_eq!(max.parse::<super::U128>().unwrap().to_string(), max);
        assert!("340282366920938463463374607431768211456".parse::<super::U128>().is_err());
        assert_eq!("0".parse::<super::U64>().unwrap().to_string(), "0");
        assert_eq!("4294967296".parse::<super::U64>().unwrap(), Uint([0, 1]));
        assert!("18446744073709551616".parse::<super::U64>().is_err());
    }

    #[test]
    fn u64_shifts_drop_bits_moved_past_the_width() {
        let mut ctx = QExecContext::new();
        let three = UintValue::<_, 2>::constant(&mut ctx, Uint([3, 0]));
        let distance = ctx.add_u32_input();
        let shifted = three.shl(&mut ctx, distance);
        assert_eq!(resolve(&ctx, shifted, vec![63], true), Uint([0, 0x80000000]));
        assert_eq!(resolve(&ctx, shifted, vec![64], true), Uint([0, 0]));
        let mut ctx = QExecContext::new();
        let three = UintValue::<_, 4>::constant(&mut ctx, Uint([3, 0, 0, 0]));
        let distance = ctx.add_u32_input();
        let shifted = three.shl(&mut ctx, distance);
        assert_eq!(resolve(&ctx, shifted, vec![127], true), Uint([0, 0, 0, 0x80000000]));
        assert_eq!(resolve(&ctx, shifted, vec![128], true), Uint([0, 0, 0, 0]));
    }

    #[test]
    fn native_lane_emits_the_native_u32_opcodes() {
        // N == 1 must lower to the same native single-limb ops the u32
        // interpreter path has always emitted — no carry-chain expansion.
        let mut ctx = QExecContext::new();
        let input = ctx.add_u32_input();
        let one = UintValue::<_, 1>::constant(&mut ctx, Uint([1]));
        let a = UintValue::<_, 1>::from_limbs(&mut ctx, [input]);
        let sum = a.add(&mut ctx, one);
        let difference = a.sub(&mut ctx, one);
        let product = a.mul(&mut ctx, one);
        let equal = a.eq(&mut ctx, one);
        let less = a.lt(&mut ctx, one);
        let (quotient, remainder) = a.div_rem(&mut ctx, one);
        let shifted = a.shl(&mut ctx, one.0[0]);
        let inverted = a.not(&mut ctx);
        let powered = a.pow(&mut ctx, one);
        let op_type = |value: SymFeltRef| format!("{:?}", ctx.get_op_type(value));
        assert!(op_type(sum.0[0]).contains("U32Add"));
        assert!(op_type(difference.0[0]).contains("U32Sub"));
        assert!(op_type(product.0[0]).contains("U32Mul"));
        assert!(op_type(equal).starts_with("Eq"));
        assert!(op_type(less).starts_with("Lt"));
        assert!(op_type(quotient.0[0]).contains("U32Div"));
        assert!(op_type(remainder.0[0]).contains("U32Mod"));
        assert!(op_type(shifted.0[0]).contains("U32ShiftLeft"));
        assert!(op_type(inverted.0[0]).contains("U32Xor"));
        assert!(op_type(powered.0[0]).contains("U32Exp"));
    }

    #[test]
    fn native_lane_felt_conversions_are_casts() {
        let mut ctx = QExecContext::new();
        let input = ctx.add_input();
        let value = UintValue::<_, 1>::from_felt(&mut ctx, input);
        let felt = value.to_felt(&mut ctx);
        let op_type = |value: SymFeltRef| format!("{:?}", ctx.get_op_type(value));
        assert!(op_type(value.0[0]).contains("CastU32"));
        assert!(op_type(felt).contains("CastFelt"));
    }

    // The deep tests below keep their original u256 shape through the aliases.
    use super::U256 as U256Host;

    #[test]
    fn symbolic_arithmetic_checks_carry_borrow_and_full_product() {
        let mut ctx = QExecContext::new();
        let a = U256Value::from_limbs(&mut ctx, std::array::from_fn(|_| SymFeltRef::new_constant(0)));
        let input = ctx.add_input();
        let mut limbs = a.0;
        limbs[0] = input;
        let a = U256Value::from_limbs(&mut ctx, limbs);
        let one = U256Value::constant(&mut ctx, Uint([1, 0, 0, 0, 0, 0, 0, 0]));
        let sum = a.add(&mut ctx, one);
        assert_eq!(resolve(&ctx, sum, vec![u32::MAX as u64], true), Uint([0, 1, 0, 0, 0, 0, 0, 0]));
        let difference = sum.sub(&mut ctx, one);
        assert_eq!(resolve(&ctx, difference, vec![u32::MAX as u64], true), Uint([u32::MAX, 0, 0, 0, 0, 0, 0, 0]));
        let product = a.mul(&mut ctx, a);
        assert_eq!(resolve(&ctx, product, vec![u32::MAX as u64], true), Uint([1, u32::MAX-1, 0, 0, 0, 0, 0, 0]));
        let mut ctx = QExecContext::new();
        let max = U256Value::constant(&mut ctx, Uint([u32::MAX; 8]));
        let one = U256Value::constant(&mut ctx, Uint([1, 0, 0, 0, 0, 0, 0, 0]));
        let sum = max.add(&mut ctx, one);
        resolve(&ctx, sum, vec![], false);
        let mut ctx = QExecContext::new();
        let max = U256Value::constant(&mut ctx, Uint([u32::MAX; 8]));
        let two = U256Value::constant(&mut ctx, Uint([2, 0, 0, 0, 0, 0, 0, 0]));
        let product = max.mul(&mut ctx, two);
        resolve(&ctx, product, vec![], false);
        let mut ctx = QExecContext::new();
        let zero = U256Value::constant(&mut ctx, Uint([0; 8]));
        let one = U256Value::constant(&mut ctx, Uint([1, 0, 0, 0, 0, 0, 0, 0]));
        let difference = zero.sub(&mut ctx, one);
        resolve(&ctx, difference, vec![], false);
    }

    #[test]
    fn narrow_conversions_reject_out_of_range_values() {
        let mut ctx = QExecContext::new();
        let zero = ctx.op_const_u32(0);
        let input = ctx.add_u32_input();
        let value = U256Value::from_limbs(&mut ctx, [input, zero, zero, zero, zero, zero, zero, zero]);
        let narrow = value.to_u32(&mut ctx);
        let wrapped = U256Value::from_limbs(&mut ctx, [narrow, zero, zero, zero, zero, zero, zero, zero]);
        assert_eq!(resolve(&ctx, wrapped, vec![7], true), Uint([7, 0, 0, 0, 0, 0, 0, 0]));
        let mut ctx = QExecContext::new();
        let zero = ctx.op_const_u32(0);
        let input = ctx.add_u32_input();
        let value = U256Value::from_limbs(&mut ctx, [input, input, zero, zero, zero, zero, zero, zero]);
        value.to_u32(&mut ctx);
        resolve(&ctx, value, vec![7], false);
        let mut ctx = QExecContext::new();
        let zero = ctx.op_const_u32(0);
        let input = ctx.add_u32_input();
        let value = U256Value::from_limbs(&mut ctx, [input, zero, input, zero, zero, zero, zero, zero]);
        let felt = value.to_felt(&mut ctx);
        let wrapped = U256Value::from_felt(&mut ctx, felt);
        resolve(&ctx, wrapped, vec![1], false);
    }

    #[test]
    fn comparisons_and_bitwise_paths_cover_high_limbs() {
        let mut ctx = QExecContext::new();
        let input = ctx.add_u32_input();
        let zero = ctx.op_const_u32(0);
        let a = U256Value::from_limbs(&mut ctx, [input, zero, zero, zero, zero, zero, zero, zero]);
        let b = U256Value::constant(&mut ctx, Uint([0xff00, 1, 0, 0, 0, 0, 0, 0]));
        let equal = a.eq(&mut ctx, a);
        let less = a.lt(&mut ctx, b);
        let reverse_less = b.lt(&mut ctx, a);
        let true_value = ctx.op_true();
        let false_value = ctx.op_false();
        ctx.assert_eq(equal, true_value, "u256 equality");
        ctx.assert_eq(less, true_value, "u256 high-limb comparison");
        ctx.assert_eq(reverse_less, false_value, "u256 reverse comparison");
        let joined = a.bitor(&mut ctx, b);
        let inverted = a.not(&mut ctx);
        assert_eq!(resolve(&ctx, joined, vec![0x1_2345], true), Uint([0x1_ff45, 1, 0, 0, 0, 0, 0, 0]));
        assert_eq!(resolve(&ctx, inverted, vec![0x1_2345], true), Uint([!0x1_2345, u32::MAX, u32::MAX, u32::MAX, u32::MAX, u32::MAX, u32::MAX, u32::MAX]));
    }

    #[test]
    fn invalid_limb_and_zero_divisor_are_rejected() {
        let mut ctx = QExecContext::new();
        let input = ctx.add_input();
        let zero = ctx.op_const_u32(0);
        let value = U256Value::from_limbs(&mut ctx, [input, zero, zero, zero, zero, zero, zero, zero]);
        let invalid = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| resolve(&ctx, value, vec![1u64 << 32], false)));
        let error = invalid.expect_err("an out-of-range limb was accepted");
        let message = error.downcast_ref::<String>().expect("range failure should explain the invalid limb");
        assert!(message.contains("CastU32: invalid u32 value"), "unexpected limb error: {message}");
        std::thread::Builder::new().stack_size(2 * 1024 * 1024).spawn(|| {
            let mut ctx = QExecContext::new();
            let numerator = U256Value::constant(&mut ctx, Uint([7, 0, 0, 0, 0, 0, 0, 0]));
            let denominator = U256Value::constant(&mut ctx, Uint([0; 8]));
            let (quotient, _) = numerator.div_rem(&mut ctx, denominator);
            resolve(&ctx, quotient, vec![], false);
        }).unwrap().join().unwrap();
    }

    #[test]
    fn left_shift_drops_bits_moved_past_the_width() {
        // Mirrors the u32 shift lane: distance < width keeps reachable bits and
        // silently drops bits moved past the top; distance >= 256 yields zero.
        let mut ctx = QExecContext::new();
        let three = U256Value::constant(&mut ctx, Uint([3, 0, 0, 0, 0, 0, 0, 0]));
        let distance = ctx.add_u32_input();
        let shifted = three.shl(&mut ctx, distance);
        assert_eq!(resolve(&ctx, shifted, vec![255], true), Uint([0, 0, 0, 0, 0, 0, 0, 0x80000000]));
        assert_eq!(resolve(&ctx, shifted, vec![256], true), Uint([0; 8]));
    }

    #[test]
    fn symbolic_division_handles_high_bit_divisor() {
        // Exercise the full fixed-round graph on a default-size thread stack.
        std::thread::Builder::new().stack_size(2 * 1024 * 1024).spawn(|| {
            let mut ctx = QExecContext::new();
            let input = ctx.add_u32_input();
            let mut limbs = [input; 8];
            limbs[0] = ctx.op_const_u32(u32::MAX);
            let a = U256Value::from_limbs(&mut ctx, limbs);
            let b = U256Value::constant(&mut ctx, Uint([0, 0, 0, 0, 0, 0, 0, 0x80000000]));
            let (quotient, remainder) = a.div_rem(&mut ctx, b);
            assert_eq!(resolve(&ctx, quotient, vec![u32::MAX as u64], true), Uint([1, 0, 0, 0, 0, 0, 0, 0]));
            assert_eq!(resolve(&ctx, remainder, vec![u32::MAX as u64], true), Uint([u32::MAX, u32::MAX, u32::MAX, u32::MAX, u32::MAX, u32::MAX, u32::MAX, 0x7fffffff]));
        }).unwrap().join().unwrap();
    }

    #[test]
    fn symbolic_shifts_and_felt_conversion_use_integer_bounds() {
        let mut ctx = QExecContext::new();
        let input = ctx.add_input();
        let value = U256Value::from_felt(&mut ctx, input);
        let distance = ctx.add_u32_input();
        let shifted = value.shl(&mut ctx, distance);
        assert_eq!(resolve(&ctx, shifted, vec![1, 255], true), Uint([0, 0, 0, 0, 0, 0, 0, 0x80000000]));
        assert_eq!(resolve(&ctx, shifted, vec![1, 256], true), Uint([0; 8]));
        let recovered = shifted.shr(&mut ctx, distance);
        assert_eq!(resolve(&ctx, recovered, vec![1, 255], true), Uint([1, 0, 0, 0, 0, 0, 0, 0]));
        let mut ctx = QExecContext::new();
        let high = ctx.add_u32_input();
        let low = ctx.add_u32_input();
        let zero = ctx.op_const_u32(0);
        let value = U256Value::from_limbs(&mut ctx, [low, high, zero, zero, zero, zero, zero, zero]);
        let felt = value.to_felt(&mut ctx);
        let converted = U256Value::from_felt(&mut ctx, felt);
        assert_eq!(resolve(&ctx, converted, vec![u32::MAX as u64, 0], true), Uint([0, u32::MAX, 0, 0, 0, 0, 0, 0]));
        resolve(&ctx, converted, vec![u32::MAX as u64, 1], false);
    }
    #[test]
    fn literals_cover_full_width_and_reject_overflow() {
        let max = "115792089237316195423570985008687907853269984665640564039457584007913129639935";
        assert_eq!(max.parse::<U256Host>().unwrap(), Uint([u32::MAX; 8]));
        assert_eq!(max.parse::<U256Host>().unwrap().to_string(), max);
        assert_eq!(format!("0x{}", "f".repeat(64)).parse::<U256Host>().unwrap().to_string(), max);
        assert!("115792089237316195423570985008687907853269984665640564039457584007913129639936".parse::<U256Host>().is_err());
        assert!(format!("0x1{}", "0".repeat(64)).parse::<U256Host>().is_err());
        for invalid in ["", "0x", "-1", "+1", "1_0", "0xg"] { assert!(invalid.parse::<U256Host>().is_err()); }
        assert_eq!("0".parse::<U256Host>().unwrap().to_string(), "0");
    }
}
