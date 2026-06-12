use std::marker::PhantomData;

use num::BigUint;
use plonky2::{
    field::{extension::Extendable, types::Field},
    hash::hash_types::RichField,
    plonk::circuit_builder::CircuitBuilder,
};

use crate::crypto::{
    bn254::{
        field::bn128_scalar::Bn128Scalar,
        gadgets::nonnative_fp::{CircuitBuilderNonNative, NonNativeTarget},
    },
    kzg::builder::CircuitBuilderKZGHelpers,
};

#[derive(Clone, Debug)]
pub struct FFTSettingsTarget<F: RichField + Extendable<D>, const D: usize> {
    pub domain_size: usize,
    pub root_of_unity: NonNativeTarget<Bn128Scalar>,
    pub roots_of_unity: Vec<NonNativeTarget<Bn128Scalar>>,
    pub inv_roots_of_unity: Vec<NonNativeTarget<Bn128Scalar>>,
    pub domain_size_inv: NonNativeTarget<Bn128Scalar>,
    _phantom: PhantomData<F>,
}

pub trait CircuitBuilderFFT<F: RichField + Extendable<D>, const D: usize> {
    fn fft_settings(&mut self, domain_size: usize) -> FFTSettingsTarget<F, D>;

    fn fft_forward(&mut self, coeffs: &[NonNativeTarget<Bn128Scalar>], settings: &FFTSettingsTarget<F, D>) -> Vec<NonNativeTarget<Bn128Scalar>>;

    fn fft_inverse(&mut self, evals: &[NonNativeTarget<Bn128Scalar>], settings: &FFTSettingsTarget<F, D>) -> Vec<NonNativeTarget<Bn128Scalar>>;

    fn lagrange_interpolate_at_point(
        &mut self,
        evaluations: &[NonNativeTarget<Bn128Scalar>],
        point: &NonNativeTarget<Bn128Scalar>,
        settings: &FFTSettingsTarget<F, D>,
    ) -> NonNativeTarget<Bn128Scalar>;

    fn primitive_root_of_unity(&mut self, n: usize) -> NonNativeTarget<Bn128Scalar>;
}

impl<F: RichField + Extendable<D>, const D: usize> CircuitBuilderFFT<F, D> for CircuitBuilder<F, D> {
    /// Creates FFT settings for a given domain size
    ///
    /// # Mathematical Foundation
    ///
    /// For domain size n (power of 2), generates:
    /// - Primitive n-th root of unity: ω where ω^n = 1
    /// - Forward roots: [1, ω, ω², ..., ω^(n-1)]
    /// - Inverse roots: [1, ω^(-1), ω^(-2), ..., ω^(-(n-1))]
    /// - Domain size inverse: n^(-1) for IFFT scaling
    fn fft_settings(&mut self, domain_size: usize) -> FFTSettingsTarget<F, D> {
        assert!(domain_size.is_power_of_two(), "Domain size must be power of 2");

        // Compute primitive n-th root of unity ω
        let root = self.primitive_root_of_unity(domain_size);

        // Generate powers of ω: [1, ω, ω², ..., ω^(n-1)]
        let mut roots_of_unity = Vec::with_capacity(domain_size);
        let mut inv_roots_of_unity = Vec::with_capacity(domain_size);

        let one = self.one_nonnative();
        roots_of_unity.push(one.clone());
        inv_roots_of_unity.push(one.clone());

        let root_inv = self.inv_nonnative(&root);

        for i in 1..domain_size {
            // roots[i] = ω^i
            let prev_root = &roots_of_unity[i - 1];
            let next_root = self.mul_nonnative(prev_root, &root);
            roots_of_unity.push(next_root);

            // inv_roots[i] = ω^(-i)
            let prev_inv_root = &inv_roots_of_unity[i - 1];
            let next_inv_root = self.mul_nonnative(prev_inv_root, &root_inv);
            inv_roots_of_unity.push(next_inv_root);
        }

        // Compute n^(-1) for IFFT normalization
        let domain_size_scalar = self.constant_nonnative(Bn128Scalar::from_canonical_usize(domain_size));
        let domain_size_inv = self.inv_nonnative(&domain_size_scalar);

        FFTSettingsTarget {
            domain_size,
            root_of_unity: root,
            roots_of_unity,
            inv_roots_of_unity,
            domain_size_inv,
            _phantom: PhantomData,
        }
    }

    /// Computes the Discrete Fourier Transform (DFT) of polynomial coefficients
    ///
    /// # Mathematical Formula
    ///
    /// For polynomial p(x) = Σ(a_i * x^i), computes evaluations:
    /// y_j = p(ω^j) = Σ(a_i * ω^(i*j)) for j = 0, 1, ..., n-1
    ///
    /// # Algorithm: Cooley-Tukey FFT
    ///
    /// 1. Bit-reversal permutation
    /// 2. Iterative butterfly operations:
    ///    - For each stage m = 2^k: u' = u + ω^j * v  (even index) v' = u - ω^j
    ///      * v  (odd index)
    ///    where ω^j are twiddle factors
    fn fft_forward(&mut self, coeffs: &[NonNativeTarget<Bn128Scalar>], settings: &FFTSettingsTarget<F, D>) -> Vec<NonNativeTarget<Bn128Scalar>> {
        let n = settings.domain_size;
        assert_eq!(coeffs.len(), n, "Input size must match domain size");

        let mut values = coeffs.to_vec();

        // Step 1: Bit-reversal permutation
        // Rearranges input for in-place FFT computation
        for i in 0..n {
            let j = reverse_bits(i, n.trailing_zeros());
            if i < j {
                values.swap(i, j);
            }
        }

        // Step 2: Cooley-Tukey iterative FFT
        let mut m = 1;
        while m < n {
            let half_m = m;
            m <<= 1;

            // Twiddle factor for this stage: ω^(n/m)
            let round_root_idx = n / m;
            let round_root = &settings.roots_of_unity[round_root_idx];

            // Process each m-point DFT
            for k in (0..n).step_by(m) {
                let mut root_power = self.one_nonnative();

                // Butterfly operations within each group
                for j in 0..half_m {
                    // t = ω^j * values[k + j + half_m]
                    let t = self.mul_nonnative(&root_power, &values[k + j + half_m]);
                    let u = values[k + j].clone();

                    // Butterfly: u' = u + t, v' = u - t
                    values[k + j] = self.add_nonnative(&u, &t);
                    values[k + j + half_m] = self.sub_nonnative(&u, &t);

                    // Update twiddle factor: ω^j -> ω^(j+1)
                    root_power = self.mul_nonnative(&root_power, round_root);
                }
            }
        }

        values
    }

    /// Computes the Inverse Discrete Fourier Transform (IDFT)
    ///
    /// # Mathematical Formula
    ///
    /// For evaluations y_j = p(ω^j), recovers coefficients:
    /// a_i = (1/n) * Σ(y_j * ω^(-i*j)) for i = 0, 1, ..., n-1
    ///
    /// # Implementation
    ///
    /// Uses same algorithm as forward FFT but with:
    /// - Inverse roots: ω^(-1) instead of ω
    /// - Final scaling by 1/n
    fn fft_inverse(&mut self, evals: &[NonNativeTarget<Bn128Scalar>], settings: &FFTSettingsTarget<F, D>) -> Vec<NonNativeTarget<Bn128Scalar>> {
        let n = settings.domain_size;
        assert_eq!(evals.len(), n, "Input size must match domain size");

        let mut values = evals.to_vec();

        // Step 1: Bit-reversal permutation (same as forward FFT)
        for i in 0..n {
            let j = reverse_bits(i, n.trailing_zeros());
            if i < j {
                values.swap(i, j);
            }
        }

        // Step 2: Cooley-Tukey FFT with inverse roots
        let mut m = 1;
        while m < n {
            let half_m = m;
            m <<= 1;

            // Use inverse twiddle factor: ω^(-(n/m))
            let round_root_idx = n / m;
            let round_root = &settings.inv_roots_of_unity[round_root_idx];

            for k in (0..n).step_by(m) {
                let mut root_power = self.one_nonnative();

                for j in 0..half_m {
                    // Same butterfly as forward FFT but with ω^(-j)
                    let t = self.mul_nonnative(&root_power, &values[k + j + half_m]);
                    let u = values[k + j].clone();

                    values[k + j] = self.add_nonnative(&u, &t);
                    values[k + j + half_m] = self.sub_nonnative(&u, &t);

                    root_power = self.mul_nonnative(&root_power, round_root);
                }
            }
        }

        // Step 3: Scale by 1/n to complete inverse transform
        for value in &mut values {
            *value = self.mul_nonnative(value, &settings.domain_size_inv);
        }

        values
    }

    /// Interpolates polynomial value at arbitrary point using Lagrange
    /// interpolation
    ///
    /// # Mathematical Formula
    ///
    /// Given evaluations y_i = p(ω^i) for i = 0, ..., n-1, computes:
    /// p(z) = Σ(y_i * L_i(z))
    ///
    /// Where Lagrange basis at z:
    /// L_i(z) = ∏_{j≠i} (z - ω^j) / (ω^i - ω^j)
    ///
    /// # Efficient Formula for Roots of Unity
    ///
    /// For domain {1, ω, ω², ..., ω^(n-1)}:
    /// p(z) = (z^n - 1)/(n) * Σ(y_i / (z - ω^i))
    fn lagrange_interpolate_at_point(
        &mut self,
        evaluations: &[NonNativeTarget<Bn128Scalar>],
        point: &NonNativeTarget<Bn128Scalar>,
        settings: &FFTSettingsTarget<F, D>,
    ) -> NonNativeTarget<Bn128Scalar> {
        let n = settings.domain_size;
        assert_eq!(evaluations.len(), n);

        // Compute denominators (z - ω^i) for each i
        let mut numerators = Vec::with_capacity(n);
        let mut denominators = Vec::with_capacity(n);

        for i in 0..n {
            // Compute z - ω^i
            let diff = self.sub_nonnative(point, &settings.roots_of_unity[i]);
            denominators.push(diff);
            numerators.push(evaluations[i].clone());
        }

        // Batch compute 1/(z - ω^i) for all i
        let inverses = self.kzg_batch_inverse(&denominators);

        // Compute Σ(y_i / (z - ω^i))
        let mut sum = self.zero_nonnative();
        for i in 0..n {
            let term = self.mul_nonnative(&numerators[i], &inverses[i]);
            sum = self.add_nonnative(&sum, &term);
        }

        // Compute (z^n - 1) / n
        let n_biguint = BigUint::from(n);
        let z_pow_n = self.pow_nonnative_biguint(point, &n_biguint);
        let one = self.one_nonnative();
        let z_pow_n_minus_1 = self.sub_nonnative(&z_pow_n, &one);
        let scaled = self.mul_nonnative(&z_pow_n_minus_1, &settings.domain_size_inv);

        // Final result: (z^n - 1)/n * Σ(y_i / (z - ω^i))
        self.mul_nonnative(&scaled, &sum)
    }

    /// Computes a primitive n-th root of unity in the scalar field
    ///
    /// # Mathematical Formula
    ///
    /// For field order r and generator g:
    /// ω = g^((r-1)/n) mod r
    ///
    /// Properties of ω:
    /// - ω^n ≡ 1 (mod r)
    /// - ω^k ≢ 1 (mod r) for 0 < k < n
    ///
    /// For BN128 scalar field:
    /// - g = 5 (multiplicative generator)
    /// - r = field order
    /// - n must divide (r-1)
    fn primitive_root_of_unity(&mut self, n: usize) -> NonNativeTarget<Bn128Scalar> {
        assert!(n.is_power_of_two(), "n must be power of 2");

        // g = 5 is a generator of the multiplicative group
        let g = self.constant_nonnative(Bn128Scalar::from_canonical_u64(5));

        // Compute exponent: (r-1)/n
        let r = Bn128Scalar::order();
        let r_minus_1 = r - BigUint::from(1u64);
        let n_biguint = BigUint::from(n);
        let exponent = r_minus_1 / n_biguint;

        // ω = g^((r-1)/n) mod r
        self.pow_nonnative_biguint(&g, &exponent)
    }
}

fn reverse_bits(x: usize, log_n: u32) -> usize {
    let mut result = 0;
    for i in 0..log_n {
        if (x >> i) & 1 == 1 {
            result |= 1 << (log_n - 1 - i);
        }
    }
    result
}

trait CircuitBuilderPowExt<F: RichField + Extendable<D>, const D: usize> {
    fn pow_nonnative_biguint(&mut self, base: &NonNativeTarget<Bn128Scalar>, exponent: &BigUint) -> NonNativeTarget<Bn128Scalar>;

    #[allow(dead_code)]
    fn pow_nonnative(&mut self, base: &NonNativeTarget<Bn128Scalar>, exponent: usize) -> NonNativeTarget<Bn128Scalar>;
}

impl<F: RichField + Extendable<D>, const D: usize> CircuitBuilderPowExt<F, D> for CircuitBuilder<F, D> {
    fn pow_nonnative_biguint(&mut self, base: &NonNativeTarget<Bn128Scalar>, exponent: &BigUint) -> NonNativeTarget<Bn128Scalar> {
        let mut result = self.one_nonnative();
        let mut temp = base.clone();

        let bits = exponent.to_bytes_le();
        for byte in bits {
            for i in 0..8 {
                if (byte >> i) & 1 == 1 {
                    result = self.mul_nonnative(&result, &temp);
                }
                temp = self.mul_nonnative(&temp, &temp);
            }
        }

        result
    }

    fn pow_nonnative(&mut self, base: &NonNativeTarget<Bn128Scalar>, exponent: usize) -> NonNativeTarget<Bn128Scalar> {
        let mut result = self.one_nonnative();
        let mut temp = base.clone();
        let mut exp = exponent;

        while exp > 0 {
            if exp & 1 == 1 {
                result = self.mul_nonnative(&result, &temp);
            }
            temp = self.mul_nonnative(&temp, &temp);
            exp >>= 1;
        }

        result
    }
}

#[cfg(test)]
mod tests {
    use plonky2::{
        iop::witness::PartialWitness,
        plonk::{
            circuit_data::CircuitConfig,
            config::{GenericConfig, PoseidonGoldilocksConfig},
        },
    };

    use super::*;

    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;
    type F = <C as GenericConfig<D>>::F;

    #[test]
    fn test_fft_roundtrip() {
        let config = CircuitConfig {
            num_wires: 400,
            ..CircuitConfig::wide_ecc_config()
        };
        let mut builder = CircuitBuilder::<F, D>::new(config);

        let domain_size = 4;
        let settings = builder.fft_settings(domain_size);

        let coeffs = vec![
            builder.constant_nonnative(Bn128Scalar::from_canonical_u64(1)),
            builder.constant_nonnative(Bn128Scalar::from_canonical_u64(2)),
            builder.constant_nonnative(Bn128Scalar::from_canonical_u64(3)),
            builder.constant_nonnative(Bn128Scalar::from_canonical_u64(4)),
        ];

        let evals = builder.fft_forward(&coeffs, &settings);

        let recovered = builder.fft_inverse(&evals, &settings);

        for i in 0..domain_size {
            builder.connect_nonnative(&coeffs[i], &recovered[i]);
        }

        let data = builder.build::<C>();
        let pw = PartialWitness::new();
        let proof = data.prove(pw).unwrap();
        data.verify(proof).unwrap();
    }
}
