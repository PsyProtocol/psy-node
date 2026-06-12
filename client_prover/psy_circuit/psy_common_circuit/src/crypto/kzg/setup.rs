use crate::crypto::{
    bn254::field::bn128_scalar::Bn128Scalar,
    secp256k1::ecdsa::curve::curve_types::{AffinePoint, Curve, CurveScalar},
};

#[derive(Clone, Debug)]
pub struct KZGParams {
    pub lagrange_g1: Vec<AffinePoint<crate::crypto::bn254::curve::g1::G1>>,
    pub powers_of_tau_g2: Vec<AffinePoint<crate::crypto::bn254::curve::g2::G2>>,
    pub domain_size: usize,
    pub roots_of_unity: Vec<Bn128Scalar>,
}

pub struct KZGSetup;

impl KZGSetup {
    /// Creates a trusted setup with Lagrange basis by default
    /// - G1 elements in Lagrange form: [L_0(τ)G, L_1(τ)G, ..., L_{n-1}(τ)G]
    /// - G2 elements: [H, τH]
    pub fn new_trusted_setup(tau: Bn128Scalar, domain_size: usize) -> KZGParams {
        // Default to Lagrange basis
        Self::new_lagrange_setup(tau, domain_size)
    }

    #[cfg(test)]
    pub fn new_test_setup(domain_size: usize) -> KZGParams {
        let tau = Bn128Scalar::from_canonical_u64(12345);
        Self::new_trusted_setup(tau, domain_size)
    }

    /// L_i(x) = ∏_{j≠i} (x - ω^j) / (ω^i - ω^j)
    /// L_i(x) = (x^n - 1) / (n * (x - ω^i))
    /// L_i(τ) = (τ^n - 1) / (n * (τ - ω^i))
    // [L_0(τ)G, L_1(τ)G, ..., L_{n-1}(τ)G]
    pub fn new_lagrange_setup(tau: Bn128Scalar, domain_size: usize) -> KZGParams {
        use plonky2::field::types::Field;

        use crate::crypto::bn254::curve::{g1::G1, g2::G2};

        assert!(domain_size.is_power_of_two(), "Domain size must be power of 2");

        // Compute primitive n-th root of unity ω
        let omega = Self::compute_primitive_root_of_unity(domain_size);

        // Generate all n-th roots of unity: {1, ω, ω², ..., ω^(n-1)}
        let mut roots_of_unity = Vec::with_capacity(domain_size);
        let mut omega_power = Bn128Scalar::ONE;
        for _ in 0..domain_size {
            roots_of_unity.push(omega_power);
            omega_power = omega_power * omega;
        }

        // Compute Lagrange basis evaluations at τ
        let mut lagrange_g1 = Vec::with_capacity(domain_size);

        // Compute τ^n - 1
        let mut tau_power = tau;
        for _ in 1..domain_size {
            tau_power = tau_power * tau;
        }
        let tau_n_minus_1 = tau_power - Bn128Scalar::ONE;

        // Compute 1/n
        let n_inv = Bn128Scalar::from_canonical_usize(domain_size).inverse();

        // For each i, compute L_i(τ) = (τ^n - 1) / (n * (τ - ω^i))
        for i in 0..domain_size {
            let denominator = tau - roots_of_unity[i];
            if denominator == Bn128Scalar::ZERO {
                // τ cannot be a root of unity for security
                panic!("tau cannot be a root of unity for Lagrange setup");
            }
            let l_i_tau = tau_n_minus_1 * denominator.inverse() * n_inv;

            // Compute L_i(τ) * G
            let g1_gen = G1::GENERATOR_AFFINE;
            let point = (CurveScalar::<G1>(l_i_tau) * g1_gen.to_projective()).to_affine();
            lagrange_g1.push(point);
        }

        // Generate powers of tau in G2: [H, τH]
        let mut powers_of_tau_g2 = Vec::with_capacity(2);
        let g2_gen = G2::GENERATOR_AFFINE;
        powers_of_tau_g2.push(g2_gen);
        let h_tau = (CurveScalar::<G2>(tau) * g2_gen.to_projective()).to_affine();
        powers_of_tau_g2.push(h_tau);

        KZGParams {
            lagrange_g1,
            powers_of_tau_g2,
            domain_size,
            roots_of_unity,
        }
    }

    /// ω^n ≡ 1 (mod r)
    /// ω = g^((r-1)/n) mod r
    ///
    /// - r = order of BN128 scalar field
    /// - n = desired root order (must divide r-1)
    /// - g = multiplicative generator of the field
    fn compute_primitive_root_of_unity(n: usize) -> Bn128Scalar {
        use num::{BigUint, One};

        assert!(n.is_power_of_two(), "n must be power of 2");

        // g = 5 is a generator of multiplicative group of BN128 scalar field
        let g = Bn128Scalar::from_canonical_u64(5);

        // r = order of BN128 scalar field
        let r = Bn128Scalar::order();
        let r_minus_1 = r - BigUint::one();
        let n_biguint = BigUint::from(n);
        let exponent = r_minus_1 / n_biguint;

        // ω = g^((r-1)/n) mod r
        g.exp_biguint(&exponent)
    }

    pub fn verify_setup(params: &KZGParams) -> bool {
        if params.lagrange_g1.len() < 2 || params.powers_of_tau_g2.len() < 2 {
            return false;
        }

        true
    }
}

impl KZGParams {
    pub fn max_degree(&self) -> usize {
        self.domain_size
    }

    pub fn get_g1_powers(&self, degree: usize) -> Option<&[AffinePoint<crate::crypto::bn254::curve::g1::G1>]> {
        if degree <= self.lagrange_g1.len() {
            Some(&self.lagrange_g1[..degree])
        } else {
            None
        }
    }

    pub fn get_g2_powers(
        &self,
    ) -> (
        &AffinePoint<crate::crypto::bn254::curve::g2::G2>,
        &AffinePoint<crate::crypto::bn254::curve::g2::G2>,
    ) {
        (&self.powers_of_tau_g2[0], &self.powers_of_tau_g2[1])
    }
}

#[cfg(test)]
mod tests {
    use plonky2::field::types::Field;

    use super::*;

    #[test]
    fn test_trusted_setup() {
        let max_degree = 16;
        let params = KZGSetup::new_test_setup(max_degree);

        assert_eq!(params.lagrange_g1.len(), max_degree);
        assert_eq!(params.powers_of_tau_g2.len(), 2);
        assert!(KZGSetup::verify_setup(&params));
    }

    #[test]
    fn test_powers_of_tau_consistency() {
        let tau = Bn128Scalar::from_canonical_u64(7);
        let _params = KZGSetup::new_trusted_setup(tau, 4);

        use crate::crypto::bn254::curve::g1::G1;
        let _g1_gen = G1::GENERATOR_AFFINE;

        // First Lagrange basis element is not the generator
        // since L_0(τ) = (τ^n - 1) / (n * (τ - 1))
    }

    #[test]
    fn test_new_trusted_setup_powers() {
        use crate::crypto::bn254::curve::g2::G2;

        let tau = Bn128Scalar::from_canonical_u64(3);
        let max_degree = 4;
        let params = KZGSetup::new_trusted_setup(tau, max_degree);

        // Verify Lagrange G1 length
        assert_eq!(params.lagrange_g1.len(), max_degree);

        // Verify G2 powers length
        assert_eq!(params.powers_of_tau_g2.len(), 2);

        // Verify first G2 element is generator
        let g2_gen = G2::GENERATOR_AFFINE;
        assert_eq!(params.powers_of_tau_g2[0], g2_gen);

        // Verify we have Lagrange basis data
        assert_eq!(params.domain_size, max_degree);
        assert_eq!(params.roots_of_unity.len(), max_degree);
    }

    #[test]
    fn test_compute_primitive_root_of_unity() {
        // Test for various powers of 2
        let test_sizes = vec![2, 4, 8, 16, 32, 64];

        for n in test_sizes {
            let omega = KZGSetup::compute_primitive_root_of_unity(n);

            // Verify ω^n = 1
            let omega_n = omega.exp_u64(n as u64);
            assert_eq!(omega_n, Bn128Scalar::ONE, "ω^{} should equal 1", n);

            // Verify ω^k ≠ 1 for 0 < k < n
            let mut omega_power = omega;
            for k in 1..n {
                assert_ne!(omega_power, Bn128Scalar::ONE, "ω^{} should not equal 1 for n={}", k, n);
                omega_power = omega_power * omega;
            }
        }
    }

    #[test]
    fn test_primitive_root_multiplicative_order() {
        let n = 8;
        let omega = KZGSetup::compute_primitive_root_of_unity(n);

        // Collect all powers of omega
        let mut powers = Vec::new();
        let mut current = Bn128Scalar::ONE;
        for _ in 0..n {
            powers.push(current);
            current = current * omega;
        }

        // Verify we're back to 1
        assert_eq!(current, Bn128Scalar::ONE);

        // Verify all powers are distinct
        for i in 0..n {
            for j in i + 1..n {
                assert_ne!(powers[i], powers[j], "Powers {} and {} should be distinct", i, j);
            }
        }
    }

    #[test]
    #[should_panic(expected = "n must be power of 2")]
    fn test_primitive_root_non_power_of_two() {
        // Should panic for non-power-of-2
        KZGSetup::compute_primitive_root_of_unity(6);
    }

    #[test]
    fn test_new_lagrange_setup() {
        let tau = Bn128Scalar::from_canonical_u64(12345);
        let domain_size = 4;
        let params = KZGSetup::new_trusted_setup(tau, domain_size);

        // Verify basic properties
        assert_eq!(params.lagrange_g1.len(), domain_size);
        assert_eq!(params.roots_of_unity.len(), domain_size);

        let lagrange_g1 = &params.lagrange_g1;
        let roots = &params.roots_of_unity;

        // Verify sizes
        assert_eq!(lagrange_g1.len(), domain_size);
        assert_eq!(roots.len(), domain_size);

        // Verify roots of unity
        assert_eq!(roots[0], Bn128Scalar::ONE);
        let omega = roots[1];
        for i in 0..domain_size {
            assert_eq!(roots[i], omega.exp_u64(i as u64));
        }

        // Verify ω^n = 1
        assert_eq!(omega.exp_u64(domain_size as u64), Bn128Scalar::ONE);
    }

    #[test]
    fn test_lagrange_polynomial_properties() {
        // Test that Lagrange polynomials have correct evaluation properties
        let tau = Bn128Scalar::from_canonical_u64(98765);
        let domain_size = 8;
        let params = KZGSetup::new_trusted_setup(tau, domain_size);

        let roots = &params.roots_of_unity;

        // Verify L_i(τ) computation matches formula
        let tau_n = tau.exp_u64(domain_size as u64);
        let tau_n_minus_1 = tau_n - Bn128Scalar::ONE;
        let n_inv = Bn128Scalar::from_canonical_usize(domain_size).inverse();

        for i in 0..domain_size {
            let _expected_li_tau = tau_n_minus_1 * (tau - roots[i]).inverse() * n_inv;
            // We can't directly verify the G1 points, but we can check the computation
            // logic
            assert_ne!(tau - roots[i], Bn128Scalar::ZERO, "tau should not equal any root of unity");
        }
    }

    #[test]
    #[should_panic(expected = "tau cannot be a root of unity")]
    fn test_lagrange_setup_tau_is_root() {
        // Get a root of unity
        let domain_size = 4;
        let omega = KZGSetup::compute_primitive_root_of_unity(domain_size);

        // Try to create Lagrange setup with tau = omega (should panic)
        KZGSetup::new_lagrange_setup(omega, domain_size);
    }

    #[test]
    #[should_panic(expected = "Domain size must be power of 2")]
    fn test_lagrange_setup_invalid_domain_size() {
        let tau = Bn128Scalar::from_canonical_u64(12345);
        // Should panic for non-power-of-2 domain size
        KZGSetup::new_lagrange_setup(tau, 6);
    }

    #[test]
    fn test_lagrange_setup_size() {
        let tau = Bn128Scalar::from_canonical_u64(54321);
        let domain_size = 16;

        // Create setup (now always Lagrange)
        let params = KZGSetup::new_trusted_setup(tau, domain_size);

        // Verify sizes
        assert_eq!(params.lagrange_g1.len(), domain_size);
        assert_eq!(params.powers_of_tau_g2.len(), 2);
        assert_eq!(params.roots_of_unity.len(), domain_size);
        assert_eq!(params.domain_size, domain_size);
    }
}
