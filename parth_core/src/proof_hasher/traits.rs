use super::{MaybeBasicFieldTraitsPlonky2Goldilocks, MaybePlonky2AlgebraicHasher};

pub trait QProofBackendGroupTraitsField: MaybeBasicFieldTraitsPlonky2Goldilocks {}
impl<F: MaybeBasicFieldTraitsPlonky2Goldilocks> QProofBackendGroupTraitsField for F {}


pub trait QProofBackendGroupTraitsHasher<F: QProofBackendGroupTraitsField>: MaybePlonky2AlgebraicHasher<F> {}
impl<F: QProofBackendGroupTraitsField, Hasher: MaybePlonky2AlgebraicHasher<F>> QProofBackendGroupTraitsHasher<F> for Hasher {}

pub trait QProofBackendHasher<F: QProofBackendGroupTraitsField>: QProofBackendGroupTraitsHasher<F> {}
impl<F: QProofBackendGroupTraitsField, Hasher: QProofBackendGroupTraitsHasher<F>> QProofBackendHasher<F> for Hasher {}