mod traits;
pub use traits::*;

/// Internal helper macro to avoid code duplication. Do not use directly.
#[doc(hidden)]
#[macro_export]
macro_rules! __impl_psy_canonical_serialize_for_fixed_type_internal {
    (
        // The <T, U> part
        ( $($impl_generics:tt)* ),
        // The full type, e.g., MyStruct<T, U>
        $type:ty,
        // The `where T: Trait` part
        ( $($where_clause:tt)* ),
        // The fixed size expression
        $size:expr
    ) => {
        impl $($impl_generics)* psy_serialize::PsyIOReadWrite for $type $($where_clause)* {
            fn pio_serialized_size(&self) -> usize {
                <$type as psy_serialize::PsyIOReadWriteFixedTemplate<{$size}>>::fx_tpl_pio_serialized_size(self)
            }

            fn pio_write_to_io<W: psy_io::Write>(&self, writer: &mut W) -> anyhow::Result<()> {
                <$type as psy_serialize::PsyIOReadWriteFixedTemplate<{$size}>>::fx_tpl_pio_write_to_io(self, writer)
            }

            fn pio_read_from_io<R: psy_io::Read>(reader: &mut R) -> anyhow::Result<Self> {
                <$type as psy_serialize::PsyIOReadWriteFixedTemplate<{$size}>>::fx_tpl_pio_read_from_io(reader)
            }

            fn pio_get_variable_serialized_size(&self) -> usize {
                <$type as psy_serialize::PsyIOReadWriteFixedTemplate<{$size}>>::fx_tpl_pio_get_variable_serialized_size(self)
            }

            fn pio_write_to_io_many<W: psy_io::Write>(items: &[$type], writer: &mut W, write_fixed_items_count: bool) -> anyhow::Result<()> {
                <$type as psy_serialize::PsyIOReadWriteFixedTemplate<{$size}>>::fx_tpl_pio_write_to_io_many(items, writer, write_fixed_items_count)
            }

            fn pio_read_from_io_many<R: psy_io::Read>(reader: &mut R, known_size: Option<usize>, include_size_for_fixed: bool) -> anyhow::Result<Vec<Self>> {
                <$type as psy_serialize::PsyIOReadWriteFixedTemplate<{$size}>>::fx_tpl_pio_read_from_io_many(reader, known_size, include_size_for_fixed)
            }

            fn pio_serialized_size_vec(items: &[$type], include_size_for_fixed: bool) -> usize {
                <$type as psy_serialize::PsyIOReadWriteFixedTemplate<{$size}>>::fx_tpl_pio_serialized_size_vec(items, include_size_for_fixed)
            }

            fn pio_read_many_from_ref_bytes(data: &[u8], known_size: Option<usize>, include_size_for_fixed: bool) -> anyhow::Result<Vec<Self>> {
                <$type as psy_serialize::PsyIOReadWriteFixedTemplate<{$size}>>::fx_tpl_pio_read_many_from_ref_bytes(data, known_size, include_size_for_fixed)
            }

            // Delegate the default method to ensure consistency, even though it's defaulted in the trait
            fn pio_write_many_to_bytes(items: &[$type], write_fixed_items_count: bool) -> anyhow::Result<Vec<u8>> {
                let total_size = Self::pio_serialized_size_vec(items, write_fixed_items_count);
                let mut buffer = Vec::with_capacity(total_size);
                {
                    let mut writer = psy_io::Cursor::new(&mut buffer);
                    Self::pio_write_to_io_many(items, &mut writer, write_fixed_items_count)?;
                }
                Ok(buffer)
            }
        }

        impl $($impl_generics)* psy_serialize::PsyCanonicalDatabaseSerializeBaseSingle for $type $($where_clause)* {
            fn psydbser_from_slice(data: &[u8]) -> anyhow::Result<Self> {
                <$type as psy_serialize::PsyCanonicalDatabaseSerializeBaseSingleFixedTemplate<{$size}>>::fx_tpl_psydbser_from_slice(data)
            }

            fn psydbser_to_bytes_vec(&self) -> anyhow::Result<Vec<u8>> {
                <$type as psy_serialize::PsyCanonicalDatabaseSerializeBaseSingleFixedTemplate<{$size}>>::fx_tpl_psydbser_to_bytes_vec(self)
            }

            fn psydbser_into_bytes_vec(self) -> anyhow::Result<Vec<u8>> {
                <$type as psy_serialize::PsyCanonicalDatabaseSerializeBaseSingleFixedTemplate<{$size}>>::fx_tpl_psydbser_into_bytes_vec(self)
            }

            fn psydbser_from_owned_bytes_vec(data: Vec<u8>) -> anyhow::Result<Self> {
                <$type as psy_serialize::PsyCanonicalDatabaseSerializeBaseSingleFixedTemplate<{$size}>>::fx_tpl_psydbser_from_owned_bytes_vec(data)
            }
        }

        impl $($impl_generics)* psy_serialize::PsyCanonicalDatabaseSerializeBaseMulti for $type $($where_clause)* {
            fn psydbser_serialize_vec_of_self_ref(data: &[$type], write_fixed_items_count: bool) -> Vec<u8> {
                <$type as psy_serialize::PsyCanonicalDatabaseSerializeBaseMultiFixedTemplate<{$size}>>::fx_tpl_psydbser_serialize_vec_of_self_ref(data, write_fixed_items_count)
            }

            fn psydbser_serialize_vec_of_self(data: Vec<$type>, write_fixed_items_count: bool) -> Vec<u8> {
                <$type as psy_serialize::PsyCanonicalDatabaseSerializeBaseMultiFixedTemplate<{$size}>>::fx_tpl_psydbser_serialize_vec_of_self(data, write_fixed_items_count)
            }

            fn psydbser_deserialize_vec_of_self(data: &[u8], include_size_for_fixed: bool) -> anyhow::Result<Vec<Self>> {
                <$type as psy_serialize::PsyCanonicalDatabaseSerializeBaseMultiFixedTemplate<{$size}>>::fx_tpl_psydbser_deserialize_vec_of_self(data, include_size_for_fixed)
            }

            fn psydbser_deserialize_vec_of_self_owned(data: Vec<u8>, include_size_for_fixed: bool) -> anyhow::Result<Vec<Self>> {
                <$type as psy_serialize::PsyCanonicalDatabaseSerializeBaseMultiFixedTemplate<{$size}>>::fx_tpl_psydbser_deserialize_vec_of_self_owned(data, include_size_for_fixed)
            }
        }
    };
}

#[macro_export]
macro_rules! impl_psy_canonical_serialize_for_fixed_type {
    //
    // Arm 1: Generic type with a non-empty `where` clause.
    //
    // Usage:
    // impl_psy_canonical_serialize_for_fixed_type!(
    //     MyStruct,
    //     { T: Clone, U: Debug } => { T, U },
    //     128
    // );
    //
    (
        $type_name:ident,
        { $($where_clause:tt)+ } => { $($generics:tt)+ },
        $size:expr
    ) => {
        $crate::__impl_psy_canonical_serialize_for_fixed_type_internal!(
            ( <$($generics)*> ),
            $type_name<$($generics)*>,
            ( where $($where_clause)* ),
            $size
        );
    };

    //
    // Arm 2: Generic type with an empty `where` clause.
    //
    // Usage:
    // impl_psy_canonical_serialize_for_fixed_type!(
    //     MyStruct,
    //     {} => { T, U },
    //     128
    // );
    //
    (
        $type_name:ident,
        {} => { $($generics:tt)+ },
        $size:expr
    ) => {
        $crate::__impl_psy_canonical_serialize_for_fixed_type_internal!(
            ( <$($generics)*> ),
            $type_name<$($generics)*>,
            ( ), // No where clause
            $size
        );
    };

    //
    // Arm 3: Simple, non-generic type (your original case).
    //
    // Usage:
    // impl_psy_canonical_serialize_for_fixed_type!(MySimpleStruct, 64);
    //
    ($type:ty, $size:expr) => {
        $crate::__impl_psy_canonical_serialize_for_fixed_type_internal!(
            ( ), // No generics
            $type,
            ( ), // No where clause
            $size
        );
    };
}