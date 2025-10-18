
/// Internal helper macro to avoid code duplication. Do not use directly.
#[doc(hidden)]
#[macro_export]
macro_rules! impl_psy_canonical_serialize_for_fixed_type_crate {
    // Arm 1: Generic type with a non-empty `where` clause.
    (
        $type_name:ident,
        { $($where_clause:tt)+ } => { $($generics:tt)+ },
        $size:expr
    ) => {
        $crate::__impl_psy_canonical_serialize_for_fixed_type_internal_crate!(
            ( <$($generics)*> ),
            $type_name<$($generics)*>,
            ( where $($where_clause)* ),
            $size
        );
    };

    // Arm 2: Generic type with an empty `where` clause.
    (
        $type_name:ident,
        {} => { $($generics:tt)+ },
        $size:expr
    ) => {
        $crate::__impl_psy_canonical_serialize_for_fixed_type_internal_crate!(
            ( <$($generics)*> ),
            $type_name<$($generics)*>,
            ( ), // No where clause
            $size
        );
    };

    // Arm 3: Simple, non-generic type (matches the usage for primitives).
    ($type:ty, $size:expr) => {
        $crate::__impl_psy_canonical_serialize_for_fixed_type_internal_crate!(
            ( ), // No generics
            $type,
            ( ), // No where clause
            $size
        );
    };
}



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

        impl psy_io::PsyIOReadableFixedSizeCanonicalStruct<$size> for $type $($where_clause)* {
            #[inline(always)]
            fn psy_io_read_fixed_canonical_struct_from<R: psy_io::Read>(reader: &mut R) -> anyhow::Result<Self> {
                Self::fx_tpl_pio_read_from_io(reader)
            }

            #[inline]
            fn psy_io_read_vec_of_fixed_canonical_structs_from<R: psy_io::Read>(
                reader: &mut R,
            ) -> anyhow::Result<Vec<Self>> {
                Self::fx_tpl_pio_read_from_io_many(reader, None)
            }
        }
        impl $($impl_generics)* psy_serialize::PsyIOReadWrite for $type $($where_clause)* {
            #[inline(always)]
            fn pio_serialized_size(&self) -> usize {
                <$type as psy_serialize::PsyIOReadWriteFixedTemplate<{$size}>>::fx_tpl_pio_serialized_size(self)
            }

            #[inline(always)]
            fn pio_write_to_io<W: psy_io::Write>(&self, writer: &mut W) -> anyhow::Result<()> {
                <$type as psy_serialize::PsyIOReadWriteFixedTemplate<{$size}>>::fx_tpl_pio_write_to_io(self, writer)
            }

            #[inline(always)]
            fn pio_read_from_io<R: psy_io::Read>(reader: &mut R) -> anyhow::Result<Self> {
                <$type as psy_serialize::PsyIOReadWriteFixedTemplate<{$size}>>::fx_tpl_pio_read_from_io(reader)
            }

            #[inline(always)]
            fn pio_get_variable_serialized_size(&self) -> usize {
                <$type as psy_serialize::PsyIOReadWriteFixedTemplate<{$size}>>::fx_tpl_pio_get_variable_serialized_size(self)
            }

            #[inline(always)]
            fn pio_write_to_io_many<W: psy_io::Write>(items: &[$type], writer: &mut W, write_fixed_items_count: bool) -> anyhow::Result<()> {
                <$type as psy_serialize::PsyIOReadWriteFixedTemplate<{$size}>>::fx_tpl_pio_write_to_io_many(items, writer, write_fixed_items_count)
            }

            #[inline(always)]
            fn pio_read_from_io_many<R: psy_io::Read>(reader: &mut R, known_count: Option<usize>) -> anyhow::Result<Vec<Self>> {
                <$type as psy_serialize::PsyIOReadWriteFixedTemplate<{$size}>>::fx_tpl_pio_read_from_io_many(reader, known_size)
            }

            #[inline(always)]
            fn pio_serialized_size_vec(items: &[$type], include_size_for_fixed: bool) -> usize {
                <$type as psy_serialize::PsyIOReadWriteFixedTemplate<{$size}>>::fx_tpl_pio_serialized_size_vec(items, include_size_for_fixed)
            }

            #[inline(always)]
            fn pio_read_many_from_ref_bytes(data: &[u8], known_count: Option<usize>) -> anyhow::Result<Vec<Self>> {
                <$type as psy_serialize::PsyIOReadWriteFixedTemplate<{$size}>>::fx_tpl_pio_read_many_from_ref_bytes(data, known_size)
            }
            // Delegate the default method to ensure consistency, even though it's defaulted in the trait

            #[inline(always)]
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

            #[inline(always)]
            fn psy_ser_from_slice(data: &[u8]) -> anyhow::Result<Self> {
                <$type as psy_serialize::PsyCanonicalDatabaseSerializeBaseSingleFixedTemplate<{$size}>>::fx_tpl_psy_ser_from_slice(data)
            }

            #[inline(always)]
            fn psy_ser_to_bytes_vec(&self) -> anyhow::Result<Vec<u8>> {
                <$type as psy_serialize::PsyCanonicalDatabaseSerializeBaseSingleFixedTemplate<{$size}>>::fx_tpl_psy_ser_to_bytes_vec(self)
            }

            #[inline(always)]
            fn psy_ser_into_bytes_vec(self) -> anyhow::Result<Vec<u8>> {
                <$type as psy_serialize::PsyCanonicalDatabaseSerializeBaseSingleFixedTemplate<{$size}>>::fx_tpl_psy_ser_into_bytes_vec(self)
            }

            #[inline(always)]
            fn psy_ser_from_owned_bytes_vec(data: Vec<u8>) -> anyhow::Result<Self> {
                <$type as psy_serialize::PsyCanonicalDatabaseSerializeBaseSingleFixedTemplate<{$size}>>::fx_tpl_psy_ser_from_owned_bytes_vec(data)
            }
        }

        impl $($impl_generics)* psy_serialize::PsyCanonicalDatabaseSerializeBaseMulti for $type $($where_clause)* {

            #[inline(always)]
            fn psy_ser_serialize_vec_of_self_ref(data: &[$type], write_fixed_items_count: bool) -> Vec<u8> {
                <$type as psy_serialize::PsyCanonicalDatabaseSerializeBaseMultiFixedTemplate<{$size}>>::fx_tpl_psy_ser_serialize_vec_of_self_ref(data, write_fixed_items_count)
            }

            #[inline(always)]
            fn psy_ser_serialize_vec_of_self(data: Vec<$type>, write_fixed_items_count: bool) -> Vec<u8> {
                <$type as psy_serialize::PsyCanonicalDatabaseSerializeBaseMultiFixedTemplate<{$size}>>::fx_tpl_psy_ser_serialize_vec_of_self(data, write_fixed_items_count)
            }

            #[inline(always)]
            fn psy_ser_deserialize_vec_of_self(data: &[u8], include_size_for_fixed: bool) -> anyhow::Result<Vec<Self>> {
                <$type as psy_serialize::PsyCanonicalDatabaseSerializeBaseMultiFixedTemplate<{$size}>>::fx_tpl_psy_ser_deserialize_vec_of_self(data, include_size_for_fixed)
            }
            
            #[inline(always)]
            fn psy_ser_deserialize_vec_of_self_owned(data: Vec<u8>, include_size_for_fixed: bool) -> anyhow::Result<Vec<Self>> {
                <$type as psy_serialize::PsyCanonicalDatabaseSerializeBaseMultiFixedTemplate<{$size}>>::fx_tpl_psy_ser_deserialize_vec_of_self_owned(data, include_size_for_fixed)
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



/// Internal helper macro to avoid code duplication. Do not use directly.
#[doc(hidden)]
#[macro_export]
macro_rules! __impl_psy_canonical_serialize_for_fixed_type_internal_crate {
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


        impl $($impl_generics)* crate::PsyIOReadWrite for $type $($where_clause)* {
            #[inline(always)]
            fn pio_serialized_size(&self) -> usize {
                <$type as crate::PsyIOReadWriteFixedTemplate<{$size}>>::fx_tpl_pio_serialized_size(self)
            }

            #[inline(always)]
            fn pio_write_to_io<W: psy_io::Write>(&self, writer: &mut W) -> anyhow::Result<()> {
                <$type as crate::PsyIOReadWriteFixedTemplate<{$size}>>::fx_tpl_pio_write_to_io(self, writer)
            }

            #[inline(always)]
            fn pio_read_from_io<R: psy_io::Read>(reader: &mut R) -> anyhow::Result<Self> {
                <$type as crate::PsyIOReadWriteFixedTemplate<{$size}>>::fx_tpl_pio_read_from_io(reader)
            }

            #[inline(always)]
            fn pio_get_variable_serialized_size(&self) -> usize {
                <$type as crate::PsyIOReadWriteFixedTemplate<{$size}>>::fx_tpl_pio_get_variable_serialized_size(self)
            }

            #[inline(always)]
            fn pio_write_to_io_many<W: psy_io::Write>(items: &[$type], writer: &mut W, write_fixed_items_count: bool) -> anyhow::Result<()> {
                <$type as crate::PsyIOReadWriteFixedTemplate<{$size}>>::fx_tpl_pio_write_to_io_many(items, writer, write_fixed_items_count)
            }

            #[inline(always)]
            fn pio_read_from_io_many<R: psy_io::Read>(reader: &mut R, known_size: Option<usize>) -> anyhow::Result<Vec<Self>> {
                <$type as crate::PsyIOReadWriteFixedTemplate<{$size}>>::fx_tpl_pio_read_from_io_many(reader, known_size)
            }

            #[inline(always)]
            fn pio_serialized_size_vec(items: &[$type], include_size_for_fixed: bool) -> usize {
                <$type as crate::PsyIOReadWriteFixedTemplate<{$size}>>::fx_tpl_pio_serialized_size_vec(items, include_size_for_fixed)
            }

            #[inline(always)]
            fn pio_read_many_from_ref_bytes(data: &[u8], known_count: Option<usize>) -> anyhow::Result<Vec<Self>> {
                <$type as crate::PsyIOReadWriteFixedTemplate<{$size}>>::fx_tpl_pio_read_many_from_ref_bytes(data, known_size)
            }
            // Delegate the default method to ensure consistency, even though it's defaulted in the trait

            #[inline(always)]
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

        impl $($impl_generics)* crate::PsyCanonicalDatabaseSerializeBaseSingle for $type $($where_clause)* {

            #[inline(always)]
            fn psy_ser_from_slice(data: &[u8]) -> anyhow::Result<Self> {
                <$type as crate::PsyCanonicalDatabaseSerializeBaseSingleFixedTemplate<{$size}>>::fx_tpl_psy_ser_from_slice(data)
            }

            #[inline(always)]
            fn psy_ser_to_bytes_vec(&self) -> anyhow::Result<Vec<u8>> {
                <$type as crate::PsyCanonicalDatabaseSerializeBaseSingleFixedTemplate<{$size}>>::fx_tpl_psy_ser_to_bytes_vec(self)
            }

            #[inline(always)]
            fn psy_ser_into_bytes_vec(self) -> anyhow::Result<Vec<u8>> {
                <$type as crate::PsyCanonicalDatabaseSerializeBaseSingleFixedTemplate<{$size}>>::fx_tpl_psy_ser_into_bytes_vec(self)
            }

            #[inline(always)]
            fn psy_ser_from_owned_bytes_vec(data: Vec<u8>) -> anyhow::Result<Self> {
                <$type as crate::PsyCanonicalDatabaseSerializeBaseSingleFixedTemplate<{$size}>>::fx_tpl_psy_ser_from_owned_bytes_vec(data)
            }
        }

        impl $($impl_generics)* crate::PsyCanonicalDatabaseSerializeBaseMulti for $type $($where_clause)* {

            #[inline(always)]
            fn psy_ser_serialize_vec_of_self_ref(data: &[$type], write_fixed_items_count: bool) -> Vec<u8> {
                <$type as crate::PsyCanonicalDatabaseSerializeBaseMultiFixedTemplate<{$size}>>::fx_tpl_psy_ser_serialize_vec_of_self_ref(data, write_fixed_items_count)
            }

            #[inline(always)]
            fn psy_ser_serialize_vec_of_self(data: Vec<$type>, write_fixed_items_count: bool) -> Vec<u8> {
                <$type as crate::PsyCanonicalDatabaseSerializeBaseMultiFixedTemplate<{$size}>>::fx_tpl_psy_ser_serialize_vec_of_self(data, write_fixed_items_count)
            }

            #[inline(always)]
            fn psy_ser_deserialize_vec_of_self(data: &[u8], include_size_for_fixed: bool) -> anyhow::Result<Vec<Self>> {
                <$type as crate::PsyCanonicalDatabaseSerializeBaseMultiFixedTemplate<{$size}>>::fx_tpl_psy_ser_deserialize_vec_of_self(data, include_size_for_fixed)
            }
            
            #[inline(always)]
            fn psy_ser_deserialize_vec_of_self_owned(data: Vec<u8>, include_size_for_fixed: bool) -> anyhow::Result<Vec<Self>> {
                <$type as crate::PsyCanonicalDatabaseSerializeBaseMultiFixedTemplate<{$size}>>::fx_tpl_psy_ser_deserialize_vec_of_self_owned(data, include_size_for_fixed)
            }
        }
    };
}


/// Internal helper macro to avoid code duplication. Do not use directly.
#[doc(hidden)]
#[macro_export]
macro_rules! __impl_psy_canonical_serialize_for_speedy_internal {
    (
        // The <T, U> part
        ( $($impl_generics:tt)* ),
        // The full type, e.g., MyStruct<T, U>
        $type:ty,
        // The `where T: Trait` part from the user
        ( $($user_where_clause:tt)* ),
        // The speedy trait bounds we need to add for the generics
        ( $($speedy_where_clause:tt)* )
    ) => {
        impl $($impl_generics)* psy_serialize::PsyIOReadWrite for $type
        where
            $($user_where_clause)*
            $($speedy_where_clause)*
        {
            #[inline(always)]
            fn pio_serialized_size(&self) -> usize {
                // Per plan, unwrap is acceptable as size calculation is not expected to fail.
                use speedy::Writable;
                Writable::<speedy::LittleEndian>::bytes_needed(&self).unwrap()
            }

            #[inline(always)]
            fn pio_write_to_io<W: psy_io::Write>(&self, writer: &mut W) -> anyhow::Result<()> {
                use speedy::Writable;
                self.write_to_stream_with_ctx(speedy::LittleEndian::default(), writer)
                    .map_err(anyhow::Error::from)
            }

            #[inline(always)]
            fn pio_read_from_io<R: psy_io::Read>(reader: &mut R) -> anyhow::Result<Self> {
                use speedy::Readable;
                Self::read_from_stream_buffered_with_ctx(speedy::LittleEndian::default(), reader)
                    .map_err(anyhow::Error::from)
            }

            #[inline(always)]
            fn pio_get_variable_serialized_size(&self) -> usize {
                // Speedy does not differentiate, so this is the same as the total size.
                self.pio_serialized_size() + 4 // 4 bytes for the length prefix
            }

            #[inline(always)]
            fn pio_write_to_io_many<W: psy_io::Write>(items: &[$type], writer: &mut W, write_fixed_items_count: bool) -> anyhow::Result<()> {
                    use speedy::Writable;
                    // Write items back-to-back without a length prefix.
                if write_fixed_items_count || !Self::IS_FIXED_SIZE {
                    // Speedy's slice implementation includes a length prefix.
                    items.write_to_stream_with_ctx(speedy::LittleEndian::default(), writer)?;
                } else {
                    // Write items back-to-back without a length prefix.
                    for item in items {
                        item.write_to_stream_with_ctx(speedy::LittleEndian::default(), &mut *writer)?;
                    }
                }
                Ok(())
            }
            #[inline(always)]
            fn pio_read_from_io_many<R: psy_io::Read>(reader: &mut R, known_count: Option<usize>) -> anyhow::Result<Vec<Self>> {
                use speedy::Readable;
                
                if include_size_for_fixed || !Self::IS_FIXED_SIZE {
                    // Speedy's Vec implementation reads a length prefix.
                    Vec::<Self>::read_from_stream_buffered_with_ctx(speedy::LittleEndian::default(), reader)
                        .map_err(anyhow::Error::from)
                } else {
                    // If no size is encoded, we MUST know it beforehand.
                    match known_size {
                        Some(n) => {
                            let mut vec = Vec::with_capacity(n);
                            for _ in 0..n {
                                vec.push(Self::read_from_stream_buffered_with_ctx(speedy::LittleEndian::default(), &mut *reader)?);
                            }
                            Ok(vec)
                        }
                        None => Err(anyhow::anyhow!("Cannot read items without a known size or an encoded size prefix.")),
                    }
                }
            }

            #[inline(always)]
            fn pio_serialized_size_vec(items: &[$type], include_size_for_fixed: bool) -> usize {
                use speedy::Writable;
                if include_size_for_fixed|| !Self::IS_FIXED_SIZE {
                    // Speedy's slice implementation includes the length prefix size.
                    Writable::<speedy::LittleEndian>::bytes_needed(items).unwrap()
                } else {
                    // Sum the size of each item individually.
                    items.iter().map(|item| item.pio_serialized_size()).sum()
                }
            }

            #[inline(always)]
            fn pio_read_many_from_ref_bytes(data: &[u8], known_count: Option<usize>) -> anyhow::Result<Vec<Self>> {
                let mut cursor = psy_io::Cursor::new(data);
                Self::pio_read_from_io_many(&mut cursor, known_size)
            }
        }

        impl $($impl_generics)* psy_serialize::PsyCanonicalDatabaseSerializeBaseSingle for $type
        where
            $($user_where_clause)*
            $($speedy_where_clause)*
        {
            #[inline(always)]
            fn psy_ser_from_slice(data: &[u8]) -> anyhow::Result<Self> {
                use speedy::Readable;
                // MUST use copying_data to avoid lifetime issues.
                Self::read_from_buffer_copying_data_with_ctx(speedy::LittleEndian::default(), data)
                    .map_err(anyhow::Error::from)
            }

            #[inline(always)]
            fn psy_ser_to_bytes_vec(&self) -> anyhow::Result<Vec<u8>> {
                use speedy::Writable;
                self.write_to_vec_with_ctx(speedy::LittleEndian::default()).map_err(anyhow::Error::from)
            }

            #[inline(always)]
            fn psy_ser_into_bytes_vec(self) -> anyhow::Result<Vec<u8>> {
                // No special speedy optimization for owned self, delegate to ref version.
                self.psy_ser_to_bytes_vec()
            }

            #[inline(always)]
            fn psy_ser_from_owned_bytes_vec(data: Vec<u8>) -> anyhow::Result<Self> {
                Self::psy_ser_from_slice(&data)
            }
        }

        impl $($impl_generics)* psy_serialize::PsyCanonicalDatabaseSerializeBaseMulti for $type
        where
            $($user_where_clause)*
            $($speedy_where_clause)*
        {
            #[inline(always)]
            fn psy_ser_serialize_vec_of_self_ref(data: &[$type], write_fixed_items_count: bool) -> Vec<u8> {
                // pio_write_many_to_bytes provides a Result, but this trait expects Vec<u8>.
                // We unwrap as serialization to a Vec should not fail if size calculation succeeded.
                <Self as psy_serialize::PsyIOReadWrite>::pio_write_many_to_bytes(data, write_fixed_items_count).unwrap()
            }

            #[inline(always)]
            fn psy_ser_serialize_vec_of_self(data: Vec<$type>, write_fixed_items_count: bool) -> Vec<u8> {
                Self::psy_ser_serialize_vec_of_self_ref(&data, write_fixed_items_count)
            }

            /*
            #[inline(always)]
            fn psy_ser_deserialize_vec_of_self(data: &[u8], include_size_for_fixed: bool) -> anyhow::Result<Vec<Self>> {
                use speedy::{Readable, Writable};
                if include_size_for_fixed {
                    Vec::<Self>::read_from_buffer_copying_data_with_ctx(speedy::LittleEndian::default(), data)
                        .map_err(anyhow::Error::from)
                } else {
                    // Manual iteration is required if there's no length prefix.
                    let mut items = Vec::new();
                    let mut cursor = 0;
                    while cursor < data.len() {
                        let (item_result, bytes_read) = Self::read_with_length_from_buffer_copying_data_with_ctx(speedy::LittleEndian::default(), &data[cursor..]);
                        let item = item_result?;
                        if bytes_read == 0 {
                            // This would mean an infinite loop or an error state.
                            return Err(anyhow::anyhow!("Deserialization read zero bytes, preventing progress."));
                        }
                        items.push(item);
                        cursor += bytes_read;
                    }
                    Ok(items)
                }
            }
            */

            #[inline(always)]
            fn psy_ser_deserialize_vec_of_self_owned(data: Vec<u8>, include_size_for_fixed: bool) -> anyhow::Result<Vec<Self>> {
                Self::psy_ser_deserialize_vec_of_self(&data, include_size_for_fixed)
            }
        }
    };
}

/// Implements `PsyCanonicalDatabaseSerialize` traits for a type that derives `speedy::Readable` and `speedy::Writable`.
///
/// This macro provides a highly performant bridge to the `speedy` serialization library,
/// using a canonical little-endian format.
///
/// # Usage
///
/// ## For a simple, non-generic type:
/// ```rust,ignore
/// use speedy::{Readable, Writable};
///
/// #[derive(Readable, Writable, PartialEq, Debug)]
/// struct MySimpleStruct {
///     a: u32,
///     b: i64,
/// }
///
/// impl_psy_canonical_serialize_for_speedy!(MySimpleStruct);
/// ```
///
/// ## For a generic type:
/// The macro syntax requires separating the `where` clause bounds from the generic parameters.
/// The macro will automatically add the required `speedy` trait bounds.
///
/// ```rust,ignore
/// use speedy::{Readable, Writable};
/// use std::fmt::Debug;
///
/// #[derive(Readable, Writable, PartialEq, Debug)]
/// struct MyGenericStruct<T, U> {
///     t: T,
///     u: U,
/// }
///
/// // With a `where` clause:
/// impl_psy_canonical_serialize_for_speedy!(
///     MyGenericStruct,
///     { T: Debug, U: Clone + Debug } => { T, U }
/// );
///
/// // With no extra `where` clause:
/// impl_psy_canonical_serialize_for_speedy!(
///     MyGenericStruct,
///     {} => { T, U }
/// );
/// ```
#[macro_export]
macro_rules! impl_psy_canonical_serialize_for_speedy {
    //
    // Arm 1: Generic type with a non-empty `where` clause.
    //
    (
        $type_name:ident,
        { $($where_clause:tt)+ } => { $($generics:ident),+ }
    ) => {
        $crate::__impl_psy_canonical_serialize_for_speedy_internal!(
            ( <$($generics),*> ),
            $type_name<$($generics),*>,
            // FIX: Pass only the user-provided bounds, not the 'where' keyword.
            ( $($where_clause)* ),
            // Add a leading comma to separate the speedy bounds from the user bounds.
            ( $(, $generics: speedy::Readable<'static, speedy::LittleEndian> + speedy::Writable<speedy::LittleEndian> )* )
        );
    };

    //
    // Arm 2: Generic type with an empty `where` clause.
    //
    (
        $type_name:ident,
        {} => { $($generics:ident),+ }
    ) => {
        $crate::__impl_psy_canonical_serialize_for_speedy_internal!(
            ( <$($generics),*> ),
            $type_name<$($generics),*>,
            ( ), // No user where clause.
            // FIX: Pass only the speedy bounds. No leading comma needed.
            ( $($generics: speedy::Readable<'static, speedy::LittleEndian> + speedy::Writable<speedy::Endianness::LittleEndian>),* )
        );
    };

    //
    // Arm 3: Simple, non-generic type.
    //
    ($type:ty) => {
        $crate::__impl_psy_canonical_serialize_for_speedy_internal!(
            ( ), // No generics.
            $type,
            // FIX: Add a trivial bound to prevent an empty `where` clause, which is a syntax error.
            ( Self: Sized ),
            ( )  // No extra speedy bounds needed.
        );
    };
}