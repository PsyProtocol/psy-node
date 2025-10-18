mod traits;
pub use traits::*;

/// Internal helper macro to avoid code duplication. Do not use directly.
#[doc(hidden)]
#[macro_export]
macro_rules! __impl_psy_canonical_serialize_for_fixed_type_internal {
    (
        ( $($impl_generics:tt)* ),
        $type:ty,
        ( $($where_clause:tt)* ),
        $size:expr
    ) => {

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
            fn pio_write_to_io_many<W: psy_io::Write>(items: &[$type], writer: &mut W, write_count: bool) -> anyhow::Result<()> {
                <$type as psy_serialize::PsyIOReadWriteFixedTemplate<{$size}>>::fx_tpl_pio_write_to_io_many(items, writer, write_count)
            }

            #[inline(always)]
            fn pio_read_from_io_many<R: psy_io::Read>(reader: &mut R, known_count: Option<usize>) -> anyhow::Result<Vec<Self>> {
                <$type as psy_serialize::PsyIOReadWriteFixedTemplate<{$size}>>::fx_tpl_pio_read_from_io_many(reader, known_count)
            }

            #[inline(always)]
            fn pio_serialized_size_vec(items: &[$type], include_size: bool) -> usize {
                <$type as psy_serialize::PsyIOReadWriteFixedTemplate<{$size}>>::fx_tpl_pio_serialized_size_vec(items, include_size)
            }

            #[inline(always)]
            fn pio_read_many_from_ref_bytes(data: &[u8], known_count: Option<usize>) -> anyhow::Result<Vec<Self>> {
                <$type as psy_serialize::PsyIOReadWriteFixedTemplate<{$size}>>::fx_tpl_pio_read_many_from_ref_bytes(data, known_count)
            }

            #[inline(always)]
            fn pio_write_many_to_bytes(items: &[$type], write_count: bool) -> anyhow::Result<Vec<u8>> {
                <$type as psy_serialize::PsyIOReadWriteFixedTemplate<{$size}>>::fx_tpl_pio_write_many_to_bytes(items, write_count)
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
            fn psy_ser_serialize_vec_of_self_ref(data: &[$type], write_count: bool) -> Vec<u8> {
                <$type as psy_serialize::PsyCanonicalDatabaseSerializeBaseMultiFixedTemplate<{$size}>>::fx_tpl_psy_ser_serialize_vec_of_self_ref(data, write_count)
            }

            #[inline(always)]
            fn psy_ser_serialize_vec_of_self(data: Vec<$type>, write_count: bool) -> Vec<u8> {
                <$type as psy_serialize::PsyCanonicalDatabaseSerializeBaseMultiFixedTemplate<{$size}>>::fx_tpl_psy_ser_serialize_vec_of_self(data, write_count)
            }

            #[inline(always)]
            fn psy_ser_deserialize_vec_of_self(data: &[u8], include_count_for_fixed: bool) -> anyhow::Result<Vec<Self>> {
                <$type as psy_serialize::PsyCanonicalDatabaseSerializeBaseMultiFixedTemplate<{$size}>>::fx_tpl_psy_ser_deserialize_vec_of_self(data, include_count_for_fixed)
            }
            
            #[inline(always)]
            fn psy_ser_deserialize_vec_of_self_owned(data: Vec<u8>, include_count_for_fixed: bool) -> anyhow::Result<Vec<Self>> {
                <$type as psy_serialize::PsyCanonicalDatabaseSerializeBaseMultiFixedTemplate<{$size}>>::fx_tpl_psy_ser_deserialize_vec_of_self_owned(data, include_count_for_fixed)
            }
        }
    };
}

#[macro_export]
macro_rules! impl_psy_canonical_serialize_for_fixed_type {
    ($type_name:ident, { $($where_clause:tt)+ } => { $($generics:tt)+ }, $size:expr) => {
        $crate::__impl_psy_canonical_serialize_for_fixed_type_internal!(
            ( <$($generics)*> ),
            $type_name<$($generics)*>,
            ( where $($where_clause)* ),
            $size
        );
    };
    ($type_name:ident, {} => { $($generics:tt)+ }, $size:expr) => {
        $crate::__impl_psy_canonical_serialize_for_fixed_type_internal!(
            ( <$($generics)*> ),
            $type_name<$($generics)*>,
            ( ),
            $size
        );
    };
    ($type:ty, $size:expr) => {
        $crate::__impl_psy_canonical_serialize_for_fixed_type_internal!(
            ( ),
            $type,
            ( ),
            $size
        );
    };
}

#[doc(hidden)]
#[macro_export]
macro_rules! __impl_psy_canonical_serialize_for_fixed_type_internal_crate {
    (($($impl_generics:tt)*), $type:ty, ($($where_clause:tt)*), $size:expr) => {
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
            fn pio_write_to_io_many<W: psy_io::Write>(items: &[$type], writer: &mut W, write_count: bool) -> anyhow::Result<()> {
                <$type as crate::PsyIOReadWriteFixedTemplate<{$size}>>::fx_tpl_pio_write_to_io_many(items, writer, write_count)
            }

            #[inline(always)]
            fn pio_read_from_io_many<R: psy_io::Read>(reader: &mut R, known_count: Option<usize>) -> anyhow::Result<Vec<Self>> {
                <$type as crate::PsyIOReadWriteFixedTemplate<{$size}>>::fx_tpl_pio_read_from_io_many(reader, known_count)
            }

            #[inline(always)]
            fn pio_serialized_size_vec(items: &[$type], include_size: bool) -> usize {
                <$type as crate::PsyIOReadWriteFixedTemplate<{$size}>>::fx_tpl_pio_serialized_size_vec(items, include_size)
            }

            #[inline(always)]
            fn pio_read_many_from_ref_bytes(data: &[u8], known_count: Option<usize>) -> anyhow::Result<Vec<Self>> {
                <$type as crate::PsyIOReadWriteFixedTemplate<{$size}>>::fx_tpl_pio_read_many_from_ref_bytes(data, known_count)
            }

            #[inline(always)]
            fn pio_write_many_to_bytes(items: &[$type], write_count: bool) -> anyhow::Result<Vec<u8>> {
                 <Self as crate::PsyIOReadWriteFixedTemplate<{$size}>>::fx_tpl_pio_write_many_to_bytes(items, write_count)
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
            fn psy_ser_serialize_vec_of_self_ref(data: &[$type], write_count: bool) -> Vec<u8> {
                <$type as crate::PsyCanonicalDatabaseSerializeBaseMultiFixedTemplate<{$size}>>::fx_tpl_psy_ser_serialize_vec_of_self_ref(data, write_count)
            }

            #[inline(always)]
            fn psy_ser_serialize_vec_of_self(data: Vec<$type>, write_count: bool) -> Vec<u8> {
                <$type as crate::PsyCanonicalDatabaseSerializeBaseMultiFixedTemplate<{$size}>>::fx_tpl_psy_ser_serialize_vec_of_self(data, write_count)
            }

            #[inline(always)]
            fn psy_ser_deserialize_vec_of_self(data: &[u8], include_count_for_fixed: bool) -> anyhow::Result<Vec<Self>> {
                <$type as crate::PsyCanonicalDatabaseSerializeBaseMultiFixedTemplate<{$size}>>::fx_tpl_psy_ser_deserialize_vec_of_self(data, include_count_for_fixed)
            }

            #[inline(always)]
            fn psy_ser_deserialize_vec_of_self_owned(data: Vec<u8>, include_count_for_fixed: bool) -> anyhow::Result<Vec<Self>> {
                <$type as crate::PsyCanonicalDatabaseSerializeBaseMultiFixedTemplate<{$size}>>::fx_tpl_psy_ser_deserialize_vec_of_self_owned(data, include_count_for_fixed)
            }
        }
    };
}


/// Internal helper macro to avoid code duplication. Do not use directly.
#[doc(hidden)]
#[macro_export]

macro_rules! impl_psy_canonical_serialize_for_fixed_type_crate {
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
        $crate::__impl_psy_canonical_serialize_for_fixed_type_internal_crate!(
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
        $crate::__impl_psy_canonical_serialize_for_fixed_type_internal_crate!(
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
        $crate::__impl_psy_canonical_serialize_for_fixed_type_internal_crate!(
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
macro_rules! __impl_psy_canonical_serialize_for_speedy_internal {
    (
        ( $($impl_generics:tt)* ),
        $type:ty,
        ( $($user_where_clause:tt)* ),
        ( $($speedy_where_clause:tt)* )
    ) => {
        impl $($impl_generics)* psy_serialize::PsyIOReadWrite for $type
        where
            $($user_where_clause)*
            $($speedy_where_clause)*
        {
            #[inline(always)]
            fn pio_serialized_size(&self) -> usize {
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
            fn pio_write_to_io_many<W: psy_io::Write>(items: &[$type], writer: &mut W, write_count: bool) -> anyhow::Result<()> {
                use speedy::Writable;
                if write_count {
                    // Speedy's slice `Writable` impl writes a length prefix, which is what we want.
                    items.write_to_stream_with_ctx(speedy::LittleEndian::default(), writer)?;
                } else {
                    // No length prefix desired, so we iterate and write each item individually.
                    for item in items {
                        item.write_to_stream_with_ctx(speedy::LittleEndian::default(), &mut *writer)?;
                    }
                }
                Ok(())
            }

            #[inline(always)]
            fn pio_read_from_io_many<R: psy_io::Read>(reader: &mut R, known_count: Option<usize>) -> anyhow::Result<Vec<Self>> {
                use speedy::Readable;
                match known_count {
                    Some(n) => {
                        let mut vec = Vec::with_capacity(n);
                        for _ in 0..n {
                            vec.push(Self::read_from_stream_buffered_with_ctx(speedy::LittleEndian::default(), &mut *reader)?);
                        }
                        Ok(vec)
                    }
                    None => {
                        // `known_count` is None, so we rely on Speedy to read the length prefix from the stream.
                        Vec::<Self>::read_from_stream_buffered_with_ctx(speedy::LittleEndian::default(), reader)
                            .map_err(anyhow::Error::from)
                    }
                }
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
                Self::read_from_buffer_copying_data_with_ctx(speedy::LittleEndian::default(), data)
                    .map_err(anyhow::Error::from)
            }

            #[inline(always)]
            fn psy_ser_to_bytes_vec(&self) -> anyhow::Result<Vec<u8>> {
                use speedy::Writable;
                self.write_to_vec_with_ctx(speedy::LittleEndian::default()).map_err(anyhow::Error::from)
            }
        }

        impl $($impl_generics)* psy_serialize::PsyCanonicalDatabaseSerializeBaseMulti for $type
        where
            $($user_where_clause)*
            $($speedy_where_clause)*
        {
            // The default implementations in the trait are sufficient and correct.
        }
    };
}


#[macro_export]
macro_rules! impl_psy_canonical_serialize_for_speedy {
    ($type_name:ident, { $($where_clause:tt)+ } => { $($generics:ident),+ }) => {
        $crate::__impl_psy_canonical_serialize_for_speedy_internal!(
            ( <$($generics),*> ),
            $type_name<$($generics),*>,
            ( $($where_clause)* ),
            ( $(, $generics: speedy::Readable<'static, speedy::LittleEndian> + speedy::Writable<speedy::LittleEndian> )* )
        );
    };
    ($type_name:ident, {} => { $($generics:ident),+ }) => {
        $crate::__impl_psy_canonical_serialize_for_speedy_internal!(
            ( <$($generics),*> ),
            $type_name<$($generics),*>,
            ( ),
            ( $($generics: speedy::Readable<'static, speedy::LittleEndian> + speedy::Writable<speedy::LittleEndian>),* )
        );
    };
    ($type:ty) => {
        $crate::__impl_psy_canonical_serialize_for_speedy_internal!(
            ( ),
            $type,
            ( Self: Sized ),
            ( )
        );
    };
}